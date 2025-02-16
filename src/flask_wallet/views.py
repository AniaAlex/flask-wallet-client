import logging
from flask import jsonify
import werkzeug
from cryptojwt import JWT
from cryptojwt.utils import b64e
from fedservice.entity import get_verified_trust_chains
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import send_from_directory
from idpyoidc import verified_claim_name
from idpyoidc.client.defaults import CC_METHOD
from idpyoidc.key_import import import_jwks
from idpyoidc.key_import import store_under_other_id
from idpyoidc.message import Message
from idpyoidc.util import rndstr
from openid4v.message import WalletInstanceAttestationJWT
import pdb
import json
import os  


#wallet_provider
#wallet_instance_request
# qr_code 
#authz => auth_cb/<dsfsdf>


logger = logging.getLogger(__name__)

entity = Blueprint('entity', __name__, url_prefix='')

# Get the current directory where the script is located
json_file_path = "session_data.json"
def hash_func(value):
    _hash_method = CC_METHOD["S256"]
    _hv = _hash_method(value.encode()).digest()
    return b64e(_hv).decode("ascii")


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


@entity.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@entity.route('/')
def index():
    return render_template('base.html')


@entity.route('/img/<path:path>')
def send_image(path):
    return send_from_directory('img', path)


@entity.route('/wallet_provider')
def wallet_provider():
    wp_id = request.args["entity_id"]
    #session["wallet_provider_id"] = wp_id
    session_data = {
    "wallet_provider_id": wp_id
}

    # Define the path of the JSON file (same directory)
    json_file_path = "session_data.json"

    # Write the session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)
    wallet_entity = current_app.server["wallet"]
    print(wallet_entity)

    trust_chain = wallet_entity.get_trust_chains(wp_id)
    print(trust_chain)

    return jsonify("/wallet_provider --- success")
  


@entity.route('/wallet_attestation_issuance')
def wai():
    return render_template('wallet_attestation_issuance.html')


@entity.route('/wallet_instance_request')
def wir():
    with open(json_file_path, "r") as json_file:
            session_data = json.load(json_file)
    ####what is attestation request 
    # This is where the attestation request is constructed and sent to the Wallet Provider.
    # And where the response is unpacked.
    wallet_entity = current_app.server["wallet"]
    #wallet_provider_id = session["wallet_provider_id"]

    #session_data
    wallet_provider_id=session_data["wallet_provider_id"]
    ##wallet_provider_id="https://openidfed-dev-1.sunet.se:5001"

    ephemeral_key = wallet_entity.mint_new_key()
    
    print("----EPHEMERAL_KEY----")
    print(ephemeral_key)

    # Check if the JSON file already exists
    if os.path.exists(json_file_path):
        # Load existing data from the file
        with open(json_file_path, "r") as json_file:
            session_data = json.load(json_file)
    else:
        # If the file doesn't exist, initialize an empty dictionary
        session_data = {}

    # Add or update the wallet_provider_id in the session data
    session_data["ephemeral_key_tag"] = ephemeral_key.kid

    # Save the updated session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)

    session["ephemeral_key_tag"] = ephemeral_key.kid

    

    wallet_entity.context.wia_flow[ephemeral_key.kid]["ephemeral_key_tag"] = ephemeral_key.kid
    pdb.set_trace()
    _wia_info = wallet_entity.context.wia_flow[ephemeral_key.kid]

    wallet_instance_attestation, war_payload = wallet_entity.request_wallet_instance_attestation(
        wallet_provider_id,
        challenge="__not__applicable__",
        ephemeral_key_tag=ephemeral_key.kid,
        integrity_assertion="__not__applicable__",
        hardware_signature="__not__applicable__",
        crypto_hardware_key_tag="__not__applicable__"
    )

    _wia_info["wallet_instance_attestation"] = wallet_instance_attestation

    _jwt = JWT(key_jar=wallet_entity.keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation["assertion"])

    print("----REQUEST-ARGS----")
    print(war_payload)
    print("----ATTESTATION----")
    print(_ass)

    return jsonify("/wallet_instance_request --- success")

    # return render_template('wallet_instance_attestation_request.html',
    #                        request_args=war_payload,
    #                        wallet_instance_attestation=_ass,
    #                        response_headers=_ass.jws_header)


def find_credential_issuers():
    res = []
    entity_type = "openid_credential_issuer"
    ta_id = list(current_app.federation_entity.trust_anchors.keys())[0]
    list_resp = current_app.federation_entity.do_request('list', entity_id=ta_id)

    logger.debug(f"Subordinates to TA ({ta_id}): {list_resp}")
    for entity_id in list_resp:
        # first find out if the entity is an openid credential issuer
        _metadata = current_app.federation_entity.get_verified_metadata(entity_id)
        if not _metadata:  # Simple fix
            continue
        if "openid_credential_issuer" in _metadata:
            res.append(entity_id)
        logger.debug(
            f"Trawling beneath '{entity_id}' looking for '{entity_type}'")
        _subs = current_app.federation_entity.trawl(ta_id, entity_id, entity_type=entity_type)
        if _subs:
            for sub in _subs:
                if sub not in res:
                    res.append(sub)
    return res


def find_credential_type_issuers(credential_issuers, credential_type):
    _oci = {}
    # Other possibility = 'PDA1Credential'
    # credential_type = "EHICCredential"
    for pid in set(credential_issuers):
        oci_metadata = current_app.federation_entity.get_verified_metadata(pid)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for id, cs in oci_metadata['openid_credential_issuer'][
            "credential_configurations_supported"].items():
            if credential_type in cs["credential_definition"]["type"]:
                _oci[pid] = oci_metadata
                break
    return _oci


def find_issuers_of_trustmark(credential_issuers, credential_type):
    cred_issuer_to_use = []
    # tmi = {}
    trustmark_id = f'http://dc4eu.example.com/{credential_type}/se'

    for eid, metadata in credential_issuers.items():
        _trust_chain = current_app.federation_entity.get_trust_chains(eid)[0]
        _entity_conf = _trust_chain.verified_chain[-1]
        if "trust_marks" in _entity_conf:
            # tmi[eid] = []
            for _mark in _entity_conf["trust_marks"]:
                _verified_trust_mark = current_app.federation_entity.verify_trust_mark(
                    _mark, check_with_issuer=True)
                if _verified_trust_mark:
                    # tmi[eid].append(_verified_trust_mark)
                    if _verified_trust_mark.get("id") == trustmark_id:
                        cred_issuer_to_use.append(eid)
                else:
                    logger.warning("Could not verify trust mark")

    return cred_issuer_to_use


@entity.route('/qr_code')
def qr_code():
    msg = Message().from_urlencoded(request.url.split("?")[1])
    credential_type = f"{msg['document_type']}Credential"
    # Remove so not part of issuer state
    del msg["document_type"]

    session["issuer_state"] = msg.to_urlencoded()
    # credential_type = "EHICCredential"

     # Check if the JSON file already exists
    if os.path.exists(json_file_path):
        # Load existing data from the file
        with open(json_file_path, "r") as json_file:
            session_data = json.load(json_file)
    else:
        # If the file doesn't exist, initialize an empty dictionary
        session_data = {}
    session_data["issuer_state"] = msg.to_urlencoded()
    # Save the updated session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)


    # All credential issuers
    credential_issuers = find_credential_issuers()
    logger.debug(f"Credential Issuers: {credential_issuers}")

    # Credential issuers that issue a specific credential type
    _oci = find_credential_type_issuers(credential_issuers, credential_type)
    credential_type_issuers = set(list(_oci.keys()))
    logger.debug(f"{credential_type} Issuers: {credential_type_issuers}")

    # Credential issuer that has a specific trust mark
    cred_issuer_to_use = find_issuers_of_trustmark(_oci, credential_type)
    logger.debug(f"Credential Issuer to use: {cred_issuer_to_use}")

    print("---ISSUER-TO-USE---")
    print(cred_issuer_to_use[0])


    session["cred_issuer_to_use"] = cred_issuer_to_use[0]

    session_data["cred_issuer_to_use"] = cred_issuer_to_use[0]

    session["credential_type"] = credential_type
    session_data["credential_type"] = credential_type
  

    # Save the updated session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)

    return jsonify("/qr_code --- success")

    # return render_template('picking_credential_issuer.html',
    #                        credential_type=credential_type,
    #                        credential_issuers=credential_issuers,
    #                        credential_type_issuers=credential_type_issuers,
    #                        credential_issuer_to_use=cred_issuer_to_use)


@entity.route('/picking_ehic_issuer')
def picking_ehic_issuer():
    credential_type = "EHICCredential"

    # All credential issuers
    credential_issuers = find_credential_issuers()
    logger.debug(f"Credential Issuers: {credential_issuers}")

    # Credential issuers that issue a specific credential type
    _oci = find_credential_type_issuers(credential_issuers, credential_type)
    cred_issuers = set(list(_oci.keys()))
    logger.debug(f"{credential_type} Issuers: {cred_issuers}")

    # Credential issuer that has a specific trust mark
    cred_issuer_to_use = find_issuers_of_trustmark(_oci, credential_type)
    logger.debug(f"Credential Issuer to use: {cred_issuer_to_use}")

    session["cred_issuer_to_use"] = cred_issuer_to_use[0]
    session["credential_type"] = credential_type

    return render_template('picking_pid_issuer.html',
                           credential_issuers=credential_issuers,
                           credential_type__issuers=cred_issuer_to_use,
                           cred_issuer_to_use=cred_issuer_to_use)


@entity.route('/picking_pda1_issuer')
def picking_pda1_issuer():
    credential_type = "PDA1Credential"

    # All credential issuers
    credential_issuers = find_credential_issuers()
    logger.debug(f"Credential Issuers: {credential_issuers}")

    # Credential issuers that issue a specific credential type
    _oci = find_credential_type_issuers(credential_issuers, credential_type)
    cred_issuers = set(list(_oci.keys()))
    logger.debug(f"{credential_type} Issuers: {cred_issuers}")

    # Credential issuer that has a specific trust mark
    cred_issuer_to_use = find_issuers_of_trustmark(_oci, credential_type)
    logger.debug(f"Credential Issuer to use: {cred_issuer_to_use}")

    session["cred_issuer_to_use"] = cred_issuer_to_use[0]
    session["credential_type"] = credential_type

    return render_template('picking_pid_issuer.html',
                           credential_issuers=credential_issuers,
                           credential_type__issuers=cred_issuer_to_use,
                           cred_issuer_to_use=cred_issuer_to_use)


CRED_CHOICE = {
    "EHICCredential": "authentic_source=authentic_source_se&document_type=EHIC&collect_id=collect_id_10",
    "PDA1Credential": "authentic_source=authentic_source_dk&document_type=PDA1&collect_id=collect_id_20"
}


@entity.route('/authz')
def authz():
    #get values from session data instead of securedsessioncookie
    with open(json_file_path, 'r') as f:
        session_data=json.load(f)
    



    #pid_issuer = session["cred_issuer_to_use"]
   
    
    # pid issuer from session data instead 
    pid_issuer=session_data["cred_issuer_to_use"]


    parent = current_app.server["pid_eaa_consumer"]
    pdb.set_trace()
    _actor = parent.get_consumer(pid_issuer)


    if _actor is None:
        actor = parent.new_consumer(pid_issuer)
    else:
        actor = _actor

    wallet_entity = current_app.server["wallet"]

    b64hash = hash_func(pid_issuer)


    _redirect_uri = f"{parent.entity_id}/authz_cb/{b64hash}"


    session["redirect_uri"] = _redirect_uri

    session_data["redirect_uri"]=_redirect_uri

   


    pdb.set_trace()
    #_key_tag = session["ephemeral_key_tag"]

    _key_tag=session_data["ephemeral_key_tag"]





   
    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    request_args = {
        "authorization_details": [{
            "type": "openid_credential",
            "format": "vc+sd-jwt",
            #"vct": session["credential_type"]
            "vct": session_data["credential_type"]
        }],
        "response_type": "code",
        "client_id": _key_tag,
        "redirect_uri": _redirect_uri,
        "issuer_state": session_data["issuer_state"]
        #"issuer_state": session["issuer_state"]
    }
    session["authz_req_args"] = request_args

    #save in session data
     
    session_data["authz_req_args"]= request_args
    
   

    kwargs = {
        "state": rndstr(24),
        "behaviour_args": {
            "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"]["assertion"],
            "client_assertion": _wia_flow["wallet_instance_attestation"]["assertion"]
        }
    }

    if "pushed_authorization" in actor.context.add_on:
        _metadata = current_app.federation_entity.get_verified_metadata(actor.context.issuer)
        if "pushed_authorization_request_endpoint" in _metadata["oauth_authorization_server"]:
            kwargs["behaviour_args"]["pushed_authorization_request_endpoint"] = _metadata[
                "oauth_authorization_server"]["pushed_authorization_request_endpoint"]

    _wia_flow["state"] = kwargs["state"]

    _service = actor.get_service("authorization")
    _service.certificate_issuer_id = pid_issuer

    req_info = _service.get_request_parameters(request_args, **kwargs)

    session["auth_req_uri"] = req_info['url']

    session_data["auth_req_uri"] = req_info['url']

    #save to serssion data
    # Save the updated session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)


    logger.info(f"Redirect to: {req_info['url']}")
    redir = redirect(req_info["url"])
    redir.status_code = 302
    return redir


# @entity.route('/qr_code')
# def qr_code():
#     pid_issuer = session["cred_issuer_to_use"]
#     parent = current_app.server["pid_eaa_consumer"]
#     _actor = parent.get_consumer(pid_issuer)
#     if _actor is None:
#         actor = parent.new_consumer(pid_issuer)
#     else:
#         actor = _actor
#
#     wallet_entity = current_app.server["wallet"]
#
#     b64hash = hash_func(pid_issuer)
#     _redirect_uri = f"{parent.entity_id}/authz_cb/{b64hash}"
#     session["redirect_uri"] = _redirect_uri
#
#     _key_tag = session["ephemeral_key_tag"]
#     _wia_flow = wallet_entity.context.wia_flow[_key_tag]
#
#     msg = Message(authentic_source=request.form["authentic_source"],
#                   collect_id=request.form["collect_id"],
#                   # document_type=request.form["document_type"],
#                   )
#
#     _credential_type = f"{request.form['document_type']}Credential"
#
#     request_args = {
#         "authorization_details": [{
#             "type": "openid_credential",
#             "format": "vc+sd-jwt",
#             "vct": _credential_type
#         }],
#         "response_type": "code",
#         "client_id": _key_tag,
#         "redirect_uri": _redirect_uri,
#         "issuer_state": msg.to_urlencoded()
#     }
#     session["authz_req_args"] = request_args
#
#     kwargs = {
#         "state": rndstr(24),
#         "behaviour_args": {
#             "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"]["assertion"],
#             "client_assertion": _wia_flow["wallet_instance_attestation"]["assertion"]
#         }
#     }
#
#     if "pushed_authorization" in actor.context.add_on:
#         _metadata = current_app.federation_entity.get_verified_metadata(actor.context.issuer)
#         if "pushed_authorization_request_endpoint" in _metadata["oauth_authorization_server"]:
#             kwargs["behaviour_args"]["pushed_authorization_request_endpoint"] = _metadata[
#                 "oauth_authorization_server"]["pushed_authorization_request_endpoint"]
#
#     _wia_flow["state"] = kwargs["state"]
#
#     _service = actor.get_service("authorization")
#     _service.certificate_issuer_id = pid_issuer
#
#     req_info = _service.get_request_parameters(request_args, **kwargs)
#
#     session["auth_req_uri"] = req_info['url']
#     logger.info(f"Redirect to: {req_info['url']}")
#     redir = redirect(req_info["url"])
#     redir.status_code = 302
#     return redir
#

def get_consumer(issuer):
    actor = current_app.server["pid_eaa_consumer"]
    _consumer = None
    pdb.set_trace()
    for iss in actor.issuers():
        if hash_func(iss) == issuer:
            _consumer = actor.get_consumer(iss)
            break

    return _consumer


@entity.route('/authz_cb/<issuer>')
def authz_cb(issuer):
    with open(json_file_path, 'r') as f:
        session_data=json.load(f)
    _consumer = get_consumer(issuer)
    print('----_CONSUMER---/authz_cb/<issuer>---')
    print(_consumer)

    # if _consumer is None
    # -- some error message

    _consumer.finalize_auth(request.args)
    session["issuer"] = issuer
    session_data["issuer"] = issuer

    #save to serssion data
    # Save the updated session data to the JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(session_data, json_file, indent=4)

    return jsonify(f"/authz_cb/<issuer>--success{session_data["authz_req_args"]}")

    # return render_template('authorization.html',
    #                        par_request=session["authz_req_args"],
    #                        auth_req_uri=session["auth_req_uri"],
    #                        response=request.args.to_dict())


@entity.route('/token')
def token():
    with open(json_file_path, "r") as json_file:
        session_data=json.load(json_file)
    

    #consumer = get_consumer(session["issuer"])
    consumer= get_consumer(session_data["issuer"])

    wallet_entity = current_app.server["wallet"]
    
    #_key_tag = session["ephemeral_key_tag"]
    _key_tag=session_data["ephemeral_key_tag"]
    pdb.set_trace()

    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    _req_args = consumer.context.cstate.get_set(_wia_flow["state"],
                                                claim=["redirect_uri", "code", "nonce"])

    _args = {
        "audience": consumer.context.issuer,
        "thumbprint": _key_tag,
        "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"]["assertion"],
        "signing_key": wallet_entity.get_ephemeral_key(_key_tag)
    }
    _nonce = _req_args.get("nonce", "")
    if _nonce:
        _args["nonce"] = _nonce
    _lifetime = consumer.context.config["conf"].get("jwt_lifetime")
    if _lifetime:
        _args["lifetime"] = _lifetime

    _request_args = {
        "code": _req_args["code"],
        "grant_type": "authorization_code",
        "redirect_uri": _req_args["redirect_uri"],
        "state": _wia_flow["state"]
    }

    # Just for display purposes
    _service = consumer.get_service("accesstoken")
    _metadata = current_app.federation_entity.get_verified_metadata(consumer.context.issuer)
    _args["endpoint"] = _metadata['oauth_authorization_server']['token_endpoint']
    req_info = _service.get_request_parameters(_request_args, **_args)

    # Real request
    resp = consumer.do_request(
        "accesstoken",
        request_args=_request_args,
        state=_wia_flow["state"],
        **_args
    )
    del req_info["request"]
    return jsonify(f"token ---- success {resp}")
    #return render_template('token.html', request=req_info, response=resp)


@entity.route('/credential')
def credential():
    with open(json_file_path, "r") as json_file:
        session_data=json.load(json_file)
    
    #consumer = get_consumer(session["issuer"])
    
    #from session 
    consumer = get_consumer(session_data["issuer"])
    pdb.set_trace()



    trust_chains = get_verified_trust_chains(consumer, consumer.context.issuer)
    trust_chain = trust_chains[0]
    wallet_entity = current_app.server["wallet"]

    # TODO: wallet_entity import_jwks check later 
    # Author: [Anna Alexeeva ]
    # wallet_entity = import_jwks(wallet_entity.keyjar,
    #                                    trust_chain.metadata["openid_credential_issuer"]["jwks"],
    #                                    consumer.context.issuer)



    # consumer.context.keyjar = wallet_entity.keyjar
    consumer.keyjar = wallet_entity.keyjar

    # consumer key tag 
    #_key_tag = session["ephemeral_key_tag"]


    _key_tag = session_data["ephemeral_key_tag"]

    _wia_flow = wallet_entity.context.wia_flow[_key_tag]

    _req_args = consumer.context.cstate.get_set(_wia_flow["state"], claim=["access_token"])

    _request_args = {
        "format": "vc+sd-jwt"
    }

    _service = consumer.get_service("credential")
    req_info = _service.get_request_parameters(_request_args,
                                               access_token=_req_args["access_token"],
                                               state=_wia_flow["state"])

    # Issuer Fix
    if "https://127.0.0.1:8080" in consumer.keyjar:
        consumer.keyjar = store_under_other_id(consumer.keyjar, fro="https://127.0.0.1:8080",
                                               to="https://vc-interop-1.sunet.se")
    if "https://satosa-test-1.sunet.se" in consumer.keyjar:
        consumer.keyjar = store_under_other_id(consumer.keyjar, fro="https://satosa-test-1.sunet.se",
                                               to="https://vc-interop-1.sunet.se")

    logger.debug(
        f"vc-interop-1.sunet.se keys: {consumer.keyjar.export_jwks_as_json(issuer_id='https://vc-interop-1.sunet.se')}")

    resp = consumer.do_request(
        "credential",
        request_args=_request_args,
        access_token=_req_args["access_token"],
        state=_wia_flow["state"],
        endpoint=trust_chain.metadata['openid_credential_issuer']['credential_endpoint']
    )

    del req_info["request"]
    # return render_template('credential.html', request=req_info,
    #                        response=resp, signed_jwt=resp["credentials"][0]["credential"],
    #                        display=resp[verified_claim_name("credential")])
    return jsonify({
    "template": "credential.html",
    "request": req_info,
    "response": resp,
    "signed_jwt": resp["credentials"][0]["credential"],
    "display": resp[verified_claim_name("credential")]})


@entity.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400





