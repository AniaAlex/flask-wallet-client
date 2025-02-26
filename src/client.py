#!/usr/bin/env python3

import json
import logging
import pprint
from urllib.parse import parse_qsl, urlparse

import requests
import typer
import urllib3
from bs4 import BeautifulSoup
from cryptojwt import JWT
from cryptojwt.utils import b64e
from fedservice.entity import get_verified_trust_chains
from fedservice.utils import make_federation_combo
from idpyoidc import verified_claim_name
from idpyoidc.client.defaults import CC_METHOD
from idpyoidc.key_import import import_jwks, store_under_other_id
from idpyoidc.message import Message
from idpyoidc.util import rndstr
from openid4v.message import WalletInstanceAttestationJWT

urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def get_consumer(app, issuer):
    actor = app["pid_eaa_consumer"]
    _consumer = None
    for iss in actor.issuers():
        if hash_func(iss) == issuer:
            _consumer = actor.get_consumer(iss)
            break
    return _consumer


def hash_func(value):
    _hash_method = CC_METHOD["S256"]
    _hv = _hash_method(value.encode()).digest()
    return b64e(_hv).decode("ascii")


def find_credential_issuers(app):
    res = []
    entity_type = "openid_credential_issuer"
    ta_id = list(app["federation_entity"].trust_anchors.keys())[0]
    list_resp = app["federation_entity"].do_request("list", entity_id=ta_id)

    print(f"Subordinates to TA ({ta_id}): {list_resp}")

    for entity_id in list_resp:
        # first find out if the entity is an openid credential issuer
        try:
            _metadata = app["federation_entity"].get_verified_metadata(entity_id)
        except Exception as e:
            logger.error(f"Failed subordinates metadata retrieval: {str(e)}")
            continue
        if not _metadata:  # Simple fix
            continue
        if "openid_credential_issuer" in _metadata:
            res.append(entity_id)
        print(f"Trawling beneath '{entity_id}' looking for '{entity_type}'")
        _subs = app["federation_entity"].trawl(
            ta_id, entity_id, entity_type=entity_type
        )
        if _subs:
            for sub in _subs:
                if sub not in res:
                    res.append(sub)
    return res


def find_credential_type_issuers(app, credential_issuers, credential_type):
    _oci = {}
    # Other possibility = 'PDA1Credential'
    # credential_type = "EHICCredential"
    for pid in set(credential_issuers):
        oci_metadata = app["federation_entity"].get_verified_metadata(pid)
        # logger.info(json.dumps(oci_metadata, sort_keys=True, indent=4))
        for _, cs in oci_metadata["openid_credential_issuer"][
            "credential_configurations_supported"
        ].items():
            if credential_type in cs["credential_definition"]["type"]:
                _oci[pid] = oci_metadata
                break
    return _oci


def find_issuers_of_trustmark(app, credential_issuers, credential_type):
    cred_issuer_to_use = []
    # tmi = {}
    trustmark_id = f"http://dc4eu.example.com/{credential_type}/se"

    for eid, _ in credential_issuers.items():
        _trust_chain = app["federation_entity"].get_trust_chains(eid)[0]
        _entity_conf = _trust_chain.verified_chain[-1]
        if "trust_marks" in _entity_conf:
            # tmi[eid] = []
            for _mark in _entity_conf["trust_marks"]:
                _verified_trust_mark = app["federation_entity"].verify_trust_mark(
                    _mark, check_with_issuer=True
                )
                if _verified_trust_mark:
                    # tmi[eid].append(_verified_trust_mark)
                    if _verified_trust_mark.get("id") == trustmark_id:
                        cred_issuer_to_use.append(eid)
                else:
                    print("Could not verify trust mark")
    return cred_issuer_to_use


def main(config: str):
    ephemeral_key = None

    cnf = json.loads(open(config, "r").read())
    wallet_provider = cnf["wallet_provider"]
    app = make_federation_combo(**cnf["entity"])
    app.federation_entity = app["federation_entity"]
    trust_anchor = app.federation_entity.function.trust_chain_collector.trust_anchors

    print(pprint.pp(trust_anchor))

    print("== Getting Wallet Instance Attestation ==")
    ephemeral_key = app["wallet"].mint_new_key()
    app["wallet"].context.wia_flow[ephemeral_key.kid][
        "ephemeral_key_tag"
    ] = ephemeral_key.kid
    _wia_info = app["wallet"].context.wia_flow[ephemeral_key.kid]
    wallet_instance_attestation, war_payload = app[
        "wallet"
    ].request_wallet_instance_attestation(
        wallet_provider,
        challenge="__not__applicable__",
        ephemeral_key_tag=ephemeral_key.kid,
        integrity_assertion="__not__applicable__",
        hardware_signature="__not__applicable__",
        crypto_hardware_key_tag="__not__applicable__",
    )
    _wia_info["wallet_instance_attestation"] = wallet_instance_attestation
    _jwt = JWT(key_jar=app["wallet"].keyjar)
    _jwt.msg_cls = WalletInstanceAttestationJWT
    _ass = _jwt.unpack(token=wallet_instance_attestation["assertion"])

    print(f"{wallet_instance_attestation['assertion']}\n unpacked:{_ass}")

    print("== Finding issuers in the federation through TrustMarks ==")

    msg = Message().from_dict(
        {
            "collect_id": "collect_id_ehic_122",
            "authentic_source": "EHIC:00001",
            "document_type": "EHIC",
        }
    )
    credential_type = f"{msg['document_type']}Credential"
    # Remove so not part of issuer state
    del msg["document_type"]

    issuer_state = msg.to_urlencoded()
    # All credential issuers
    credential_issuers = find_credential_issuers(app)
    print(f"Credential Issuers: {credential_issuers}")

    # Credential issuers that issue a specific credential type
    _oci = find_credential_type_issuers(app, credential_issuers, credential_type)
    credential_type_issuers = set(list(_oci.keys()))
    print(f"{credential_type} Issuers: {credential_type_issuers}")

    # Credential issuer that has a specific trust mark
    cred_issuer_to_use = find_issuers_of_trustmark(app, _oci, credential_type)
    print(f"Credential Issuer to use: {cred_issuer_to_use}")

    # Picking the first one
    cred_issuer_to_use = cred_issuer_to_use[0]

    print("== Get authz for credential ==")

    parent = app["pid_eaa_consumer"]
    _actor = parent.get_consumer(cred_issuer_to_use)
    if _actor is None:
        actor = parent.new_consumer(cred_issuer_to_use)
    else:
        actor = _actor

    wallet_entity = app["wallet"]

    b64hash = hash_func(cred_issuer_to_use)
    _redirect_uri = f"{parent.entity_id}/authz_cb/{b64hash}"
    print(_redirect_uri)

    _wia_flow = wallet_entity.context.wia_flow[ephemeral_key.kid]

    request_args = {
        "authorization_details": [
            {
                "type": "openid_credential",
                "format": "vc+sd-jwt",
                "vct": credential_type,
            }
        ],
        "response_type": "code",
        "client_id": ephemeral_key.kid,
        "redirect_uri": _redirect_uri,
        "issuer_state": issuer_state,
    }

    kwargs = {
        "state": rndstr(24),
        "behaviour_args": {
            "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"][
                "assertion"
            ],
            "client_assertion": _wia_flow["wallet_instance_attestation"]["assertion"],
        },
    }

    if "pushed_authorization" in actor.context.add_on:
        _metadata = app["federation_entity"].get_verified_metadata(actor.context.issuer)
        if (
            "pushed_authorization_request_endpoint"
            in _metadata["oauth_authorization_server"]
        ):
            kwargs["behaviour_args"]["pushed_authorization_request_endpoint"] = (
                _metadata["oauth_authorization_server"][
                    "pushed_authorization_request_endpoint"
                ]
            )

    _wia_flow["state"] = kwargs["state"]

    _service = actor.get_service("authorization")
    _service.certificate_issuer_id = cred_issuer_to_use

    req_info = _service.get_request_parameters(request_args, **kwargs)
    print("== Following SAML2 flow ==")

    print(f"Redirect to: {req_info['url']}")
    session = requests.session()
    resp = session.get(req_info["url"])
    form = BeautifulSoup(resp.content, features="html.parser").find_all("form")[1]
    form_payload = {}
    for input in form.find_all("input"):
        form_payload[input.get("name")] = "theron"
    resp = session.post(form.get("action"), data=form_payload)
    form = BeautifulSoup(resp.content, features="html.parser").find("form")
    form_payload = {}
    for input in form.find_all("input"):
        form_payload[input.get("name")] = input.get("value", "")
    resp = session.post(form.get("action"), data=form_payload, allow_redirects=False)
    assert resp.is_redirect
    url = resp.text
    issuer_string = urlparse(url).path.split("/authz_cb/")[1]

    print("== Getting token ==")
    _consumer = get_consumer(app, issuer_string)
    _consumer.finalize_auth(dict(parse_qsl(urlparse(url).query)))
    response = urlparse(url).query
    print(response)

    _wia_flow = app["wallet"].context.wia_flow[ephemeral_key.kid]

    _req_args = _consumer.context.cstate.get_set(
        _wia_flow["state"], claim=["redirect_uri", "code", "nonce"]
    )

    _args = {
        "audience": _consumer.context.issuer,
        "thumbprint": ephemeral_key.kid,
        "wallet_instance_attestation": _wia_flow["wallet_instance_attestation"][
            "assertion"
        ],
        "signing_key": wallet_entity.get_ephemeral_key(ephemeral_key.kid),
    }
    _nonce = _req_args.get("nonce", "")
    if _nonce:
        _args["nonce"] = _nonce
    _lifetime = _consumer.context.config["conf"].get("jwt_lifetime")
    if _lifetime:
        _args["lifetime"] = _lifetime

    _request_args = {
        "code": _req_args["code"],
        "grant_type": "authorization_code",
        "redirect_uri": _req_args["redirect_uri"],
        "state": _wia_flow["state"],
    }

    # Just for display purposes
    _service = _consumer.get_service("accesstoken")
    _metadata = app["federation_entity"].get_verified_metadata(_consumer.context.issuer)
    _args["endpoint"] = _metadata["oauth_authorization_server"]["token_endpoint"]
    req_info = _service.get_request_parameters(_request_args, **_args)

    # Real request
    resp = _consumer.do_request(
        "accesstoken", request_args=_request_args, state=_wia_flow["state"], **_args
    )
    pprint.pp(resp.to_dict())
    del req_info["request"]
    print("== Getting credential ==")

    trust_chains = get_verified_trust_chains(_consumer, _consumer.context.issuer)
    trust_chain = trust_chains[0]
    wallet_entity = app["wallet"]
    wallet_entity.keyjar = import_jwks(
        wallet_entity.keyjar,
        trust_chain.metadata["openid_credential_issuer"]["jwks"],
        _consumer.context.issuer,
    )

    # consumer.context.keyjar = wallet_entity.keyjar
    _consumer.keyjar = wallet_entity.keyjar
    _wia_flow = wallet_entity.context.wia_flow[ephemeral_key.kid]

    _req_args = _consumer.context.cstate.get_set(
        _wia_flow["state"], claim=["access_token"]
    )

    _request_args = {"format": "vc+sd-jwt"}

    _service = _consumer.get_service("credential")
    req_info = _service.get_request_parameters(
        _request_args, access_token=_req_args["access_token"], state=_wia_flow["state"]
    )

    vc_instance = "vc-interop-1.sunet.se"
    # Issuer Fix
    if "https://127.0.0.1:8080" in _consumer.keyjar:
        _consumer.keyjar = store_under_other_id(
            _consumer.keyjar,
            fro="https://127.0.0.1:8080",
            to=f"https://{vc_instance}",
        )
    if "https://satosa-test-1.sunet.se" in _consumer.keyjar:
        _consumer.keyjar = store_under_other_id(
            _consumer.keyjar,
            fro="https://satosa-test-1.sunet.se",
            to=f"https://{vc_instance}",
        )

    if "https://satosa-dev-1.sunet.se" in _consumer.keyjar:
        vc_instance = "vc-interop-2.sunet.se"
        _consumer.keyjar = store_under_other_id(
            _consumer.keyjar,
            fro="https://satosa-dev-1.sunet.se",
            to=f"https://{vc_instance}",
        )

    print(
        f"{vc_instance} keys: {
            _consumer.keyjar.export_jwks_as_json(issuer_id='https://{vc_instance}')
        }"
    )

    resp = _consumer.do_request(
        "credential",
        request_args=_request_args,
        access_token=_req_args["access_token"],
        state=_wia_flow["state"],
        endpoint=trust_chain.metadata["openid_credential_issuer"][
            "credential_endpoint"
        ],
    )

    print(
        f"Signed JWT: {pprint.pp(resp['credentials'])} \n verified_claim: {
            pprint.pp(resp[verified_claim_name('credential')])
        }"
    )


if __name__ == "__main__":
    typer.run(main)
