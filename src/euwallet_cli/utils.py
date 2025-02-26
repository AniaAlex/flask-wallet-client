import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, Union

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SaveLoadManager:
    """
    Class for loading configuration file
    Saving the final data
    """

    @staticmethod
    def load_config(config_path: str) -> Union[Dict]:
        """
        Load configuration file
        """
        try:
            with open(config_path, "r") as f:
                cnf = json.load(f)
            return cnf
        except FileNotFoundError as e:
            logger.error("Configuration file not found")
            raise e
        except Exception as e:
            logger.error(f"Error loading configuration file {str(e)}")
            raise e

    @staticmethod
    def save_received_verifiable_credentials(
        request_result: dict,
        message_origin: str,
        credential_issuer_to_use: str,
        file_path: str = "local",
    ) -> None:
        # Remove protocol from folder name for readability
        replace_url = re.sub(r"^.*?://", "", credential_issuer_to_use)

        base_path = os.path.join(file_path, "verifiable_credentials", replace_url)
        # Check if the folder exists, otherwise create
        os.makedirs(base_path, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create full path to file with the timestamp
        full_path = os.path.join(base_path, f"{timestamp}")
        try:
            metadata = {
                "message_origin": message_origin,
                "timestamp": timestamp,
                "verifiable_credentials": request_result,
            }
            with open(f"{full_path}.json", "w") as f:
                json.dump(metadata, f)

            logger.info(f"Verifiable Credentials saved: {full_path}")

        except Exception as e:
            logger.error(f"Fail while saving verifiable credentials: {str(e)}")
            raise
