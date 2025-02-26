import json
import os
from datetime import datetime
from unittest.mock import patch

import pytest

from euwallet_cli.utils import SaveLoadManager


@patch("euwallet_cli.utils.logger")
def test_save_received_verifiable_credentials(mock_logger, tmp_path):
    """Test that verifiable credentials are correctly saved to a file."""
    test_path = tmp_path / "local"

    with patch("euwallet_cli.utils.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 3, 15, 23, 11, 12, 432048)

        request_result = {"credential": "test-data"}
        message_origin = "test-origin"
        credential_issuer_to_use = "http://test-issuer.se"

        SaveLoadManager.save_received_verifiable_credentials(
            request_result, message_origin, credential_issuer_to_use, test_path
        )

    expected_full_path = os.path.join(
        tmp_path,
        "local",
        "verifiable_credentials",
        "test-issuer.se",
        "20220315_231112",
    )

    assert os.path.exists(f"{expected_full_path}.json")

    with open(f"{expected_full_path}.json", "r") as f:
        data = json.load(f)

    assert data["message_origin"] == message_origin
    assert data["timestamp"] == "20220315_231112"
    assert data["verifiable_credentials"] == request_result

    mock_logger.info.assert_called_with(
        f"Verifiable Credentials saved: {expected_full_path}"
    )


@patch("euwallet_cli.utils.logger")
def test_failed_to_save_wrong_format(mock_logger, tmp_path):
    """Test that verifiable credentials are correctly saved to a file."""
    test_path = tmp_path / "local"
    with patch("euwallet_cli.utils.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime(2022, 3, 15, 23, 11, 12, 432048)

        request_result = {"test-data"}
        message_origin = "test-origin"
        credential_issuer_to_use = "http://test-issuer.se"
        with pytest.raises(TypeError):
            SaveLoadManager.save_received_verifiable_credentials(
                request_result, message_origin, credential_issuer_to_use, test_path
            )

    mock_logger.error.assert_called_with(
        "Fail while saving verifiable credentials: Object of type set is not JSON serializable"
    )
