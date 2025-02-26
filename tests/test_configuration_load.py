from unittest.mock import mock_open, patch

import pytest

from euwallet_cli.utils import SaveLoadManager


@patch("builtins.open", mock_open(read_data='{"key": "value"}'))
def test_load_config():
    """
    Test for the load_config method of SaveLoadManager
    """

    config = SaveLoadManager.load_config("test_path")

    expected_config = {"key": "value"}
    assert config == expected_config

    open.assert_called_once_with("test_path", "r")


@patch("euwallet_cli.utils.logger")
def test_load_config_file_not_found(mock_logger):
    """
    FileNotFoundError to be raised
    When configuration file is not found
    """
    with patch("builtins.open", side_effect=FileNotFoundError):
        with pytest.raises(FileNotFoundError):
            SaveLoadManager.load_config("wrong_cong_file.conf")
    mock_logger.error.assert_called_with("Configuration file not found")
