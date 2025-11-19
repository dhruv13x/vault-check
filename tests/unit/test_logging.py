from __future__ import annotations

from unittest.mock import patch

from vault_check.logging import setup_logging


@patch("logging.basicConfig")
def test_setup_logging(mock_basic_config):
    """Verify that logging is configured correctly."""
    setup_logging("DEBUG", "json", True)
    mock_basic_config.assert_called_once()
