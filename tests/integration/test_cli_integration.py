# tests/integration/test_cli_integration.py

from unittest.mock import patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
@patch("vault_check.runner.send_email_alert")
async def test_cli_integration_dry_run(mock_send_email_alert):
    return_code = await main(
        ["--env-file", "tests/integration/test.env", "--dry-run"]
    )
    assert return_code == 0
    mock_send_email_alert.assert_not_called()
