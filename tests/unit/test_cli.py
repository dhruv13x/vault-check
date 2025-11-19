# tests/unit/test_cli.py

from unittest.mock import AsyncMock, patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
@patch("vault_check.cli.Runner")
@patch("vault_check.cli.load_secrets", new_callable=AsyncMock)
async def test_main_success(mock_load_secrets, mock_runner):
    mock_runner_instance = mock_runner.return_value
    mock_runner_instance.run = AsyncMock(return_value=0)
    mock_load_secrets.return_value = {}

    return_code = await main(["--dry-run"])

    assert return_code == 0
    mock_runner_instance.run.assert_called_once()


@pytest.mark.asyncio
@patch("vault_check.cli.Runner")
@patch("vault_check.cli.load_secrets", new_callable=AsyncMock)
async def test_main_failure(mock_load_secrets, mock_runner):
    mock_runner_instance = mock_runner.return_value
    mock_runner_instance.run = AsyncMock(return_value=2)
    mock_load_secrets.return_value = {}

    return_code = await main(["--dry-run"])

    assert return_code == 2
    mock_runner_instance.run.assert_called_once()
