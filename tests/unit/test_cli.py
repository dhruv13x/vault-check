from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
@patch("vault_check.cli.print_summary")
@patch("vault_check.cli.VerifierRegistry")
@patch("vault_check.cli.asyncio.gather", new_callable=AsyncMock)
async def test_main_success(mock_gather, mock_registry, mock_print_summary):
    mock_registry.return_value.checks = [
        {
            "name": "test_check",
            "callable": AsyncMock(),
            "args": [],
            "kwargs": {},
            "is_warn_only": False,
        }
    ]
    mock_gather.return_value = [([], [])]

    return_code = await main(["--dry-run"])

    assert return_code == 0
    mock_print_summary.assert_called_once()
    assert mock_print_summary.call_args[0][0].status == "PASSED"


@pytest.mark.asyncio
@patch("vault_check.cli.print_summary")
@patch("vault_check.cli.VerifierRegistry")
@patch("vault_check.cli.asyncio.gather", new_callable=AsyncMock)
async def test_main_failure(mock_gather, mock_registry, mock_print_summary):
    mock_registry.return_value.checks = [
        {
            "name": "test_check",
            "callable": AsyncMock(side_effect=Exception("Test failure")),
            "args": [],
            "kwargs": {},
            "is_warn_only": False,
        }
    ]
    mock_gather.return_value = [(["Test failure"], [])]

    return_code = await main(["--dry-run"])

    assert return_code == 2
    mock_print_summary.assert_called_once()
    assert mock_print_summary.call_args[0][0].status == "FAILED"
