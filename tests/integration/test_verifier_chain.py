from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
async def test_verifier_chain_integration():
    """Verify that a chain of verifiers runs correctly."""
    with patch("vault_check.verifiers.DatabaseVerifier.verify", new_callable=AsyncMock), patch(
        "vault_check.verifiers.RedisVerifier.verify", new_callable=AsyncMock
    ):
        return_code = await main(
            [
                "--env-file",
                "tests/integration/test.env",
                "--dry-run",
            ]
        )
        assert return_code == 0


@pytest.mark.asyncio
@patch("vault_check.secrets.HTTPClient.get_json")
async def test_secret_sourcing_fallback(mock_get_json):
    """Verify that the secret sourcing falls back from Doppler to .env."""
    mock_get_json.side_effect = Exception("Doppler fetch failed")
    return_code = await main(
        [
            "--env-file",
            "tests/integration/test.env",
            "--dry-run",
        ]
    )
    assert return_code == 0


@pytest.mark.asyncio
@patch("vault_check.runner.print_summary")
async def test_cli_flow(mock_print_summary):
    """Verify the full CLI flow, from argument parsing to summary output."""
    return_code = await main(
        [
            "--env-file",
            "tests/integration/test.env",
            "--dry-run",
            "--output-json",
            "test_output.json",
        ]
    )
    assert return_code == 0
    mock_print_summary.assert_called_once()
