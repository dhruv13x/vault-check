# tests/unit/test_runner.py

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.runner import Runner


@pytest.mark.asyncio
async def test_runner_orchestration():
    """Verify that the runner correctly orchestrates the verifiers."""
    http_client = AsyncMock()
    runner = Runner(
        http_client=http_client,
        concurrency=1,
        db_timeout=1.0,
        retries=1,
        dry_run=True,
        skip_live=True,
        output_json=None,
        email_alert=None,
        verifiers=None,
    )

    loaded_secrets = {"CORE_PLATFORM_DB_URL": "test_db_url"}

    # We now mock VerifierBootstrap instead of VerifierRegistry directly in the Runner
    with patch("vault_check.runner.VerifierBootstrap") as mock_bootstrap_cls:
        mock_bootstrap = MagicMock()
        mock_registry = MagicMock()
        mock_registry.checks = [
            {
                "name": "Test Check",
                "callable": AsyncMock(),
                "args": [],
                "kwargs": {},
                "is_warn_only": False,
            }
        ]
        mock_bootstrap.bootstrap.return_value = mock_registry
        mock_bootstrap_cls.return_value = mock_bootstrap

        exit_code = await runner.run(loaded_secrets, "1.0.0")
        assert exit_code == 0
        mock_bootstrap.bootstrap.assert_called_with(loaded_secrets)


@pytest.mark.asyncio
async def test_runner_handles_failures():
    """Verify that the runner correctly handles verifier failures."""
    http_client = AsyncMock()
    runner = Runner(
        http_client=http_client,
        concurrency=1,
        db_timeout=1.0,
        retries=1,
        dry_run=False,
        skip_live=False,
        output_json=None,
        email_alert=None,
        verifiers=None,
    )

    failing_check = AsyncMock(side_effect=ValueError("Test Failure"))
    loaded_secrets = {"CORE_PLATFORM_DB_URL": "test_db_url"}

    with patch("vault_check.runner.VerifierBootstrap") as mock_bootstrap_cls:
        mock_bootstrap = MagicMock()
        mock_registry = MagicMock()
        mock_registry.checks = [
            {
                "name": "Failing Check",
                "callable": failing_check,
                "args": [],
                "kwargs": {},
                "is_warn_only": False,
            }
        ]
        mock_bootstrap.bootstrap.return_value = mock_registry
        mock_bootstrap_cls.return_value = mock_bootstrap

        exit_code = await runner.run(loaded_secrets, "1.0.0")
        assert exit_code == 2
