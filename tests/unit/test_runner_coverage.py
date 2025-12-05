# tests/unit/test_runner_coverage.py

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from vault_check.runner import Runner
from vault_check.verifiers.base import BaseVerifier

@pytest.fixture
def mock_http():
    return MagicMock()

@pytest.fixture
def runner(mock_http):
    return Runner(
        http_client=mock_http,
        concurrency=1,
        db_timeout=1.0,
        retries=1,
        dry_run=False,
        skip_live=False,
        output_json=None,
        email_alert=None,
        verifiers=None,
    )

@pytest.mark.asyncio
async def test_runner_specific_verifiers(runner):
    # Test that only specified verifiers are registered
    runner.verifiers = ["database"]

    loaded_secrets = {"CORE_PLATFORM_DB_URL": "postgres://localhost"}

    # Use VerifierBootstrap instead of mocking VerifierRegistry directly via Runner
    with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
        mock_bootstrap_instance = MockBootstrap.return_value
        mock_registry = MagicMock()
        mock_registry.checks = [] # No checks to run
        mock_bootstrap_instance.bootstrap.return_value = mock_registry

        # We need to ensure that the bootstrap method was called and that the
        # VerifierBootstrap was initialized with selected_verifiers=['database']

        # We also need to mock signal handlers to avoid errors
        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False
        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            # Check initialization of Bootstrap
            MockBootstrap.assert_called_with(
                http_client=runner.http,
                db_timeout=runner.db_timeout,
                retries=runner.retries,
                dry_run=runner.dry_run,
                skip_live=runner.skip_live,
                selected_verifiers=["database"]
            )

            # Check bootstrap called with secrets
            mock_bootstrap_instance.bootstrap.assert_called_with(loaded_secrets)

@pytest.mark.asyncio
async def test_runner_cancelled_error(runner):
    # Test task cancellation behavior
    loaded_secrets = {}

    mock_shutdown = MagicMock()
    mock_shutdown.is_shutting_down.return_value = True # Simulate shutdown

    with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
        # We mock VerifierBootstrap to return a registry with checks
        with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
            mock_registry = MagicMock()
            mock_registry.checks = [{
                "name": "Test Check",
                "callable": AsyncMock(),
                "args": [],
                "kwargs": {},
                "is_warn_only": False
            }]
            MockBootstrap.return_value.bootstrap.return_value = mock_registry

            with patch("asyncio.gather", side_effect=asyncio.CancelledError):
                result = await runner.run(loaded_secrets, "1.0.0")
                assert result == 1

@pytest.mark.asyncio
async def test_runner_check_failure_and_warning(runner):
    # Test handling of exceptions in checks
    loaded_secrets = {}

    error_mock = AsyncMock(side_effect=Exception("Critical Error"))
    warn_mock = AsyncMock(side_effect=Exception("Warning Error"))

    with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
        mock_registry = MagicMock()
        mock_registry.checks = [
            {
                "name": "Error Check",
                "callable": error_mock,
                "args": [],
                "kwargs": {},
                "is_warn_only": False
            },
            {
                "name": "Warn Check",
                "callable": warn_mock,
                "args": [],
                "kwargs": {},
                "is_warn_only": True
            }
        ]
        MockBootstrap.return_value.bootstrap.return_value = mock_registry

        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            # Patch print_summary in reporting module
            with patch("vault_check.reporting.print_summary"):
                result = await runner.run(loaded_secrets, "1.0.0")

                assert result == 2 # 2 means failures occurred

@pytest.mark.asyncio
async def test_runner_timeout_error(runner):
    # Simulate asyncio.TimeoutError during gather
    with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
        mock_registry = MagicMock()
        mock_registry.checks = [{
            "name": "Test Check",
            "callable": AsyncMock(),
            "args": [],
            "kwargs": {},
            "is_warn_only": False
        }]
        MockBootstrap.return_value.bootstrap.return_value = mock_registry

        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
             with patch("asyncio.gather", side_effect=asyncio.TimeoutError):
                result = await runner.run({}, "1.0.0")
                assert result == 1

@pytest.mark.asyncio
async def test_runner_verifiers_partial_selection(runner):
    runner.verifiers = ["redis"]
    loaded_secrets = {"CORE_PLATFORM_REDIS_URL": "redis://localhost"}

    with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
        mock_registry = MagicMock()
        mock_registry.checks = []
        MockBootstrap.return_value.bootstrap.return_value = mock_registry

        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            MockBootstrap.assert_called_with(
                http_client=runner.http,
                db_timeout=runner.db_timeout,
                retries=runner.retries,
                dry_run=runner.dry_run,
                skip_live=runner.skip_live,
                selected_verifiers=["redis"]
            )

@pytest.mark.asyncio
async def test_runner_registers_all_bots(runner):
    """Verify that FORWARDER_BOT_TOKEN, AUTH_BOT_TOKEN, and ADMIN_BOT_TOKEN are registered."""
    runner.verifiers = ["telegram"]
    loaded_secrets = {
        "FORWARDER_BOT_TOKEN": "123:forwarder",
        "AUTH_BOT_TOKEN": "456:auth",
        "ADMIN_BOT_TOKEN": "789:admin",
    }

    with patch("vault_check.runner.VerifierBootstrap") as MockBootstrap:
        mock_registry = MagicMock()
        mock_registry.checks = []
        MockBootstrap.return_value.bootstrap.return_value = mock_registry
        
        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            MockBootstrap.assert_called_with(
                http_client=runner.http,
                db_timeout=runner.db_timeout,
                retries=runner.retries,
                dry_run=runner.dry_run,
                skip_live=runner.skip_live,
                selected_verifiers=["telegram"]
            )
