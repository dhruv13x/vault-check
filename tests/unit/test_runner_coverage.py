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

    with patch("vault_check.runner.VerifierRegistry.add") as mock_add:
        # We need to mock install_signal_handlers to return a mock
        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False
        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            # Check that only database verifiers were added
            names = [call.args[0] for call in mock_add.call_args_list]
            assert "Core Platform DB" in names
            assert "Core Platform Redis" not in names

@pytest.mark.asyncio
async def test_runner_cancelled_error(runner):
    # Test task cancellation behavior
    loaded_secrets = {}

    mock_shutdown = MagicMock()
    mock_shutdown.is_shutting_down.return_value = True # Simulate shutdown

    with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
        # We mock VerifierRegistry class
        with patch("vault_check.runner.VerifierRegistry") as MockRegistry:
            registry_instance = MockRegistry.return_value
            # We must set .checks on the instance
            registry_instance.checks = [{
                "name": "Test Check",
                "callable": AsyncMock(),
                "args": [],
                "kwargs": {},
                "is_warn_only": False
            }]

            # sem_safe_check will raise CancelledError because is_shutting_down is True.
            # However, runner.run gathers tasks.
            # results = await asyncio.gather(*check_tasks, return_exceptions=True)
            # If sem_safe_check raises CancelledError, it's returned in results if return_exceptions=True.

            # The exception handling in runner.run is:
            # except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            #    logging.error(f"Execution stopped: {e}")
            #    return 1

            # This try/except wraps asyncio.gather.
            # If gather is cancelled, it raises CancelledError.
            # But here individual tasks are raising CancelledError inside sem_safe_check.
            # If return_exceptions=True, gather returns [CancelledError()].
            # Then loop iterates over results.
            # if isinstance(result, Exception): all_errors.append(str(result))

            # Wait, if shutdown_mgr.is_shutting_down() is True, sem_safe_check raises CancelledError.
            # Does gather raise? No, if return_exceptions=True.

            # So result will contain CancelledError.
            # Then runner returns 2 (Failed).

            # But we want to test the `except (asyncio.CancelledError)` block around gather.
            # This happens if the MAIN task waiting on gather is cancelled, or if gather itself propagates cancellation differently.

            # If we want to hit `return 1`, we need gather to raise CancelledError.

            with patch("asyncio.gather", side_effect=asyncio.CancelledError):
                result = await runner.run(loaded_secrets, "1.0.0")
                assert result == 1

@pytest.mark.asyncio
async def test_runner_check_failure_and_warning(runner):
    # Test handling of exceptions in checks
    loaded_secrets = {}

    error_mock = AsyncMock(side_effect=Exception("Critical Error"))
    warn_mock = AsyncMock(side_effect=Exception("Warning Error"))

    with patch("vault_check.runner.VerifierRegistry") as MockRegistry:
        registry_instance = MockRegistry.return_value
        registry_instance.checks = [
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

        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            # Also patch console print to avoid clutter
            with patch("vault_check.runner.print_summary"):
                result = await runner.run(loaded_secrets, "1.0.0")

                assert result == 2 # 2 means failures occurred

@pytest.mark.asyncio
async def test_runner_timeout_error(runner):
    # Simulate asyncio.TimeoutError during gather
    with patch("vault_check.runner.VerifierRegistry") as MockRegistry:
        registry_instance = MockRegistry.return_value
        registry_instance.checks = [{
            "name": "Test Check",
            "callable": AsyncMock(),
            "args": [],
            "kwargs": {},
            "is_warn_only": False
        }]

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

    with patch("vault_check.runner.VerifierRegistry") as MockRegistry:
        registry = MockRegistry.return_value
        registry.checks = []

        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            # Since we mocked registry, we check calls to it
            added_names = [call.args[0] for call in registry.add.call_args_list]
            assert "Core Platform Redis" in added_names
            assert "Core Platform DB" not in added_names

@pytest.mark.asyncio
async def test_runner_registers_all_bots(runner):
    """Verify that FORWARDER_BOT_TOKEN, AUTH_BOT_TOKEN, and ADMIN_BOT_TOKEN are registered."""
    runner.verifiers = ["telegram"]
    loaded_secrets = {
        "FORWARDER_BOT_TOKEN": "123:forwarder",
        "AUTH_BOT_TOKEN": "456:auth",
        "ADMIN_BOT_TOKEN": "789:admin",
    }

    with patch("vault_check.runner.VerifierRegistry") as MockRegistry:
        registry = MockRegistry.return_value
        registry.checks = []
        
        mock_shutdown = MagicMock()
        mock_shutdown.is_shutting_down.return_value = False

        with patch("vault_check.runner.install_signal_handlers", return_value=mock_shutdown):
            await runner.run(loaded_secrets, "1.0.0")

            # Check that all 3 bot verifiers were added
            added_names = [call.args[0] for call in registry.add.call_args_list]
            
            assert "Forwarder Bot Token" in added_names
            assert "Auth Bot Token" in added_names
            assert "Admin Bot Token" in added_names