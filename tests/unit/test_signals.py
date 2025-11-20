import asyncio
import signal
from unittest.mock import MagicMock, patch
import pytest

from vault_check.signals import install_signal_handlers, ShutdownManager


def test_install_signal_handlers():
    mock_loop = MagicMock()
    mock_task = MagicMock()
    mock_task.done.return_value = False
    mock_tasks = [mock_task]

    shutdown_manager = install_signal_handlers(mock_loop, mock_tasks)
    assert shutdown_manager is not None
    assert not shutdown_manager.is_shutting_down()

    # Simulate a signal by calling the handler lambda
    # The lambda is registered for both SIGINT and SIGTERM
    # We can grab it from the first call to add_signal_handler
    handler_lambda = mock_loop.add_signal_handler.call_args_list[0].args[1]
    handler_lambda()

    assert shutdown_manager.is_shutting_down()
    mock_task.cancel.assert_called_once()


@pytest.mark.asyncio
async def test_shutdown_manager():
    manager = ShutdownManager()
    assert not manager.is_shutting_down()

    shutdown_task = asyncio.create_task(manager.wait())

    # Task should not be done yet
    await asyncio.sleep(0.01)
    assert not shutdown_task.done()

    manager.trigger()
    await asyncio.sleep(0.01)

    assert manager.is_shutting_down()
    assert shutdown_task.done()
