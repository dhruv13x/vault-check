# tests/unit/test_signals_coverage.py

import signal
import asyncio
import pytest
from unittest.mock import MagicMock, patch
from vault_check.signals import install_signal_handlers, ShutdownManager

def test_install_signal_handlers_main_thread():
    loop = MagicMock()
    # Force NotImplementedError on add_signal_handler to test fallback to signal.signal
    loop.add_signal_handler.side_effect = NotImplementedError

    tasks = []

    with patch("signal.signal") as mock_signal:
        with patch("asyncio.current_task", return_value=MagicMock()):
             mgr = install_signal_handlers(loop, tasks)
             assert isinstance(mgr, ShutdownManager)
             # signal.signal should be called for SIGINT, SIGTERM
             assert mock_signal.call_count >= 2

def test_shutdown_manager_trigger():
    tasks = [MagicMock(), MagicMock()]

    # We test ShutdownManager directly but it doesn't take tasks in __init__
    mgr = ShutdownManager()

    assert not mgr.is_shutting_down()

    mgr.trigger()
    assert mgr.is_shutting_down()

def test_install_signal_handlers_cancellation():
    # Test that the handler cancels tasks
    loop = MagicMock()
    task = MagicMock()
    task.done.return_value = False
    tasks = [task]

    # We need to capture the handler

    mgr = install_signal_handlers(loop, tasks)

    # loop.add_signal_handler called with (sig, handler)
    # Get the handler for SIGINT
    # call_args is (args, kwargs) -> ((SIGINT, handler), {})
    handler = None
    for call in loop.add_signal_handler.call_args_list:
        if call.args[0] == signal.SIGINT:
            handler = call.args[1]
            break

    assert handler is not None

    # Call the handler
    handler()

    assert mgr.is_shutting_down()
    task.cancel.assert_called_once()
