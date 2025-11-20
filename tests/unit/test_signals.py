# tests/unit/test_signals.py

import asyncio
import signal
from unittest.mock import MagicMock, patch

import pytest

from vault_check.signals import ShutdownManager, install_signal_handlers


@pytest.fixture
def mock_loop():
    """Fixture for a mocked asyncio event loop."""
    loop = MagicMock(spec=asyncio.AbstractEventLoop)
    loop.add_signal_handler = MagicMock()
    loop.remove_signal_handler = MagicMock()
    return loop


def test_shutdown_manager():
    """Verify that shutdown manager works as expected."""
    manager = ShutdownManager()
    assert not manager.is_shutting_down()
    manager.trigger()
    assert manager.is_shutting_down()


def test_install_signal_handlers(mock_loop):
    """Verify that signal handlers are installed correctly."""
    tasks = [MagicMock(spec=asyncio.Task)]
    manager = install_signal_handlers(mock_loop, tasks)

    assert isinstance(manager, ShutdownManager)
    assert len(mock_loop.add_signal_handler.call_args_list) == 2
