from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from vault_check.signals import install_signal_handlers


def test_install_signal_handlers():
    """Verify that signal handlers are installed correctly."""
    loop = MagicMock(spec=asyncio.AbstractEventLoop)
    install_signal_handlers(loop, [])
    assert loop.add_signal_handler.call_count == 2
