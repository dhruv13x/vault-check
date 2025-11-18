from __future__ import annotations

import asyncio
import logging
import signal
from typing import List


# ----- SHUTDOWN -----
class ShutdownManager:
    def __init__(self):
        self._event = asyncio.Event()

    def is_shutting_down(self) -> bool:
        return self._event.is_set()

    def trigger(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


def install_signal_handlers(
    loop: asyncio.AbstractEventLoop, tasks: List[asyncio.Task]
) -> ShutdownManager:
    mgr = ShutdownManager()

    def handle(sig: int) -> None:
        logging.warning(f"Signal {sig} received, shutting down...")
        mgr.trigger()
        for task in tasks:
            if not task.done():
                task.cancel()

    try:
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, lambda s=s: handle(s))
    except NotImplementedError:
        try:
            signal.signal(signal.SIGINT, lambda s, f: handle(signal.SIGINT))
            signal.signal(signal.SIGTERM, lambda s, f: handle(signal.SIGTERM))
        except Exception:
            pass

    return mgr
