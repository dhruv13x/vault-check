from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Tuple

import aiohttp

from .config import DEFAULT_BACKOFF, DEFAULT_JITTER, DEFAULT_RETRIES
from .utils import _sleep_backoff


# ----- HTTP CLIENT -----
class HTTPClient:
    """Async HTTP client with retries."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        jitter_frac: float = DEFAULT_JITTER,
    ):
        self.session = session
        self.retries = max(0, retries)
        self.backoff = max(0.0, backoff)
        self.jitter_frac = max(0.0, jitter_frac)

    async def _request(
        self, method: str, url: str, **kwargs
    ) -> Tuple[int, Dict[str, str], str]:
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    text = await resp.text()
                    resp.raise_for_status()
                    headers = dict(resp.headers)
                    return resp.status, headers, text
            except aiohttp.ClientResponseError as e:
                last_exc = e
                logging.debug("HTTP response error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exc = e
                logging.debug("HTTP network error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            await asyncio.sleep(_sleep_backoff(self.backoff, attempt, self.jitter_frac))
        raise last_exc or RuntimeError("HTTP request failed")

    async def get_json(self, url: str, **kwargs) -> Any:
        _, _, text = await self._request("GET", url, **kwargs)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text  # Fallback to text if not JSON

    async def get_text(self, url: str, **kwargs) -> str:
        _, _, text = await self._request("GET", url, **kwargs)
        return text
