from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class RazorpayVerifier(BaseVerifier):
    """Verifier for Razorpay credentials."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        key_id: Optional[str],
        key_secret: Optional[str],
        webhook_secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        if not key_id and not key_secret and not webhook_secret:
            logging.info("Razorpay optional, not set")
            return
        if not key_id or not key_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Razorpay[/bold] (ID: {mask_sensitive(key_id)})")
        if not webhook_secret:
            logging.warning("WEBHOOK_SECRET missing (recommended for security)")
        if dry_run or skip_live:
            logging.info("Razorpay: Skipping live check")
            return
        url = "https://api.razorpay.com/v1/plans"
        auth = aiohttp.BasicAuth(key_id, key_secret)
        try:
            await self.http.get_json(url, auth=auth)
            logging.info("Razorpay ok")
        except aiohttp.ClientResponseError as e:
            if getattr(e, "status", None) == 401:
                raise ValueError("Invalid credentials")
            raise
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")
