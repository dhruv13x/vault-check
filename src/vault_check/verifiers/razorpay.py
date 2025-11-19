# src/vault_check/verifiers/razorpay.py

import logging

import aiohttp

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class RazorpayVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, key_id: str | None, key_secret: str | None, webhook_secret: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        if not key_id and not key_secret:
            logging.info("Razorpay optional, not set")
            return
        if not key_id or not key_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Razorpay[/bold] (ID: {mask_sensitive(key_id)})")
        if not webhook_secret:
            logging.warning("RAZORPAY_WEBHOOK_SECRET missing (recommended)")
        if not dry_run and not skip_live:
            url = "https://api.razorpay.com/v1/plans"
            auth = aiohttp.BasicAuth(key_id, key_secret)
            await self.http.get_json(url, auth=auth)
