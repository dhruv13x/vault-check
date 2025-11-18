from __future__ import annotations

import logging
from typing import Optional

from ..http_client import HTTPClient
from ..utils import mask_sensitive, mask_url, validate_url_format
from .base import BaseVerifier


class AccountsAPIVerifier(BaseVerifier):
    """Verifier for Accounts API."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        api_key: Optional[str],
        api_url: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(
            f"Checking [bold]Accounts API[/bold] at {mask_url(api_url)} (key: {mask_sensitive(api_key)})"
        )
        if not api_key or not api_url:
            raise ValueError("Missing URL or key")
        if not validate_url_format(api_url, ["http", "https"]):
            raise ValueError("Invalid URL format")
        if dry_run or skip_live:
            logging.info("Accounts API: Skipping live check")
            return
        url = f"{api_url.rstrip('/')}/status"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            await self.http.get_json(url, headers=headers)
            logging.info("Accounts API ok")
            if "localhost" in api_url:
                logging.warning("Using local instance (not recommended for production)")
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")
