from __future__ import annotations

import logging
from typing import Optional

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class GoogleOAuthVerifier(BaseVerifier):
    """Verifier for Google OAuth credentials."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        client_id: Optional[str],
        client_secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        if not client_id and not client_secret:
            logging.info("Google OAuth optional, not set")
            return
        if not client_id or not client_secret:
            raise ValueError("Incomplete keys")
        logging.info(
            f"Checking [bold]Google OAuth[/bold] (ID: {mask_sensitive(client_id)})"
        )
        if dry_run or skip_live:
            logging.info("Google OAuth: Skipping live check")
            return
        # New: Basic metadata check
        url = "https://accounts.google.com/.well-known/openid-configuration"
        try:
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or "issuer" not in data:
                raise RuntimeError("Invalid Google metadata response")
            logging.info("Google OAuth metadata ok")
        except Exception as e:
            raise RuntimeError(f"Metadata check failed: {e}")
