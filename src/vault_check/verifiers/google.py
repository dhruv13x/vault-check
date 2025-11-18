import logging

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class GoogleOAuthVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, client_id: str | None, client_secret: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        if not client_id and not client_secret:
            logging.info("Google OAuth optional, not set")
            return
        if not client_id or not client_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Google OAuth[/bold] (ID: {mask_sensitive(client_id)})")
        if not dry_run and not skip_live:
            url = "https://accounts.google.com/.well-known/openid-configuration"
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or "issuer" not in data:
                raise RuntimeError("Invalid Google metadata response")
