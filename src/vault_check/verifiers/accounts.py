# src/vault_check/verifiers/accounts.py

import logging

from ..http_client import HTTPClient
from ..utils import mask_url, validate_url_format
from .base import BaseVerifier


class AccountsAPIVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, api_key: str | None, api_url: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]Accounts API[/bold] at {mask_url(api_url)}")
        if not api_key or not api_url:
            raise ValueError("Missing URL or key")
        if not validate_url_format(api_url, ["http", "https"]):
            raise ValueError("Invalid URL format")
        if not dry_run and not skip_live:
            url = f"{api_url.rstrip('/')}/status"
            headers = {"Authorization": f"Bearer {api_key}"}
            await self.http.get_json(url, headers=headers)
