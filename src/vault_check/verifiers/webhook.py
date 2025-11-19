# src/vault_check/verifiers/webhook.py

import logging

from ..utils import validate_url_format
from .base import BaseVerifier


class WebhookVerifier(BaseVerifier):
    async def verify(self, url: str | None, secret: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]BASE_WEBHOOK_URL[/bold]: {url or '(missing)'}")
        if not url or not validate_url_format(url, ["http", "https"]):
            raise ValueError("Invalid URL")
        if url.startswith("http://") and "localhost" not in url:
            logging.warning("Non-SSL (https recommended for production)")
        if not secret:
            logging.warning("WEBHOOK_SECRET_TOKEN missing (recommended)")
