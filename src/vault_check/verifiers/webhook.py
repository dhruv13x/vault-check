from __future__ import annotations

import logging
from typing import Optional

from ..utils import validate_url_format
from .base import BaseVerifier


class WebhookVerifier(BaseVerifier):
    """Verifier for webhook settings."""

    async def verify(
        self,
        url: Optional[str],
        secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(f"Checking [bold]BASE_WEBHOOK_URL[/bold]: {url or '(missing)'}")
        if not url:
            raise ValueError("BASE_WEBHOOK_URL missing")
        if not validate_url_format(url, ["http", "https"]):
            raise ValueError("Invalid URL")
        if url.startswith("http://") and "localhost" not in url:
            logging.warning("Non-SSL (https recommended for production)")
        if not secret:
            logging.warning("WEBHOOK_SECRET_TOKEN missing (recommended for security)")
        logging.info("Webhook ok")
