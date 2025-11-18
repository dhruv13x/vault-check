from __future__ import annotations

import logging
import re
from typing import Optional

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class TelegramAPIVerifier(BaseVerifier):
    """Verifier for Telegram API credentials."""

    async def verify_api_id(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(
            f"Checking [bold]API_ID[/bold]: {mask_sensitive(val) if val else '(missing)'}"
        )
        if not val:
            raise ValueError("API_ID missing")
        try:
            if int(val) <= 0:
                raise ValueError("Must be positive integer")
            logging.info("API_ID ok")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")

    async def verify_api_hash(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]API_HASH[/bold] (masked: {mask_sensitive(val)})")
        if not val:
            raise ValueError("API_HASH missing")
        if not re.match(r"^[0-9a-fA-F]{32}$", val):
            logging.warning("Non-standard format; verify manually")
        logging.info("API_HASH ok")


class TelegramIDVerifier(BaseVerifier):
    """Verifier for Telegram IDs."""

    async def verify_owner_id(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]OWNER_TELEGRAM_ID[/bold]: {val or '(missing)'}")
        if not val:
            raise ValueError("OWNER_TELEGRAM_ID missing")
        try:
            if int(val) <= 0:
                raise ValueError("Must be positive")
            logging.info("OWNER_TELEGRAM_ID ok")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")

    async def verify_admin_ids(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]ADMIN_USER_IDS[/bold]: {val or '(none)'}")
        if not val:
            logging.info("ADMIN_USER_IDS optional")
            return
        try:
            ids = [int(x.strip()) for x in val.split(",") if x.strip()]
            if any(i <= 0 for i in ids):
                raise ValueError("All must be positive")
            logging.info(f"ADMIN_USER_IDS ok (count={len(ids)})")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")


class TelegramBotVerifier(BaseVerifier):
    """Verifier for Telegram bot tokens."""

    def __init__(self, http: HTTPClient):
        self.http = http
        self._re = re.compile(r"^\d+:[A-Za-z0-9_\-]+$")

    async def verify_bot_token(
        self,
        bot_name: str,
        token: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(
            f"Checking [bold]{bot_name}[/bold] (masked: {mask_sensitive(token)})"
        )
        if not token:
            raise ValueError(f"{bot_name} missing")
        if not self._re.match(token):
            logging.warning(f"{bot_name} non-standard format")
        if dry_run or skip_live:
            logging.info(f"{bot_name}: Skipping live check")
            return
        url = f"https://api.telegram.org/bot{token}/getMe"
        try:
            data = await self.http.get_json(url)
            if isinstance(data, str):
                raise RuntimeError("Unexpected non-JSON response from Telegram")
            if not data.get("ok"):
                raise RuntimeError(data.get("description", "unknown"))
            logging.info(
                f"{bot_name} valid -> Bot: {data['result'].get('username', 'unknown')}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")
