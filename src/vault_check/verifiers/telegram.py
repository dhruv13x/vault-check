import logging
import re

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class TelegramAPIVerifier(BaseVerifier):
    async def verify_api_id(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]API_ID[/bold]: {mask_sensitive(val) if val else '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")

    async def verify_api_hash(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]API_HASH[/bold] (masked: {mask_sensitive(val)})")
        if not val or not re.match(r"^[0-9a-fA-F]{32}$", val):
            raise ValueError("Invalid format")


class TelegramIDVerifier(BaseVerifier):
    async def verify_owner_id(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]OWNER_TELEGRAM_ID[/bold]: {val or '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")

    async def verify_admin_ids(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]ADMIN_USER_IDS[/bold]: {val or '(none)'}")
        if val:
            if not all(x.strip().isdigit() for x in val.split(",")):
                raise ValueError("All IDs must be numeric")


class TelegramBotVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify_bot_token(
        self, bot_name: str, token: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{bot_name}[/bold] (masked: {mask_sensitive(token)})")
        if not token:
            raise ValueError(f"{bot_name} missing")
        if not re.match(r"^\d+:[A-Za-z0-9_\-]+$", token):
            logging.warning(f"{bot_name} non-standard format")
        if not dry_run and not skip_live:
            url = f"https://api.telegram.org/bot{token}/getMe"
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or not data.get("ok"):
                raise RuntimeError(f"Failed: {data.get('description', 'unknown')}")
