# src/vault_check/verifiers/jwt.py

import logging

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class JWTSecretVerifier(BaseVerifier):
    async def verify(self, key: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]JWT_SECRET[/bold] (masked: {mask_sensitive(key)})")
        if not key:
            raise ValueError("JWT_SECRET missing")
        if len(key) < 32:
            raise ValueError("JWT_SECRET too short (>=32 recommended)")
        check_entropy(key)


class JWTExpirationVerifier(BaseVerifier):
    async def verify(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]JWT_EXPIRATION_MINUTES[/bold]: {val or '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")
        if int(val) > 1440:
            logging.warning(f"JWT expiration too long ({val} min > 1 day)")
