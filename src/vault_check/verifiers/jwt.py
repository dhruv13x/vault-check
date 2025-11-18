from __future__ import annotations

import logging
from typing import Optional

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class JWTSecretVerifier(BaseVerifier):
    """Verifier for JWT secret."""

    async def verify(
        self, key: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(
            f"Checking [bold]JWT_SECRET[/bold] (masked: {mask_sensitive(key)})"
        )
        if not key:
            raise ValueError("JWT_SECRET missing")
        if len(key) < 32:
            raise ValueError("JWT_SECRET too short (>=32 recommended)")
        check_entropy(key)  # New: entropy check
        logging.info("JWT_SECRET ok")


class JWTExpirationVerifier(BaseVerifier):
    """Verifier for JWT expiration."""

    async def verify(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(
            f"Checking [bold]JWT_EXPIRATION_MINUTES[/bold]: {val or '(missing)'}"
        )
        if not val:
            raise ValueError("JWT_EXPIRATION_MINUTES missing")
        try:
            minutes = int(val)
            if minutes <= 0:
                raise ValueError("Must be positive integer")
            if minutes > 1440:  # New: warn on excessive expiration
                logging.warning(f"JWT expiration too long ({minutes} min > 1 day)")
            logging.info(f"JWT_EXPIRATION_MINUTES ok ({minutes} min)")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")
