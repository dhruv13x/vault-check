from __future__ import annotations

import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class SessionKeyVerifier(BaseVerifier):
    """Verifier for session encryption key."""

    async def verify(
        self, key: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(
            f"Checking [bold]SESSION_ENCRYPTION_KEY[/bold] (masked: {mask_sensitive(key)})"
        )
        if not key:
            raise ValueError("SESSION_ENCRYPTION_KEY missing")
        try:
            b = key.encode()
            padded = b + b"=" * ((4 - len(b) % 4) % 4)
            raw = base64.urlsafe_b64decode(padded)
            if len(raw) != 32:
                raise ValueError("Decoded key is not 32 bytes (invalid Fernet key)")
            check_entropy(key)  # New: entropy check
        except Exception as e:
            raise ValueError(f"Invalid base64 Fernet key: {e}")
        if dry_run or skip_live:
            logging.info("SESSION_ENCRYPTION_KEY: Format ok, skipping test")
            return
        try:
            f = Fernet(padded)
            token = f.encrypt(b"health-check")
            if f.decrypt(token) != b"health-check":
                raise InvalidToken("Roundtrip failed")
            logging.info("SESSION_ENCRYPTION_KEY validated")
        except Exception as e:
            raise RuntimeError(f"Fernet health-check failed: {e}")
