# src/vault_check/verifiers/session_key.py

import base64
import logging

from cryptography.fernet import Fernet

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class SessionKeyVerifier(BaseVerifier):
    async def verify(self, key: str | None, dry_run: bool = False, skip_live: bool = False) -> None:
        logging.info(f"Checking [bold]SESSION_ENCRYPTION_KEY[/bold] (masked: {mask_sensitive(key)})")
        if not key:
            raise ValueError("SESSION_ENCRYPTION_KEY missing")
        try:
            padded = key.encode() + b"=" * ((4 - len(key) % 4) % 4)
            if len(base64.urlsafe_b64decode(padded)) != 32:
                raise ValueError("Decoded key is not 32 bytes")
            check_entropy(key)
        except Exception as e:
            raise ValueError(f"Invalid base64 Fernet key: {e}") from e
        if not dry_run and not skip_live:
            Fernet(padded).encrypt(b"health-check")
