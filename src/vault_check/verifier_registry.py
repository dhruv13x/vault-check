from __future__ import annotations

from typing import Dict, List

from .http_client import HTTPClient
from .verifiers.accounts import AccountsAPIVerifier
from .verifiers.base import BaseVerifier
from .verifiers.database import DatabaseVerifier
from .verifiers.google import GoogleOAuthVerifier
from .verifiers.jwt import JWTExpirationVerifier, JWTSecretVerifier
from .verifiers.razorpay import RazorpayVerifier
from .verifiers.redis import RedisVerifier
from .verifiers.session_key import SessionKeyVerifier
from .verifiers.telegram import (
    TelegramAPIVerifier,
    TelegramBotVerifier,
    TelegramIDVerifier,
)
from .verifiers.webhook import WebhookVerifier


class VerifierRegistry:
    def __init__(self, http_client: HTTPClient, args):
        self.verifiers: Dict[str, BaseVerifier] = {
            "db": DatabaseVerifier(
                args.db_timeout,
                args.pool_min_size,
                args.pool_max_size,
                retries=args.retries,
                backoff=args.backoff,
            ),
            "redis": RedisVerifier(),
            "session": SessionKeyVerifier(),
            "jwt_secret": JWTSecretVerifier(),
            "jwt_exp": JWTExpirationVerifier(),
            "tg_api": TelegramAPIVerifier(),
            "tg_id": TelegramIDVerifier(),
            "tg_bot": TelegramBotVerifier(http_client),
            "accounts": AccountsAPIVerifier(http_client),
            "webhook": WebhookVerifier(),
            "razorpay": RazorpayVerifier(http_client),
            "google": GoogleOAuthVerifier(http_client),
        }

    def get_verifier(self, name: str) -> BaseVerifier:
        return self.verifiers[name]

    def get_all_verifiers(self) -> List[BaseVerifier]:
        return list(self.verifiers.values())
