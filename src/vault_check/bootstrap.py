from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .config import SECRET_KEYS
from .heuristics import HeuristicsEngine
from .registry import VerifierRegistry
from .plugins import load_plugins
from .verifiers import (
    DatabaseVerifier,
    GoogleOAuthVerifier,
    JWTExpirationVerifier,
    JWTSecretVerifier,
    RazorpayVerifier,
    RedisVerifier,
    SessionKeyVerifier,
    TelegramAPIVerifier,
    TelegramBotVerifier,
    TelegramIDVerifier,
    TelegramSessionVerifier,
    WebhookVerifier,
    S3Verifier,
    SMTPVerifier,
)


class VerifierBootstrap:
    """
    Responsible for populating the VerifierRegistry based on configuration and secrets.
    """

    def __init__(
        self,
        http_client: Any,
        db_timeout: float,
        retries: int,
        dry_run: bool,
        skip_live: bool,
        selected_verifiers: Optional[List[str]] = None,
    ):
        self.http = http_client
        self.db_timeout = db_timeout
        self.retries = retries
        self.dry_run = dry_run
        self.skip_live = skip_live
        self.verifiers = selected_verifiers

    def bootstrap(self, loaded_secrets: Dict[str, Any]) -> VerifierRegistry:
        registry = VerifierRegistry()

        # Load external plugins
        load_plugins(registry)

        self._register_database_verifiers(registry, loaded_secrets)
        self._register_redis_verifiers(registry, loaded_secrets)
        self._register_session_verifiers(registry, loaded_secrets)
        self._register_jwt_verifiers(registry, loaded_secrets)
        self._register_telegram_verifiers(registry, loaded_secrets)
        self._register_webhook_verifiers(registry, loaded_secrets)
        self._register_razorpay_verifiers(registry, loaded_secrets)
        self._register_google_verifiers(registry, loaded_secrets)
        self._register_auto_discovered_verifiers(registry, loaded_secrets)

        return registry

    def _should_run(self, verifier_name: str) -> bool:
        return not self.verifiers or verifier_name in self.verifiers

    def _register_database_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("database"):
            return

        db_verifier = DatabaseVerifier(self.db_timeout, retries=self.retries)
        for db_key, db_name in [
            ("CORE_PLATFORM_DB_URL", "Core Platform DB"),
            ("HEAVY_WORKER_DB_URL", "Heavy Worker DB"),
            ("GENERAL_PRODUCT_DB_URL", "General Product DB"),
        ]:
            if db_url := secrets.get(db_key):
                registry.add(
                    db_name,
                    db_verifier.verify,
                    args=[db_name, db_url],
                    kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                )

    def _register_redis_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("redis"):
            return

        redis_verifier = RedisVerifier()
        for redis_key, redis_name in [
            ("CORE_PLATFORM_REDIS_URL", "Core Platform Redis"),
            ("HEAVY_WORKER_REDIS_URL", "Heavy Worker Redis"),
            ("GENERAL_PRODUCT_REDIS_URL", "General Product Redis"),
        ]:
            if redis_url := secrets.get(redis_key):
                registry.add(
                    redis_name,
                    redis_verifier.verify,
                    args=[redis_name, redis_url],
                    kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                )

    def _register_session_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("session"):
            return

        session_verifier = SessionKeyVerifier()
        registry.add(
            "Session Encryption Key",
            session_verifier.verify,
            args=[secrets.get("SESSION_ENCRYPTION_KEY")],
            kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
        )

    def _register_jwt_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("jwt"):
            return

        jwt_verifier = JWTSecretVerifier()
        registry.add(
            "JWT Secret", jwt_verifier.verify, args=[secrets.get("JWT_SECRET")]
        )

        jwt_exp_verifier = JWTExpirationVerifier()
        registry.add(
            "JWT Expiration",
            jwt_exp_verifier.verify,
            args=[secrets.get("JWT_EXPIRATION_MINUTES")],
        )

    def _register_telegram_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("telegram"):
            return

        tg_api_verifier = TelegramAPIVerifier()
        registry.add(
            "Telegram API ID",
            tg_api_verifier.verify_api_id,
            args=[secrets.get("API_ID")],
        )
        registry.add(
            "Telegram API Hash",
            tg_api_verifier.verify_api_hash,
            args=[secrets.get("API_HASH")],
        )

        tg_id_verifier = TelegramIDVerifier()
        registry.add(
            "Owner Telegram ID",
            tg_id_verifier.verify_owner_id,
            args=[secrets.get("OWNER_TELEGRAM_ID")],
        )
        registry.add(
            "Admin User IDs",
            tg_id_verifier.verify_admin_ids,
            args=[secrets.get("ADMIN_USER_IDS")],
            is_warn_only=True,
        )

        tg_session_verifier = TelegramSessionVerifier()
        if session_str := secrets.get("OWNER_SESSION_STRING"):
            registry.add(
                "Owner Session String",
                tg_session_verifier.verify,
                args=[session_str],
            )

        tg_bot_verifier = TelegramBotVerifier(self.http)
        for bot_key, bot_name in [
            ("FORWARDER_BOT_TOKEN", "Forwarder Bot Token"),
            ("AUTH_BOT_TOKEN", "Auth Bot Token"),
            ("ADMIN_BOT_TOKEN", "Admin Bot Token"),
        ]:
            if token := secrets.get(bot_key):
                registry.add(
                    bot_name,
                    tg_bot_verifier.verify_bot_token,
                    args=[bot_name, token],
                    kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                )

    def _register_webhook_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("webhook"):
            return

        webhook_verifier = WebhookVerifier()
        registry.add(
            "Webhook Settings",
            webhook_verifier.verify,
            args=[
                secrets.get("BASE_WEBHOOK_URL"),
                secrets.get("WEBHOOK_SECRET_TOKEN"),
            ],
        )

    def _register_razorpay_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("razorpay"):
            return

        razorpay_verifier = RazorpayVerifier(self.http)
        registry.add(
            "Razorpay",
            razorpay_verifier.verify,
            args=[
                secrets.get("RAZORPAY_KEY_ID"),
                secrets.get("RAZORPAY_KEY_SECRET"),
                secrets.get("RAZORPAY_WEBHOOK_SECRET"),
            ],
            kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
            is_warn_only=True,
        )

    def _register_google_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("google"):
            return

        google_verifier = GoogleOAuthVerifier(self.http)
        registry.add(
            "Google OAuth",
            google_verifier.verify,
            args=[
                secrets.get("GOOGLE_CLIENT_ID"),
                secrets.get("GOOGLE_CLIENT_SECRET"),
            ],
            kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
            is_warn_only=True,
        )

    def _register_auto_discovered_verifiers(self, registry: VerifierRegistry, secrets: Dict[str, Any]):
        if not self._should_run("auto"):
            return

        processed_keys = set(SECRET_KEYS.keys())
        for key, value in secrets.items():
            if key in processed_keys:
                continue

            verifier_cls = HeuristicsEngine.match(value)
            if verifier_cls:
                kwargs = {"dry_run": self.dry_run, "skip_live": self.skip_live}
                args = []

                if issubclass(verifier_cls, DatabaseVerifier):
                    verifier = verifier_cls(self.db_timeout, retries=self.retries)
                    name = f"{key} (Auto)"
                    args = [name, value]
                elif issubclass(verifier_cls, RedisVerifier):
                    verifier = verifier_cls()
                    name = f"{key} (Auto)"
                    args = [name, value]
                elif issubclass(verifier_cls, S3Verifier):
                    verifier = verifier_cls()
                    name = f"{key} (Auto)"
                    args = [value]
                elif issubclass(verifier_cls, SMTPVerifier):
                    verifier = verifier_cls()
                    name = f"{key} (Auto)"
                    args = [value]
                else:
                    try:
                        verifier = verifier_cls()
                        name = f"{key} (Auto)"
                    except TypeError:
                        logging.warning(f"Could not instantiate auto-discovered verifier for {key}")
                        continue

                registry.add(
                    name,
                    verifier.verify,
                    args=args,
                    kwargs=kwargs,
                )
