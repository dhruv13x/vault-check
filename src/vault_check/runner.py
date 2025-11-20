from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from typing import Any, Dict, List

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from .config import Summary
from .output import print_summary, send_email_alert
from .registry import VerifierRegistry
from .signals import install_signal_handlers
from .verifiers import (
#    AccountsAPIVerifier,
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
    WebhookVerifier,
)


class Runner:
    def __init__(
        self,
        http_client: Any,
        concurrency: int,
        db_timeout: float,
        retries: int,
        dry_run: bool,
        skip_live: bool,
        output_json: str | None,
        email_alert: List[str] | None,
        verifiers: List[str] | None,
    ):
        self.http = http_client
        self.concurrency = concurrency
        self.db_timeout = db_timeout
        self.retries = retries
        self.dry_run = dry_run
        self.skip_live = skip_live
        self.output_json = output_json
        self.email_alert = email_alert
        self.verifiers = verifiers

    async def run(self, loaded_secrets: Dict[str, Any], version: str) -> int:
        registry = VerifierRegistry()

        if not self.verifiers or "database" in self.verifiers:
            db_verifier = DatabaseVerifier(self.db_timeout, retries=self.retries)
            for db_key, db_name in [
                ("CORE_PLATFORM_DB_URL", "Core Platform DB"),
                ("HEAVY_WORKER_DB_URL", "Heavy Worker DB"),
                ("GENERAL_PRODUCT_DB_URL", "General Product DB"),
            ]:
                if db_url := loaded_secrets.get(db_key):
                    registry.add(
                        db_name,
                        db_verifier.verify,
                        args=[db_name, db_url],
                        kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                    )

        if not self.verifiers or "redis" in self.verifiers:
            redis_verifier = RedisVerifier()
            for redis_key, redis_name in [
                ("CORE_PLATFORM_REDIS_URL", "Core Platform Redis"),
                ("HEAVY_WORKER_REDIS_URL", "Heavy Worker Redis"),
                ("GENERAL_PRODUCT_REDIS_URL", "General Product Redis"),
            ]:
                if redis_url := loaded_secrets.get(redis_key):
                    registry.add(
                        redis_name,
                        redis_verifier.verify,
                        args=[redis_name, redis_url],
                        kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                    )

        if not self.verifiers or "session" in self.verifiers:
            session_verifier = SessionKeyVerifier()
            registry.add(
                "Session Encryption Key",
                session_verifier.verify,
                args=[loaded_secrets.get("SESSION_ENCRYPTION_KEY")],
                kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
            )

        if not self.verifiers or "jwt" in self.verifiers:
            jwt_verifier = JWTSecretVerifier()
            registry.add(
                "JWT Secret", jwt_verifier.verify, args=[loaded_secrets.get("JWT_SECRET")]
            )

            jwt_exp_verifier = JWTExpirationVerifier()
            registry.add(
                "JWT Expiration",
                jwt_exp_verifier.verify,
                args=[loaded_secrets.get("JWT_EXPIRATION_MINUTES")],
            )

        if not self.verifiers or "telegram" in self.verifiers:
            tg_api_verifier = TelegramAPIVerifier()
            registry.add(
                "Telegram API ID",
                tg_api_verifier.verify_api_id,
                args=[loaded_secrets.get("API_ID")],
            )
            registry.add(
                "Telegram API Hash",
                tg_api_verifier.verify_api_hash,
                args=[loaded_secrets.get("API_HASH")],
            )

            tg_id_verifier = TelegramIDVerifier()
            registry.add(
                "Owner Telegram ID",
                tg_id_verifier.verify_owner_id,
                args=[loaded_secrets.get("OWNER_TELEGRAM_ID")],
            )
            registry.add(
                "Admin User IDs",
                tg_id_verifier.verify_admin_ids,
                args=[loaded_secrets.get("ADMIN_USER_IDS")],
                is_warn_only=True,
            )

            tg_bot_verifier = TelegramBotVerifier(self.http)
            for bot_key, bot_name in [
                ("FORWARDER_BOT_TOKEN", "Forwarder Bot Token"),
                ("AUTH_BOT_TOKEN", "Auth Bot Token"),
            ]:
                if token := loaded_secrets.get(bot_key):
                    registry.add(
                        bot_name,
                        tg_bot_verifier.verify_bot_token,
                        args=[bot_name, token],
                        kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                    )

#        if not self.verifiers or "accounts" in self.verifiers:
#            accounts_verifier = AccountsAPIVerifier(self.http)
#            registry.add(
#                "Accounts API",
#                accounts_verifier.verify,
#                args=[
#                    loaded_secrets.get("ACCOUNTS_API_KEY"),
#                    loaded_secrets.get("ACCOUNTS_API_URL"),
#                ],
#                kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
#            )

        if not self.verifiers or "webhook" in self.verifiers:
            webhook_verifier = WebhookVerifier()
            registry.add(
                "Webhook Settings",
                webhook_verifier.verify,
                args=[
                    loaded_secrets.get("BASE_WEBHOOK_URL"),
                    loaded_secrets.get("WEBHOOK_SECRET_TOKEN"),
                ],
            )

        if not self.verifiers or "razorpay" in self.verifiers:
            razorpay_verifier = RazorpayVerifier(self.http)
            registry.add(
                "Razorpay",
                razorpay_verifier.verify,
                args=[
                    loaded_secrets.get("RAZORPAY_KEY_ID"),
                    loaded_secrets.get("RAZORPAY_KEY_SECRET"),
                    loaded_secrets.get("RAZORPAY_WEBHOOK_SECRET"),
                ],
                kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                is_warn_only=True,
            )

        if not self.verifiers or "google" in self.verifiers:
            google_verifier = GoogleOAuthVerifier(self.http)
            registry.add(
                "Google OAuth",
                google_verifier.verify,
                args=[
                    loaded_secrets.get("GOOGLE_CLIENT_ID"),
                    loaded_secrets.get("GOOGLE_CLIENT_SECRET"),
                ],
                kwargs={"dry_run": self.dry_run, "skip_live": self.skip_live},
                is_warn_only=True,
            )

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(self.concurrency)
        check_tasks: List[asyncio.Task] = []
        shutdown_mgr = install_signal_handlers(loop, check_tasks)

        async def sem_safe_check(progress, task_id, check):
            async with semaphore:
                if shutdown_mgr.is_shutting_down():
                    raise asyncio.CancelledError
                errors, warnings = [], []
                try:
                    await check["callable"](*check["args"], **check["kwargs"])
                    progress.update(task_id, completed=100)
                except Exception as e:
                    msg = f"{check['name']} failed: {e}"
                    progress.update(
                        task_id, description=f"[red]{check['name']} (Failed)[/red]"
                    )
                    if check["is_warn_only"]:
                        warnings.append(msg)
                        logging.warning(msg)
                    else:
                        errors.append(msg)
                        logging.error(msg)
                return errors, warnings

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True,
        ) as progress:
            for check in registry.checks:
                task_id = progress.add_task(check["name"], total=100)
                check_tasks.append(
                    loop.create_task(sem_safe_check(progress, task_id, check))
                )

            try:
                results = await asyncio.gather(*check_tasks, return_exceptions=True)
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:
                logging.error(f"Execution stopped: {e}")
                return 1

        all_errors = []
        all_warnings = []
        for result in results:
            if isinstance(result, Exception):
                all_errors.append(str(result))
            else:
                errors, warnings = result
                all_errors.extend(errors)
                all_warnings.extend(warnings)

        status = "FAILED" if all_errors else "PASSED"
        summary = Summary(version, all_errors, all_warnings, status)

        print_summary(summary, "text", Console())
        if self.output_json:
            with open(self.output_json, "w") as f:
                json.dump(asdict(summary), f, indent=2)
        if self.email_alert and status == "FAILED":
            send_email_alert(summary, *self.email_alert)

        return 2 if all_errors else 0
