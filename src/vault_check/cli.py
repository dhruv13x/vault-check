#!/usr/bin/env python3
# verify_secrets.py
# Production-grade secrets verifier

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import asdict
from typing import Any, Dict, List

import aiohttp
import boto3
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from .config import (
    DEFAULT_BACKOFF,
    DEFAULT_CONCURRENCY,
    DEFAULT_DB_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_JITTER,
    DEFAULT_OVERALL_TIMEOUT,
    DEFAULT_RETRIES,
    SECRET_KEYS,
    Summary,
)
from .http_client import HTTPClient
from .logging import setup_logging
from .output import print_summary, send_email_alert
from .registry import VerifierRegistry
from .signals import install_signal_handlers
from .utils import get_secret_value
from .verifiers import (
    AccountsAPIVerifier,
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

__version__ = "1.0.0"


# ----- MAIN -----
async def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=f"Secrets verifier ({__version__})")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--doppler-project", default="default_project")
    parser.add_argument("--doppler-config", default="dev")
    parser.add_argument("--aws-ssm-prefix", help="AWS SSM parameter prefix")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument("--log-format", default="text", choices=["text", "json"])
    parser.add_argument("--color", action="store_true")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT)
    parser.add_argument("--db-timeout", type=float, default=DEFAULT_DB_TIMEOUT)
    parser.add_argument("--overall-timeout", type=float, default=DEFAULT_OVERALL_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--output-json", help="JSON output file")
    parser.add_argument("--email-alert", nargs=4, metavar=("SMTP_SERVER", "FROM", "TO", "PASS"))
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    setup_logging(args.log_level, args.log_format, args.color)
    load_dotenv(args.env_file)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=args.http_timeout)) as session:
        http = HTTPClient(session, args.retries, DEFAULT_BACKOFF, DEFAULT_JITTER)

        secrets: Dict[str, Any] = {}
        doppler_token = os.getenv("DOPPLER_TOKEN")
        aws_ssm_client = None
        if args.aws_ssm_prefix:
            try:
                aws_ssm_client = boto3.client("ssm")
                logging.info("Using AWS SSM for secrets")
            except Exception as e:
                logging.warning(f"AWS SSM init failed: {e}; falling back")

        if doppler_token and not args.dry_run:
            doppler_url = f"https://api.doppler.com/v3/configs/config/secrets?project={args.doppler_project}&config={args.doppler_config}"
            try:
                data = await http.get_json(
                    doppler_url, headers={"Authorization": f"Bearer {doppler_token}"}
                )
                if not isinstance(data, dict):
                    raise ValueError("Unexpected Doppler response type")
                secrets = data.get("secrets", data)
                logging.info(f"Doppler secrets fetched (count={len(secrets)})")
            except Exception as e:
                logging.warning(f"Doppler fetch failed: {e}; using .env")
        elif aws_ssm_client:
            try:
                for key in SECRET_KEYS:
                    param_name = f"{args.aws_ssm_prefix}/{key}"
                    param = aws_ssm_client.get_parameter(
                        Name=param_name, WithDecryption=True
                    )
                    secrets[key] = param["Parameter"]["Value"]
                logging.info(f"AWS SSM secrets fetched (count={len(secrets)})")
            except Exception as e:
                logging.warning(f"AWS SSM fetch failed: {e}; using .env")

        loaded_secrets = {k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS}

        registry = VerifierRegistry()

        db_verifier = DatabaseVerifier(args.db_timeout, retries=args.retries)
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
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

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
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

        session_verifier = SessionKeyVerifier()
        registry.add(
            "Session Encryption Key",
            session_verifier.verify,
            args=[loaded_secrets.get("SESSION_ENCRYPTION_KEY")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
        )

        jwt_verifier = JWTSecretVerifier()
        registry.add("JWT Secret", jwt_verifier.verify, args=[loaded_secrets.get("JWT_SECRET")])

        jwt_exp_verifier = JWTExpirationVerifier()
        registry.add("JWT Expiration", jwt_exp_verifier.verify, args=[loaded_secrets.get("JWT_EXPIRATION_MINUTES")])

        tg_api_verifier = TelegramAPIVerifier()
        registry.add("Telegram API ID", tg_api_verifier.verify_api_id, args=[loaded_secrets.get("API_ID")])
        registry.add("Telegram API Hash", tg_api_verifier.verify_api_hash, args=[loaded_secrets.get("API_HASH")])

        tg_id_verifier = TelegramIDVerifier()
        registry.add("Owner Telegram ID", tg_id_verifier.verify_owner_id, args=[loaded_secrets.get("OWNER_TELEGRAM_ID")])
        registry.add("Admin User IDs", tg_id_verifier.verify_admin_ids, args=[loaded_secrets.get("ADMIN_USER_IDS")], is_warn_only=True)

        tg_bot_verifier = TelegramBotVerifier(http)
        for bot_key, bot_name in [
            ("FORWARDER_BOT_TOKEN", "Forwarder Bot Token"),
            ("AUTH_BOT_TOKEN", "Auth Bot Token"),
        ]:
            if token := loaded_secrets.get(bot_key):
                registry.add(
                    bot_name,
                    tg_bot_verifier.verify_bot_token,
                    args=[bot_name, token],
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

        accounts_verifier = AccountsAPIVerifier(http)
        registry.add(
            "Accounts API",
            accounts_verifier.verify,
            args=[loaded_secrets.get("ACCOUNTS_API_KEY"), loaded_secrets.get("ACCOUNTS_API_URL")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
        )

        webhook_verifier = WebhookVerifier()
        registry.add(
            "Webhook Settings",
            webhook_verifier.verify,
            args=[loaded_secrets.get("BASE_WEBHOOK_URL"), loaded_secrets.get("WEBHOOK_SECRET_TOKEN")],
        )

        razorpay_verifier = RazorpayVerifier(http)
        registry.add(
            "Razorpay",
            razorpay_verifier.verify,
            args=[
                loaded_secrets.get("RAZORPAY_KEY_ID"),
                loaded_secrets.get("RAZORPAY_KEY_SECRET"),
                loaded_secrets.get("RAZORPAY_WEBHOOK_SECRET"),
            ],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
            is_warn_only=True,
        )

        google_verifier = GoogleOAuthVerifier(http)
        registry.add(
            "Google OAuth",
            google_verifier.verify,
            args=[loaded_secrets.get("GOOGLE_CLIENT_ID"), loaded_secrets.get("GOOGLE_CLIENT_SECRET")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
            is_warn_only=True,
        )

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(args.concurrency)
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
                    progress.update(task_id, description=f"[red]{check['name']} (Failed)[/red]")
                    if check["is_warn_only"]:
                        warnings.append(msg)
                        logging.warning(msg)
                    else:
                        errors.append(msg)
                        logging.error(msg)
                return errors, warnings

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as progress:
            for check in registry.checks:
                task_id = progress.add_task(check["name"], total=100)
                check_tasks.append(loop.create_task(sem_safe_check(progress, task_id, check)))

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
        summary = Summary(__version__, all_errors, all_warnings, status)

        print_summary(summary, args.log_format, Console())
        if args.output_json:
            with open(args.output_json, "w") as f:
                json.dump(asdict(summary), f, indent=2)
        if args.email_alert and status == "FAILED":
            send_email_alert(summary, *args.email_alert)

        return 2 if all_errors else 0


def entry_point():
    """Wrapper for the async main function."""
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry_point()
