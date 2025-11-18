#!/usr/bin/env python3
# verify_secrets.py
# Production-grade secrets verifier
# Enhanced version 2.3.0:
# - Added entropy checks for keys using zxcvbn.
# - Completed incomplete warnings and fixed minor bugs.
# - Added optional AWS SSM support for secrets fetching.
# - Improved Google OAuth with basic metadata check.
# - Added email alert on failure (--email-alert).
# - Better UI handling in JSON mode.
# - More docstrings and refactoring for clarity.
# - Original version: 2.2.0.

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from typing import Any, Callable, Dict, List, Tuple

import aiohttp
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
    DEFAULT_POOL_MAX_SIZE,
    DEFAULT_POOL_MIN_SIZE,
    DEFAULT_RETRIES,
    SECRET_KEYS,
    Summary,
)
from .http_client import HTTPClient
from .logging import setup_logging
from .output import print_summary, send_email_alert
from .signals import install_signal_handlers
from .utils import get_secret_value
from .verifier_registry import VerifierRegistry

__version__ = "1.0.0"


# ----- SAFE CHECK WITH PROGRESS -----
async def safe_check(
    progress: Progress,
    task_id: Any,
    name: str,
    verifier_callable: Callable[..., Any],
    *args,
    is_warn_only: bool = False,
    **kwargs,
) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    try:
        await verifier_callable(*args, **kwargs)
        progress.update(task_id, completed=100)
        logging.debug(f"{name} success")
    except Exception as e:
        msg = f"{name} failed: {str(e)}"
        progress.update(
            task_id, description=f"[red]{name} (Failed)[/red]", completed=100
        )
        if is_warn_only:
            warnings.append(msg)
            logging.warning(msg)
        else:
            errors.append(msg)
            logging.error(msg)
    return errors, warnings


# ----- MAIN -----
async def main(argv: List[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description=f"Production-grade secrets verifier ({__version__})."
    )
    parser.add_argument("--doppler-env", default="doppler.env")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--doppler-project", default="default_project")
    parser.add_argument("--doppler-config", default="dev")
    parser.add_argument(
        "--aws-ssm-prefix", default=None, help="AWS SSM parameter prefix (optional)"
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    parser.add_argument("--log-format", default="text", choices=["text", "json"])
    parser.add_argument("--color", action="store_true")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT)
    parser.add_argument("--db-timeout", type=float, default=DEFAULT_DB_TIMEOUT)
    parser.add_argument("--pool-min-size", type=int, default=DEFAULT_POOL_MIN_SIZE)
    parser.add_argument("--pool-max-size", type=int, default=DEFAULT_POOL_MAX_SIZE)
    parser.add_argument(
        "--overall-timeout", type=float, default=DEFAULT_OVERALL_TIMEOUT
    )
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF)
    parser.add_argument(
        "--jitter",
        type=float,
        default=DEFAULT_JITTER,
        help="fractional jitter to apply to backoff (0.0 - 1.0)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--output-json", help="JSON output file")
    parser.add_argument(
        "--email-alert",
        nargs=4,
        metavar=("SMTP_SERVER", "FROM", "TO", "PASS"),
        help="Send email on failure: smtp_server from_email to_email password",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    setup_logging(args.log_level, args.log_format, args.color)
    logging.info(
        f"Starting verifier v{__version__} (dry-run: {args.dry_run}, skip-live: {args.skip_live})"
    )

    load_dotenv(args.doppler_env)
    load_dotenv(args.env_file)

    http_timeout = aiohttp.ClientTimeout(total=args.http_timeout)
    async with aiohttp.ClientSession(timeout=http_timeout) as session:
        http = HTTPClient(session, args.retries, args.backoff, args.jitter)

        secrets: Dict[str, Any] = {}
        doppler_token = os.getenv("DOPPLER_TOKEN")
        aws_ssm_client = None
        if args.aws_ssm_prefix:
            try:
                import boto3

                aws_ssm_client = boto3.client("ssm")
                logging.info("Using AWS SSM for secrets")
            except ImportError:
                logging.error(
                    "The 'boto3' library is required for AWS SSM support. Please install it with 'pip install boto3'."
                )
                return 1
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
        else:
            logging.info("No Doppler/AWS or dry-run; using .env")

        loaded_secrets = {
            k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS
        }

        jwt_algorithm = loaded_secrets.get("JWT_ALGORITHM") or "HS256"
        logging.info(f"JWT Algorithm: {jwt_algorithm}")
        if jwt_algorithm in ("HS256", "HS384", "HS512"):
            logging.warning(
                "JWT using symmetric algo (consider asymmetric like RS256 for prod)"
            )
        jwt_expiration_minutes = loaded_secrets.get("JWT_EXPIRATION_MINUTES") or "60"
        logging.info(f"JWT Expiration: {jwt_expiration_minutes} min")

        registry = VerifierRegistry(http, args)

        console = (
            Console() if args.log_format != "json" else None
        )  # Suppress Rich in JSON mode
        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(args.concurrency)
        check_tasks: List[asyncio.Task] = []
        shutdown_mgr = install_signal_handlers(loop, check_tasks)

        async def sem_safe_check(
            progress: Progress,
            task_id: Any,
            name: str,
            verifier_callable: Callable[..., Any],
            *args,
            **kwargs,
        ) -> Tuple[List[str], List[str]]:
            async with semaphore:
                if shutdown_mgr.is_shutting_down():
                    raise asyncio.CancelledError("Shutdown triggered")
                return await safe_check(
                    progress, task_id, name, verifier_callable, *args, **kwargs
                )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True,
            console=console,
        ) as progress:
            # DBs
            for db_key, db_name in [
                ("CORE_PLATFORM_DB_URL", "Core Platform DB"),
                ("HEAVY_WORKER_DB_URL", "Heavy Worker DB"),
                ("GENERAL_PRODUCT_DB_URL", "General Product DB"),
            ]:
                db_url = loaded_secrets.get(db_key)
                if db_url:
                    task_id = progress.add_task(db_name, total=100)
                    check_tasks.append(
                        loop.create_task(
                            sem_safe_check(
                                progress,
                                task_id,
                                db_name,
                                registry.get_verifier("db").verify,
                                db_name,
                                db_url,
                                dry_run=args.dry_run,
                                skip_live=args.skip_live,
                            )
                        )
                    )
                else:
                    task_id = progress.add_task(f"{db_name} (missing)", total=100)
                    progress.update(task_id, completed=100)
                    check_tasks.append(
                        loop.create_task(
                            asyncio.sleep(0, result=([f"{db_name} missing"], []))
                        )
                    )

            # Redis
            for redis_key, redis_name in [
                ("CORE_PLATFORM_REDIS_URL", "Core Platform Redis"),
                ("HEAVY_WORKER_REDIS_URL", "Heavy Worker Redis"),
                ("GENERAL_PRODUCT_REDIS_URL", "General Product Redis"),
            ]:
                redis_url = loaded_secrets.get(redis_key)
                if redis_url:
                    task_id = progress.add_task(redis_name, total=100)
                    check_tasks.append(
                        loop.create_task(
                            sem_safe_check(
                                progress,
                                task_id,
                                redis_name,
                                registry.get_verifier("redis").verify,
                                redis_name,
                                redis_url,
                                dry_run=args.dry_run,
                                skip_live=args.skip_live,
                            )
                        )
                    )
                else:
                    task_id = progress.add_task(f"{redis_name} (missing)", total=100)
                    progress.update(task_id, completed=100)
                    check_tasks.append(
                        loop.create_task(
                            asyncio.sleep(0, result=([f"{redis_name} missing"], []))
                        )
                    )

            # Session Encryption Key
            session_key = loaded_secrets.get("SESSION_ENCRYPTION_KEY")
            session_name = "Session Encryption Key"
            if session_key:
                task_id = progress.add_task(session_name, total=100)
                check_tasks.append(
                    loop.create_task(
                        sem_safe_check(
                            progress,
                            task_id,
                            session_name,
                            registry.get_verifier("session").verify,
                            session_key,
                            dry_run=args.dry_run,
                            skip_live=args.skip_live,
                        )
                    )
                )
            else:
                task_id = progress.add_task(f"{session_name} (missing)", total=100)
                progress.update(task_id, completed=100)
                check_tasks.append(
                    loop.create_task(
                        asyncio.sleep(
                            0, result=(["SESSION_ENCRYPTION_KEY missing"], [])
                        )
                    )
                )

            # JWT Secret
            jwt_secret = loaded_secrets.get("JWT_SECRET")
            jwt_name = "JWT Secret"
            task_id = progress.add_task(jwt_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        jwt_name,
                        registry.get_verifier("jwt_secret").verify,
                        jwt_secret,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # JWT Expiration
            jwt_exp = loaded_secrets.get("JWT_EXPIRATION_MINUTES")
            jwt_exp_name = "JWT Expiration"
            task_id = progress.add_task(jwt_exp_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        jwt_exp_name,
                        registry.get_verifier("jwt_exp").verify,
                        jwt_exp,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Telegram API_ID
            api_id = loaded_secrets.get("API_ID")
            api_id_name = "Telegram API_ID"
            task_id = progress.add_task(api_id_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        api_id_name,
                        registry.get_verifier("tg_api").verify_api_id,
                        api_id,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Telegram API_HASH
            api_hash = loaded_secrets.get("API_HASH")
            api_hash_name = "Telegram API_HASH"
            task_id = progress.add_task(api_hash_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        api_hash_name,
                        registry.get_verifier("tg_api").verify_api_hash,
                        api_hash,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Owner Telegram ID
            owner_id = loaded_secrets.get("OWNER_TELEGRAM_ID")
            owner_name = "Owner Telegram ID"
            task_id = progress.add_task(owner_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        owner_name,
                        registry.get_verifier("tg_id").verify_owner_id,
                        owner_id,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Admin User IDs
            admin_ids = loaded_secrets.get("ADMIN_USER_IDS")
            admin_name = "Admin User IDs"
            task_id = progress.add_task(admin_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        admin_name,
                        registry.get_verifier("tg_id").verify_admin_ids,
                        admin_ids,
                        is_warn_only=True,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Bots
            for bot_key, bot_name in [
                ("FORWARDER_BOT_TOKEN", "Forwarder Bot Token"),
                ("AUTH_BOT_TOKEN", "Auth Bot Token"),
            ]:
                token = loaded_secrets.get(bot_key)
                if token:
                    task_id = progress.add_task(bot_name, total=100)
                    check_tasks.append(
                        loop.create_task(
                            sem_safe_check(
                                progress,
                                task_id,
                                bot_name,
                                registry.get_verifier("tg_bot").verify_bot_token,
                                bot_name,
                                token,
                                dry_run=args.dry_run,
                                skip_live=args.skip_live,
                            )
                        )
                    )
                else:
                    task_id = progress.add_task(f"{bot_name} (missing)", total=100)
                    progress.update(task_id, completed=100)
                    check_tasks.append(
                        loop.create_task(
                            asyncio.sleep(0, result=([f"{bot_name} missing"], []))
                        )
                    )

            # Accounts API
            accounts_url = loaded_secrets.get("ACCOUNTS_API_URL")
            accounts_key = loaded_secrets.get("ACCOUNTS_API_KEY")
            accounts_name = "Accounts API"
            task_id = progress.add_task(accounts_name, total=100)
            if accounts_url and accounts_key:
                check_tasks.append(
                    loop.create_task(
                        sem_safe_check(
                            progress,
                            task_id,
                            accounts_name,
                            registry.get_verifier("accounts").verify,
                            accounts_key,
                            accounts_url,
                            dry_run=args.dry_run,
                            skip_live=args.skip_live,
                        )
                    )
                )
            else:
                progress.update(
                    task_id,
                    description=f"[yellow]{accounts_name} (missing)[/yellow]",
                    completed=100,
                )
                check_tasks.append(
                    loop.create_task(
                        asyncio.sleep(
                            0,
                            result=(
                                ["ACCOUNTS_API_URL or ACCOUNTS_API_KEY missing"],
                                [],
                            ),
                        )
                    )
                )

            # Webhook Settings
            webhook_url = loaded_secrets.get("BASE_WEBHOOK_URL")
            webhook_secret = loaded_secrets.get("WEBHOOK_SECRET_TOKEN")
            webhook_name = "Webhook Settings"
            task_id = progress.add_task(webhook_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        webhook_name,
                        registry.get_verifier("webhook").verify,
                        webhook_url,
                        webhook_secret,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Razorpay
            razorpay_id = loaded_secrets.get("RAZORPAY_KEY_ID")
            razorpay_secret = loaded_secrets.get("RAZORPAY_KEY_SECRET")
            razorpay_webhook = loaded_secrets.get("RAZORPAY_WEBHOOK_SECRET")
            razorpay_name = "Razorpay"
            task_id = progress.add_task(razorpay_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        razorpay_name,
                        registry.get_verifier("razorpay").verify,
                        razorpay_id,
                        razorpay_secret,
                        razorpay_webhook,
                        is_warn_only=True,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            # Google OAuth
            google_id = loaded_secrets.get("GOOGLE_CLIENT_ID")
            google_secret = loaded_secrets.get("GOOGLE_CLIENT_SECRET")
            google_name = "Google OAuth"
            task_id = progress.add_task(google_name, total=100)
            check_tasks.append(
                loop.create_task(
                    sem_safe_check(
                        progress,
                        task_id,
                        google_name,
                        registry.get_verifier("google").verify,
                        google_id,
                        google_secret,
                        is_warn_only=True,
                        dry_run=args.dry_run,
                        skip_live=args.skip_live,
                    )
                )
            )

            try:
                async with asyncio.timeout(args.overall_timeout):
                    results = await asyncio.gather(*check_tasks, return_exceptions=True)
            except asyncio.TimeoutError:
                logging.error("Overall timeout exceeded")
                return 4
            except asyncio.CancelledError:
                logging.warning("Cancelled due to shutdown")
                return 3

        all_errors: List[str] = []
        all_warnings: List[str] = []
        for result in results:
            if isinstance(result, Exception):
                all_errors.append(str(result))
            else:
                errs, warns = result
                all_errors.extend(errs)
                all_warnings.extend(warns)

        status = "FAILED" if all_errors else "PASSED"
        summary = Summary(__version__, all_errors, all_warnings, status)

        print_summary(summary, args.log_format, console or Console())

        if args.output_json:
            try:
                with open(args.output_json, "w") as f:
                    json.dump(asdict(summary), f, indent=2)
                logging.info(f"Wrote JSON to {args.output_json}")
            except Exception as e:
                logging.error(f"Failed writing JSON output: {e}")
                return 5

        if args.email_alert and status == "FAILED":
            send_email_alert(summary, *args.email_alert)

        return 2 if all_errors else 0


def main_sync():
    """Wrapper for asyncio.run() to be used by the entry point."""
    sys.exit(asyncio.run(main(sys.argv[1:])))


if __name__ == "__main__":
    main_sync()
