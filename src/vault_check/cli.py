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
import base64
import json
import logging
import os
import random
import re
import signal
import smtplib
import sys
import time
from dataclasses import asdict, dataclass
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse, urlunparse

import aiohttp
import aiosqlite
import asyncpg
import boto3  # For AWS SSM (optional)
import redis.asyncio as aioredis
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from zxcvbn import zxcvbn  # For entropy/strength checks

__version__ = "1.0.0"

# ----- CONFIG -----
SECRET_KEYS = {
    "CORE_PLATFORM_DB_URL": "Core Platform DB",
    "HEAVY_WORKER_DB_URL": "Heavy Worker DB",
    "GENERAL_PRODUCT_DB_URL": "General Product DB",
    "CORE_PLATFORM_REDIS_URL": "Core Platform Redis",
    "HEAVY_WORKER_REDIS_URL": "Heavy Worker Redis",
    "GENERAL_PRODUCT_REDIS_URL": "General Product Redis",
    "SESSION_ENCRYPTION_KEY": "Session Encryption Key",
    "JWT_SECRET": "JWT Secret",
    "JWT_ALGORITHM": "JWT Algorithm",
    "JWT_EXPIRATION_MINUTES": "JWT Expiration Minutes",
    "API_ID": "Telegram API_ID",
    "API_HASH": "Telegram API_HASH",
    "OWNER_TELEGRAM_ID": "Owner Telegram ID",
    "ADMIN_USER_IDS": "Admin User IDs",
    "FORWARDER_BOT_TOKEN": "Forwarder Bot Token",
    "AUTH_BOT_TOKEN": "Auth Bot Token",
    "ACCOUNTS_API_URL": "Accounts API URL",
    "ACCOUNTS_API_KEY": "Accounts API Key",
    "BASE_WEBHOOK_URL": "Base Webhook URL",
    "WEBHOOK_SECRET_TOKEN": "Webhook Secret Token",
    "RAZORPAY_KEY_ID": "Razorpay Key ID",
    "RAZORPAY_KEY_SECRET": "Razorpay Key Secret",
    "RAZORPAY_WEBHOOK_SECRET": "Razorpay Webhook Secret",
    "GOOGLE_CLIENT_ID": "Google Client ID",
    "GOOGLE_CLIENT_SECRET": "Google Client Secret",
}

DEFAULT_CONCURRENCY = 5
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 0.6
DEFAULT_HTTP_TIMEOUT = 12.0
DEFAULT_DB_TIMEOUT = 10.0
DEFAULT_OVERALL_TIMEOUT = 60.0
DEFAULT_POOL_MIN_SIZE = 1
DEFAULT_POOL_MAX_SIZE = 10
DEFAULT_JITTER = 0.2
MIN_ENTROPY_SCORE = 3  # zxcvbn score threshold (0-4, 3+ is strong)


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"


# ----- LOGGING WITH RICH -----
def setup_logging(level: str, fmt: str = "text", color: bool = False) -> None:
    """Set up logging with Rich or JSON handler."""
    level_num = getattr(logging, level.upper(), logging.INFO)
    if fmt == "json":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
    else:
        handler = RichHandler(
            console=Console(color_system="auto" if color else None),
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
        )
    logging.basicConfig(level=level_num, handlers=[handler], force=True)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


# ----- UTILS -----
def _sleep_backoff(
    base: float, attempt: int, jitter_frac: float = DEFAULT_JITTER
) -> float:
    backoff = base * (2 ** (attempt - 1))
    jitter = backoff * jitter_frac * (random.random() * 2 - 1)
    return max(0.0, backoff + jitter)


def mask_sensitive(
    value: Optional[str], show_first: int = 6, show_last: int = 4
) -> str:
    if not value:
        return "(missing)"
    s = str(value)
    if len(s) <= show_first + show_last:
        return "*" * len(s)
    return s[:show_first] + "*" * (len(s) - show_first - show_last) + s[-show_last:]


def mask_url(url: Optional[str]) -> str:
    if not url:
        return "(missing)"
    parsed = urlparse(url)
    if parsed.password:
        netloc = parsed.netloc.replace(parsed.password, "*****")
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def get_secret_value(secrets: Dict[str, Any], key: str) -> Optional[str]:
    val = secrets.get(key)
    if isinstance(val, dict):
        return val.get("computed") or val.get("raw")
    return val if isinstance(val, str) else None


def validate_url_format(url: Optional[str], schemes: List[str]) -> bool:
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url)
    base_scheme = parsed.scheme.lower().split("+")[0]
    return base_scheme in schemes and bool(parsed.netloc)


def check_entropy(key: str, min_score: int = MIN_ENTROPY_SCORE) -> None:
    """Check key strength using zxcvbn."""
    result = zxcvbn(key)
    if result["score"] < min_score:
        raise ValueError(
            f"Weak key (score {result['score']}/4): {result['feedback']['warning']}"
        )


async def retry_backoff(
    func: Callable,
    retries: int = DEFAULT_RETRIES,
    base_backoff: float = DEFAULT_BACKOFF,
    jitter_frac: float = DEFAULT_JITTER,
    *args,
    **kwargs,
) -> Any:
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exc = e
            logging.debug("Retry attempt %d failed: %s", attempt, e)
            if attempt == retries:
                raise
            await asyncio.sleep(_sleep_backoff(base_backoff, attempt, jitter_frac))
    raise last_exc or RuntimeError("Retry failed")


# ----- HTTP CLIENT -----
class HTTPClient:
    """Async HTTP client with retries."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        jitter_frac: float = DEFAULT_JITTER,
    ):
        self.session = session
        self.retries = max(0, retries)
        self.backoff = max(0.0, backoff)
        self.jitter_frac = max(0.0, jitter_frac)

    async def _request(
        self, method: str, url: str, **kwargs
    ) -> Tuple[int, Dict[str, str], str]:
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    text = await resp.text()
                    resp.raise_for_status()
                    headers = dict(resp.headers)
                    return resp.status, headers, text
            except aiohttp.ClientResponseError as e:
                last_exc = e
                logging.debug("HTTP response error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exc = e
                logging.debug("HTTP network error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            await asyncio.sleep(_sleep_backoff(self.backoff, attempt, self.jitter_frac))
        raise last_exc or RuntimeError("HTTP request failed")

    async def get_json(self, url: str, **kwargs) -> Any:
        _, _, text = await self._request("GET", url, **kwargs)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text  # Fallback to text if not JSON

    async def get_text(self, url: str, **kwargs) -> str:
        _, _, text = await self._request("GET", url, **kwargs)
        return text


# ----- VERIFIERS -----
class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError


class DatabaseVerifier(BaseVerifier):
    """Verifier for database connections."""

    def __init__(
        self,
        pg_pool_timeout: float = DEFAULT_DB_TIMEOUT,
        pool_min_size: int = DEFAULT_POOL_MIN_SIZE,
        pool_max_size: int = DEFAULT_POOL_MAX_SIZE,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
    ):
        self.pg_pool_timeout = pg_pool_timeout
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.retries = retries
        self.backoff = backoff

    async def _create_pool(self, dsn: str) -> asyncpg.Pool:
        return await asyncpg.create_pool(
            dsn,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
            timeout=self.pg_pool_timeout,
        )

    async def verify(
        self, db_name: str, db_url: str, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{db_name}[/bold] at {mask_url(db_url)}")
        if not isinstance(db_url, str):
            raise ValueError("DB URL is not a string")
        parsed = urlparse(db_url)
        scheme_base = parsed.scheme.lower().split("+")[0]
        valid_schemes = ["postgres", "postgresql", "sqlite"]
        if scheme_base not in valid_schemes or (
            scheme_base != "sqlite" and not parsed.netloc
        ):
            raise ValueError(f"Invalid DB URL format (scheme: {parsed.scheme})")

        if dry_run or skip_live:
            logging.info(f"{db_name}: Format valid, skipping live connection")
            return

        if scheme_base in ("postgres", "postgresql"):
            dsn = re.sub(r"\+asyncpg", "", db_url, flags=re.IGNORECASE)
            if parsed.hostname and parsed.hostname.endswith(".supabase.com"):
                query = parse_qs(parsed.query or "")
                if "sslmode" not in [k.lower() for k in query]:
                    dsn += "&sslmode=disable" if "?" in dsn else "?sslmode=disable"
                    logging.info(f"{db_name}: Added sslmode=disable for Supabase")

            async def connect_and_check():
                pool = await self._create_pool(dsn)
                try:
                    async with pool.acquire() as conn:
                        version = await conn.fetchval("SELECT version();")
                        logging.info(f"{db_name} connected (Postgres): {version}")
                        if parsed.hostname in ("localhost", "127.0.0.1"):
                            logging.warning(
                                f"{db_name} using local instance (not recommended for production)"
                            )
                finally:
                    await pool.close()

            await retry_backoff(
                connect_and_check, retries=self.retries, base_backoff=self.backoff
            )
        else:  # sqlite
            db_path = parsed.path.lstrip("/")
            conn = await aiosqlite.connect(db_path)
            try:
                async with conn.execute("SELECT sqlite_version();") as cursor:
                    row = await cursor.fetchone()
                    logging.info(
                        f"{db_name} connected (SQLite): {row[0] if row else 'unknown'}"
                    )
                    logging.warning(
                        f"{db_name} using SQLite (dev only, not recommended for production)"
                    )
            finally:
                await conn.close()


class RedisVerifier(BaseVerifier):
    """Verifier for Redis connections."""

    async def verify(
        self,
        redis_name: str,
        redis_url: str,
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(f"Checking [bold]{redis_name}[/bold] at {mask_url(redis_url)}")
        if not isinstance(redis_url, str):
            raise ValueError("Redis URL not a string")
        if not validate_url_format(redis_url, ["redis", "rediss"]):
            raise ValueError("Invalid Redis URL format")
        if dry_run or skip_live:
            logging.info(f"{redis_name}: Format valid, skipping live connection")
            return
        client = aioredis.Redis.from_url(redis_url, decode_responses=True)
        try:
            pong = await client.ping()
            if not pong:
                raise RuntimeError("PING failed")
            info = await client.info("server")
            logging.info(
                f"{redis_name} connected (Redis): {info.get('redis_version', 'unknown')}"
            )
            if "localhost" in redis_url or "127.0.0.1" in redis_url:
                logging.warning(
                    f"{redis_name} using local instance (not recommended for production)"
                )
            if (
                redis_url.startswith("redis://")
                and "localhost" not in redis_url
                and "127.0.0.1" not in redis_url
            ):
                logging.warning(
                    f"{redis_name} using non-SSL for remote connection (rediss:// recommended for production)"
                )
        finally:
            await client.aclose()


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


class TelegramAPIVerifier(BaseVerifier):
    """Verifier for Telegram API credentials."""

    async def verify_api_id(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(
            f"Checking [bold]API_ID[/bold]: {mask_sensitive(val) if val else '(missing)'}"
        )
        if not val:
            raise ValueError("API_ID missing")
        try:
            if int(val) <= 0:
                raise ValueError("Must be positive integer")
            logging.info("API_ID ok")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")

    async def verify_api_hash(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]API_HASH[/bold] (masked: {mask_sensitive(val)})")
        if not val:
            raise ValueError("API_HASH missing")
        if not re.match(r"^[0-9a-fA-F]{32}$", val):
            logging.warning("Non-standard format; verify manually")
        logging.info("API_HASH ok")


class TelegramIDVerifier(BaseVerifier):
    """Verifier for Telegram IDs."""

    async def verify_owner_id(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]OWNER_TELEGRAM_ID[/bold]: {val or '(missing)'}")
        if not val:
            raise ValueError("OWNER_TELEGRAM_ID missing")
        try:
            if int(val) <= 0:
                raise ValueError("Must be positive")
            logging.info("OWNER_TELEGRAM_ID ok")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")

    async def verify_admin_ids(
        self, val: Optional[str], dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]ADMIN_USER_IDS[/bold]: {val or '(none)'}")
        if not val:
            logging.info("ADMIN_USER_IDS optional")
            return
        try:
            ids = [int(x.strip()) for x in val.split(",") if x.strip()]
            if any(i <= 0 for i in ids):
                raise ValueError("All must be positive")
            logging.info(f"ADMIN_USER_IDS ok (count={len(ids)})")
        except Exception as e:
            raise ValueError(f"Invalid: {e}")


class TelegramBotVerifier(BaseVerifier):
    """Verifier for Telegram bot tokens."""

    def __init__(self, http: HTTPClient):
        self.http = http
        self._re = re.compile(r"^\d+:[A-Za-z0-9_\-]+$")

    async def verify_bot_token(
        self,
        bot_name: str,
        token: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(
            f"Checking [bold]{bot_name}[/bold] (masked: {mask_sensitive(token)})"
        )
        if not token:
            raise ValueError(f"{bot_name} missing")
        if not self._re.match(token):
            logging.warning(f"{bot_name} non-standard format")
        if dry_run or skip_live:
            logging.info(f"{bot_name}: Skipping live check")
            return
        url = f"https://api.telegram.org/bot{token}/getMe"
        try:
            data = await self.http.get_json(url)
            if isinstance(data, str):
                raise RuntimeError("Unexpected non-JSON response from Telegram")
            if not data.get("ok"):
                raise RuntimeError(data.get("description", "unknown"))
            logging.info(
                f"{bot_name} valid -> Bot: {data['result'].get('username', 'unknown')}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")


class AccountsAPIVerifier(BaseVerifier):
    """Verifier for Accounts API."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        api_key: Optional[str],
        api_url: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(
            f"Checking [bold]Accounts API[/bold] at {mask_url(api_url)} (key: {mask_sensitive(api_key)})"
        )
        if not api_key or not api_url:
            raise ValueError("Missing URL or key")
        if not validate_url_format(api_url, ["http", "https"]):
            raise ValueError("Invalid URL format")
        if dry_run or skip_live:
            logging.info("Accounts API: Skipping live check")
            return
        url = f"{api_url.rstrip('/')}/status"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            await self.http.get_json(url, headers=headers)
            logging.info("Accounts API ok")
            if "localhost" in api_url:
                logging.warning("Using local instance (not recommended for production)")
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")


class WebhookVerifier(BaseVerifier):
    """Verifier for webhook settings."""

    async def verify(
        self,
        url: Optional[str],
        secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        logging.info(f"Checking [bold]BASE_WEBHOOK_URL[/bold]: {url or '(missing)'}")
        if not url:
            raise ValueError("BASE_WEBHOOK_URL missing")
        if not validate_url_format(url, ["http", "https"]):
            raise ValueError("Invalid URL")
        if url.startswith("http://") and "localhost" not in url:
            logging.warning("Non-SSL (https recommended for production)")
        if not secret:
            logging.warning("WEBHOOK_SECRET_TOKEN missing (recommended for security)")
        logging.info("Webhook ok")


class RazorpayVerifier(BaseVerifier):
    """Verifier for Razorpay credentials."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        key_id: Optional[str],
        key_secret: Optional[str],
        webhook_secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        if not key_id and not key_secret and not webhook_secret:
            logging.info("Razorpay optional, not set")
            return
        if not key_id or not key_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Razorpay[/bold] (ID: {mask_sensitive(key_id)})")
        if not webhook_secret:
            logging.warning("WEBHOOK_SECRET missing (recommended for security)")
        if dry_run or skip_live:
            logging.info("Razorpay: Skipping live check")
            return
        url = "https://api.razorpay.com/v1/plans"
        auth = aiohttp.BasicAuth(key_id, key_secret)
        try:
            await self.http.get_json(url, auth=auth)
            logging.info("Razorpay ok")
        except aiohttp.ClientResponseError as e:
            if getattr(e, "status", None) == 401:
                raise ValueError("Invalid credentials")
            raise
        except Exception as e:
            raise RuntimeError(f"Failed: {e}")


class GoogleOAuthVerifier(BaseVerifier):
    """Verifier for Google OAuth credentials."""

    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self,
        client_id: Optional[str],
        client_secret: Optional[str],
        dry_run: bool = False,
        skip_live: bool = False,
    ) -> None:
        if not client_id and not client_secret:
            logging.info("Google OAuth optional, not set")
            return
        if not client_id or not client_secret:
            raise ValueError("Incomplete keys")
        logging.info(
            f"Checking [bold]Google OAuth[/bold] (ID: {mask_sensitive(client_id)})"
        )
        if dry_run or skip_live:
            logging.info("Google OAuth: Skipping live check")
            return
        # New: Basic metadata check
        url = "https://accounts.google.com/.well-known/openid-configuration"
        try:
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or "issuer" not in data:
                raise RuntimeError("Invalid Google metadata response")
            logging.info("Google OAuth metadata ok")
        except Exception as e:
            raise RuntimeError(f"Metadata check failed: {e}")


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


# ----- SUMMARY -----
@dataclass
class Summary:
    version: str
    errors: List[str]
    warnings: List[str]
    status: str


def print_summary(summary: Summary, fmt: str, console: Console) -> None:
    if fmt == "json":
        logging.info(json.dumps(asdict(summary), indent=2))
        return

    table = Table(
        title="Verification Summary", show_header=True, header_style="bold magenta"
    )
    table.add_column("Category", style="dim")
    table.add_column("Details")

    table.add_row("Version", summary.version)
    table.add_row(
        "Status",
        f"[{'green' if summary.status == 'PASSED' else 'red'}]{summary.status}[/]",
    )
    if summary.warnings:
        table.add_row("Warnings", "\n".join(summary.warnings))
    if summary.errors:
        table.add_row("Errors", "\n".join(summary.errors))
    else:
        table.add_row("Errors", "None ✅")

    console.print(table)


# ----- SHUTDOWN -----
class ShutdownManager:
    def __init__(self):
        self._event = asyncio.Event()

    def is_shutting_down(self) -> bool:
        return self._event.is_set()

    def trigger(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


def install_signal_handlers(
    loop: asyncio.AbstractEventLoop, tasks: List[asyncio.Task]
) -> ShutdownManager:
    mgr = ShutdownManager()

    def handle(sig: int) -> None:
        logging.warning(f"Signal {sig} received, shutting down...")
        mgr.trigger()
        for task in tasks:
            if not task.done():
                task.cancel()

    try:
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, lambda s=s: handle(s))
    except NotImplementedError:
        try:
            signal.signal(signal.SIGINT, lambda s, f: handle(signal.SIGINT))
            signal.signal(signal.SIGTERM, lambda s, f: handle(signal.SIGTERM))
        except Exception:
            pass

    return mgr


# ----- EMAIL ALERT -----
def send_email_alert(
    summary: Summary, smtp_server: str, from_email: str, to_email: str, password: str
) -> None:
    """Send email alert on failure."""
    if summary.status != "FAILED":
        return
    msg = MIMEText(json.dumps(asdict(summary), indent=2))
    msg["Subject"] = "Secrets Verifier Failed"
    msg["From"] = from_email
    msg["To"] = to_email
    try:
        with smtplib.SMTP(smtp_server) as server:
            server.login(from_email, password)
            server.send_message(msg)
        logging.info("Email alert sent")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")


# ----- MAIN -----
async def main(argv: List[str]) -> int:
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

        db_verifier = DatabaseVerifier(
            args.db_timeout,
            args.pool_min_size,
            args.pool_max_size,
            retries=args.retries,
            backoff=args.backoff,
        )
        redis_verifier = RedisVerifier()
        session_verifier = SessionKeyVerifier()
        jwt_verifier = JWTSecretVerifier()
        jwt_exp_verifier = JWTExpirationVerifier()
        tg_api_verifier = TelegramAPIVerifier()
        tg_id_verifier = TelegramIDVerifier()
        tg_bot_verifier = TelegramBotVerifier(http)
        accounts_verifier = AccountsAPIVerifier(http)
        webhook_verifier = WebhookVerifier()
        razorpay_verifier = RazorpayVerifier(http)
        google_verifier = GoogleOAuthVerifier(http)  # Updated with http

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
                                db_verifier.verify,
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
                                redis_verifier.verify,
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
                            session_verifier.verify,
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
                        jwt_verifier.verify,
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
                        jwt_exp_verifier.verify,
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
                        tg_api_verifier.verify_api_id,
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
                        tg_api_verifier.verify_api_hash,
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
                        tg_id_verifier.verify_owner_id,
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
                        tg_id_verifier.verify_admin_ids,
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
                                tg_bot_verifier.verify_bot_token,
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
                            accounts_verifier.verify,
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
                        webhook_verifier.verify,
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
                        razorpay_verifier.verify,
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
                        google_verifier.verify,
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


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
