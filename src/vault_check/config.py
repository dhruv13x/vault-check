# src/vault_check/config.py

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


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
    "OWNER_SESSION_STRING": "Owner Session String",
    "ADMIN_USER_IDS": "Admin User IDs",
    "FORWARDER_BOT_TOKEN": "Forwarder Bot Token",
    "AUTH_BOT_TOKEN": "Auth Bot Token",
    "ADMIN_BOT_TOKEN": "Admin Bot Token",
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
MIN_ENTROPY_SCORE = 3


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"


@dataclass
class Summary:
    version: str
    errors: List[str]
    warnings: List[str]
    status: str
