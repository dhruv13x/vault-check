
import pytest
from unittest.mock import MagicMock, AsyncMock
from vault_check.bootstrap import VerifierBootstrap

def test_bootstrap_filtering():
    http_client = MagicMock()
    # Only run "database" verifiers
    bootstrap = VerifierBootstrap(
        http_client=http_client,
        db_timeout=1.0,
        retries=1,
        dry_run=True,
        skip_live=True,
        selected_verifiers=["database"]
    )

    loaded_secrets = {
        "CORE_PLATFORM_DB_URL": "postgres://localhost",
        "CORE_PLATFORM_REDIS_URL": "redis://localhost",
        "SESSION_ENCRYPTION_KEY": "key",
        "JWT_SECRET": "secret",
        "API_ID": "123",
        "BASE_WEBHOOK_URL": "http://webhook",
        "RAZORPAY_KEY_ID": "rzp_123",
        "GOOGLE_CLIENT_ID": "google_123",
        "UNKNOWN_SECRET": "s3://bucket"
    }

    registry = bootstrap.bootstrap(loaded_secrets)
    checks = registry.checks
    names = [c["name"] for c in checks]

    assert "Core Platform DB" in names
    assert "Core Platform Redis" not in names
    assert "Session Encryption Key" not in names
    assert "JWT Secret" not in names
    assert "Telegram API ID" not in names
    assert "Webhook Settings" not in names
    assert "Razorpay" not in names
    assert "Google OAuth" not in names
    assert "UNKNOWN_SECRET (Auto)" not in names

def test_bootstrap_filtering_redis():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["redis"]
    )
    registry = bootstrap.bootstrap({"CORE_PLATFORM_REDIS_URL": "redis://localhost"})
    names = [c["name"] for c in registry.checks]
    assert "Core Platform Redis" in names

def test_bootstrap_filtering_session():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["session"]
    )
    registry = bootstrap.bootstrap({"SESSION_ENCRYPTION_KEY": "key"})
    names = [c["name"] for c in registry.checks]
    assert "Session Encryption Key" in names

def test_bootstrap_filtering_jwt():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["jwt"]
    )
    registry = bootstrap.bootstrap({"JWT_SECRET": "secret"})
    names = [c["name"] for c in registry.checks]
    assert "JWT Secret" in names

def test_bootstrap_filtering_telegram():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["telegram"]
    )
    registry = bootstrap.bootstrap({"API_ID": "123"})
    names = [c["name"] for c in registry.checks]
    assert "Telegram API ID" in names

def test_bootstrap_filtering_webhook():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["webhook"]
    )
    registry = bootstrap.bootstrap({"BASE_WEBHOOK_URL": "http://hook"})
    names = [c["name"] for c in registry.checks]
    assert "Webhook Settings" in names

def test_bootstrap_filtering_razorpay():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["razorpay"]
    )
    registry = bootstrap.bootstrap({"RAZORPAY_KEY_ID": "rzp"})
    names = [c["name"] for c in registry.checks]
    assert "Razorpay" in names

def test_bootstrap_filtering_google():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["google"]
    )
    registry = bootstrap.bootstrap({"GOOGLE_CLIENT_ID": "gclient"})
    names = [c["name"] for c in registry.checks]
    assert "Google OAuth" in names

def test_bootstrap_filtering_auto():
    bootstrap = VerifierBootstrap(
        http_client=MagicMock(), db_timeout=1.0, retries=1, dry_run=True, skip_live=True,
        selected_verifiers=["auto"]
    )
    registry = bootstrap.bootstrap({"UNKNOWN_SECRET": "s3://bucket"})
    names = [c["name"] for c in registry.checks]
    assert "UNKNOWN_SECRET (Auto)" in names
