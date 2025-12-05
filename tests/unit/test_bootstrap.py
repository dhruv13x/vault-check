from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock
import pytest
from vault_check.bootstrap import VerifierBootstrap
from vault_check.verifiers.database import DatabaseVerifier
from vault_check.verifiers.redis import RedisVerifier
from vault_check.verifiers.s3 import S3Verifier
from vault_check.verifiers.smtp import SMTPVerifier

def test_bootstrap_auto_discovery():
    """Verify that the bootstrap automatically discovers and registers checks for unknown secrets."""
    http_client = AsyncMock()
    bootstrap = VerifierBootstrap(
        http_client=http_client,
        db_timeout=1.0,
        retries=1,
        dry_run=True,
        skip_live=True,
        selected_verifiers=None,
    )

    loaded_secrets = {
        "CORE_PLATFORM_DB_URL": "postgres://known-db",
        "MY_CUSTOM_DB_URL": "postgres://custom-db:5432/mydb",
        "ANOTHER_REDIS_URL": "redis://localhost:6379/1",
        "BACKUP_S3_URL": "s3://my-backup-bucket",
        "APP_SMTP_URL": "smtp://user:pass@smtp.mail.com:587",
        "NON_SECRET": "just_a_string"
    }

    registry = bootstrap.bootstrap(loaded_secrets)
    checks = registry.checks

    # Helper to find a check
    def find_check(name):
        return next((c for c in checks if c["name"] == name), None)

    # 1. Known key
    known_check = find_check("Core Platform DB")
    assert known_check is not None
    assert known_check["args"][1] == "postgres://known-db"

    # 2. Auto-discovered DB
    auto_db_check = find_check("MY_CUSTOM_DB_URL (Auto)")
    assert auto_db_check is not None
    assert auto_db_check["args"][1] == "postgres://custom-db:5432/mydb"

    # 3. Auto-discovered Redis
    auto_redis_check = find_check("ANOTHER_REDIS_URL (Auto)")
    assert auto_redis_check is not None
    assert auto_redis_check["args"][1] == "redis://localhost:6379/1"

    # 4. Auto-discovered S3
    auto_s3_check = find_check("BACKUP_S3_URL (Auto)")
    assert auto_s3_check is not None
    assert auto_s3_check["args"][0] == "s3://my-backup-bucket"

    # 5. Auto-discovered SMTP
    auto_smtp_check = find_check("APP_SMTP_URL (Auto)")
    assert auto_smtp_check is not None
    assert auto_smtp_check["args"][0] == "smtp://user:pass@smtp.mail.com:587"

    # 6. Non-secret
    non_secret_check = find_check("NON_SECRET (Auto)")
    assert non_secret_check is None
