from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from vault_check.runner import Runner
from vault_check.verifiers.database import DatabaseVerifier
from vault_check.verifiers.redis import RedisVerifier
from vault_check.verifiers.s3 import S3Verifier
from vault_check.verifiers.smtp import SMTPVerifier

@pytest.mark.asyncio
async def test_runner_auto_discovery():
    """Verify that the runner automatically discovers and registers checks for unknown secrets."""
    http_client = AsyncMock()
    runner = Runner(
        http_client=http_client,
        concurrency=1,
        db_timeout=1.0,
        retries=1,
        dry_run=True,
        skip_live=True,
        output_json=None,
        email_alert=None,
        verifiers=None,  # Should enable auto-discovery
    )

    # loaded_secrets contains one known key and one unknown but matchable key
    loaded_secrets = {
        "CORE_PLATFORM_DB_URL": "postgres://known-db", # Known key, will be processed by explicit logic
        "MY_CUSTOM_DB_URL": "postgres://custom-db:5432/mydb", # Unknown DB key, valid pattern
        "ANOTHER_REDIS_URL": "redis://localhost:6379/1", # Unknown Redis key, valid pattern
        "BACKUP_S3_URL": "s3://my-backup-bucket", # Unknown S3 key, valid pattern
        "APP_SMTP_URL": "smtp://user:pass@smtp.mail.com:587", # Unknown SMTP key, valid pattern
        "NON_SECRET": "just_a_string" # Should not match any heuristic
    }

    with patch("vault_check.runner.VerifierRegistry") as mock_registry_cls:
        mock_registry = MagicMock()
        # We'll capture the checks added to the registry
        added_checks = []
        
        def add_side_effect(name, func, args=None, kwargs=None, is_warn_only=False):
            added_checks.append({"name": name, "func_name": func.__name__, "args": args, "kwargs": kwargs})
        
        mock_registry.add.side_effect = add_side_effect
        
        # Mock checks list to be empty so execution loop doesn't crash or run anything
        mock_registry.checks = []
        
        mock_registry_cls.return_value = mock_registry

        # Run the runner
        await runner.run(loaded_secrets, "1.0.0")

        # Assertions
        # 1. Check that the known key was added (via explicit logic)
        known_check = next((c for c in added_checks if c["name"] == "Core Platform DB"), None)
        assert known_check is not None, "Explicitly configured secret was not registered"
        assert known_check["args"][1] == "postgres://known-db"
        assert known_check["func_name"] == DatabaseVerifier().verify.__name__
        
        # 2. Check that the unknown DB key was added (via auto-discovery)
        auto_db_check = next((c for c in added_checks if c["name"] == "MY_CUSTOM_DB_URL (Auto)"), None)
        assert auto_db_check is not None, "Auto-discovered DB secret was not registered"
        assert auto_db_check["args"][1] == "postgres://custom-db:5432/mydb"
        assert auto_db_check["func_name"] == DatabaseVerifier().verify.__name__

        # 3. Check that the unknown Redis key was added (via auto-discovery)
        auto_redis_check = next((c for c in added_checks if c["name"] == "ANOTHER_REDIS_URL (Auto)"), None)
        assert auto_redis_check is not None, "Auto-discovered Redis secret was not registered"
        assert auto_redis_check["args"][1] == "redis://localhost:6379/1"
        assert auto_redis_check["func_name"] == RedisVerifier().verify.__name__

        # 4. Check that the unknown S3 key was added (via auto-discovery)
        auto_s3_check = next((c for c in added_checks if c["name"] == "BACKUP_S3_URL (Auto)"), None)
        assert auto_s3_check is not None, "Auto-discovered S3 secret was not registered"
        assert auto_s3_check["args"][0] == "s3://my-backup-bucket"
        assert auto_s3_check["func_name"] == S3Verifier().verify.__name__

        # 5. Check that the unknown SMTP key was added (via auto-discovery)
        auto_smtp_check = next((c for c in added_checks if c["name"] == "APP_SMTP_URL (Auto)"), None)
        assert auto_smtp_check is not None, "Auto-discovered SMTP secret was not registered"
        assert auto_smtp_check["args"][0] == "smtp://user:pass@smtp.mail.com:587"
        assert auto_smtp_check["func_name"] == SMTPVerifier().verify.__name__

        # 6. Ensure non-matching keys are not added
        non_secret_check = next((c for c in added_checks if c["name"] == "NON_SECRET (Auto)"), None)
        assert non_secret_check is None, "Non-secret was incorrectly auto-discovered"

