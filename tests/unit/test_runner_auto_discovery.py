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
    # Since we moved logic to bootstrap, this test now tests the integration of runner with bootstrap
    # But effectively, if we want to test auto-discovery, we should test the Bootstrap class directly.
    # However, to keep this test working with Runner, we need to let the real Bootstrap run or mock it carefully.

    # Let's test the Bootstrap class directly in a new test file, but here we will just verify
    # that runner calls the bootstrap correctly.

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
        verifiers=None,
    )

    loaded_secrets = {"CORE_PLATFORM_DB_URL": "test_db_url"}

    with patch("vault_check.runner.VerifierBootstrap") as mock_bootstrap_cls:
        mock_bootstrap = MagicMock()
        mock_registry = MagicMock()
        mock_registry.checks = []
        mock_bootstrap.bootstrap.return_value = mock_registry
        mock_bootstrap_cls.return_value = mock_bootstrap
        
        await runner.run(loaded_secrets, "1.0.0")
        
        mock_bootstrap.bootstrap.assert_called_with(loaded_secrets)
        # Verify initialization args
        mock_bootstrap_cls.assert_called_with(
            http_client=http_client,
            db_timeout=1.0,
            retries=1,
            dry_run=True,
            skip_live=True,
            selected_verifiers=None
        )
