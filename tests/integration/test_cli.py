from __future__ import annotations

import asyncio

import pytest

from vault_check.cli import main


@pytest.fixture
def sample_env_file(tmp_path):
    db_path = tmp_path / "test.db"
    env_content = f"""
    SESSION_ENCRYPTION_KEY=Yl95Zmlkd3FhaW1vb3R6a2R5Z3hmY2p3bHZ2Z2E2b2g=
    JWT_SECRET=a-very-strong-and-long-secret-key-that-is-at-least-32-chars
    JWT_EXPIRATION_MINUTES=60
    CORE_PLATFORM_DB_URL=sqlite:///{db_path}
    HEAVY_WORKER_DB_URL=sqlite:///{db_path}
    GENERAL_PRODUCT_DB_URL=sqlite:///{db_path}
    CORE_PLATFORM_REDIS_URL=redis://localhost:6379/0
    HEAVY_WORKER_REDIS_URL=redis://localhost:6379/0
    GENERAL_PRODUCT_REDIS_URL=redis://localhost:6379/0
    API_ID=12345
    API_HASH=1234567890abcdef1234567890abcdef
    OWNER_TELEGRAM_ID=123456789
    FORWARDER_BOT_TOKEN=123456:ABC-DEF1234567890
    AUTH_BOT_TOKEN=123456:ABC-DEF1234567890
    ACCOUNTS_API_URL=http://localhost:8000
    ACCOUNTS_API_KEY=test-key
    BASE_WEBHOOK_URL=http://localhost:8000
    WEBHOOK_SECRET_TOKEN=test-secret
    """
    env_file = tmp_path / ".env"
    env_file.write_text(env_content)
    return env_file


@pytest.mark.asyncio
async def test_cli_dry_run_success(sample_env_file, capsys):
    await main(["--env-file", str(sample_env_file), "--dry-run"])
    captured = capsys.readouterr()
    assert "PASSED" in captured.out


@pytest.mark.asyncio
async def test_cli_live_run_failure(sample_env_file, capsys):
    await main(["--env-file", str(sample_env_file)])
    captured = capsys.readouterr()
    assert "FAILED" in captured.out
    assert "unable to open database file" in captured.out.lower()
