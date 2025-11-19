# tests/unit/verifiers/test_database.py

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.verifiers import DatabaseVerifier


@pytest.mark.asyncio
@patch("asyncpg.create_pool", new_callable=AsyncMock)
async def test_database_verifier_postgres_success(mock_create_pool):
    mock_pool = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = "PostgreSQL 13.3"

    @asynccontextmanager
    async def acquire_context_manager(*args, **kwargs):
        yield mock_conn

    mock_pool.acquire = MagicMock(return_value=acquire_context_manager())
    mock_create_pool.return_value = mock_pool

    verifier = DatabaseVerifier()
    await verifier.verify(
        "test_db", "postgresql://user:pass@host/db", dry_run=False, skip_live=False
    )
    mock_create_pool.assert_called_once()


@pytest.mark.asyncio
@patch("aiosqlite.connect", new_callable=AsyncMock)
async def test_database_verifier_sqlite_success(mock_connect):
    mock_connection = AsyncMock()
    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = ("3.36.0",)

    @asynccontextmanager
    async def execute_context_manager(*args, **kwargs):
        yield mock_cursor

    mock_connection.execute = MagicMock(return_value=execute_context_manager())
    mock_connect.return_value = mock_connection

    verifier = DatabaseVerifier()
    await verifier.verify(
        "test_db", "sqlite:///test.db", dry_run=False, skip_live=False
    )
    mock_connect.assert_called_once()


@pytest.mark.asyncio
async def test_database_verifier_dry_run():
    verifier = DatabaseVerifier()
    # This should not raise an exception, even with an invalid URL
    await verifier.verify(
        "test_db", "postgresql://user:pass@host/db", dry_run=True, skip_live=False
    )


@pytest.mark.asyncio
async def test_database_verifier_invalid_url():
    verifier = DatabaseVerifier()
    with pytest.raises(ValueError, match="Invalid DB URL format"):
        await verifier.verify("test_db", "invalid_url")
