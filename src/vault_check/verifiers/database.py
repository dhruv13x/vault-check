# src/vault_check/verifiers/database.py

import logging
import re
from urllib.parse import parse_qs, urlparse

import aiosqlite
import asyncpg

from ..config import (
    DEFAULT_BACKOFF,
    DEFAULT_DB_TIMEOUT,
    DEFAULT_POOL_MAX_SIZE,
    DEFAULT_POOL_MIN_SIZE,
    DEFAULT_RETRIES,
)
from ..utils import mask_url, retry_backoff
from .base import BaseVerifier


class DatabaseVerifier(BaseVerifier):
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
                finally:
                    await pool.close()

            await retry_backoff(
                connect_and_check, retries=self.retries, base_backoff=self.backoff
            )
        else:
            db_path = parsed.path.lstrip("/")
            conn = await aiosqlite.connect(db_path)
            try:
                async with conn.execute("SELECT sqlite_version();") as cursor:
                    row = await cursor.fetchone()
                    logging.info(f"{db_name} connected (SQLite): {row[0] if row else 'unknown'}")
            finally:
                await conn.close()
