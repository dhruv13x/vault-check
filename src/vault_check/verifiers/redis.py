from __future__ import annotations

import logging

import redis.asyncio as aioredis

from ..utils import mask_url, validate_url_format
from .base import BaseVerifier


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
