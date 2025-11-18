import logging
import redis.asyncio as aioredis

from ..utils import mask_url, validate_url_format
from .base import BaseVerifier


class RedisVerifier(BaseVerifier):
    async def verify(
        self, redis_name: str, redis_url: str, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{redis_name}[/bold] at {mask_url(redis_url)}")
        if not validate_url_format(redis_url, ["redis", "rediss"]):
            raise ValueError("Invalid Redis URL format")
        if dry_run or skip_live:
            return
        client = aioredis.Redis.from_url(redis_url, decode_responses=True)
        try:
            await client.ping()
        finally:
            await client.aclose()
