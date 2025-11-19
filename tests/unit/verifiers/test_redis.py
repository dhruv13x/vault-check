# tests/unit/verifiers/test_redis.py

import pytest

from vault_check.verifiers import RedisVerifier


@pytest.mark.asyncio
async def test_redis_verifier_invalid_url():
    verifier = RedisVerifier()
    with pytest.raises(ValueError, match="Invalid Redis URL format"):
        await verifier.verify("test_redis", "invalid_url")
