# tests/unit/verifiers/test_verifiers_coverage.py

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from vault_check.verifiers.accounts import AccountsAPIVerifier
from vault_check.verifiers.google import GoogleOAuthVerifier
from vault_check.verifiers.redis import RedisVerifier
from vault_check.verifiers.webhook import WebhookVerifier
from vault_check.verifiers.base import BaseVerifier

# Accounts
@pytest.mark.asyncio
async def test_accounts_verifier_failure():
    mock_http = MagicMock()
    mock_http.get_json = AsyncMock(side_effect=Exception("API Error"))

    verifier = AccountsAPIVerifier(mock_http)

    with pytest.raises(Exception, match="API Error"):
        await verifier.verify("api_key", "http://api.com")

# Google
@pytest.mark.asyncio
async def test_google_verifier_missing_args():
    mock_http = MagicMock()
    verifier = GoogleOAuthVerifier(mock_http)
    await verifier.verify(None, None)
    # Should not raise

@pytest.mark.asyncio
async def test_google_verifier_failure():
    mock_http = MagicMock()
    mock_http.get_json = AsyncMock(side_effect=Exception("Auth Error"))

    verifier = GoogleOAuthVerifier(mock_http)

    with pytest.raises(Exception, match="Auth Error"):
        await verifier.verify("id", "secret")

# Redis
@pytest.mark.asyncio
async def test_redis_verifier_connection_error():
    verifier = RedisVerifier()
    # Mock redis.from_url
    mock_client = AsyncMock()
    mock_client.ping.side_effect = Exception("Connection refused")
    mock_client.aclose = AsyncMock()

    with pytest.raises(Exception):
        with patch("vault_check.verifiers.redis.aioredis.Redis.from_url", return_value=mock_client):
             await verifier.verify("Redis", "redis://localhost")

@pytest.mark.asyncio
async def test_redis_verifier_invalid_url_scheme():
    verifier = RedisVerifier()
    with pytest.raises(ValueError):
        await verifier.verify("Redis", "http://localhost")

# Webhook
@pytest.mark.asyncio
async def test_webhook_verifier_failure():
    verifier = WebhookVerifier()
    with pytest.raises(ValueError):
        await verifier.verify("not_a_url", "secret")

@pytest.mark.asyncio
async def test_webhook_verifier_missing_args():
    verifier = WebhookVerifier()
    with pytest.raises(ValueError):
        await verifier.verify(None, None)
