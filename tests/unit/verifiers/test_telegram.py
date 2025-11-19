# tests/unit/verifiers/test_telegram.py

from unittest.mock import AsyncMock, MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import (
    TelegramAPIVerifier,
    TelegramBotVerifier,
    TelegramIDVerifier,
)


@pytest.mark.asyncio
async def test_telegram_api_verifier_invalid_id():
    verifier = TelegramAPIVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify_api_id("invalid")


@pytest.mark.asyncio
async def test_telegram_id_verifier_invalid_id():
    verifier = TelegramIDVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify_owner_id("invalid")


@pytest.mark.asyncio
async def test_telegram_bot_verifier_invalid_token():
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value='{"ok": false, "description": "Invalid token"}')
    mock_session.request.return_value.__aenter__.return_value = mock_response

    http_client = HTTPClient(mock_session)
    verifier = TelegramBotVerifier(http_client)
    with pytest.raises(RuntimeError, match="Failed: Invalid token"):
        await verifier.verify_bot_token("test_bot", "invalid_token")
