from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from vault_check.verifiers.telegram import TelegramBotVerifier


@pytest.fixture
def mock_http_client():
    return AsyncMock()


@pytest.mark.asyncio
async def test_telegram_bot_verifier_valid(mock_http_client):
    mock_http_client.get_json.return_value = {
        "ok": True,
        "result": {"username": "test_bot"},
    }
    verifier = TelegramBotVerifier(mock_http_client)
    await verifier.verify_bot_token(
        "Test Bot", "123456:ABC-DEF1234567890", skip_live=False
    )


@pytest.mark.asyncio
async def test_telegram_bot_verifier_missing(mock_http_client):
    verifier = TelegramBotVerifier(mock_http_client)
    with pytest.raises(ValueError, match="Test Bot missing"):
        await verifier.verify_bot_token("Test Bot", None)


@pytest.mark.asyncio
async def test_telegram_bot_verifier_invalid_token(mock_http_client):
    mock_http_client.get_json.return_value = {"ok": False, "description": "Unauthorized"}
    verifier = TelegramBotVerifier(mock_http_client)
    with pytest.raises(RuntimeError, match="Failed: Unauthorized"):
        await verifier.verify_bot_token(
            "Test Bot", "123456:ABC-DEF1234567890", skip_live=False
        )


@pytest.mark.asyncio
async def test_telegram_bot_verifier_skip_live(mock_http_client):
    verifier = TelegramBotVerifier(mock_http_client)
    await verifier.verify_bot_token(
        "Test Bot", "123456:ABC-DEF1234567890", skip_live=True
    )
    mock_http_client.get_json.assert_not_called()
