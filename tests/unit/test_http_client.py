from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from vault_check.http_client import HTTPClient


@pytest.fixture
def mock_session():
    return AsyncMock(aiohttp.ClientSession)


@pytest.mark.asyncio
async def test_http_client_get_json_success(mock_session):
    mock_response = AsyncMock()
    mock_response.text.return_value = '{"key": "value"}'
    mock_response.status = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.raise_for_status = MagicMock()

    mock_session.request.return_value.__aenter__.return_value = mock_response

    http_client = HTTPClient(mock_session, retries=1)
    result = await http_client.get_json("http://test.com")

    assert result == {"key": "value"}


@pytest.mark.asyncio
async def test_http_client_get_json_retry(mock_session):
    # Fail first, then succeed
    mock_response_success = AsyncMock()
    mock_response_success.text.return_value = '{"key": "value"}'
    mock_response_success.status = 200
    mock_response_success.headers = {"Content-Type": "application/json"}
    mock_response_success.raise_for_status = MagicMock()

    mock_session.request.return_value.__aenter__.side_effect = [
        aiohttp.ClientError("Failed connection"),
        mock_response_success,
    ]

    http_client = HTTPClient(mock_session, retries=2, backoff=0.01)
    result = await http_client.get_json("http://test.com")

    assert result == {"key": "value"}
    assert mock_session.request.call_count == 2


@pytest.mark.asyncio
async def test_http_client_fails_after_retries(mock_session):
    mock_session.request.return_value.__aenter__.side_effect = aiohttp.ClientError(
        "Failed connection"
    )

    http_client = HTTPClient(mock_session, retries=3, backoff=0.01)

    with pytest.raises(aiohttp.ClientError):
        await http_client.get_json("http://test.com")

    assert mock_session.request.call_count == 3
