# tests/unit/test_http_client_coverage.py

import pytest
from unittest.mock import MagicMock, AsyncMock
import aiohttp
import asyncio
from vault_check.http_client import HTTPClient

@pytest.fixture
def mock_session():
    return MagicMock(spec=aiohttp.ClientSession)

@pytest.mark.asyncio
async def test_http_client_exhaust_retries_client_response_error(mock_session):
    # Setup mock to always raise ClientResponseError
    mock_response = MagicMock()
    error = aiohttp.ClientResponseError(
        request_info=MagicMock(),
        history=(),
        status=500,
        message="Internal Server Error"
    )
    mock_response.raise_for_status = MagicMock(side_effect=error)
    mock_response.text = AsyncMock(return_value="Error")

    mock_session.request.return_value.__aenter__.return_value = mock_response

    # retries=2 means max 2 attempts in this codebase (loop range(1, 3))
    client = HTTPClient(mock_session, retries=2, backoff=0.01)

    with pytest.raises(aiohttp.ClientResponseError):
        await client.get_json("http://example.com")

    assert mock_session.request.call_count == 2

@pytest.mark.asyncio
async def test_http_client_exhaust_retries_network_error(mock_session):
    mock_session.request.return_value.__aenter__.side_effect = aiohttp.ClientError("Network Error")

    client = HTTPClient(mock_session, retries=2, backoff=0.01)

    with pytest.raises(aiohttp.ClientError):
        await client.get_json("http://example.com")

    assert mock_session.request.call_count == 2

@pytest.mark.asyncio
async def test_http_client_exhaust_retries_timeout_error(mock_session):
    mock_session.request.return_value.__aenter__.side_effect = asyncio.TimeoutError("Timeout")

    client = HTTPClient(mock_session, retries=2, backoff=0.01)

    with pytest.raises(asyncio.TimeoutError):
        await client.get_json("http://example.com")

    assert mock_session.request.call_count == 2

@pytest.mark.asyncio
async def test_http_client_network_error_retry_success(mock_session):
    # Fail once with network error, then succeed
    mock_response_success = MagicMock()
    mock_response_success.status = 200
    mock_response_success.text = AsyncMock(return_value='{"ok": true}')
    mock_response_success.headers = {}
    mock_response_success.raise_for_status = MagicMock() # No error

    # Side effect on __aenter__
    mock_session.request.return_value.__aenter__.side_effect = [
        aiohttp.ClientError("Network Fluke"),
        mock_response_success
    ]

    client = HTTPClient(mock_session, retries=2, backoff=0.01)
    data = await client.get_json("http://example.com")

    assert data == {"ok": True}
    assert mock_session.request.call_count == 2
