# tests/unit/test_http_client.py

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from vault_check.http_client import HTTPClient


@pytest.fixture
def mock_session():
    return MagicMock(spec=aiohttp.ClientSession)


@pytest.mark.asyncio
async def test_http_client_get_json_success(mock_session):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value='{"key": "value"}')
    mock_response.headers = {}
    mock_session.request.return_value.__aenter__.return_value = mock_response

    client = HTTPClient(mock_session)
    response = await client.get_json("http://example.com")

    assert response == {"key": "value"}
    mock_session.request.assert_called_once_with("GET", "http://example.com")


@pytest.mark.asyncio
async def test_http_client_get_json_retry(mock_session):
    mock_response_fail = MagicMock()
    mock_response_fail.raise_for_status = MagicMock(side_effect=aiohttp.ClientResponseError(None, None))
    mock_response_fail.text = AsyncMock(return_value="{}")  # Added this line

    mock_response_success = MagicMock()
    mock_response_success.status = 200
    mock_response_success.text = AsyncMock(return_value='{"key": "value"}')
    mock_response_success.headers = {}

    mock_session.request.return_value.__aenter__.side_effect = [
        mock_response_fail,
        mock_response_success,
    ]

    client = HTTPClient(mock_session, retries=2)
    response = await client.get_json("http://example.com")

    assert response == {"key": "value"}
    assert mock_session.request.call_count == 2
