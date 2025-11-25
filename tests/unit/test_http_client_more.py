# tests/unit/test_http_client_more.py

import pytest
from unittest.mock import MagicMock, AsyncMock
from vault_check.http_client import HTTPClient


@pytest.mark.asyncio
async def test_http_client_get_text_success():
    mock_session = MagicMock()
    mock_response = mock_session.request.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value="Hello, world!")
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock()  # Explicitly set to avoid AsyncMock warning
    http_client = HTTPClient(mock_session)
    text = await http_client.get_text("https://example.com")
    assert text == "Hello, world!"


@pytest.mark.asyncio
async def test_http_client_get_json_invalid_json():
    mock_session = MagicMock()
    mock_response = mock_session.request.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value="not json")
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock()  # Explicitly set to avoid AsyncMock warning
    http_client = HTTPClient(mock_session)
    result = await http_client.get_json("https://example.com")
    assert result == "not json"
