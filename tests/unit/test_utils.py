# tests/unit/test_utils.py

import asyncio
from unittest.mock import Mock, patch

import pytest

from vault_check.utils import mask_sensitive, mask_url, retry_backoff


def test_mask_sensitive():
    assert mask_sensitive("1234567890123456") == "123456******3456"
    assert mask_sensitive("short") == "*****"
    assert mask_sensitive(None) == "(missing)"


def test_mask_url():
    assert mask_url("https://user:password@example.com") == "https://user:*****@example.com"
    assert mask_url("https://example.com") == "https://example.com"
    assert mask_url(None) == "(missing)"


@pytest.mark.asyncio
async def test_retry_backoff():
    # A mock async function that fails twice then succeeds
    mock_func = Mock(
        side_effect=[asyncio.TimeoutError, asyncio.TimeoutError, "Success"]
    )

    async def async_mock_func(*args, **kwargs):
        return mock_func(*args, **kwargs)

    with patch("asyncio.sleep", return_value=None):
        result = await retry_backoff(async_mock_func, retries=3)
        assert result == "Success"
        assert mock_func.call_count == 3


@pytest.mark.asyncio
async def test_retry_backoff_fails():
    mock_func = Mock(side_effect=asyncio.TimeoutError)

    async def async_mock_func(*args, **kwargs):
        return mock_func(*args, **kwargs)

    with patch("asyncio.sleep", return_value=None):
        with pytest.raises(asyncio.TimeoutError):
            await retry_backoff(async_mock_func, retries=3)
        assert mock_func.call_count == 3
