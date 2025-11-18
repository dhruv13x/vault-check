from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from vault_check.utils import (
    _sleep_backoff,
    check_entropy,
    get_secret_value,
    mask_sensitive,
    mask_url,
    retry_backoff,
    validate_url_format,
)


def test_sleep_backoff():
    # Test with jitter = 0 to make it deterministic
    assert _sleep_backoff(1, 1, 0) == 1
    assert _sleep_backoff(1, 2, 0) == 2
    assert _sleep_backoff(1, 3, 0) == 4
    assert _sleep_backoff(1.5, 2, 0) == 3


def test_mask_sensitive():
    assert mask_sensitive("1234567890", show_first=4, show_last=2) == "1234****90"
    assert mask_sensitive("short") == "*****"
    assert mask_sensitive(None) == "(missing)"


def test_mask_url():
    assert mask_url("http://user:pass@host.com/path") == "http://user:*****@host.com/path"
    assert mask_url("http://host.com/path") == "http://host.com/path"
    assert mask_url(None) == "(missing)"


def test_get_secret_value():
    assert get_secret_value({"key": "value"}, "key") == "value"
    assert get_secret_value({"key": {"raw": "raw_val"}}, "key") == "raw_val"
    assert (
        get_secret_value({"key": {"computed": "comp_val"}}, "key") == "comp_val"
    )
    assert get_secret_value({}, "key") is None


def test_validate_url_format():
    assert validate_url_format("http://host.com", ["http"])
    assert not validate_url_format("ftp://host.com", ["http"])
    assert not validate_url_format("just-a-string", ["http"])


def test_check_entropy():
    # A known weak password
    with pytest.raises(ValueError):
        check_entropy("password")
    # A known strong password
    check_entropy("Tr0ub4dor&3")


@pytest.mark.asyncio
async def test_retry_backoff():
    # A function that will succeed on the 3rd attempt
    mock_func = MagicMock(
        side_effect=[Exception("fail"), Exception("fail"), "success"]
    )
    # Convert to an async mock
    async_mock_func = AsyncMock(wraps=mock_func)

    result = await retry_backoff(async_mock_func, retries=3, base_backoff=0.01)

    assert result == "success"
    assert async_mock_func.call_count == 3


@pytest.mark.asyncio
async def test_retry_backoff_fails():
    # A function that will always fail
    mock_func = MagicMock(side_effect=Exception("fail"))
    async_mock_func = AsyncMock(wraps=mock_func)

    with pytest.raises(Exception):
        await retry_backoff(async_mock_func, retries=3, base_backoff=0.01)

    assert async_mock_func.call_count == 3
