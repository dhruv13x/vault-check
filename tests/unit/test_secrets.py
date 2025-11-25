# tests/unit/test_secrets.py

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.secrets import load_secrets


@pytest.mark.asyncio
async def test_load_secrets_from_env():
    """Verify that secrets are loaded from environment variables."""
    with patch("os.getenv") as mock_getenv:
        mock_getenv.return_value = "test_value"
        http_client = AsyncMock()
        secrets = await load_secrets(http_client)
        assert secrets["CORE_PLATFORM_DB_URL"] == "test_value"


@pytest.mark.asyncio
async def test_load_secrets_from_doppler():
    """Verify that secrets are loaded from Doppler."""
    http_client = AsyncMock()
    http_client.get_json.return_value = {
        "secrets": {"CORE_PLATFORM_DB_URL": "doppler_value"}
    }
    with patch("os.getenv") as mock_getenv:
        mock_getenv.return_value = "doppler_token"
        secrets = await load_secrets(http_client)
        assert secrets["CORE_PLATFORM_DB_URL"] == "doppler_value"


@pytest.mark.asyncio
@patch("boto3.client")
async def test_load_secrets_from_aws_ssm(mock_boto3_client):
    """Verify that secrets are loaded from AWS SSM."""
    mock_ssm_client = MagicMock()
    mock_ssm_client.get_parameter.return_value = {
        "Parameter": {"Value": "ssm_value"}
    }
    mock_boto3_client.return_value = mock_ssm_client
    http_client = AsyncMock()
    with patch("os.getenv") as mock_getenv:
        mock_getenv.return_value = None
        secrets = await load_secrets(http_client, aws_ssm_prefix="/test")
        assert secrets["CORE_PLATFORM_DB_URL"] == "ssm_value"
