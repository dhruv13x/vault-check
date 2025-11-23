import pytest
from unittest.mock import MagicMock, AsyncMock
from vault_check.http_client import HTTPClient
from vault_check.verifiers.google import GoogleOAuthVerifier
from vault_check.verifiers.razorpay import RazorpayVerifier


@pytest.mark.asyncio
async def test_google_oauth_verifier_success():
    mock_session = MagicMock()
    mock_response = mock_session.request.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(
        return_value='{"scopes": "read"}'
    )
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock() # Explicitly set
    http_client = HTTPClient(mock_session)
    verifier = GoogleOAuthVerifier(http_client)
    await verifier.verify("test_client_id", "test_client_secret", "test_project_id")


@pytest.mark.asyncio
async def test_razorpay_verifier_success():
    mock_session = MagicMock()
    mock_response = mock_session.request.return_value.__aenter__.return_value
    mock_response.status = 200
    mock_response.text = AsyncMock(
        return_value='{"count": 0}'
    )
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock() # Explicitly set
    http_client = HTTPClient(mock_session)
    verifier = RazorpayVerifier(http_client)
    await verifier.verify("test_key_id", "test_key_secret", "test_webhook_secret")
