from unittest.mock import AsyncMock, MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import AccountsAPIVerifier


@pytest.mark.asyncio
async def test_accounts_api_verifier_missing_credentials():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = AccountsAPIVerifier(http_client)
    with pytest.raises(ValueError, match="Missing URL or key"):
        await verifier.verify(None, None)
