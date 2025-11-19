from unittest.mock import MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import GoogleOAuthVerifier


@pytest.mark.asyncio
async def test_google_oauth_verifier_incomplete_keys():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = GoogleOAuthVerifier(http_client)
    with pytest.raises(ValueError, match="Incomplete keys"):
        await verifier.verify("client_id", None)
