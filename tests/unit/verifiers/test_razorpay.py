# tests/unit/verifiers/test_razorpay.py

from unittest.mock import MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import RazorpayVerifier


@pytest.mark.asyncio
async def test_razorpay_verifier_incomplete_keys():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = RazorpayVerifier(http_client)
    with pytest.raises(ValueError, match="Incomplete keys"):
        await verifier.verify("key_id", None, None)
