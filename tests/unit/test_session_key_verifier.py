from __future__ import annotations

import pytest

from vault_check.verifiers.session_key import SessionKeyVerifier


@pytest.mark.asyncio
async def test_session_key_verifier_valid():
    verifier = SessionKeyVerifier()
    # A valid Fernet key
    await verifier.verify("Yl95Zmlkd3FhaW1vb3R6a2R5Z3hmY2p3bHZ2Z2E2b2g=")


@pytest.mark.asyncio
async def test_session_key_verifier_missing():
    verifier = SessionKeyVerifier()
    with pytest.raises(ValueError, match="SESSION_ENCRYPTION_KEY missing"):
        await verifier.verify(None)


@pytest.mark.asyncio
async def test_session_key_verifier_invalid():
    verifier = SessionKeyVerifier()
    with pytest.raises(ValueError, match="Invalid base64 Fernet key"):
        await verifier.verify("not-a-valid-key")


@pytest.mark.asyncio
async def test_session_key_verifier_weak():
    verifier = SessionKeyVerifier()
    # A key that is valid base64 but weak
    with pytest.raises(ValueError, match="Weak key"):
        await verifier.verify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")
