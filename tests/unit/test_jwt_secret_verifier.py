from __future__ import annotations

import pytest

from vault_check.verifiers.jwt import JWTSecretVerifier


@pytest.mark.asyncio
async def test_jwt_secret_verifier_valid():
    verifier = JWTSecretVerifier()
    await verifier.verify("a-very-strong-and-long-secret-key-that-is-at-least-32-chars")


@pytest.mark.asyncio
async def test_jwt_secret_verifier_missing():
    verifier = JWTSecretVerifier()
    with pytest.raises(ValueError, match="JWT_SECRET missing"):
        await verifier.verify(None)


@pytest.mark.asyncio
async def test_jwt_secret_verifier_too_short():
    verifier = JWTSecretVerifier()
    with pytest.raises(ValueError, match="JWT_SECRET too short"):
        await verifier.verify("short-key")


@pytest.mark.asyncio
async def test_jwt_secret_verifier_weak():
    verifier = JWTSecretVerifier()
    with pytest.raises(ValueError, match="Weak key"):
        await verifier.verify("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
