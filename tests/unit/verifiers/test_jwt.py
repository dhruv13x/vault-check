# tests/unit/verifiers/test_jwt.py

import pytest

from vault_check.verifiers import JWTExpirationVerifier, JWTSecretVerifier


@pytest.mark.asyncio
async def test_jwt_secret_verifier_short_key():
    verifier = JWTSecretVerifier()
    with pytest.raises(ValueError, match="JWT_SECRET too short"):
        await verifier.verify("short_key")


@pytest.mark.asyncio
async def test_jwt_expiration_verifier_invalid_value():
    verifier = JWTExpirationVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify("invalid")
