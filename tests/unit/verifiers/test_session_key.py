import pytest

from vault_check.verifiers import SessionKeyVerifier


@pytest.mark.asyncio
async def test_session_key_verifier_invalid_key():
    verifier = SessionKeyVerifier()
    with pytest.raises(ValueError, match="Invalid base64 Fernet key"):
        await verifier.verify("invalid_key")


@pytest.mark.asyncio
async def test_session_key_verifier_valid_key():
    verifier = SessionKeyVerifier()
    # A valid base64-encoded 32-byte key
    valid_key = "y_s3V1e_fJ7N4X-g9hQbRzLwP6K2aI5cE1tD8UvYj0o="
    await verifier.verify(valid_key)  # Should not raise an exception
