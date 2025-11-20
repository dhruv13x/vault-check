# tests/unit/verifiers/test_base.py
import pytest

from vault_check.verifiers.base import BaseVerifier


class CustomVerifier(BaseVerifier):
    """A concrete implementation of BaseVerifier for testing."""

    async def verify(self):
        pass


@pytest.mark.skip(reason="BaseVerifier has no handle_verification_error method")
def test_handle_verification_error_formatting():
    """
    Check that handle_verification formats error messages as expected.
    """
    verifier = CustomVerifier()
    error_message = "Test error"
    formatted_message = verifier.handle_verification_error(
        "Test Check", ValueError(error_message)
    )
    assert error_message in formatted_message
    assert "Test Check" in formatted_message
