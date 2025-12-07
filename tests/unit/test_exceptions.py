# tests/unit/test_exceptions.py

import pytest
from vault_check.exceptions import VerificationError

def test_verification_error_instantiation():
    """Test that VerificationError can be instantiated with a message."""
    exc = VerificationError("Test message")
    assert exc.message == "Test message"
    assert exc.fix_suggestion is None
    assert str(exc) == "Test message"

def test_verification_error_instantiation_with_suggestion():
    """Test that VerificationError can be instantiated with a message and a fix suggestion."""
    exc = VerificationError("Test message", "Try this fix")
    assert exc.message == "Test message"
    assert exc.fix_suggestion == "Try this fix"
    assert str(exc) == "Test message"

def test_verification_error_raise_and_catch():
    """Test that VerificationError can be raised and caught."""
    with pytest.raises(VerificationError) as exc_info:
        raise VerificationError("Error during verification")
    assert exc_info.value.message == "Error during verification"
    assert exc_info.value.fix_suggestion is None
