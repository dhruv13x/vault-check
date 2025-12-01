import pytest
from vault_check.verifiers.telegram import TelegramSessionVerifier

@pytest.mark.asyncio
async def test_telegram_session_verifier_valid():
    verifier = TelegramSessionVerifier()
    # A fake but valid-looking session string (alphanumeric + symbols, long)
    valid_session = "1BVtsOMABu3YIaQL68xxxxxxxccWZC1KNJSXGhh28zhuhmCgny5unQxmzOoNGUbOO_yeRbWD6i_td-rtyyyyyyyyuyyytt-GgA5G4O-ccdffffgft-ggghhhhhhhs55778yyg="
    await verifier.verify(valid_session)

@pytest.mark.asyncio
async def test_telegram_session_verifier_too_short():
    verifier = TelegramSessionVerifier()
    short_session = "1BVtsOMA"
    with pytest.raises(ValueError, match="Session string too short"):
        await verifier.verify(short_session)

@pytest.mark.asyncio
async def test_telegram_session_verifier_invalid_chars():
    verifier = TelegramSessionVerifier()
    # Contains invalid char '!'
    invalid_session = "1BVtsOMABu3YIaQL68xxxxxxxccWZC1KNJSXGhh28zhuhmCgny5unQxmzOoNGUbOO_yeRbWD6i_td-rtyyyyyyyyuyyytt-GgA5G4O-ccdffffgft-ggghhhhhhhs55778yyg!"
    with pytest.raises(ValueError, match="Invalid base64url characters"):
        await verifier.verify(invalid_session)

@pytest.mark.asyncio
async def test_telegram_session_verifier_missing():
    verifier = TelegramSessionVerifier()
    with pytest.raises(ValueError, match="Missing session string"):
        await verifier.verify(None)
