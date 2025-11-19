import pytest

from vault_check.verifiers import WebhookVerifier


@pytest.mark.asyncio
async def test_webhook_verifier_invalid_url():
    verifier = WebhookVerifier()
    with pytest.raises(ValueError, match="Invalid URL"):
        await verifier.verify("invalid_url", "secret")
