# src/vault_check/verifiers/base.py

from vault_check.exceptions import VerificationError

class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError
