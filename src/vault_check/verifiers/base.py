# src/vault_check/verifiers/base.py

class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError
