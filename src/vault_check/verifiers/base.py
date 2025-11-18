from __future__ import annotations


class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError
