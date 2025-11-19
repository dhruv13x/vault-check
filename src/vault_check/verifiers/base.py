class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError
