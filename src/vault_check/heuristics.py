import re
from typing import Optional, Type, Tuple

from .verifiers.base import BaseVerifier
from .verifiers.database import DatabaseVerifier
from .verifiers.redis import RedisVerifier
from .verifiers.s3 import S3Verifier
from .verifiers.smtp import SMTPVerifier


class HeuristicsEngine:
    """
    Matches secret values against regex patterns to determine the appropriate Verifier.
    """
    
    # List of (regex_pattern, VerifierClass, default_kwargs)
    # Note: DatabaseVerifier and RedisVerifier verify() methods expect specific signatures.
    # We might need to handle that in the Runner.
    PATTERNS: list[Tuple[str, Type[BaseVerifier]]] = [
        (r"^postgres(ql)?(\+asyncpg)?://.+", DatabaseVerifier),
        (r"^sqlite://.+", DatabaseVerifier),
        (r"^redis(s)?://.+", RedisVerifier),
        (r"^s3://.+", S3Verifier),
        (r"^smtp(s)?://.+", SMTPVerifier),
    ]

    @classmethod
    def match(cls, value: str) -> Optional[Type[BaseVerifier]]:
        if not isinstance(value, str):
            return None
        # Simple heuristic: if it looks like a URL of a known scheme
        for pattern, verifier_cls in cls.PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return verifier_cls
        return None
