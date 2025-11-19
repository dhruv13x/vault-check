import asyncio
import logging
import random
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from zxcvbn import zxcvbn

from .config import DEFAULT_JITTER, DEFAULT_RETRIES, DEFAULT_BACKOFF, MIN_ENTROPY_SCORE


def _sleep_backoff(
    base: float, attempt: int, jitter_frac: float = DEFAULT_JITTER
) -> float:
    backoff = base * (2 ** (attempt - 1))
    jitter = backoff * jitter_frac * (random.random() * 2 - 1)
    return max(0.0, backoff + jitter)


def mask_sensitive(
    value: Optional[str], show_first: int = 6, show_last: int = 4
) -> str:
    if not value:
        return "(missing)"
    s = str(value)
    if len(s) <= show_first + show_last:
        return "*" * len(s)
    return s[:show_first] + "*" * (len(s) - show_first - show_last) + s[-show_last:]


def mask_url(url: Optional[str]) -> str:
    if not url:
        return "(missing)"
    parsed = urlparse(url)
    if parsed.password:
        netloc = parsed.netloc.replace(parsed.password, "*****")
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def get_secret_value(secrets: Dict[str, Any], key: str) -> Optional[str]:
    val = secrets.get(key)
    if isinstance(val, dict):
        return val.get("computed") or val.get("raw")
    return val if isinstance(val, str) else None


def validate_url_format(url: Optional[str], schemes: List[str]) -> bool:
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url)
    base_scheme = parsed.scheme.lower().split("+")[0]
    return base_scheme in schemes and bool(parsed.netloc)


def check_entropy(key: str, min_score: int = MIN_ENTROPY_SCORE) -> None:
    """Check key strength using zxcvbn."""
    result = zxcvbn(key)
    if result["score"] < min_score:
        raise ValueError(
            f"Weak key (score {result['score']}/4): {result['feedback']['warning']}"
        )


async def retry_backoff(
    func: Callable,
    retries: int = DEFAULT_RETRIES,
    base_backoff: float = DEFAULT_BACKOFF,
    jitter_frac: float = DEFAULT_JITTER,
    *args,
    **kwargs,
) -> Any:
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            last_exc = e
            logging.debug("Retry attempt %d failed: %s", attempt, e)
            if attempt == retries:
                raise
            await asyncio.sleep(_sleep_backoff(base_backoff, attempt, jitter_frac))
    raise last_exc or RuntimeError("Retry failed")
