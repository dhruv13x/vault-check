# src/vault_check/logging.py

import json
import logging
import sys
import time

from rich.console import Console
from rich.logging import RichHandler


def setup_logging(level: str, fmt: str = "text", color: bool = False) -> None:
    """Set up logging with Rich or JSON handler."""
    level_num = getattr(logging, level.upper(), logging.INFO)
    if fmt == "json":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
    else:
        handler = RichHandler(
            console=Console(color_system="auto" if color else None),
            show_time=True,
            show_level=True,
            show_path=False,
            markup=True,
        )
    logging.basicConfig(level=level_num, handlers=[handler], force=True)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)
