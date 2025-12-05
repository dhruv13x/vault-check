# tests/unit/test_logging.py

import json
import logging
import sys
from unittest.mock import MagicMock, patch

from vault_check.logger import JsonFormatter, setup_logging


@patch("vault_check.logger.RichHandler")
@patch("logging.basicConfig")
def test_setup_logging_text(mock_basic_config, mock_rich_handler):
    """Verify text logging setup."""
    handler_instance = MagicMock()
    mock_rich_handler.return_value = handler_instance

    setup_logging("INFO", fmt="text", color=True)

    mock_rich_handler.assert_called_once()
    mock_basic_config.assert_called_once_with(
        level=logging.INFO, handlers=[handler_instance], force=True
    )


@patch("logging.StreamHandler")
@patch("logging.basicConfig")
def test_setup_logging_json(mock_basic_config, mock_stream_handler):
    """Verify JSON logging setup."""
    handler_instance = MagicMock()
    mock_stream_handler.return_value = handler_instance

    setup_logging("DEBUG", fmt="json", extra={"app": "test"})

    mock_stream_handler.assert_called_once()
    handler_instance.setFormatter.assert_called_once()
    formatter = handler_instance.setFormatter.call_args[0][0]
    assert isinstance(formatter, JsonFormatter)
    assert formatter.extra == {"app": "test"}

    mock_basic_config.assert_called_once_with(
        level=logging.DEBUG, handlers=[handler_instance], force=True
    )


def test_json_formatter():
    """Verify JSON formatter creates correct payload."""
    formatter = JsonFormatter(extra={"component": "test"})
    record = logging.LogRecord(
        "test", logging.INFO, "test_path", 10, "Test message", None, None
    )
    log_output = json.loads(formatter.format(record))

    assert log_output["level"] == "INFO"
    assert log_output["msg"] == "Test message"
    assert log_output["component"] == "test"
    assert "ts" in log_output

    # Test with exception
    try:
        raise ValueError("test exception")
    except ValueError:
        record_with_exc = logging.LogRecord(
            "test_exc",
            logging.ERROR,
            "exc_path",
            20,
            "Error message",
            None,
            sys.exc_info(),
        )

    log_output_exc = json.loads(formatter.format(record_with_exc))
    assert log_output_exc["level"] == "ERROR"
    assert "exc" in log_output_exc
    assert "ValueError: test exception" in log_output_exc["exc"]