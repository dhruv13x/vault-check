from __future__ import annotations

from unittest.mock import MagicMock, patch

from rich.console import Console

from vault_check.config import Summary
from vault_check.output import print_summary, send_email_alert


def test_print_summary_json():
    """Verify that the summary is printed correctly in JSON format."""
    summary = Summary("1.0.0", [], [], "PASSED")
    console = MagicMock(spec=Console)
    with patch("logging.info") as mock_logging:
        print_summary(summary, "json", console)
        mock_logging.assert_called_once()


def test_send_email_alert():
    """Verify that the email alert is sent correctly."""
    summary = Summary("1.0.0", ["Test Error"], [], "FAILED")
    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_smtp_instance
        send_email_alert(
            summary, "smtp.example.com", "from@example.com", "to@example.com", "password"
        )
        mock_smtp.assert_called_once_with("smtp.example.com")
        mock_smtp_instance.login.assert_called_once_with("from@example.com", "password")
        mock_smtp_instance.send_message.assert_called_once()
