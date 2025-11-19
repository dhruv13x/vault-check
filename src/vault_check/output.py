import json
import logging
import smtplib
from dataclasses import asdict
from email.mime.text import MIMEText

from rich.console import Console
from rich.table import Table

from .config import Summary


def print_summary(summary: Summary, fmt: str, console: Console) -> None:
    if fmt == "json":
        logging.info(json.dumps(asdict(summary), indent=2))
        return

    table = Table(
        title="Verification Summary", show_header=True, header_style="bold magenta"
    )
    table.add_column("Category", style="dim")
    table.add_column("Details")

    table.add_row("Version", summary.version)
    table.add_row(
        "Status",
        f"[{'green' if summary.status == 'PASSED' else 'red'}]{summary.status}[/]",
    )
    if summary.warnings:
        table.add_row("Warnings", "\n".join(summary.warnings))
    if summary.errors:
        table.add_row("Errors", "\n".join(summary.errors))
    else:
        table.add_row("Errors", "None ✅")

    console.print(table)


def send_email_alert(
    summary: Summary, smtp_server: str, from_email: str, to_email: str, password: str
) -> None:
    """Send email alert on failure."""
    if summary.status != "FAILED":
        return
    msg = MIMEText(json.dumps(asdict(summary), indent=2))
    msg["Subject"] = "Secrets Verifier Failed"
    msg["From"] = from_email
    msg["To"] = to_email
    try:
        with smtplib.SMTP(smtp_server) as server:
            server.login(from_email, password)
            server.send_message(msg)
        logging.info("Email alert sent")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")
