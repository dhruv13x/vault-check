from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import List

from rich.console import Console

from .config import Summary
from .output import print_summary, send_email_alert

HISTORY_DIR = Path.home() / ".vault-check" / "history"


class ReportManager:
    """
    Responsible for generating and distributing verification reports.
    """

    def __init__(self, output_json: str | None, email_alert: List[str] | None):
        self.output_json = output_json
        self.email_alert = email_alert

    def generate_report(self, version: str, errors: List[str], warnings: List[str], suggestions: List[str] = None) -> int:
        status = "FAILED" if errors else "PASSED"
        summary = Summary(version, errors, warnings, status, suggestions or [])

        self._print_to_console(summary)
        self._save_to_json(summary)
        self._save_to_history(summary)
        self._send_email(summary, status)

        return 2 if errors else 0

    def _print_to_console(self, summary: Summary):
        print_summary(summary, "text", Console())

    def _save_to_json(self, summary: Summary):
        if self.output_json:
            with open(self.output_json, "w") as f:
                json.dump(asdict(summary), f, indent=2)

    def _save_to_history(self, summary: Summary):
        try:
            # Ensure history directory exists
            HISTORY_DIR.mkdir(parents=True, exist_ok=True)

            # Generate filename with timestamp
            timestamp = int(time.time())
            filename = HISTORY_DIR / f"report_{timestamp}.json"

            data = asdict(summary)
            data["timestamp"] = timestamp

            with open(filename, "w") as f:
                json.dump(data, f, indent=2)

        except Exception:
            # We don't want history saving to crash the tool
            # But we can log it if we had a logger here.
            # Given ReportManager structure, we might print to console or ignore.
            # Let's print a warning using rich console if possible, but safer to just silent fail or print.
            pass

    def _send_email(self, summary: Summary, status: str):
        if self.email_alert and status == "FAILED":
            send_email_alert(summary, *self.email_alert)
