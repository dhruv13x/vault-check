# src/vault_check/runner.py

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Tuple, Optional

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from .registry import VerifierRegistry
from .signals import install_signal_handlers
from .bootstrap import VerifierBootstrap
from .reporting import ReportManager


class ExecutionEngine:
    """
    Responsible for executing the verifiers concurrently.
    """
    def __init__(self, concurrency: int):
        self.concurrency = concurrency

    async def execute(
        self,
        registry: VerifierRegistry,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> Tuple[List[str], List[str]]:
        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(self.concurrency)
        check_tasks: List[asyncio.Task] = []
        shutdown_mgr = install_signal_handlers(loop, check_tasks)

        async def sem_safe_check(progress, task_id, check):
            async with semaphore:
                if shutdown_mgr.is_shutting_down():
                    raise asyncio.CancelledError

                if event_callback:
                    await event_callback({"type": "check_start", "check": check["name"]})

                errors, warnings = [], []
                status = "OK"
                try:
                    await check["callable"](*check["args"], **check["kwargs"])
                    progress.update(task_id, completed=100)
                    logging.info(
                        f"Verification check finished: {check['name']} - OK",
                        extra={"check_name": check["name"], "status": "OK"},
                    )
                except Exception as e:
                    msg = f"{check['name']} failed: {e}"
                    status = "FAILED"
                    progress.update(
                        task_id, description=f"[red]{check['name']} (Failed)[/red]"
                    )
                    if check["is_warn_only"]:
                        status = "WARNING"
                        warnings.append(msg)
                        logging.warning(
                            f"Verification check finished: {check['name']} - WARNING - {msg}",
                            extra={
                                "check_name": check["name"],
                                "status": "WARNING",
                                "reason": msg,
                            },
                        )
                    else:
                        errors.append(msg)
                        logging.error(
                            f"Verification check finished: {check['name']} - ERROR - {msg}",
                            extra={
                                "check_name": check["name"],
                                "status": "ERROR",
                                "reason": msg,
                            },
                        )

                if event_callback:
                    await event_callback({
                        "type": "check_complete",
                        "check": check["name"],
                        "status": status,
                        "errors": errors,
                        "warnings": warnings
                    })

                return errors, warnings

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True,
        ) as progress:
            for check in registry.checks:
                task_id = progress.add_task(check["name"], total=100)
                check_tasks.append(
                    loop.create_task(sem_safe_check(progress, task_id, check))
                )

            try:
                results = await asyncio.gather(*check_tasks, return_exceptions=True)
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:
                logging.error(f"Execution stopped: {e}")
                # In case of cancellation, we might want to return what we have or just empty
                return ["Execution stopped"], []

        all_errors = []
        all_warnings = []
        for result in results:
            if isinstance(result, Exception):
                all_errors.append(str(result))
            else:
                errors, warnings = result
                all_errors.extend(errors)
                all_warnings.extend(warnings)

        return all_errors, all_warnings


class Runner:
    def __init__(
        self,
        http_client: Any,
        concurrency: int,
        db_timeout: float,
        retries: int,
        dry_run: bool,
        skip_live: bool,
        output_json: str | None,
        email_alert: List[str] | None,
        verifiers: List[str] | None,
    ):
        self.http = http_client
        self.db_timeout = db_timeout
        self.retries = retries
        self.dry_run = dry_run
        self.skip_live = skip_live
        self.verifiers = verifiers

        self.reporter = ReportManager(output_json, email_alert)
        self.execution_engine = ExecutionEngine(concurrency)

    async def run(
        self,
        loaded_secrets: Dict[str, Any],
        version: str,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> int:
        bootstrap = VerifierBootstrap(
            http_client=self.http,
            db_timeout=self.db_timeout,
            retries=self.retries,
            dry_run=self.dry_run,
            skip_live=self.skip_live,
            selected_verifiers=self.verifiers,
        )
        registry = bootstrap.bootstrap(loaded_secrets)

        errors, warnings = await self.execution_engine.execute(registry, event_callback)

        # Check if execution was stopped/cancelled which usually returns just one error "Execution stopped"
        if len(errors) == 1 and errors[0].startswith("Execution stopped"):
             return 1

        return self.reporter.generate_report(version, errors, warnings)
