#!/usr/bin/env python3
# verify_secrets.py
# Production-grade secrets verifier

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import List

import aiohttp
from dotenv import load_dotenv

from .config import (
    DEFAULT_BACKOFF,
    DEFAULT_CONCURRENCY,
    DEFAULT_DB_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_JITTER,
    DEFAULT_OVERALL_TIMEOUT,
    DEFAULT_RETRIES,
)
from .http_client import HTTPClient
from .logger import setup_logging
from .runner import Runner
from .secrets import load_secrets
from .banner import print_logo

__version__ = "2.3.1"


# ----- MAIN -----
async def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=f"Secrets verifier ({__version__})")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--doppler-project", default="bot-platform")
    parser.add_argument("--doppler-config", default="dev_bot-platform")
    parser.add_argument("--aws-ssm-prefix", help="AWS SSM parameter prefix")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument("--log-format", default="text", choices=["text", "json"])
    parser.add_argument("--color", action="store_true")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT)
    parser.add_argument("--db-timeout", type=float, default=DEFAULT_DB_TIMEOUT)
    parser.add_argument("--overall-timeout", type=float, default=DEFAULT_OVERALL_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-live", action="store_true")
    parser.add_argument("--output-json", help="JSON output file")
    parser.add_argument(
        "--email-alert", nargs=4, metavar=("SMTP_SERVER", "FROM", "TO", "PASS")
    )
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--verifiers", nargs="+", help="A list of verifiers to run")
    parser.add_argument("--dashboard", action="store_true", help="Start the web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=8000, help="Port for the dashboard")
    parser.add_argument("--reports-dir", default=".", help="Directory to load reports from for the dashboard")
    parser.add_argument(
        "project_path",
        nargs="?",
        help="Path to the project directory containing .env file",
    )
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    setup_logging(
        args.log_level,
        args.log_format,
        args.color,
        extra={"app_name": "vault-check", "app_version": __version__},
    )

    if args.dashboard:
        from .dashboard import create_dashboard_app
        print(f"Starting dashboard on http://localhost:{args.dashboard_port}")
        print(f"Serving reports from: {os.path.abspath(args.reports_dir)}")

        # Define runner factory for dashboard to spawn new runners
        async def runner_factory():
            # This factory needs to create a fresh http session and runner on demand
            # Or reuse existing configuration but we need to load secrets freshly potentially
            # For simplicity, we create a new session/runner similar to CLI flow.
            # NOTE: args are captured from outer scope

            # Re-load secrets to be fresh
            initial_doppler_token_inner = os.getenv("DOPPLER_TOKEN")
            env_path_inner = args.env_file
            if args.project_path:
                 if not os.path.isabs(env_path_inner):
                    env_path_inner = os.path.join(args.project_path, env_path_inner)
            load_dotenv(env_path_inner)

            # We need a new connector/session for the background task?
            # Or we can share if we are careful. But aiohttp sessions should be closed.
            # Best to make a new one.
            connector = aiohttp.TCPConnector(ssl=True)
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=args.http_timeout),
                connector=connector
            )

            # Note: The session needs to be closed properly.
            # In this simple implementation we might rely on GC or context manager if we can structure it.
            # However, `runner_factory` is returning (runner, secrets, version).
            # The caller will use `runner.run()`.
            # `Runner` has `self.http`.
            # We should probably attach session cleanup to the runner or handle it in dashboard.

            http = HTTPClient(session, args.retries, DEFAULT_BACKOFF, DEFAULT_JITTER)

            loaded_secrets = await load_secrets(
                http,
                args.aws_ssm_prefix,
                args.doppler_project,
                args.doppler_config,
                args.dry_run,
                include_all=True,
                initial_doppler_token=initial_doppler_token_inner,
            )

            runner_instance = Runner(
                http,
                args.concurrency,
                args.db_timeout,
                args.retries,
                args.dry_run,
                args.skip_live,
                args.output_json,
                args.email_alert,
                args.verifiers,
            )

            # Patch run to close session after
            original_run = runner_instance.run
            async def run_with_cleanup(*a, **kw):
                try:
                    return await original_run(*a, **kw)
                finally:
                    await session.close()

            runner_instance.run = run_with_cleanup

            return runner_instance, loaded_secrets, __version__

        web_app = create_dashboard_app(args.reports_dir, runner_factory=runner_factory)
        runner = aiohttp.web.AppRunner(web_app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, 'localhost', args.dashboard_port)
        await site.start()
        # Keep the event loop running
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await runner.cleanup()
        return 0

    # Capture initial state of DOPPLER_TOKEN to distinguish source later
    initial_doppler_token = os.getenv("DOPPLER_TOKEN")

    env_path = args.env_file
    if args.project_path:
        if not os.path.isdir(args.project_path):
            print(
                f"Error: Directory '{args.project_path}' not found or is not a directory.",
                file=sys.stderr,
            )
            return 1
        if not os.path.isabs(env_path):
            env_path = os.path.join(args.project_path, env_path)

    load_dotenv(env_path)

    connector = aiohttp.TCPConnector(ssl=True)
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=args.http_timeout),
        connector=connector
    ) as session:
        http = HTTPClient(session, args.retries, DEFAULT_BACKOFF, DEFAULT_JITTER)

        loaded_secrets = await load_secrets(
            http,
            args.aws_ssm_prefix,
            args.doppler_project,
            args.doppler_config,
            args.dry_run,
            include_all=True,
            initial_doppler_token=initial_doppler_token,
        )

        runner = Runner(
            http,
            args.concurrency,
            args.db_timeout,
            args.retries,
            args.dry_run,
            args.skip_live,
            args.output_json,
            args.email_alert,
            args.verifiers,
        )

        return await runner.run(loaded_secrets, __version__)


def entry_point():
    """Wrapper for the async main function."""
    print_logo()
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry_point()
