#!/usr/bin/env python3
# verify_secrets.py
# Production-grade secrets verifier

from __future__ import annotations

import argparse
import asyncio
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
from .logging import setup_logging
from .runner import Runner
from .secrets import load_secrets
from .banner import print_logo

__version__ = "2.3.1"


# ----- MAIN -----
async def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=f"Secrets verifier ({__version__})")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--doppler-project", default="default_project")
    parser.add_argument("--doppler-config", default="dev")
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
    load_dotenv(args.env_file)

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
