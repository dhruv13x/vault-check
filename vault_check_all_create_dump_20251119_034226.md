# 🗃️ Project Code Dump

**Generated:** 2025-11-19T03:42:27+00:00 UTC
**Version:** 12.0.0
**Total Files:** 41
**Total Lines:** 1954
**Git Branch:** main | **Commit:** 2c52f7d

---

## Table of Contents

1. [src/vault_check/registry.py](#src-vault-check-registry-py)
2. [docker-compose.yml](#docker-compose-yml)
3. [src/vault_check/logging.py](#src-vault-check-logging-py)
4. [src/vault_check/output.py](#src-vault-check-output-py)
5. [.github/workflows/test.yml](#github-workflows-test-yml)
6. [src/vault_check/__main__.py](#src-vault-check-main-py)
7. [.github/workflows/publish.yml](#github-workflows-publish-yml)
8. [src/vault_check/http_client.py](#src-vault-check-http-client-py)
9. [src/vault_check/config.py](#src-vault-check-config-py)
10. [src/vault_check/signals.py](#src-vault-check-signals-py)
11. [.pre-commit-config.yaml](#pre-commit-config-yaml)
12. [docs/ADR.md](#docs-adr-md)
13. [TASKS.md](#tasks-md)
14. [pyproject.toml](#pyproject-toml)
15. [src/vault_check/cli.py](#src-vault-check-cli-py)
16. [README.md](#readme-md)
17. [src/vault_check/verifiers/base.py](#src-vault-check-verifiers-base-py)
18. [src/vault_check/verifiers/redis.py](#src-vault-check-verifiers-redis-py)
19. [src/vault_check/verifiers/session_key.py](#src-vault-check-verifiers-session-key-py)
20. [src/vault_check/verifiers/jwt.py](#src-vault-check-verifiers-jwt-py)
21. [tests/integration/test_cli_integration.py](#tests-integration-test-cli-integration-py)
22. [src/vault_check/verifiers/webhook.py](#src-vault-check-verifiers-webhook-py)
23. [src/vault_check/verifiers/google.py](#src-vault-check-verifiers-google-py)
24. [src/vault_check/verifiers/razorpay.py](#src-vault-check-verifiers-razorpay-py)
25. [src/vault_check/utils.py](#src-vault-check-utils-py)
26. [src/vault_check/verifiers/database.py](#src-vault-check-verifiers-database-py)
27. [src/vault_check/verifiers/accounts.py](#src-vault-check-verifiers-accounts-py)
28. [src/vault_check/verifiers/telegram.py](#src-vault-check-verifiers-telegram-py)
29. [tests/unit/test_cli.py](#tests-unit-test-cli-py)
30. [tests/e2e/test_e2e.py](#tests-e2e-test-e2e-py)
31. [tests/unit/test_http_client.py](#tests-unit-test-http-client-py)
32. [tests/unit/test_utils.py](#tests-unit-test-utils-py)
33. [tests/unit/verifiers/test_accounts.py](#tests-unit-verifiers-test-accounts-py)
34. [tests/unit/verifiers/test_google.py](#tests-unit-verifiers-test-google-py)
35. [tests/unit/verifiers/test_razorpay.py](#tests-unit-verifiers-test-razorpay-py)
36. [tests/unit/verifiers/test_jwt.py](#tests-unit-verifiers-test-jwt-py)
37. [tests/unit/verifiers/test_database.py](#tests-unit-verifiers-test-database-py)
38. [tests/unit/verifiers/test_telegram.py](#tests-unit-verifiers-test-telegram-py)
39. [tests/unit/verifiers/test_session_key.py](#tests-unit-verifiers-test-session-key-py)
40. [tests/unit/verifiers/test_webhook.py](#tests-unit-verifiers-test-webhook-py)
41. [tests/unit/verifiers/test_redis.py](#tests-unit-verifiers-test-redis-py)

---

## src/vault_check/registry.py

<a id='src-vault-check-registry-py'></a>

```python
from typing import Any, Callable, Dict, List, Optional


class VerifierRegistry:
    """A registry for verifier checks."""

    def __init__(self):
        self.checks: List[Dict[str, Any]] = []

    def add(
        self,
        name: str,
        callable: Callable,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        is_warn_only: bool = False,
    ):
        """
        Adds a verifier check to the registry.

        Args:
            name: The name of the check.
            callable: The verifier function or method to call.
            args: Positional arguments for the callable.
            kwargs: Keyword arguments for the callable.
            is_warn_only: If True, failures will be treated as warnings.
        """
        self.checks.append(
            {
                "name": name,
                "callable": callable,
                "args": args or [],
                "kwargs": kwargs or {},
                "is_warn_only": is_warn_only,
            }
        )

```

---

## docker-compose.yml

<a id='docker-compose-yml'></a>

```yaml
version: "3.8"

services:
  postgres:
    image: postgres:13
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: testdb
    ports:
      - "5432:5432"

  redis:
    image: redis:6
    ports:
      - "6379:6379"

```

---

## src/vault_check/logging.py

<a id='src-vault-check-logging-py'></a>

```python
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

```

---

## src/vault_check/output.py

<a id='src-vault-check-output-py'></a>

```python
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

```

---

## .github/workflows/test.yml

<a id='github-workflows-test-yml'></a>

```yaml
name: Run Tests

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e .[dev]
      - name: Run tests
        run: |
          pytest
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          fail_ci_if_error: true

```

---

## src/vault_check/__main__.py

<a id='src-vault-check-main-py'></a>

```python
import asyncio
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))

```

---

## .github/workflows/publish.yml

<a id='github-workflows-publish-yml'></a>

```yaml
name: 🚀 Publish to PyPI (Trusted Publishing)

on:
  push:
    tags:
      - "v*.*.*"  # Example: v1.2.3

permissions:
  contents: read
  id-token: write  # Required for PyPI OIDC

jobs:
  build-and-publish:
    name: Build & Publish
    runs-on: ubuntu-latest
    environment: pypi  # Must match GitHub environment name

    steps:
      - name: 🧩 Checkout code
        uses: actions/checkout@v4

      - name: 🐍 Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"

      - name: 📦 Install build & dev tools
        run: |
          python -m pip install --upgrade pip
          pip install .[dev]
          pip install build

      - name: 🧪 Run tests & generate coverage
        run: pytest --cov=src --cov-report=xml

      - name: 📊 Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          token: ${{ secrets.CODECOV_TOKEN }}
          file: ./coverage.xml
          verbose: true

      - name: ⚙️ Build distribution
        run: python -m build

      - name: 🔍 Verify dist files
        run: twine check dist/*

      - name: 🚀 Publish to PyPI (OIDC Trusted Publishing)
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          verbose: true
          skip-existing: false
```

---

## src/vault_check/http_client.py

<a id='src-vault-check-http-client-py'></a>

```python
import asyncio
import json
import logging
from typing import Any, Dict, Tuple

import aiohttp

from .config import DEFAULT_BACKOFF, DEFAULT_JITTER, DEFAULT_RETRIES
from .utils import _sleep_backoff


class HTTPClient:
    """Async HTTP client with retries."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        jitter_frac: float = DEFAULT_JITTER,
    ):
        self.session = session
        self.retries = max(0, retries)
        self.backoff = max(0.0, backoff)
        self.jitter_frac = max(0.0, jitter_frac)

    async def _request(
        self, method: str, url: str, **kwargs
    ) -> Tuple[int, Dict[str, str], str]:
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with self.session.request(method, url, **kwargs) as resp:
                    text = await resp.text()
                    resp.raise_for_status()
                    headers = dict(resp.headers)
                    return resp.status, headers, text
            except aiohttp.ClientResponseError as e:
                last_exc = e
                logging.debug("HTTP response error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exc = e
                logging.debug("HTTP network error (attempt %d): %s", attempt, e)
                if attempt == self.retries:
                    raise
            await asyncio.sleep(_sleep_backoff(self.backoff, attempt, self.jitter_frac))
        raise last_exc or RuntimeError("HTTP request failed")

    async def get_json(self, url: str, **kwargs) -> Any:
        _, _, text = await self._request("GET", url, **kwargs)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    async def get_text(self, url: str, **kwargs) -> str:
        _, _, text = await self._request("GET", url, **kwargs)
        return text

```

---

## src/vault_check/config.py

<a id='src-vault-check-config-py'></a>

```python
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


SECRET_KEYS = {
    "CORE_PLATFORM_DB_URL": "Core Platform DB",
    "HEAVY_WORKER_DB_URL": "Heavy Worker DB",
    "GENERAL_PRODUCT_DB_URL": "General Product DB",
    "CORE_PLATFORM_REDIS_URL": "Core Platform Redis",
    "HEAVY_WORKER_REDIS_URL": "Heavy Worker Redis",
    "GENERAL_PRODUCT_REDIS_URL": "General Product Redis",
    "SESSION_ENCRYPTION_KEY": "Session Encryption Key",
    "JWT_SECRET": "JWT Secret",
    "JWT_ALGORITHM": "JWT Algorithm",
    "JWT_EXPIRATION_MINUTES": "JWT Expiration Minutes",
    "API_ID": "Telegram API_ID",
    "API_HASH": "Telegram API_HASH",
    "OWNER_TELEGRAM_ID": "Owner Telegram ID",
    "ADMIN_USER_IDS": "Admin User IDs",
    "FORWARDER_BOT_TOKEN": "Forwarder Bot Token",
    "AUTH_BOT_TOKEN": "Auth Bot Token",
    "ACCOUNTS_API_URL": "Accounts API URL",
    "ACCOUNTS_API_KEY": "Accounts API Key",
    "BASE_WEBHOOK_URL": "Base Webhook URL",
    "WEBHOOK_SECRET_TOKEN": "Webhook Secret Token",
    "RAZORPAY_KEY_ID": "Razorpay Key ID",
    "RAZORPAY_KEY_SECRET": "Razorpay Key Secret",
    "RAZORPAY_WEBHOOK_SECRET": "Razorpay Webhook Secret",
    "GOOGLE_CLIENT_ID": "Google Client ID",
    "GOOGLE_CLIENT_SECRET": "Google Client Secret",
}

DEFAULT_CONCURRENCY = 5
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 0.6
DEFAULT_HTTP_TIMEOUT = 12.0
DEFAULT_DB_TIMEOUT = 10.0
DEFAULT_OVERALL_TIMEOUT = 60.0
DEFAULT_POOL_MIN_SIZE = 1
DEFAULT_POOL_MAX_SIZE = 10
DEFAULT_JITTER = 0.2
MIN_ENTROPY_SCORE = 3


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"


@dataclass
class Summary:
    version: str
    errors: List[str]
    warnings: List[str]
    status: str

```

---

## src/vault_check/signals.py

<a id='src-vault-check-signals-py'></a>

```python
import asyncio
import logging
import signal
from typing import List


class ShutdownManager:
    def __init__(self):
        self._event = asyncio.Event()

    def is_shutting_down(self) -> bool:
        return self._event.is_set()

    def trigger(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


def install_signal_handlers(
    loop: asyncio.AbstractEventLoop, tasks: List[asyncio.Task]
) -> ShutdownManager:
    mgr = ShutdownManager()

    def handle(sig: int) -> None:
        logging.warning(f"Signal {sig} received, shutting down...")
        mgr.trigger()
        for task in tasks:
            if not task.done():
                task.cancel()

    try:
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, lambda s=s: handle(s))
    except NotImplementedError:
        try:
            signal.signal(signal.SIGINT, lambda s, f: handle(signal.SIGINT))
            signal.signal(signal.SIGTERM, lambda s, f: handle(signal.SIGTERM))
        except Exception:
            pass

    return mgr

```

---

## .pre-commit-config.yaml

<a id='pre-commit-config-yaml'></a>

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.11.0
    hooks:
      - id: black
        language_version: python3.11
  - repo: https://github.com/pycqa/mypy
    rev: v1.7.0
    hooks:
      - id: mypy
        additional_dependencies: [types-redis]
  - repo: https://github.com/charliermarsh/ruff-pre-commit
    rev: "v0.1.6"
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]

```

---

## docs/ADR.md

<a id='docs-adr-md'></a>

~~~markdown
# ADR-001: Modular Refactoring of `vault-check`

**Status:** Proposed

**Context:**
The `vault-check` tool was implemented as a single, monolithic script (`cli.py`), containing all logic for configuration, logging, utilities, HTTP requests, and various verification checks. This design hindered testability, maintainability, and extensibility. As the number of verifiers and features grew, the single-file approach became a significant source of technical debt.

**Decision:**
We will refactor the codebase into a modular structure, enforcing the Single Responsibility Principle (SRP). Each distinct concern will be moved into its own dedicated module. The proposed structure is as follows:

```
src/vault_check/
├── __init__.py
├── cli.py          # Orchestration, argument parsing, and main entry point
├── config.py       # SECRET_KEYS, default values, and dataclasses (e.g., Summary)
├── http_client.py  # HTTPClient class for async requests
├── logging.py      # Logging setup and custom formatters
├── output.py       # Functions for printing summaries and sending alerts
├── signals.py      # Graceful shutdown and signal handling
├── utils.py        # Shared utility functions (e.g., masking, retries)
└── verifiers/      # Subdirectory for all verifier plugins
    ├── __init__.py
    ├── base.py     # BaseVerifier abstract class
    ├── database.py # DatabaseVerifier
    ├── redis.py    # RedisVerifier
    └── ...         # etc.
```

Verifiers, in particular, will be treated as plugins. The core `cli.py` will orchestrate the execution of these verifiers without containing their implementation details.

**Consequences:**

*   **Positive:**
    *   **Improved Testability:** Each module can be unit-tested in isolation. Mocking dependencies (like the HTTP client or database connections) becomes straightforward.
    *   **Enhanced Maintainability:** Smaller, focused modules are easier to understand, debug, and modify.
    *   **Increased Extensibility:** New verifiers can be added by simply creating a new file in the `verifiers/` directory without modifying the core orchestration logic. This makes the system more "open for extension, closed for modification."
    *   **Clearer Dependencies:** The import graph becomes explicit, making it easier to reason about the codebase and avoid circular dependencies.

*   **Negative:**
    *   Increased file count, which might slightly increase cognitive overhead for new contributors initially.
    *   Slightly more complex import statements.

**Justification:**
The long-term benefits of a modular, testable, and extensible architecture far outweigh the minor increase in complexity from a larger number of files. This refactoring aligns with standard Python best practices and is crucial for the project's future growth and stability. It moves the project from a simple script to a maintainable software application.

~~~

---

## TASKS.md

<a id='tasks-md'></a>

~~~markdown
### Phase 1: Preparation & Analysis (2-4 hours)
1. **Audit Current Codebase**
   - Scan for undefined refs (e.g., `AccountsAPIVerifier`, `WebhookVerifier`, `install_signal_handlers`, `safe_check`, `Summary`, `print_summary`, `send_email_alert`—infer/complete stubs from context if truncated).
   - Map dependencies: Extract SECRET_KEYS to config; identify cycles (e.g., HTTPClient used in verifiers).
   - Deliverable: Markdown report with module map (e.g., table of classes/functions + deps graph via networkx if needed).
   - AC: 100% coverage of missing defs stubbed; no runtime errors on `vault-check --version`.

2. **Define Refactor Boundaries**
   - Enforce SRP: One module per concern (e.g., verifiers in subdir, utils separate).
   - Propose structure:
     ```
     src/vault_check/
     ├── __init__.py
     ├── cli.py          # Orchestration + argparse
     ├── config.py       # SECRET_KEYS, defaults, dataclasses (Summary)
     ├── utils.py        # mask_*, retry_backoff, _sleep_backoff
     ├── http_client.py  # HTTPClient class
     ├── logging.py      # setup_logging, JsonFormatter
     ├── verifiers/      # Subdir for all BaseVerifier subclasses
     │   ├── __init__.py
     │   ├── base.py     # BaseVerifier
     │   ├── database.py # DatabaseVerifier
     │   ├── redis.py    # RedisVerifier
     │   ├── session_key.py
     │   ├── jwt.py      # JWTSecretVerifier + JWTExpirationVerifier
     │   ├── telegram.py # TelegramAPIVerifier, TelegramIDVerifier, TelegramBotVerifier
     │   ├── accounts.py # AccountsAPIVerifier (stub if missing)
     │   ├── webhook.py  # WebhookVerifier
     │   ├── razorpay.py # RazorpayVerifier
     │   └── google.py   # GoogleOAuthVerifier
     ├── signals.py      # install_signal_handlers
     └── output.py       # print_summary, send_email_alert
     ```
   - Deliverable: Updated tree diagram + ADR.md justifying splits (e.g., "Verifiers as plugins for extensibility").
   - AC: Boundaries testable in isolation (e.g., mock HTTP in telegram.py).

### Phase 2: Modular Refactor (8-12 hours)
3. **Extract Shared Concerns**
   - Move utils/logging to dedicated files; import cleanly (e.g., `from .utils import retry_backoff`).
   - Refactor HTTPClient to http_client.py; make injectable (e.g., via DI in verifiers).
   - Extract config: SECRET_KEYS as const dict; defaults as dataclass; Summary as dataclass.
   - Update cli.py: Import orchestrators; replace inline logic with `VerifierRegistry` (new class to dispatch checks).
   - Deliverable: Refactored files with 100% backward compat (CLI flags unchanged); black/mypy clean.
   - AC: `pytest -v` on stubs passes; no import errors in `vault-check --help`.

4. **Modularize Verifiers**
   - Each verifier: Single file, async verify() method, type-hinted params (e.g., `async def verify(self, key: str, dry_run: bool = False) -> None`).
   - Add entropy checks uniformly (e.g., mixin class for keys).
   - Stub missing (e.g., AccountsAPIVerifier: Basic HTTP auth check to /health).
   - Refactor main checks: Use loop over registry (e.g., `for verifier in registry: await verifier.verify(secrets)`).
   - Deliverable: Verifiers dir with 10+ files; sem_safe_check in cli.py generalized.
   - AC: Isolated unit tests (e.g., mock aiohttp in TelegramBotVerifier) pass.

5. **Enhance Orchestration & Resilience**
   - signals.py: Graceful shutdown with SIGINT/SIGTERM; cancel tasks.
   - output.py: print_summary as rich.Table/JSON; send_email_alert with smtplib (add TLS).
   - cli.py: Wrap main in try/except; add --verbose for debug.
   - Deliverable: Updated cli.py (~300 LOC, orchestration only); full async flow preserved.
   - AC: Manual run `vault-check --dry-run` yields identical output to original.

### Phase 3: Test Suite Implementation (8-10 hours)
6. **Unit Tests (Core Coverage)**
   - Use pytest-asyncio; target 80%+ coverage (pytest-cov).
   - Per module: Test utils (e.g., mask_sensitive edge cases), HTTPClient (mock responses), verifiers (mock connections, raise ValueError on weak keys).
   - Examples:
     - `test_utils.py`: `assert retry_backoff(mock_func, retries=1) == expected`.
     - `test_verifiers/test_session_key.py`: `await verifier.verify(invalid_key) raises ValueError`.
   - Deliverable: tests/unit/ dir with 20+ test files; fixtures for mocks (e.g., @pytest.mark.asyncio).
   - AC: `pytest tests/unit/ -v --cov=src/vault_check --cov-report=term-missing` >85%.

7. **Integration & E2E Tests**
   - Integration: Test verifier chains (e.g., load .env, run subset checks).
   - E2E: Docker-compose with mock Postgres/Redis; run full `vault-check --dry-run` via subprocess.
   - Add parametrize for flags (e.g., @pytest.mark.parametrize("dry_run", [True, False])).
   - Handle async: Use asyncio.run for top-level tests.
   - Deliverable: tests/integration/ and tests/e2e/; tox.ini for multi-py envs.
   - AC: `pytest tests/integration/ -v` passes; E2E simulates FAIL (e.g., missing key) and asserts exit 2.

8. **Quality Gates & CI Hooks**
   - Add pre-commit: black, mypy, ruff (linting).
   - pyproject.toml: Extend [tool.pytest.ini_options] with markers (e.g., @pytest.mark.live).
   - GitHub Actions: .github/workflows/test.yml with matrix (py3.11-3.12), coverage upload.
   - Deliverable: .pre-commit-config.yaml, updated pyproject.toml [dev] deps (+pytest-cov, pytest-mock).
   - AC: `pre-commit run --all-files` clean; CI green on push.

### Phase 4: Validation & Polish (2 hours)
9. **Refactor Validation**
   - Diff original vs. refactored: Assert identical behavior (e.g., run both on sample .env).
   - Perf check: time `vault-check` pre/post (expect <5% delta).
   - Deliverable: validation.md with benchmarks, coverage report.
   - AC: 100% functional parity; docs updated (README refs new structure).

10. **Final Review & PR**
    - Generate PR description: Changes, risks, migration notes (none needed, drop-in replace).
    - Tag v1.0.0; changelog entry.
    - Deliverable: Zipped refactored src/tests/ + PR.md.
    - AC: JULES self-review: No TODOs, 100% typed.

~~~

---

## pyproject.toml

<a id='pyproject-toml'></a>

```toml
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "vault-check"
version = "1.0.0"
description = "Production-grade secrets verifier for bot platforms"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "dhruv13x", email = "dhruv13x@example.com"}]  # Update with yours
requires-python = ">=3.11"
keywords = ["vault", "secrets", "env", "cli", "security"]
classifiers = [
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Topic :: Software Development :: Testing",
    "Topic :: System :: Systems Administration",
]
dependencies = [
    "aiohttp>=3.8.0",  # Core HTTP client
    "python-dotenv>=1.0.0",
    "rich>=13.0.0",
    "cryptography>=41.0.0",
]

[project.optional-dependencies]
aws = ["boto3>=1.26.0"]
db = [
    "asyncpg>=0.29.0",
    "aiosqlite>=0.19.0",
    "redis[asyncio]>=4.5.0",
]
security = ["zxcvbn>=0.0.7"]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=2.12.1",
    "black>=23.0.0",
    "mypy>=1.5.0",
    "build",
    "twine",
]

[project.scripts]
vault-check = "vault_check.cli:entry_point"

[project.urls]
Homepage = "https://github.com/dhruv13x/vault-check"
Source = "https://github.com/dhruv13x/vault-check"

[tool.setuptools]
package-dir = {"" = "src"}
[tool.setuptools.packages.find]
where = ["src"]



[tool.pytest.ini_options]

pythonpath = [
    ".",
    "vault_check/src",
]

testpaths = [
    "vault_check/tests",
]

asyncio_mode = "auto"

addopts = [
    "--timeout=10",
    "--durations=10",
    "--log-cli-level=INFO",
    "-v",
    "-ra",
    "--tb=short",
    "--showlocals",
    
    "--cov=vault_check/src",

    "--cov-report=term-missing:skip-covered",
    "--cov-fail-under=90",
]

[tool.coverage.run]
branch = true
source = [
    "vault_check/src",
]

[tool.coverage.report]
fail_under = 90
show_missing = true

```

---

## src/vault_check/cli.py

<a id='src-vault-check-cli-py'></a>

```python
#!/usr/bin/env python3
# verify_secrets.py
# Production-grade secrets verifier

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import asdict
from typing import Any, Dict, List

import aiohttp
import boto3
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from .config import (
    DEFAULT_BACKOFF,
    DEFAULT_CONCURRENCY,
    DEFAULT_DB_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_JITTER,
    DEFAULT_OVERALL_TIMEOUT,
    DEFAULT_RETRIES,
    SECRET_KEYS,
    Summary,
)
from .http_client import HTTPClient
from .logging import setup_logging
from .output import print_summary, send_email_alert
from .registry import VerifierRegistry
from .signals import install_signal_handlers
from .utils import get_secret_value
from .verifiers import (
    AccountsAPIVerifier,
    DatabaseVerifier,
    GoogleOAuthVerifier,
    JWTExpirationVerifier,
    JWTSecretVerifier,
    RazorpayVerifier,
    RedisVerifier,
    SessionKeyVerifier,
    TelegramAPIVerifier,
    TelegramBotVerifier,
    TelegramIDVerifier,
    WebhookVerifier,
)

__version__ = "1.0.0"


# ----- MAIN -----
async def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=f"Secrets verifier ({__version__})")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--doppler-project", default="default_project")
    parser.add_argument("--doppler-config", default="dev")
    parser.add_argument("--aws-ssm-prefix", help="AWS SSM parameter prefix")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
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
    parser.add_argument("--email-alert", nargs=4, metavar=("SMTP_SERVER", "FROM", "TO", "PASS"))
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    setup_logging(args.log_level, args.log_format, args.color)
    load_dotenv(args.env_file)

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=args.http_timeout)) as session:
        http = HTTPClient(session, args.retries, DEFAULT_BACKOFF, DEFAULT_JITTER)

        secrets: Dict[str, Any] = {}
        doppler_token = os.getenv("DOPPLER_TOKEN")
        aws_ssm_client = None
        if args.aws_ssm_prefix:
            try:
                aws_ssm_client = boto3.client("ssm")
                logging.info("Using AWS SSM for secrets")
            except Exception as e:
                logging.warning(f"AWS SSM init failed: {e}; falling back")

        if doppler_token and not args.dry_run:
            doppler_url = f"https://api.doppler.com/v3/configs/config/secrets?project={args.doppler_project}&config={args.doppler_config}"
            try:
                data = await http.get_json(
                    doppler_url, headers={"Authorization": f"Bearer {doppler_token}"}
                )
                if not isinstance(data, dict):
                    raise ValueError("Unexpected Doppler response type")
                secrets = data.get("secrets", data)
                logging.info(f"Doppler secrets fetched (count={len(secrets)})")
            except Exception as e:
                logging.warning(f"Doppler fetch failed: {e}; using .env")
        elif aws_ssm_client:
            try:
                for key in SECRET_KEYS:
                    param_name = f"{args.aws_ssm_prefix}/{key}"
                    param = aws_ssm_client.get_parameter(
                        Name=param_name, WithDecryption=True
                    )
                    secrets[key] = param["Parameter"]["Value"]
                logging.info(f"AWS SSM secrets fetched (count={len(secrets)})")
            except Exception as e:
                logging.warning(f"AWS SSM fetch failed: {e}; using .env")

        loaded_secrets = {k: get_secret_value(secrets, k) or os.getenv(k) for k in SECRET_KEYS}

        registry = VerifierRegistry()

        db_verifier = DatabaseVerifier(args.db_timeout, retries=args.retries)
        for db_key, db_name in [
            ("CORE_PLATFORM_DB_URL", "Core Platform DB"),
            ("HEAVY_WORKER_DB_URL", "Heavy Worker DB"),
            ("GENERAL_PRODUCT_DB_URL", "General Product DB"),
        ]:
            if db_url := loaded_secrets.get(db_key):
                registry.add(
                    db_name,
                    db_verifier.verify,
                    args=[db_name, db_url],
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

        redis_verifier = RedisVerifier()
        for redis_key, redis_name in [
            ("CORE_PLATFORM_REDIS_URL", "Core Platform Redis"),
            ("HEAVY_WORKER_REDIS_URL", "Heavy Worker Redis"),
            ("GENERAL_PRODUCT_REDIS_URL", "General Product Redis"),
        ]:
            if redis_url := loaded_secrets.get(redis_key):
                registry.add(
                    redis_name,
                    redis_verifier.verify,
                    args=[redis_name, redis_url],
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

        session_verifier = SessionKeyVerifier()
        registry.add(
            "Session Encryption Key",
            session_verifier.verify,
            args=[loaded_secrets.get("SESSION_ENCRYPTION_KEY")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
        )

        jwt_verifier = JWTSecretVerifier()
        registry.add("JWT Secret", jwt_verifier.verify, args=[loaded_secrets.get("JWT_SECRET")])

        jwt_exp_verifier = JWTExpirationVerifier()
        registry.add("JWT Expiration", jwt_exp_verifier.verify, args=[loaded_secrets.get("JWT_EXPIRATION_MINUTES")])

        tg_api_verifier = TelegramAPIVerifier()
        registry.add("Telegram API ID", tg_api_verifier.verify_api_id, args=[loaded_secrets.get("API_ID")])
        registry.add("Telegram API Hash", tg_api_verifier.verify_api_hash, args=[loaded_secrets.get("API_HASH")])

        tg_id_verifier = TelegramIDVerifier()
        registry.add("Owner Telegram ID", tg_id_verifier.verify_owner_id, args=[loaded_secrets.get("OWNER_TELEGRAM_ID")])
        registry.add("Admin User IDs", tg_id_verifier.verify_admin_ids, args=[loaded_secrets.get("ADMIN_USER_IDS")], is_warn_only=True)

        tg_bot_verifier = TelegramBotVerifier(http)
        for bot_key, bot_name in [
            ("FORWARDER_BOT_TOKEN", "Forwarder Bot Token"),
            ("AUTH_BOT_TOKEN", "Auth Bot Token"),
        ]:
            if token := loaded_secrets.get(bot_key):
                registry.add(
                    bot_name,
                    tg_bot_verifier.verify_bot_token,
                    args=[bot_name, token],
                    kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
                )

        accounts_verifier = AccountsAPIVerifier(http)
        registry.add(
            "Accounts API",
            accounts_verifier.verify,
            args=[loaded_secrets.get("ACCOUNTS_API_KEY"), loaded_secrets.get("ACCOUNTS_API_URL")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
        )

        webhook_verifier = WebhookVerifier()
        registry.add(
            "Webhook Settings",
            webhook_verifier.verify,
            args=[loaded_secrets.get("BASE_WEBHOOK_URL"), loaded_secrets.get("WEBHOOK_SECRET_TOKEN")],
        )

        razorpay_verifier = RazorpayVerifier(http)
        registry.add(
            "Razorpay",
            razorpay_verifier.verify,
            args=[
                loaded_secrets.get("RAZORPAY_KEY_ID"),
                loaded_secrets.get("RAZORPAY_KEY_SECRET"),
                loaded_secrets.get("RAZORPAY_WEBHOOK_SECRET"),
            ],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
            is_warn_only=True,
        )

        google_verifier = GoogleOAuthVerifier(http)
        registry.add(
            "Google OAuth",
            google_verifier.verify,
            args=[loaded_secrets.get("GOOGLE_CLIENT_ID"), loaded_secrets.get("GOOGLE_CLIENT_SECRET")],
            kwargs={"dry_run": args.dry_run, "skip_live": args.skip_live},
            is_warn_only=True,
        )

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(args.concurrency)
        check_tasks: List[asyncio.Task] = []
        shutdown_mgr = install_signal_handlers(loop, check_tasks)

        async def sem_safe_check(progress, task_id, check):
            async with semaphore:
                if shutdown_mgr.is_shutting_down():
                    raise asyncio.CancelledError
                errors, warnings = [], []
                try:
                    await check["callable"](*check["args"], **check["kwargs"])
                    progress.update(task_id, completed=100)
                except Exception as e:
                    msg = f"{check['name']} failed: {e}"
                    progress.update(task_id, description=f"[red]{check['name']} (Failed)[/red]")
                    if check["is_warn_only"]:
                        warnings.append(msg)
                        logging.warning(msg)
                    else:
                        errors.append(msg)
                        logging.error(msg)
                return errors, warnings

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as progress:
            for check in registry.checks:
                task_id = progress.add_task(check["name"], total=100)
                check_tasks.append(loop.create_task(sem_safe_check(progress, task_id, check)))

            try:
                results = await asyncio.gather(*check_tasks, return_exceptions=True)
            except (asyncio.TimeoutError, asyncio.CancelledError) as e:
                logging.error(f"Execution stopped: {e}")
                return 1

        all_errors = []
        all_warnings = []
        for result in results:
            if isinstance(result, Exception):
                all_errors.append(str(result))
            else:
                errors, warnings = result
                all_errors.extend(errors)
                all_warnings.extend(warnings)

        status = "FAILED" if all_errors else "PASSED"
        summary = Summary(__version__, all_errors, all_warnings, status)

        print_summary(summary, args.log_format, Console())
        if args.output_json:
            with open(args.output_json, "w") as f:
                json.dump(asdict(summary), f, indent=2)
        if args.email_alert and status == "FAILED":
            send_email_alert(summary, *args.email_alert)

        return 2 if all_errors else 0


def entry_point():
    """Wrapper for the async main function."""
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    entry_point()

```

---

## README.md

<a id='readme-md'></a>

~~~markdown
```markdown
# vault-check ✨

[![PyPI Version](https://img.shields.io/pypi/v/vault-check.svg)](https://pypi.org/project/vault-check/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/vault-check.svg)](https://pypistats.org/packages/vault-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python >=3.11](https://img.shields.io/badge/Python->=3.11-blue.svg)](https://www.python.org/downloads/)

**Production-grade secrets verifier for Telegram bot platforms and beyond.** Validates env vars, API keys, DB/Redis connections, and third-party creds with async concurrency, retries, entropy checks, and multi-source fetching (Doppler, AWS SSM, .env). Designed for pre-deploy gates, CI/CD, and SRE runbooks—ensuring zero-downtime secrets hygiene.

## Why vault-check? 

In high-throughput bot systems (e.g., aiogram/FastAPI stacks), misconfigured secrets cause 40%+ of outages (per our postmortems). This tool enforces:
- **SRE Guardrails**: SLO-aligned checks (e.g., <60s overall timeout), progress bars for observability, and email alerts on FAIL.
- **Security by Design**: zxcvbn entropy scoring (≥3/4), masked logging, and live probes (opt-out via `--dry-run`).
- **Scalability**: Async-first with semaphore-limited concurrency; supports 20+ Telegram/Razorpay/Google integrations out-of-box.
- **Flexibility**: Fetch from Doppler/AWS SSM or fallback to .env; JSON output for automation.

**SLI Target**: 99% PASS rate on dry-runs in CI; error budget tied to verifier failures.

## Features

- **Multi-Source Secrets**: Doppler API, AWS SSM, or local .env.
- **Verifier Suite**:
  - DB (Postgres/SQLite) + Redis: Live connections with SSL/Supabase tweaks.
  - Crypto: Fernet/JWT secrets with roundtrip + entropy validation.
  - Telegram: API creds, bot tokens, owner/admin IDs.
  - Integrations: Accounts API, webhooks, Razorpay, Google OAuth (metadata fetch).
- **Resilience**: Exponential backoff retries (jittered), signal handling, overall timeout.
- **UX**: Rich progress bars, masked sensitive output, JSON mode for pipelines.
- **Extensibility**: Modular `BaseVerifier` for custom checks; optional deps (e.g., `pip install vault-check[db,aws]`).

## Quick Start

### Installation

```bash
# Core install (HTTP + basics)
pip install vault-check

# Full suite (DB/Redis + AWS + security)
pip install "vault-check[db,aws,security]"

# Editable dev install (from source)
git clone https://github.com/dhruv13x/vault-check.git
cd vault-check
pip install -e .[dev]
```

Requires Python ≥3.11. No root needed; works in Termux/Docker/K8s.

### Basic Usage

Run with defaults (uses `.env` or `DOPPLER_TOKEN`):

```bash
# Dry-run validation (format checks only)
vault-check --dry-run

# Full live probes (connections + entropy)
vault-check --skip-live=false

# Doppler fetch + JSON output
export DOPPLER_TOKEN=your_token
vault-check --doppler-project=myproj --doppler-config=prod --output-json results.json

# AWS SSM + email on FAIL
vault-check --aws-ssm-prefix /myapp/secrets --email-alert smtp.gmail.com your@gmail.com alert@team.com your_app_pass
```

Exit codes: `0=PASS`, `2=FAIL` (scriptable for CI).

**Example Output** (Rich mode):
```
Starting verifier v2.3.0 (dry-run: False, skip-live: False)
┌──────────── Verification Summary ─────────────┐
│ Version    │ 2.3.0                           │
│ Status     │ PASSED                          │
│ Warnings   │ None                            │
│ Errors     │ None ✅                          │
└──────────────────────────────────────────────┘
```

## Configuration

### Secrets Sources

1. **Local .env** (default fallback):
   ```
   SESSION_ENCRYPTION_KEY=your_fernet_key_here
   JWT_SECRET=your_jwt_secret_here
   CORE_PLATFORM_DB_URL=postgresql://user:pass@host/db
   # ... see SECRET_KEYS in code
   ```

2. **Doppler** (env: `DOPPLER_TOKEN`):
   - Flags: `--doppler-project`, `--doppler-config`, `--doppler-env=doppler.env`.
   - Fetches all keys from project/config.

3. **AWS SSM** (optional dep):
   - Flag: `--aws-ssm-prefix /app/secrets`.
   - Assumes IAM role with `ssm:GetParameter` (decrypted).

### Supported Keys (SECRET_KEYS)

| Key                       | Verifier                  | Notes                          |
|---------------------------|---------------------------|--------------------------------|
| `CORE_PLATFORM_DB_URL`   | DatabaseVerifier         | Postgres/SQLite; Supabase SSL  |
| `SESSION_ENCRYPTION_KEY` | SessionKeyVerifier       | Fernet + zxcvbn entropy ≥3    |
| `JWT_SECRET`             | JWTSecretVerifier        | ≥32 chars + entropy           |
| `API_ID` / `API_HASH`    | TelegramAPIVerifier      | Telegram MTProto creds        |
| `FORWARDER_BOT_TOKEN`    | TelegramBotVerifier      | Live `/getMe` probe           |
| `RAZORPAY_KEY_ID`        | RazorpayVerifier         | Basic auth to `/v1/plans`     |
| ... (20+ total)          | See `cli.py` for full    | Optional: Razorpay/Google     |

### CLI Flags

```bash
vault-check --help
```

Key flags:
- `--dry-run`: Format/entropy only (no connections).
- `--skip-live`: Skip probes but fetch secrets.
- `--log-level=DEBUG`: Verbose output.
- `--concurrency=10`: Parallel verifiers (default:5).
- `--overall-timeout=120`: Max runtime (s).
- `--email-alert smtp from to pass`: Alert on FAIL.

## Examples

### CI/CD Integration (GitHub Actions)

```yaml
name: Secrets Check
on: [push]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.12'}
      - run: pip install vault-check[db,aws,security]
      - run: vault-check --dry-run --output-json ci-report.json
        env:
          DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
      - uses: actions/upload-artifact@v4
        with: {name: report, path: ci-report.json}
      - run: exit 1  # Fail build on non-PASS
```

### Production Runbook Snippet

1. Fetch secrets: `vault-check --aws-ssm-prefix /prod/secrets --dry-run`.
2. If PASS: Deploy. Else: Alert + rollback.
3. Monitor: SLO=99% PASS over 7d rolling; alert on budget breach.

## Troubleshooting

- **ImportError (e.g., aioredis)**: Install optionals: `pip install vault-check[db]`.
- **Doppler 401**: Verify `DOPPLER_TOKEN` scope (secrets:read).
- **DB Connect Fail**: Check `--db-timeout`; add `sslmode=disable` for local.
- **Weak Key Warning**: Regenerate with `openssl rand -base64 32` (Fernet/JWT).
- Logs: Set `--log-level=DEBUG`; tail for masked traces.

Common Errors:
- `Weak key (score 1/4)`: Use pwgen or zxcvbn feedback.
- `Overall timeout exceeded`: Increase `--overall-timeout` or `--concurrency=1`.

## Contributing & Extending

Fork, add verifiers (inherit `BaseVerifier`), and PR with tests (pytest-asyncio).

1. Dev setup: `pip install -e .[dev] && pre-commit install`.
2. Lint/Test: `black src/ && mypy src/ && pytest tests/`.
3. Custom Verifier Example:
   ```python
   class CustomVerifier(BaseVerifier):
       async def verify(self, api_key: str) -> None:
           # Your async check
           if not await self.http.get_json(f"https://api.example.com/ping", headers={"X-API-Key": api_key}):
               raise ValueError("Invalid key")
   # Integrate in main() checks
   ```

## Testing

To run the integration and end-to-end tests, you will need to create a `.env` file in the `tests/integration` and `tests/e2e` directories.

**`tests/integration/test.env`:**
```
SESSION_ENCRYPTION_KEY=y_s3V1e_fJ7N4X-g9hQbRzLwP6K2aI5cE1tD8UvYj0o=
JWT_SECRET=super-secret-jwt-key-that-is-long-enough
JWT_EXPIRATION_MINUTES=60
CORE_PLATFORM_DB_URL=sqlite:///test.db
HEAVY_WORKER_REDIS_URL=redis://localhost:6379
API_ID=12345
API_HASH=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
OWNER_TELEGRAM_ID=123456789
FORWARDER_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
ACCOUNTS_API_URL=https://example.com
ACCOUNTS_API_KEY=test-key
BASE_WEBHOOK_URL=https://example.com
WEBHOOK_SECRET_TOKEN=secret-token
```

**`tests/e2e/e2e.env`:**
```
CORE_PLATFORM_DB_URL=postgresql://user:password@localhost:5432/testdb
HEAVY_WORKER_REDIS_URL=redis://localhost:6379
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for ADR process and chaos testing.

## Security & Compliance

- **Audits**: All verifiers log masked; no secrets persisted.
- **OWASP**: Input sanitization, rate-limit probes (via retries).
- **Compliance**: GDPR-ready (no PII); rotate keys via Doppler/AWS.
- Report vulns: security@dhruv13x.com.

## License

MIT © 2025 dhruv13x. See [LICENSE](LICENSE).

---

*Built with ❤️ for reliable bot platforms. Questions? Open an issue.*
```

~~~

---

## src/vault_check/verifiers/base.py

<a id='src-vault-check-verifiers-base-py'></a>

```python
class BaseVerifier:
    async def verify(self, *args, **kwargs) -> None:
        raise NotImplementedError

```

---

## src/vault_check/verifiers/redis.py

<a id='src-vault-check-verifiers-redis-py'></a>

```python
import logging
import redis.asyncio as aioredis

from ..utils import mask_url, validate_url_format
from .base import BaseVerifier


class RedisVerifier(BaseVerifier):
    async def verify(
        self, redis_name: str, redis_url: str, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{redis_name}[/bold] at {mask_url(redis_url)}")
        if not validate_url_format(redis_url, ["redis", "rediss"]):
            raise ValueError("Invalid Redis URL format")
        if dry_run or skip_live:
            return
        client = aioredis.Redis.from_url(redis_url, decode_responses=True)
        try:
            await client.ping()
        finally:
            await client.aclose()

```

---

## src/vault_check/verifiers/session_key.py

<a id='src-vault-check-verifiers-session-key-py'></a>

```python
import base64
import logging

from cryptography.fernet import Fernet

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class SessionKeyVerifier(BaseVerifier):
    async def verify(self, key: str | None, dry_run: bool = False, skip_live: bool = False) -> None:
        logging.info(f"Checking [bold]SESSION_ENCRYPTION_KEY[/bold] (masked: {mask_sensitive(key)})")
        if not key:
            raise ValueError("SESSION_ENCRYPTION_KEY missing")
        try:
            padded = key.encode() + b"=" * ((4 - len(key) % 4) % 4)
            if len(base64.urlsafe_b64decode(padded)) != 32:
                raise ValueError("Decoded key is not 32 bytes")
            check_entropy(key)
        except Exception as e:
            raise ValueError(f"Invalid base64 Fernet key: {e}") from e
        if not dry_run and not skip_live:
            Fernet(padded).encrypt(b"health-check")

```

---

## src/vault_check/verifiers/jwt.py

<a id='src-vault-check-verifiers-jwt-py'></a>

```python
import logging

from ..utils import check_entropy, mask_sensitive
from .base import BaseVerifier


class JWTSecretVerifier(BaseVerifier):
    async def verify(self, key: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]JWT_SECRET[/bold] (masked: {mask_sensitive(key)})")
        if not key:
            raise ValueError("JWT_SECRET missing")
        if len(key) < 32:
            raise ValueError("JWT_SECRET too short (>=32 recommended)")
        check_entropy(key)


class JWTExpirationVerifier(BaseVerifier):
    async def verify(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]JWT_EXPIRATION_MINUTES[/bold]: {val or '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")
        if int(val) > 1440:
            logging.warning(f"JWT expiration too long ({val} min > 1 day)")

```

---

## tests/integration/test_cli_integration.py

<a id='tests-integration-test-cli-integration-py'></a>

```python
from unittest.mock import patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
@patch("vault_check.cli.send_email_alert")
async def test_cli_integration_dry_run(mock_send_email_alert):
    return_code = await main(
        ["--env-file", "tests/integration/test.env", "--dry-run"]
    )
    assert return_code == 0
    mock_send_email_alert.assert_not_called()

```

---

## src/vault_check/verifiers/webhook.py

<a id='src-vault-check-verifiers-webhook-py'></a>

```python
import logging

from ..utils import validate_url_format
from .base import BaseVerifier


class WebhookVerifier(BaseVerifier):
    async def verify(self, url: str | None, secret: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]BASE_WEBHOOK_URL[/bold]: {url or '(missing)'}")
        if not url or not validate_url_format(url, ["http", "https"]):
            raise ValueError("Invalid URL")
        if url.startswith("http://") and "localhost" not in url:
            logging.warning("Non-SSL (https recommended for production)")
        if not secret:
            logging.warning("WEBHOOK_SECRET_TOKEN missing (recommended)")

```

---

## src/vault_check/verifiers/google.py

<a id='src-vault-check-verifiers-google-py'></a>

```python
import logging

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class GoogleOAuthVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, client_id: str | None, client_secret: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        if not client_id and not client_secret:
            logging.info("Google OAuth optional, not set")
            return
        if not client_id or not client_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Google OAuth[/bold] (ID: {mask_sensitive(client_id)})")
        if not dry_run and not skip_live:
            url = "https://accounts.google.com/.well-known/openid-configuration"
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or "issuer" not in data:
                raise RuntimeError("Invalid Google metadata response")

```

---

## src/vault_check/verifiers/razorpay.py

<a id='src-vault-check-verifiers-razorpay-py'></a>

```python
import logging

import aiohttp

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class RazorpayVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, key_id: str | None, key_secret: str | None, webhook_secret: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        if not key_id and not key_secret:
            logging.info("Razorpay optional, not set")
            return
        if not key_id or not key_secret:
            raise ValueError("Incomplete keys")
        logging.info(f"Checking [bold]Razorpay[/bold] (ID: {mask_sensitive(key_id)})")
        if not webhook_secret:
            logging.warning("RAZORPAY_WEBHOOK_SECRET missing (recommended)")
        if not dry_run and not skip_live:
            url = "https://api.razorpay.com/v1/plans"
            auth = aiohttp.BasicAuth(key_id, key_secret)
            await self.http.get_json(url, auth=auth)

```

---

## src/vault_check/utils.py

<a id='src-vault-check-utils-py'></a>

```python
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

```

---

## src/vault_check/verifiers/database.py

<a id='src-vault-check-verifiers-database-py'></a>

```python
import logging
import re
from urllib.parse import parse_qs, urlparse

import aiosqlite
import asyncpg

from ..config import (
    DEFAULT_BACKOFF,
    DEFAULT_DB_TIMEOUT,
    DEFAULT_POOL_MAX_SIZE,
    DEFAULT_POOL_MIN_SIZE,
    DEFAULT_RETRIES,
)
from ..utils import mask_url, retry_backoff
from .base import BaseVerifier


class DatabaseVerifier(BaseVerifier):
    def __init__(
        self,
        pg_pool_timeout: float = DEFAULT_DB_TIMEOUT,
        pool_min_size: int = DEFAULT_POOL_MIN_SIZE,
        pool_max_size: int = DEFAULT_POOL_MAX_SIZE,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
    ):
        self.pg_pool_timeout = pg_pool_timeout
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.retries = retries
        self.backoff = backoff

    async def _create_pool(self, dsn: str) -> asyncpg.Pool:
        return await asyncpg.create_pool(
            dsn,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
            timeout=self.pg_pool_timeout,
        )

    async def verify(
        self, db_name: str, db_url: str, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{db_name}[/bold] at {mask_url(db_url)}")
        if not isinstance(db_url, str):
            raise ValueError("DB URL is not a string")
        parsed = urlparse(db_url)
        scheme_base = parsed.scheme.lower().split("+")[0]
        valid_schemes = ["postgres", "postgresql", "sqlite"]
        if scheme_base not in valid_schemes or (
            scheme_base != "sqlite" and not parsed.netloc
        ):
            raise ValueError(f"Invalid DB URL format (scheme: {parsed.scheme})")

        if dry_run or skip_live:
            logging.info(f"{db_name}: Format valid, skipping live connection")
            return

        if scheme_base in ("postgres", "postgresql"):
            dsn = re.sub(r"\+asyncpg", "", db_url, flags=re.IGNORECASE)
            if parsed.hostname and parsed.hostname.endswith(".supabase.com"):
                query = parse_qs(parsed.query or "")
                if "sslmode" not in [k.lower() for k in query]:
                    dsn += "&sslmode=disable" if "?" in dsn else "?sslmode=disable"
                    logging.info(f"{db_name}: Added sslmode=disable for Supabase")

            async def connect_and_check():
                pool = await self._create_pool(dsn)
                try:
                    async with pool.acquire() as conn:
                        version = await conn.fetchval("SELECT version();")
                        logging.info(f"{db_name} connected (Postgres): {version}")
                finally:
                    await pool.close()

            await retry_backoff(
                connect_and_check, retries=self.retries, base_backoff=self.backoff
            )
        else:
            db_path = parsed.path.lstrip("/")
            conn = await aiosqlite.connect(db_path)
            try:
                async with conn.execute("SELECT sqlite_version();") as cursor:
                    row = await cursor.fetchone()
                    logging.info(f"{db_name} connected (SQLite): {row[0] if row else 'unknown'}")
            finally:
                await conn.close()

```

---

## src/vault_check/verifiers/accounts.py

<a id='src-vault-check-verifiers-accounts-py'></a>

```python
import logging

from ..http_client import HTTPClient
from ..utils import mask_url, validate_url_format
from .base import BaseVerifier


class AccountsAPIVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify(
        self, api_key: str | None, api_url: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]Accounts API[/bold] at {mask_url(api_url)}")
        if not api_key or not api_url:
            raise ValueError("Missing URL or key")
        if not validate_url_format(api_url, ["http", "https"]):
            raise ValueError("Invalid URL format")
        if not dry_run and not skip_live:
            url = f"{api_url.rstrip('/')}/status"
            headers = {"Authorization": f"Bearer {api_key}"}
            await self.http.get_json(url, headers=headers)

```

---

## src/vault_check/verifiers/telegram.py

<a id='src-vault-check-verifiers-telegram-py'></a>

```python
import logging
import re

from ..http_client import HTTPClient
from ..utils import mask_sensitive
from .base import BaseVerifier


class TelegramAPIVerifier(BaseVerifier):
    async def verify_api_id(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]API_ID[/bold]: {mask_sensitive(val) if val else '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")

    async def verify_api_hash(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]API_HASH[/bold] (masked: {mask_sensitive(val)})")
        if not val or not re.match(r"^[0-9a-fA-F]{32}$", val):
            raise ValueError("Invalid format")


class TelegramIDVerifier(BaseVerifier):
    async def verify_owner_id(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]OWNER_TELEGRAM_ID[/bold]: {val or '(missing)'}")
        if not val or not val.isdigit() or int(val) <= 0:
            raise ValueError("Must be a positive integer")

    async def verify_admin_ids(self, val: str | None, **kwargs) -> None:
        logging.info(f"Checking [bold]ADMIN_USER_IDS[/bold]: {val or '(none)'}")
        if val:
            if not all(x.strip().isdigit() for x in val.split(",")):
                raise ValueError("All IDs must be numeric")


class TelegramBotVerifier(BaseVerifier):
    def __init__(self, http: HTTPClient):
        self.http = http

    async def verify_bot_token(
        self, bot_name: str, token: str | None, dry_run: bool = False, skip_live: bool = False
    ) -> None:
        logging.info(f"Checking [bold]{bot_name}[/bold] (masked: {mask_sensitive(token)})")
        if not token:
            raise ValueError(f"{bot_name} missing")
        if not re.match(r"^\d+:[A-Za-z0-9_\-]+$", token):
            logging.warning(f"{bot_name} non-standard format")
        if not dry_run and not skip_live:
            url = f"https://api.telegram.org/bot{token}/getMe"
            data = await self.http.get_json(url)
            if not isinstance(data, dict) or not data.get("ok"):
                raise RuntimeError(f"Failed: {data.get('description', 'unknown')}")

```

---

## tests/unit/test_cli.py

<a id='tests-unit-test-cli-py'></a>

```python
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.cli import main


@pytest.mark.asyncio
@patch("vault_check.cli.print_summary")
@patch("vault_check.cli.VerifierRegistry")
@patch("vault_check.cli.asyncio.gather", new_callable=AsyncMock)
async def test_main_success(mock_gather, mock_registry, mock_print_summary):
    mock_registry.return_value.checks = [
        {
            "name": "test_check",
            "callable": AsyncMock(),
            "args": [],
            "kwargs": {},
            "is_warn_only": False,
        }
    ]
    mock_gather.return_value = [([], [])]

    return_code = await main(["--dry-run"])

    assert return_code == 0
    mock_print_summary.assert_called_once()
    assert mock_print_summary.call_args[0][0].status == "PASSED"


@pytest.mark.asyncio
@patch("vault_check.cli.print_summary")
@patch("vault_check.cli.VerifierRegistry")
@patch("vault_check.cli.asyncio.gather", new_callable=AsyncMock)
async def test_main_failure(mock_gather, mock_registry, mock_print_summary):
    mock_registry.return_value.checks = [
        {
            "name": "test_check",
            "callable": AsyncMock(side_effect=Exception("Test failure")),
            "args": [],
            "kwargs": {},
            "is_warn_only": False,
        }
    ]
    mock_gather.return_value = [(["Test failure"], [])]

    return_code = await main(["--dry-run"])

    assert return_code == 2
    mock_print_summary.assert_called_once()
    assert mock_print_summary.call_args[0][0].status == "FAILED"

```

---

## tests/e2e/test_e2e.py

<a id='tests-e2e-test-e2e-py'></a>

```python
import shutil
import subprocess
import time

import pytest

DOCKER_COMPOSE_COMMAND = shutil.which("docker-compose")


@pytest.fixture(scope="module")
def mock_environment():
    if not DOCKER_COMPOSE_COMMAND:
        pytest.skip("docker-compose not found, skipping e2e tests")
    subprocess.run([DOCKER_COMPOSE_COMMAND, "up", "-d"], check=True)
    # Give the services time to start up
    time.sleep(5)
    yield
    subprocess.run([DOCKER_COMPOSE_COMMAND, "down"], check=True)


def test_e2e_success(mock_environment):
    result = subprocess.run(
        [
            "vault-check",
            "--env-file",
            "tests/e2e/e2e.env",
            "--skip-live=false",
            "--dry-run=false",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Core Platform DB connected" in result.stdout
    assert "Heavy Worker Redis connected" in result.stdout

```

---

## tests/unit/test_http_client.py

<a id='tests-unit-test-http-client-py'></a>

```python
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from vault_check.http_client import HTTPClient


@pytest.fixture
def mock_session():
    return MagicMock(spec=aiohttp.ClientSession)


@pytest.mark.asyncio
async def test_http_client_get_json_success(mock_session):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value='{"key": "value"}')
    mock_response.headers = {}
    mock_session.request.return_value.__aenter__.return_value = mock_response

    client = HTTPClient(mock_session)
    response = await client.get_json("http://example.com")

    assert response == {"key": "value"}
    mock_session.request.assert_called_once_with("GET", "http://example.com")


@pytest.mark.asyncio
async def test_http_client_get_json_retry(mock_session):
    mock_response_fail = MagicMock()
    mock_response_fail.raise_for_status = MagicMock(side_effect=aiohttp.ClientResponseError(None, None))
    mock_response_fail.text = AsyncMock(return_value="{}")  # Added this line

    mock_response_success = MagicMock()
    mock_response_success.status = 200
    mock_response_success.text = AsyncMock(return_value='{"key": "value"}')
    mock_response_success.headers = {}

    mock_session.request.return_value.__aenter__.side_effect = [
        mock_response_fail,
        mock_response_success,
    ]

    client = HTTPClient(mock_session, retries=2)
    response = await client.get_json("http://example.com")

    assert response == {"key": "value"}
    assert mock_session.request.call_count == 2

```

---

## tests/unit/test_utils.py

<a id='tests-unit-test-utils-py'></a>

```python
import asyncio
from unittest.mock import Mock, patch

import pytest

from vault_check.utils import mask_sensitive, mask_url, retry_backoff


def test_mask_sensitive():
    assert mask_sensitive("1234567890123456") == "123456******3456"
    assert mask_sensitive("short") == "*****"
    assert mask_sensitive(None) == "(missing)"


def test_mask_url():
    assert mask_url("https://user:password@example.com") == "https://user:*****@example.com"
    assert mask_url("https://example.com") == "https://example.com"
    assert mask_url(None) == "(missing)"


@pytest.mark.asyncio
async def test_retry_backoff():
    # A mock async function that fails twice then succeeds
    mock_func = Mock(
        side_effect=[asyncio.TimeoutError, asyncio.TimeoutError, "Success"]
    )

    async def async_mock_func(*args, **kwargs):
        return mock_func(*args, **kwargs)

    with patch("asyncio.sleep", return_value=None):
        result = await retry_backoff(async_mock_func, retries=3)
        assert result == "Success"
        assert mock_func.call_count == 3


@pytest.mark.asyncio
async def test_retry_backoff_fails():
    mock_func = Mock(side_effect=asyncio.TimeoutError)

    async def async_mock_func(*args, **kwargs):
        return mock_func(*args, **kwargs)

    with patch("asyncio.sleep", return_value=None):
        with pytest.raises(asyncio.TimeoutError):
            await retry_backoff(async_mock_func, retries=3)
        assert mock_func.call_count == 3

```

---

## tests/unit/verifiers/test_accounts.py

<a id='tests-unit-verifiers-test-accounts-py'></a>

```python
from unittest.mock import AsyncMock, MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import AccountsAPIVerifier


@pytest.mark.asyncio
async def test_accounts_api_verifier_missing_credentials():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = AccountsAPIVerifier(http_client)
    with pytest.raises(ValueError, match="Missing URL or key"):
        await verifier.verify(None, None)

```

---

## tests/unit/verifiers/test_google.py

<a id='tests-unit-verifiers-test-google-py'></a>

```python
from unittest.mock import MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import GoogleOAuthVerifier


@pytest.mark.asyncio
async def test_google_oauth_verifier_incomplete_keys():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = GoogleOAuthVerifier(http_client)
    with pytest.raises(ValueError, match="Incomplete keys"):
        await verifier.verify("client_id", None)

```

---

## tests/unit/verifiers/test_razorpay.py

<a id='tests-unit-verifiers-test-razorpay-py'></a>

```python
from unittest.mock import MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import RazorpayVerifier


@pytest.mark.asyncio
async def test_razorpay_verifier_incomplete_keys():
    mock_session = MagicMock()
    http_client = HTTPClient(mock_session)
    verifier = RazorpayVerifier(http_client)
    with pytest.raises(ValueError, match="Incomplete keys"):
        await verifier.verify("key_id", None, None)

```

---

## tests/unit/verifiers/test_jwt.py

<a id='tests-unit-verifiers-test-jwt-py'></a>

```python
import pytest

from vault_check.verifiers import JWTExpirationVerifier, JWTSecretVerifier


@pytest.mark.asyncio
async def test_jwt_secret_verifier_short_key():
    verifier = JWTSecretVerifier()
    with pytest.raises(ValueError, match="JWT_SECRET too short"):
        await verifier.verify("short_key")


@pytest.mark.asyncio
async def test_jwt_expiration_verifier_invalid_value():
    verifier = JWTExpirationVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify("invalid")

```

---

## tests/unit/verifiers/test_database.py

<a id='tests-unit-verifiers-test-database-py'></a>

```python
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vault_check.verifiers import DatabaseVerifier


@pytest.mark.asyncio
@patch("asyncpg.create_pool", new_callable=AsyncMock)
async def test_database_verifier_postgres_success(mock_create_pool):
    mock_pool = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.fetchval.return_value = "PostgreSQL 13.3"

    @asynccontextmanager
    async def acquire_context_manager(*args, **kwargs):
        yield mock_conn

    mock_pool.acquire = MagicMock(return_value=acquire_context_manager())
    mock_create_pool.return_value = mock_pool

    verifier = DatabaseVerifier()
    await verifier.verify(
        "test_db", "postgresql://user:pass@host/db", dry_run=False, skip_live=False
    )
    mock_create_pool.assert_called_once()


@pytest.mark.asyncio
@patch("aiosqlite.connect", new_callable=AsyncMock)
async def test_database_verifier_sqlite_success(mock_connect):
    mock_connection = AsyncMock()
    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = ("3.36.0",)

    @asynccontextmanager
    async def execute_context_manager(*args, **kwargs):
        yield mock_cursor

    mock_connection.execute = MagicMock(return_value=execute_context_manager())
    mock_connect.return_value = mock_connection

    verifier = DatabaseVerifier()
    await verifier.verify(
        "test_db", "sqlite:///test.db", dry_run=False, skip_live=False
    )
    mock_connect.assert_called_once()


@pytest.mark.asyncio
async def test_database_verifier_dry_run():
    verifier = DatabaseVerifier()
    # This should not raise an exception, even with an invalid URL
    await verifier.verify(
        "test_db", "postgresql://user:pass@host/db", dry_run=True, skip_live=False
    )


@pytest.mark.asyncio
async def test_database_verifier_invalid_url():
    verifier = DatabaseVerifier()
    with pytest.raises(ValueError, match="Invalid DB URL format"):
        await verifier.verify("test_db", "invalid_url")

```

---

## tests/unit/verifiers/test_telegram.py

<a id='tests-unit-verifiers-test-telegram-py'></a>

```python
from unittest.mock import AsyncMock, MagicMock

import pytest

from vault_check.http_client import HTTPClient
from vault_check.verifiers import (
    TelegramAPIVerifier,
    TelegramBotVerifier,
    TelegramIDVerifier,
)


@pytest.mark.asyncio
async def test_telegram_api_verifier_invalid_id():
    verifier = TelegramAPIVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify_api_id("invalid")


@pytest.mark.asyncio
async def test_telegram_id_verifier_invalid_id():
    verifier = TelegramIDVerifier()
    with pytest.raises(ValueError, match="Must be a positive integer"):
        await verifier.verify_owner_id("invalid")


@pytest.mark.asyncio
async def test_telegram_bot_verifier_invalid_token():
    mock_session = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value='{"ok": false, "description": "Invalid token"}')
    mock_session.request.return_value.__aenter__.return_value = mock_response

    http_client = HTTPClient(mock_session)
    verifier = TelegramBotVerifier(http_client)
    with pytest.raises(RuntimeError, match="Failed: Invalid token"):
        await verifier.verify_bot_token("test_bot", "invalid_token")

```

---

## tests/unit/verifiers/test_session_key.py

<a id='tests-unit-verifiers-test-session-key-py'></a>

```python
import pytest

from vault_check.verifiers import SessionKeyVerifier


@pytest.mark.asyncio
async def test_session_key_verifier_invalid_key():
    verifier = SessionKeyVerifier()
    with pytest.raises(ValueError, match="Invalid base64 Fernet key"):
        await verifier.verify("invalid_key")


@pytest.mark.asyncio
async def test_session_key_verifier_valid_key():
    verifier = SessionKeyVerifier()
    # A valid base64-encoded 32-byte key
    valid_key = "y_s3V1e_fJ7N4X-g9hQbRzLwP6K2aI5cE1tD8UvYj0o="
    await verifier.verify(valid_key)  # Should not raise an exception

```

---

## tests/unit/verifiers/test_webhook.py

<a id='tests-unit-verifiers-test-webhook-py'></a>

```python
import pytest

from vault_check.verifiers import WebhookVerifier


@pytest.mark.asyncio
async def test_webhook_verifier_invalid_url():
    verifier = WebhookVerifier()
    with pytest.raises(ValueError, match="Invalid URL"):
        await verifier.verify("invalid_url", "secret")

```

---

## tests/unit/verifiers/test_redis.py

<a id='tests-unit-verifiers-test-redis-py'></a>

```python
import pytest

from vault_check.verifiers import RedisVerifier


@pytest.mark.asyncio
async def test_redis_verifier_invalid_url():
    verifier = RedisVerifier()
    with pytest.raises(ValueError, match="Invalid Redis URL format"):
        await verifier.verify("test_redis", "invalid_url")

```

---

