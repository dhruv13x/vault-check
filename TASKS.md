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
