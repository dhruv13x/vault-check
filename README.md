<div align="center">
  <img src="https://raw.githubusercontent.com/dhruv13x/vault-check/main/vault-check_logo.png" alt="vault-check logo" width="200"/>
</div>

<div align="center">

<!-- Package Info -->
[![PyPI version](https://img.shields.io/pypi/v/vault-check.svg)](https://pypi.org/project/vault-check/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
![Wheel](https://img.shields.io/pypi/wheel/vault-check.svg)
[![Release](https://img.shields.io/badge/release-PyPI-blue)](https://pypi.org/project/vault-check/)

<!-- Build & Quality -->
[![Build status](https://github.com/dhruv13x/vault-check/actions/workflows/publish.yml/badge.svg)](https://github.com/dhruv13x/vault-check/actions/workflows/publish.yml)
[![Codecov](https://codecov.io/gh/dhruv13x/vault-check/graph/badge.svg)](https://codecov.io/gh/dhruv13x/vault-check)
[![Test Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen.svg)](https://github.com/dhruv13x/vault-check/actions/workflows/test.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/badge/linting-ruff-yellow.svg)](https://github.com/astral-sh/ruff)
![Security](https://img.shields.io/badge/security-CodeQL-blue.svg)

<!-- Usage -->
![Downloads](https://img.shields.io/pypi/dm/vault-check.svg)
[![PyPI Downloads](https://img.shields.io/pypi/dm/vault-check.svg)](https://pypistats.org/packages/vault-check)
![OS](https://img.shields.io/badge/os-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg)
[![Python Versions](https://img.shields.io/pypi/pyversions/vault-check.svg)](https://pypi.org/project/vault-check/)

<!-- License -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>


# vault-check ✨

**Production-grade secrets verifier for Telegram bot platforms and beyond.** Validates env vars, API keys, DB/Redis connections, and third-party creds with async concurrency, retries, entropy checks, and multi-source fetching (Doppler, AWS SSM, .env). Designed for pre-deploy gates, CI/CD, and SRE runbooks—ensuring zero-downtime secrets hygiene.

## Why vault-check? 

In high-throughput bot systems (e.g., aiogram/FastAPI stacks), misconfigured secrets cause 40%+ of outages (per our postmortems). This tool enforces:
- **SRE Guardrails**: SLO-aligned checks (e.g., <60s overall timeout), progress bars for observability, and email alerts on FAIL.
- **Security by Design**: zxcvbn entropy scoring (≥3/4), masked logging, and live probes (opt-out via `--dry-run`).
- **Scalability**: Async-first with semaphore-limited concurrency; supports 20+ Telegram/Razorpay/Google integrations out-of-box.
- **Flexibility**: Fetch from Doppler/AWS SSM or fallback to .env; JSON output for automation.

**SLI Target**: 99% PASS rate on dry-runs in CI; error budget tied to verifier failures.

## 🚀 Quick Start

### Prerequisites
- Python ≥ 3.11
- Optional: `redis` server, `postgresql` (for live connectivity checks)

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

### Usage Example

Run with defaults (uses `.env` or `DOPPLER_TOKEN`):

```bash
# Dry-run validation (format checks only)
vault-check --dry-run

# Start the Web Dashboard
vault-check --dashboard --dashboard-port 8080
```

**Example Output** (Rich mode):
```
Starting verifier (dry-run: False, skip-live: False)
┌──────────── Verification Summary ─────────────┐
│ Version    │ 4.2.1                           │
│ Status     │ PASSED                          │
│ Warnings   │ None                            │
│ Errors     │ None ✅                          │
└──────────────────────────────────────────────┘
```

## ✨ Key Features

- **Multi-Source Secrets**: Doppler API, AWS SSM, or local .env.
- **Web Dashboard (God Level)**: View and manage verification reports via a sleek web interface.
- **Auto-Discovery**: Heuristic engine automatically detects and verifies secrets based on patterns (S3, SMTP, DB, Redis).
- **Verifier Suite**:
  - **S3 Buckets**: Checks bucket existence and permissions.
  - **SMTP**: Verifies connectivity and authentication.
  - **DB (Postgres/SQLite) + Redis**: Live connections with SSL/Supabase tweaks.
  - **Crypto**: Fernet/JWT secrets with roundtrip + entropy validation.
  - **Telegram**: API creds, bot tokens, owner/admin IDs.
  - **Integrations**: Razorpay, Google OAuth (metadata fetch).
- **Resilience**: Exponential backoff retries (jittered), signal handling, overall timeout.
- **UX**: Rich progress bars, masked sensitive output, JSON mode for pipelines.
- **Extensibility**: Modular `BaseVerifier` for custom checks; optional deps (e.g., `pip install vault-check[db,aws]`).

## ⚙️ Configuration & Advanced Usage

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

### CLI Flags

The tool offers extensive command-line control.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--env-file` | `string` | `.env` | Path to the environment file. |
| `--project-path` | `string` | `None` | Path to the project directory containing .env file. |
| `--doppler-project` | `string` | `bot-platform` | Doppler project name. |
| `--doppler-config` | `string` | `dev_bot-platform` | Doppler config name. |
| `--aws-ssm-prefix` | `string` | `None` | AWS SSM parameter prefix. |
| `--log-level` | `choice` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `--log-format` | `choice` | `text` | Log output format (`text`, `json`). |
| `--color` | `bool` | `False` | Enable colorized log output. |
| `--concurrency` | `int` | `5` | Number of parallel verifiers to run. |
| `--http-timeout` | `float` | `10.0` | HTTP request timeout in seconds. |
| `--db-timeout` | `float` | `5.0` | Database connection timeout in seconds. |
| `--overall-timeout` | `float` | `60.0` | Maximum total runtime in seconds. |
| `--retries` | `int` | `3` | Number of retries for failed checks. |
| `--dry-run` | `bool` | `False` | Perform format/entropy checks only (no live probes). |
| `--skip-live` | `bool` | `False` | Fetch secrets but skip all live connection probes. |
| `--output-json` | `string` | `None` | Path to write a JSON output report. |
| `--email-alert` | `list` | `None` | Send email alert on failure (`SMTP_SERVER FROM TO PASS`). |
| `--version` | `bool` | `False` | Show version information and exit. |
| `--verifiers` | `list` | `None` | A space-separated list of specific verifiers to run. |
| `--dashboard` | `bool` | `False` | Start the web dashboard. |
| `--dashboard-port` | `int` | `8000` | Port for the dashboard. |
| `--reports-dir` | `string` | `.` | Directory to load reports from for the dashboard. |

## 🏗️ Architecture

The tool is designed with a modular, async-first architecture.

```
src/vault_check/
├── cli.py            # Entry point, argparse CLI
├── runner.py         # Orchestrates verifiers w/ asyncio
├── secrets.py        # Fetches secrets (Doppler, AWS, .env)
├── dashboard.py      # Web Dashboard implementation
├── heuristics.py     # Auto-discovery logic for secrets
├── verifiers/        # Individual check logic
│   ├── base.py       # Base class for verifiers
│   ├── s3.py         # S3 Bucket verifier
│   ├── smtp.py       # SMTP verifier
│   └── ...
└── http_client.py    # Centralized aiohttp client
```

Core flow: `cli.py` parses args -> `secrets.py` loads secrets -> `runner.py` uses `heuristics.py` to match secrets to verifiers -> executes all registered `verifiers` concurrently.

## 🗺️ Roadmap

- [x] Core verifier suite (DB, Redis, JWT, Telegram)
- [x] Multi-source secret fetching (Doppler, AWS)
- [x] Concurrency and timeouts
- [x] Plugin system for custom verifiers
- [x] Web UI for results dashboard
- [x] Auto-discovery of secrets (S3, SMTP, etc.)
- [ ] Kubernetes Operator for continuous monitoring
- [ ] Slack/Discord notifications integration

## 🤝 Contributing & License

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

**License**: MIT © 2025 dhruv13x. See [LICENSE](LICENSE).

---

*Built with ❤️ for reliable bot platforms. Questions? Open an issue.*
