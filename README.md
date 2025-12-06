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

# vault-check 🔒

**Production-grade secrets verifier and health check utility.**
Ensures your environment variables, API keys, and credentials are valid, secure, and ready for production.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- `pip`

### Installation

One command to rule them all:

```bash
pip install vault-check
```

For the full suite (AWS, Databases, Security):

```bash
pip install "vault-check[db,aws,security]"
```

### Usage Example

Run a quick dry-run check to validate formats and entropy without live network probes:

```bash
vault-check --dry-run
```

Or run the full suite with a dashboard:

```bash
vault-check --dashboard --dashboard-port 8080 --output-json ./reports/latest.json
```

---

## ✨ Key Features

- **Multi-Source Loading**: Seamlessly fetch secrets from `.env`, **Doppler**, **AWS SSM**, or **HashiCorp Vault**.
- **Comprehensive Verifiers**: Out-of-the-box checks for Database URLs, Redis, JWT secrets, Telegram Bots, Razorpay, Google OAuth, and more.
- **God Level Security Checks**:
  - **Entropy Analysis**: Uses `zxcvbn` to ensure your keys aren't weak (e.g., "password123").
  - **Live Probes**: Actually connects to DBs and APIs (e.g., `SELECT 1`, `/getMe`) to verify credentials work.
- **Web Dashboard**: Visualize your reports with a built-in web interface.
- **CI/CD Ready**: JSON outputs, exit codes, and email alerts make it perfect for pipelines.

---

## ⚙️ Configuration & Advanced Usage

### Environment Variables
Vault Check looks for a `.env` file by default (or fetching from Doppler/AWS). The verifier suite automatically detects and validates the following secret keys if they are present:

| Key | Verifier | Notes |
|---|---|---|
| `*_DB_URL` | `DatabaseVerifier` | Validates Postgres/SQLite connection strings. |
| `*_REDIS_URL` | `RedisVerifier` | Checks Redis connection and `PING` command. |
| `SESSION_ENCRYPTION_KEY` | `SessionKeyVerifier` | **God Level**: Fernet key with zxcvbn entropy check (score >= 3). |
| `JWT_SECRET` | `JWTSecretVerifier` | Checks for a high-entropy secret (>= 32 chars). |
| `JWT_EXPIRATION_MINUTES` | `JWTExpirationVerifier` | Ensures the expiration time is a valid integer. |
| `API_ID` / `API_HASH` | `TelegramAPIVerifier` | Validates Telegram MTProto API credentials. |
| `*_BOT_TOKEN` | `TelegramBotVerifier` | **God Level**: Performs a live `/getMe` probe to the Telegram Bot API. |
| `OWNER_TELEGRAM_ID` / `ADMIN_USER_IDS` | `TelegramIDVerifier` | Checks for valid Telegram user/chat IDs. |
| `ACCOUNTS_API_KEY` | `AccountsAPIVerifier` | Validates the Accounts API key format. |
| `BASE_WEBHOOK_URL` | `WebhookVerifier` | Ensures the URL is valid and reachable. |
| `RAZORPAY_KEY_ID` | `RazorpayVerifier` | Verifies Razorpay credentials via a live API call. |
| `GOOGLE_CLIENT_ID` | `GoogleOAuthVerifier` | Checks the structure of Google OAuth credentials. |

### CLI Arguments

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--env-file` | `string` | `.env` | Path to the environment file. |
| `--doppler-project` | `string` | `bot-platform` | Doppler Project Name. |
| `--doppler-config` | `string` | `dev_bot-platform` | Doppler Config Name. |
| `--aws-ssm-prefix` | `string` | `None` | AWS SSM parameter prefix to load secrets from. |
| `--vault-addr` | `env var` | `None` | HashiCorp Vault Address (via `VAULT_ADDR`). |
| `--vault-token` | `env var` | `None` | HashiCorp Vault Token (via `VAULT_TOKEN`). |
| `--log-level` | `choice` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `--log-format` | `choice` | `text` | Log format (`text`, `json`). |
| `--color` | `bool` | `False` | Enable colorized output. |
| `--concurrency` | `int` | `5` | Number of concurrent verifiers. |
| `--http-timeout` | `float` | `12.0` | Timeout for HTTP requests (seconds). |
| `--db-timeout` | `float` | `10.0` | Timeout for Database connections (seconds). |
| `--overall-timeout` | `float` | `60.0` | Global execution timeout (seconds). |
| `--retries` | `int` | `3` | Number of retries for failed checks. |
| `--dry-run` | `bool` | `False` | Validate formats only; skip network calls. |
| `--skip-live` | `bool` | `False` | Fetch secrets but skip live connectivity probes. |
| `--output-json` | `string` | `None` | Path to save the report as JSON. |
| `--email-alert` | `list` | `None` | Send email alert on failure (`SMTP_SERVER FROM TO PASS`). |
| `--verifiers` | `list` | `None` | Space-separated list of specific verifiers to run. |
| `--dashboard` | `bool` | `False` | Start the web dashboard for viewing reports. |
| `--dashboard-port` | `int` | `8000` | Port for the dashboard. |
| `--reports-dir` | `string` | `.` | Directory to serve reports from. |
| `--version` | `bool` | `False` | Show version and exit. |
| `project_path` | `string` | `None` | Optional path to project directory. |

---

## 🏗️ Architecture

The project follows a modular, asynchronous architecture designed for speed and extensibility.

```
src/vault_check/
├── cli.py          # Entry point & Argument Parsing
├── runner.py       # Core Async Engine & Verifier Orchestration
├── secrets.py      # Secret Fetching (Env, Doppler, AWS)
├── dashboard.py    # Web Dashboard Application (aiohttp)
├── verifiers/      # Plugin-based Verification Modules
│   ├── base.py     # Base Class for all Verifiers
│   ├── database.py # DB Connection Checks
│   ├── s3.py       # AWS S3 Checks
│   └── ...
└── ...
```

**Logic Flow:**
1. **CLI** parses arguments and initializes configuration.
2. **Secrets Loader** aggregates variables from `.env`, Doppler, or AWS.
3. **Runner** identifies relevant `verifiers` based on available keys.
4. **Verifiers** execute concurrently (asyncio), performing syntax checks (dry-run) or live probes.
5. **Output** is rendered to console (Rich), JSON file, or the Web Dashboard.

---

## 🗺️ Roadmap

- [x] **Core Verification Engine** (Async, Retries, Timeouts)
- [x] **Multi-Source Secrets** (Dotenv, Doppler, AWS SSM)
- [x] **Web Dashboard** (View JSON reports in browser)
- [x] **God Level Verifiers** (Telegram Bot, Database, Redis, JWT, S3, SMTP)
- [ ] **Plugin System** (Load external verifiers dynamically) - *Partially implemented*
- [ ] **Kubernetes Operator** (Continuous in-cluster monitoring)

---

## 🤝 Contributing & License

We welcome contributions! Please see `CONTRIBUTING.md` (if available) or standard GitHub flow.

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Push to the branch.
5. Open a Pull Request.

**License**: MIT
