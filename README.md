<div align="center">
  <img src="https://raw.githubusercontent.com/dhruv13x/vault-check/main/vault-check_logo.png" alt="vault-check logo" width="200"/>
</div>

<div align="center">

# vault-check

**Production-grade secrets verifier for bot platforms.**

[![Build status](https://github.com/dhruv13x/vault-check/actions/workflows/publish.yml/badge.svg)](https://github.com/dhruv13x/vault-check/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/badge/linting-ruff-yellow.svg)](https://github.com/astral-sh/ruff)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/dhruv13x/vault-check/graphs/commit-activity)

</div>

---

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- `pip`
- Docker (optional, for running tests)

### Installation

Install the core package:

```bash
pip install .
```

For full feature support (AWS, Database, Security checks):

```bash
pip install ".[db,aws,security]"
```

### Run

Run the verifier against your local `.env` file:

```bash
vault-check --env-file .env
```

### Demo

Copy-paste this snippet to see `vault-check` in action with a dummy configuration:

```bash
# Create a dummy .env file
echo "DATABASE_URL=postgres://user:pass@localhost:5432/db" > .env
echo "JWT_SECRET=supersecretpassword123" >> .env

# Run a dry-run check (validates format and entropy only)
vault-check --dry-run
```

---

## ✨ Features

### 🛡️ Security & Core
-   **Entropy Analysis**: Automatically detects weak secrets using `zxcvbn` (e.g., warns on "password123").
-   **Live Probes**: Performs actual network connections (e.g., `SELECT 1` for DBs, `/getMe` for Telegram Bots) to verify credentials.
-   **Async & Concurrent**: Built on `asyncio` and `aiohttp` for high-performance parallel verification.

### 🔌 Integrations
-   **Multi-Source Loading**: Fetch secrets from `.env`, **Doppler**, **AWS SSM**, or **HashiCorp Vault**.
-   **Broad Protocol Support**: Verifiers for PostgreSQL, Redis, Telegram API, Google OAuth, Razorpay, and more.

### 📊 Observability
-   **Web Dashboard**: Built-in dashboard to visualize verification reports and trigger runs.
-   **Actionable Reports**: JSON output and detailed logging for CI/CD pipelines.

---

## 🛠️ Configuration

### Environment Variables

`vault-check` automatically detects and verifies these keys in your environment:

| Variable Name | Description | Required |
| :--- | :--- | :--- |
| `*_DB_URL` | Database connection string (Postgres/SQLite). | No |
| `*_REDIS_URL` | Redis connection URL. | No |
| `SESSION_ENCRYPTION_KEY` | Fernet encryption key (checked for entropy). | No |
| `JWT_SECRET` | JWT signing secret (checked for entropy). | No |
| `JWT_EXPIRATION_MINUTES` | JWT expiration time (integer). | No |
| `API_ID` / `API_HASH` | Telegram Client API credentials. | No |
| `*_BOT_TOKEN` | Telegram Bot Token (checked via live API call). | No |
| `OWNER_TELEGRAM_ID` | Telegram User ID of the bot owner. | No |
| `ACCOUNTS_API_KEY` | Key for internal Accounts API. | No |
| `RAZORPAY_KEY_ID` | Razorpay public key. | No |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID. | No |

### CLI Arguments

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--env-file` | Path to the `.env` file. | `.env` |
| `--doppler-project` | Doppler project name. | `bot-platform` |
| `--aws-ssm-prefix` | Prefix for AWS SSM parameters. | `None` |
| `--log-level` | Logging verbosity (DEBUG, INFO, WARNING, ERROR). | `INFO` |
| `--concurrency` | Number of concurrent verifier tasks. | `5` |
| `--dry-run` | Validate formats/entropy without network calls. | `False` |
| `--dashboard` | Launch the web dashboard. | `False` |
| `--dashboard-port` | Port for the web dashboard. | `8000` |
| `--output-json` | Path to save the verification report as JSON. | `None` |

---

## 🏗️ Architecture

### Directory Tree

```text
src/vault_check/
├── cli.py             # Entry point, argument parsing
├── runner.py          # Orchestrates async verification tasks
├── secrets.py         # Loads secrets from Env, Doppler, AWS
├── registry.py        # Manages discovery of verifier plugins
├── dashboard.py       # Web server for the dashboard UI
├── verifiers/         # Individual verification logic
│   ├── database.py    # DB connection checks
│   ├── http_check.py  # Generic HTTP checks
│   └── ...
└── config.py          # Configuration constants and schemas
```

### Data Flow

1.  **Input**: The user invokes the CLI, specifying secret sources (local file, Doppler, AWS).
2.  **Load**: `secrets.py` aggregates secrets into a unified dictionary.
3.  **Discover**: `runner.py` inspects the secrets and matches them against registered verifiers in `registry.py`.
4.  **Execute**: The `ExecutionEngine` runs matched verifiers concurrently. Each verifier performs syntax checks (dry-run) or live probes.
5.  **Report**: Results (errors, warnings, suggestions) are collected and output to the console, a JSON file, or the Dashboard.

---

## 🐞 Troubleshooting

| Error Message | Possible Solution |
| :--- | :--- |
| `Connection refused` | Ensure the service (DB, Redis) is running and reachable from the host. |
| `Authentication failed` | Check that the username/password in the secret is correct. |
| `Entropy too low` | The secret is too weak (e.g. "123456"). Generate a stronger key. |
| `ModuleNotFoundError` | Ensure you installed optional dependencies (`pip install ".[db]"`). |

### Debug Mode

To see detailed logs of what `vault-check` is doing (including HTTP requests and secret loading details), use the `--log-level` flag:

```bash
vault-check --log-level DEBUG
```

---

## 🤝 Contributing

We welcome contributions!

### Dev Setup

1.  Clone the repository:
    ```bash
    git clone https://github.com/dhruv13x/vault-check.git
    cd vault-check
    ```

2.  Install development dependencies:
    ```bash
    pip install -e ".[dev,db,aws,security]"
    ```

3.  Run the tests to ensure everything is working:
    ```bash
    pytest
    ```

4.  Install pre-commit hooks to enforce code quality:
    ```bash
    pre-commit install
    ```

Please follow standard GitHub Pull Request workflows.

---

## 🗺️ Roadmap

- [ ] **Plugin System**: Fully documented guide for creating 3rd-party verifiers.
- [ ] **GitHub Action**: Official action for CI/CD integration.
- [ ] **Pre-commit Hook**: Native pre-commit hook support.
- [ ] **Automated Rotation**: Integration to rotate weak secrets automatically.
- [ ] **AI Anomaly Detection**: Analyze secret usage patterns for security risks.
