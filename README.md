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

To run the integration and end-to-end tests, you will need to create a `.env` file in the `tests/integration` and `tests/e2e` directories. For a template, see the `.env.example` file.

**Important**: Do not use these example values in production. Always generate strong, unique secrets for your production environment.

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
