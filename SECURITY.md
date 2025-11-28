# Security Policy

## Overview

`vault-check` is a security-focused tool designed to verify the validity and connectivity of your application's secrets (API keys, database URLs, etc.). Because this tool interacts with highly sensitive information, we adhere to strict security principles to ensure your data remains safe.

## Core Guarantees

### 1. Zero Exfiltration ("No Phone Home")
This tool is completely **passive** regarding external data transmission.
- **No Analytics:** We do not use Google Analytics, Mixpanel, Sentry, or any other tracking software.
- **No Telemetry:** We do not collect usage statistics or crash reports.
- **No Third-Party Uploads:** Your secrets are **never** sent to us or any third-party server.
- **Network Scope:** The tool only establishes network connections to:
    - The specific infrastructure you are verifying (e.g., your PostgreSQL database, your Redis instance).
    - The secret providers you explicitly configure (e.g., Doppler API, AWS SSM).
    - The SMTP server you configure (only if email alerts are enabled).

### 2. Safe Logging & Output
We prioritize preventing accidental leakage of secrets into logs (e.g., CI/CD build logs).
- **Automatic Masking:** All output functions use `mask_url` and `mask_sensitive` utilities.
    - URLs are parsed, and the password component is replaced with `*****`.
    - API keys are truncated (e.g., `sk_live_...4829`).
- **Memory Only:** Secrets are held in memory only for the duration of the check and are never written to disk, unless you explicitly use the `--output-json` flag to save a report.

### 3. Open Source Transparency
Trust is built on transparency. We encourage you to audit our code:
- **Secret Loading:** `src/vault_check/secrets.py`
- **Verification Logic:** `src/vault_check/verifiers/`
- **Network Clients:** `src/vault_check/http_client.py`

## Reporting a Vulnerability

If you discover a security vulnerability within `vault-check`, please do **not** create a public GitHub issue.

Instead, please report it responsibly to the maintainers. We will acknowledge your report and work to provide a fix as quickly as possible.
