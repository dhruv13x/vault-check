# 🗺️ Vision & Roadmap

This document outlines the strategic direction for `vault-check`, from core essentials to visionary "God Level" features. Our goal is to be the industry standard for secrets verification, integrating seamlessly into any development lifecycle.

---

### Phase 1: Foundation (Q1)
**Focus**: Core functionality, stability, security, and basic usage.

- [x] **Core Verifier Suite**: Comprehensive checks for essential services.
  - [x] Database (Postgres/SQLite)
  - [x] Redis
  - [x] JWT & Fernet Keys (with entropy scoring)
  - [x] Telegram (API, Bot, User IDs)
  - [x] Webhooks & Standard APIs (Accounts API)
- [x] **Multi-Source Secret Fetching**: Flexible secret management.
  - [x] Doppler
  - [x] AWS SSM
  - [x] Local `.env` files
- [x] **Robust CLI**: Foundational user interface.
  - [x] Dry-run and live-probe modes
  - [x] JSON output for automation
  - [x] Concurrency and timeout controls
- [ ] **Comprehensive Test Coverage**: Ensure reliability.
  - [ ] Achieve >90% unit test coverage.
  - [ ] Implement end-to-end tests for all verifiers.

---

### Phase 2: The Standard (Q2)
**Focus**: Feature parity with top competitors, user experience improvements, and robust error handling.

- [x] **Official Plugin System**: Allow users to create and share their own verifiers.
  - [x] Implement a registration system for custom verifier plugins.
  - [ ] Publish a developer guide for creating plugins.
- [ ] **Web UI Dashboard**: Visualize verification results.
  - [x] A simple web-based dashboard to view the latest and historical verification reports.
  - [ ] Real-time updates via WebSockets.
- [ ] **Enhanced Reporting**: More detailed and actionable reports.
  - [ ] Suggestions for fixing common errors (e.g., "Your Fernet key is weak, generate a new one with...").
  - [ ] Historical data and trend analysis.
- [ ] **Additional Secret Backends**:
  - [ ] HashiCorp Vault
  - [ ] Google Secret Manager
  - [ ] Azure Key Vault

---

### Phase 3: The Ecosystem (Q3 - Q4)
**Focus**: Webhooks, API exposure, 3rd party plugins, SDK generation, and extensibility.

- [ ] **Official Integrations**:
  - [ ] **CI/CD Platforms**: Native plugins for GitHub Actions, GitLab CI, and Jenkins.
  - [ ] **Infrastructure as Code**: Terraform and Ansible modules for automated setup.
  - [ ] **Monitoring and Alerting**: PagerDuty, Slack, and Datadog integrations.
- [ ] **REST API**:
  - [ ] Expose `vault-check` as a service with a secure REST API.
  - [ ] Allow for remote triggering of verification jobs.
- [ ] **SDK Generation**:
  - [ ] Auto-generate SDKs for popular languages (Python, Go, TypeScript) to interact with the `vault-check` API.

---

### Phase 4: The Vision (GOD LEVEL) (Next Year)
**Focus**: "Futuristic" features, AI integration, advanced automation, and industry-disrupting capabilities.

- [ ] **AI-Powered Anomaly Detection**:
  - [ ] Use machine learning to detect unusual patterns in secret usage and verification failures.
  - [ ] Proactively identify potential security risks.
- [ ] **Automated Secret Rotation**:
  - [ ] Integrate with secret backends to automatically rotate secrets that are about to expire or have been compromised.
- [ ] **"Chaos Engineering" for Secrets**:
  - [ ] Intentionally inject invalid secrets into a staging environment to test the resilience of the system.

---

### The Sandbox (OUT OF THE BOX / OPTIONAL)
**Focus**: Wild, creative, experimental ideas that set the project apart.

- [ ] **"Secrets Linter"**: A static analysis tool that scans code for hardcoded secrets and other security vulnerabilities.
- [ ] **Gamified Security Training**: An interactive tutorial that teaches developers about secret management best practices.
- [ ] **Decentralized Secrets Verification**: Use a blockchain-based system to verify the integrity of secrets across a distributed network.
