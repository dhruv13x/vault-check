# 🗺️ Vision & Roadmap

This document outlines the strategic direction for `vault-check`, categorizing features from **Core Essentials** to **"God Level"** ambition. Our goal is to be the industry standard for secrets verification, integrating seamlessly into any development lifecycle.

---

### Phase 1: Foundation (CRITICALLY MUST HAVE)
**Focus**: Core functionality, stability, security, and basic usage.
**Timeline**: Q1 (Completed)

- [x] **Core Verifier Suite**: Comprehensive checks for essential services.
  - [x] Database (Postgres/SQLite) & Redis
  - [x] JWT & Fernet Keys (with entropy scoring)
  - [x] Cloud Services (AWS S3, Google OAuth, Razorpay)
  - [x] Communication (Telegram Bot/API, SMTP, Webhooks)
- [x] **Multi-Source Secret Fetching**: Flexible secret management.
  - [x] Local `.env` files
  - [x] Doppler Integration
  - [x] AWS Systems Manager (SSM)
- [x] **Robust CLI**: Production-ready command line interface.
  - [x] Dry-run and live-probe modes
  - [x] JSON output for automation
  - [x] Concurrency and timeout controls
- [x] **Modular Architecture**: Plugin-ready structure with isolated verifiers.
- [x] **Comprehensive Test Coverage**: High coverage (>90%) with Unit, Integration, and E2E tests.
- [x] **Linting & Quality Gates**: `pre-commit` hooks with `ruff` and `mypy`.

---

### Phase 2: The Standard (MUST HAVE)
**Focus**: Feature parity with top competitors, user experience improvements, and robust error handling.
**Timeline**: Q2

- [x] **Basic Web UI Dashboard**: A simple web-based dashboard to view verification reports.
- [x] **Basic Plugin System**: Architecture to support external verifiers.
- [x] **Real-time Dashboard Updates**: Implement WebSockets for live verification progress on the dashboard.
- [ ] **Plugin Developer Guide**: Documentation and examples for creating and publishing custom verifiers.
- [ ] **Enhanced Reporting**:
  - [ ] Actionable fix suggestions (e.g., "Your Fernet key is weak, generate a new one with `openssl...`").
  - [ ] Historical trend analysis to track stability over time.
- [ ] **Expanded Secret Backends**:
  - [ ] HashiCorp Vault
  - [ ] Google Secret Manager
  - [ ] Azure Key Vault

---

### Phase 3: The Ecosystem (INTEGRATION & SHOULD HAVE)
**Focus**: Webhooks, API exposure, 3rd party plugins, SDK generation, and extensibility.
**Timeline**: Q3

- [ ] **Official Integrations**:
  - [ ] **GitHub Action**: Official marketplace action for easy CI/CD integration.
  - [ ] **Pre-commit Hook**: Allow users to run `vault-check` as a pre-commit hook in their projects.
  - [ ] **Infrastructure as Code**: Terraform provider or Ansible module.
- [ ] **REST API Mode**:
  - [ ] Run `vault-check` as a persistent service with a secure API.
  - [ ] Trigger verifications remotely via HTTP.
- [ ] **SDK Generation**:
  - [ ] Python client for programmatic usage.
  - [ ] Auto-generated clients for Go and TypeScript.
- [ ] **Notification Webhooks**: Native integration with Slack, Discord, and PagerDuty for failure alerts.

---

### Phase 4: The Vision (GOD LEVEL)
**Focus**: "Futuristic" features, AI integration, advanced automation, and industry-disrupting capabilities.
**Timeline**: Q4 / Next Year

- [ ] **AI-Powered Anomaly Detection**:
  - [ ] Analyze secret usage patterns to detect potential leaks or misuse.
  - [ ] Predictive failure analysis based on historical connectivity data.
- [ ] **Automated Secret Rotation**:
  - [ ] Bi-directional integration to automatically rotate weak or expiring credentials in supported backends.
- [ ] **"Chaos Engineering" for Secrets**:
  - [ ] Safe injection of network failures or invalid credentials to test application resilience.
- [ ] **Global Secret Health Score**: A single, standardized metric (0-100) to rate the security posture of an environment.

---

### The Sandbox (OUT OF THE BOX / OPTIONAL)
**Focus**: Wild, creative, experimental ideas that set the project apart.

- [ ] **Decentralized Verification**: Blockchain/Mesh-based verification for distributed systems.
- [ ] **Gamified Security Training**: Interactive "Capture the Flag" mode to teach secret management.
- [ ] **"Secrets Linter" IDE Plugin**: Real-time static analysis in VS Code / JetBrains to catch bad secrets before commit.
