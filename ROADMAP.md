# 🗺️ Strategic Roadmap V3.0

This document serves as a living strategic guide for the development of `vault-check`. It balances innovation, stability, and technical debt to ensure the project evolves sustainably.

---

## The Strategy

1.  **Prioritization**: We prioritize items based on Value vs. Effort.
2.  **Risk Assessment**: Every feature is assessed for risk (High/Medium/Low).
3.  **Phased Execution**: Dependencies are respected; Phase 2 requires Phase 1 completion.

---

## 🏁 Phase 0: The Core (Stability & Debt)
**Goal**: Solid foundation. Ensure the current codebase is robust, well-tested, and documented before expanding.

- [ ] **Testing**: Increase coverage to > 85% (Currently ~82%).
    - [ ] `[Debt]` Refactor and test `dashboard.py` (Current coverage: 19%). `(L)`
    - [ ] `[Debt]` Fix asyncio-related test warnings. `(S)`
- [ ] **CI/CD**: Maintain strict quality gates.
    - [x] `[Infra]` Pre-commit hooks (ruff, black, mypy).
    - [x] `[Infra]` GitHub Actions for testing and linting.
- [ ] **Documentation**: Close critical documentation gaps.
    - [ ] `[Docs]` Create "Plugin Developer Guide" for 3rd party integrations. `(M)`
    - [x] `[Docs]` Comprehensive README with Quick Start.
- [ ] **Refactoring**: Pay down critical technical debt.
    - [ ] `[Debt]` Standardize error handling across all verifiers. `(M)`

---

## 🚀 Phase 1: The Standard (Feature Parity)
**Goal**: Competitiveness. polish the user experience and ensure the tool is pleasant to use.

- [ ] **UX**: Improve the Command Line Interface.
    - [ ] `[Feat]` Interactive Mode (Wizard-style setup). `(M)`
    - [ ] `[Feat]` Improved Error Messages with specific, actionable hints. `(S)`
- [ ] **Config**: Robust settings management.
    - [ ] `[Feat]` Support for `pyproject.toml` configuration. `(S)`
    - [ ] `[Feat]` Global config file (e.g., `~/.vault-check/config.yaml`). `(S)`
- [ ] **Performance**: Optimization.
    - [x] `[Perf]` Async/Concurrent verifiers.
    - [ ] `[Perf]` Caching of successful checks (optional, with TTL). `(M)`
- *Risk*: Low.

---

## 🔌 Phase 2: The Ecosystem (Integration)
**Goal**: Interoperability. Make `vault-check` work seamlessly with other tools.

- [ ] **API**: Expose functionality programmatically.
    - [ ] `[Feat]` REST API Mode (persistent service). `(L)`
    - [ ] `[Feat]` GraphQL Endpoint for complex queries. `(XL)`
- [ ] **Plugins**: Expand the extension system.
    - [x] `[Core]` Basic Plugin Architecture.
    - [ ] `[Feat]` Official Plugin Registry/Index. `(M)`
- *Risk*: Medium (Requires stable API design).

---

## 🔮 Phase 3: The Vision (Innovation)
**Goal**: Market Leader. differentiating features that push the boundaries.

- [ ] **AI**: Intelligence integration.
    - [ ] `[Feat]` LLM Integration for explaining secret failures. `(XL)`
    - [ ] `[Feat]` Anomaly detection in secret usage patterns. `(L)`
- [ ] **Cloud**: Native Cloud Integration.
    - [ ] `[Feat]` K8s Operator for secret validation. `(XL)`
    - [ ] `[Feat]` Docker Extension. `(M)`
- *Risk*: High (R&D heavy).

---

## Legend
- `[Debt]`: Technical Debt / Maintenance
- `[Feat]`: New Feature
- `[Bug]`: Bug Fix
- `[Docs]`: Documentation
- `[Infra]`: Infrastructure / CI/CD
- `[Perf]`: Performance Improvement
- `(S/M/L/XL)`: T-Shirt Size Estimate (Small, Medium, Large, Extra Large)
