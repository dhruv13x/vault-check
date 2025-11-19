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
