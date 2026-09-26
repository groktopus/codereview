# Architecture decisions

These records are proposals for the PR Review Harness. No approval authority or acceptance has been recorded. A proposal must not be described as an accepted architecture decision until the responsible stakeholder explicitly accepts its scope. Later decisions should preserve history and supersede a record rather than silently rewrite an accepted rationale.

| ID | Decision | Status |
|---|---|---|
| [ADR-001](001-modular-core-and-adapters.md) | Keep a reusable local modular core behind CLI and Actions adapters | Proposed |
| [ADR-002](002-deterministic-review-controller.md) | Keep workflow, budgets, policy transitions, and disposition deterministic | Proposed |
| [ADR-003](003-durable-ledger-and-idempotent-effects.md) | Persist run evidence and make recovery/effects idempotent | Proposed |
| [ADR-004](004-isolate-untrusted-pr-execution.md) | Separate credentialed analysis from untrusted head-code execution | Proposed |
