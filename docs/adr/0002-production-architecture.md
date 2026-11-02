# 0002 — Production architecture: one modular core with typed deterministic stages

- **Status:** Accepted
- **Date:** 2026-11-01
- **Owner:** Repository maintainers (`groktopus/codereview`; `.github/CODEOWNERS` names `@magnus919`).
- **Decision authority:** Repository owner, through merged pull requests [#277](https://github.com/groktopus/codereview/pull/277) (CA-1) and [#284](https://github.com/groktopus/codereview/pull/284) (CA-2), and the architecture statement in [ARCHITECTURE.md](../ARCHITECTURE.md).
- **Scope:** Installed `src/pr_review_harness/` review path, its CLI entry point, and the boundary between production code and experiment harnesses.
- **Evidence:** Commits `e627be2` (typed stages) and `d91cfe4` (surface consolidation); [ARCHITECTURE.md](../ARCHITECTURE.md); [CA-1 and CA-2](../issues/03-controller-architecture.md); [test_surface_consolidation.py](../../tests/test_surface_consolidation.py); [test_engine.py](../../tests/test_engine.py).
- **Reversal/expiry:** No expiry. Revisit if measured workload, isolation, or ownership evidence justifies a service boundary, or if the stage boundary stops being independently testable. A change requires a new or superseding record.
- **Supersedes:** None. The legacy design proposals in `docs/design/adrs/` are not rewritten or renumbered.
- **Superseded by:** None.
- **Related:** Legacy design [ADR-001](../design/adrs/001-modular-core-and-adapters.md) and [ADR-002](../design/adrs/002-deterministic-review-controller.md) remain proposed; this record documents the decision actually taken for the production surface, not acceptance of the whole design package.

## Context

The review lifecycle originally lived in one 3,175-line `engine.run_review` function with nested closure state, and the repository carried several parallel `run_*` orchestrators that re-implemented budget, coverage, and settlement behavior. That made review behavior ambiguous and made safe change expensive. The repository needed one production review path, stage-level testability, and an explicit boundary between installed code and experiment evidence.

## Decision

Use one modular Python core with deterministic stages and thin adapters:

- `pr_review_harness.engine.run_review` is the only production review orchestrator. The CLI calls it; there is no second review path.
- Lifecycle stages are extracted into `review_stages` with an explicit run state, narrow interfaces, and independent tests. Deterministic code owns planning, budgets, retries, follow-up scheduling, reconciliation, termination, and disposition.
- Models return bounded, typed candidates and advisory assessments only. They do not choose workflow, tools, effects, or disposition.
- `budget.BudgetLedger` is the only budget ledger and is called only by the orchestrator and its stages.
- Experiment harnesses live under `experiments/harness/`, are excluded from the installed wheel, and invoke the core rather than forking it.
- CLI and GitHub Actions remain adapters over the same core; no hosted service is introduced without separate evidence.

## Consequences

- Review behavior has one implementation and one set of contract identities.
- Stages can be tested with a constructed state, and deterministic invariants (reserve-before-dispatch, fail-closed handling, blocker preservation) are stage contracts rather than incidental behavior.
- The installed surface and its source-line ceiling are machine-checked; see [ADR 0001](0001-post-ca2-feature-budget.md).
- Historical experiment code is retained in the repository for evidence but is not installed or importable as production code.
- A service split remains deferred until measured workload or isolation needs justify it.

## Alternatives considered

- **Keep the monolithic orchestration function.** Rejected: it preserved interleaved budget, retry, and disposition behavior that could not be tested in isolation.
- **Hosted service with queue and worker fleet.** Rejected for now: it adds ownership, credentials, network, consistency, and recovery burdens without evidence of need.
- **Prompt-driven agent workflow.** Rejected: it would move workflow authority into a model and conflict with deterministic budgets, termination, and evidence coverage.
- **Leave experiment orchestrators in the package.** Rejected: duplicate orchestrators made "current behavior" ambiguous and kept experiment code in the distribution.

## Evidence status

The merged pull requests and current source establish the architecture and consolidation. The installed-surface and line-count checks are `OBSERVED` in the repository. This record does not establish review quality, provider suitability, or production readiness; those are governed by [ADR 0006](0006-evaluation-gates.md).
