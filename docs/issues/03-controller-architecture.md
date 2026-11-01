# Theme: Controller architecture

**Scorecard dimension:** Architecture and modularity (current: D+); Deterministic control plane (current: B+)
**Target:** `run_review` ≤300 lines; one run path; one supported review contract/profile/limits set; ≥25% reduction in `src` lines; no import cycles; typed interfaces between stages.
**Why:** the controller is the product's brain. Today the entire lifecycle lives in one 3,175-line function with 16 nested closures and 640 branch nodes. Every improvement in this backlog passes through it, so its shape is a rate limiter on everything else.

---

## CA-1 — Extract the review lifecycle into typed stages

- **Priority:** P0
- **Dimensions:** Architecture; Control plane; Test depth
- **Problem:** `engine.run_review` (`engine.py:1370`) is 3,175 lines with 16 nested functions (`checkpoint`, `call_estimate`, `reserve_provider_call`, `start_attempt`, `finish_attempt`, `record_task_outcome`, `run_followup`, …) sharing mutable closure state. Budget arithmetic, retries, follow-up scheduling, reconciliation, and reduction are interleaved. It is hard to test in isolation and expensive to change safely.
- **Scope:**
  - Introduce an explicit `RunState` (run identity, snapshot, plan, ledger, reservations, coverage, deadlines) passed between stages.
  - Extract stages with narrow interfaces: preflight, snapshot binding, planning, dispatch/settlement, reconciliation, reduction, rendering.
  - Preserve byte-identical outputs for existing fixtures; move behavior, not just code.
  - Make each stage independently testable with a constructed state, without a full run.
  - Keep the deterministic invariants (reserve-before-dispatch, fail-closed, blocker preservation) as explicit stage contracts.
- **Exit criteria:** `run_review` is a thin coordinator (≤300 lines); stages are separately importable and tested; all existing golden outputs are byte-identical; no mutable closure state remains.
- **Verification:** a behavior-preserving golden corpus run (same hashes); stage-level unit tests; an AST check asserting the line-count ceiling; import graph has no cycles.
- **Depends on:** none.
- **Non-goals:** changing review semantics, budgets, prompts, or report format.

---

## CA-2 — Consolidate experiment and production surfaces

- **Priority:** P1
- **Dimensions:** Architecture; Test depth
- **Problem:** Nine `run_*` entry points and parallel orchestrators exist (`run_review`, `run_provider_trial`, `run_current_provider_trial`, `run_shadow_audit`, `run_trials`, `run_trial`, `run_two_case_trial`, `run_protected_publication`, `run_actions_canary`). Several re-implement ledger, coverage, and settlement logic. Superseded trial modules remain importable, tested, and packaged. "Current behavior" is ambiguous and fixes do not propagate.
- **Scope:**
  - Classify each orchestrator as production, reusable experiment harness, or obsolete.
  - Move experiment harnesses to `experiments/` (outside the installable package) or delete them, preserving historical artifacts.
  - Keep one production run path; experiments must call the core rather than fork it.
  - Remove superseded cross-model and trial versions after their evidence is archived.
  - Measure and record the resulting source reduction.
- **Exit criteria:** One production orchestrator; experiment code is not in the wheel; ≥25% reduction in `src` lines; no duplicated budget/settlement logic; the package's public surface is documented.
- **Verification:** wheel inventory (`unzip -l`) contains no experiment modules; `rg "def run_"` count; line-count diff; tests of archived evidence still pass.
- **Depends on:** CA-1.
- **Non-goals:** deleting historical evidence or rewriting past experiment records.

---

## CA-3 — Create a contract and version registry with deprecation policy

- **Priority:** P1
- **Dimensions:** Architecture; Governance
- **Problem:** The repository carries nine SlopSearX profile generations (v9–v17), three limits revisions, three claim-assessment contract versions (`.1`–`.3`), review contracts (`legacy-v14`, `bounded-production-v16/v17`), and canary receipt `v1`/`v2`. There is no single place that states which are supported, what changed, or when one may be removed. Operators cannot tell which combination is current.
- **Scope:**
  - Add one machine-readable registry: contract name, version, status (`supported`, `deprecated`, `archived`), owner, replaced-by, and invariants.
  - Reduce the supported matrix to one review contract, one profile, and one limits set; archive the rest as immutable files with a note.
  - Define a deprecation policy: announcement, replacement path, compatibility window, and removal evidence.
  - Validate profile/limits compatibility at preflight and reject unknown combinations with typed errors.
  - Emit the effective contract set in every run artifact.
- **Exit criteria:** The registry exists and is validated in CI; only one combination is selectable by default; every archived version is labeled; preflight rejects unsupported combinations; run artifacts record the contract set.
- **Verification:** registry schema test; CI check that no archived version is referenced by production code; a run artifact showing contract identity.
- **Depends on:** CA-1.
- **Non-goals:** deleting historical profiles that evidence depends on.

---

## CA-4 — Type the module boundaries and remove dictionary soup

- **Priority:** P1
- **Dimensions:** Architecture; Test depth
- **Problem:** The core passes `dict[str, Any]` across almost every boundary (snapshot, plan, task, ledger, coverage, result). Renames and shape changes fail at runtime, not at review time. There is no static type enforcement anywhere in CI.
- **Scope:**
  - Introduce `TypedDict`/dataclasses for the stable contracts: snapshot, plan, task, attempt, ledger entry, finding, coverage row, result.
  - Convert stage interfaces first, then the highest-churn modules (`engine`, `planner`, `reconcile`, `report`).
  - Keep runtime validation at external edges (JSON, provider payloads, workflow inputs); types do not replace validation.
  - Add `mypy` or `pyright` in strict mode for the typed core, with an explicit allowlist during migration.
  - Remove the `pickle.dumps` size proxy (`engine.py:560`) in favor of canonical identity hashing.
- **Exit criteria:** Core stage interfaces are typed; strict type checking passes for the migrated modules; no new untyped boundary is added; `pickle` is gone from the engine.
- **Verification:** CI type-check job; `rg "dict\[str, Any\]"` trend in core modules; a deliberately wrong-shape probe fails type checking.
- **Depends on:** CA-1.
- **Non-goals:** typing every experiment module or rewriting dynamic provider payload handling.
