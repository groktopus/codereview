# Theme: Verification depth

**Scorecard dimension:** Test depth (current: B−)
**Target:** coverage ≥85% overall and ≥90% on `github`, `publisher`, `checks`, and `actions_publication`; strict typing on core; mutation score ≥70% on reducer/validators; property tests for budget and state invariants; a compatibility suite separate from ordinary tests.
**Why:** the suite is large (2,663 passing tests with packaging ignored, 81.4% coverage) but proves plumbing more than behavior under variation. The lowest coverage is on the modules that touch credentials, publication, and external checks.

---

## VD-1 — Add coverage gates with critical-module floors

- **Priority:** P1
- **Dimensions:** Test depth; Operational readiness
- **Problem:** Coverage is 81.4% overall but uneven: `github.py` 61.9%, `publisher.py` 71.0%, `checks.py` 74.3%, `cli.py` 76.2%. These are the credential, publication, and check-binding paths. Nothing in CI reports or enforces coverage, so it can drift.
- **Scope:**
  - Publish coverage in CI for every run (JSON + summary) and retain the artifact.
  - Set an overall floor and per-module floors for the critical set; grandfather no module silently.
  - Identify uncovered error/refusal branches and add tests that assert the typed reason and the absence of effects.
  - Keep coverage as a floor, not a quality claim.
- **Exit criteria:** CI fails below the floors; a coverage report is retained per run; the critical modules meet ≥90%; uncovered lines in those modules are justified or tested.
- **Verification:** `pytest --cov` artifact; a seeded deletion showing the gate fails; per-module table in the job summary.
- **Depends on:** CA-1 (stage extraction makes targeted tests possible).
- **Non-goals:** chasing 100% or counting lines without assertions.

---

## VD-2 — Add property, mutation, and fault-injection testing

- **Priority:** P1
- **Dimensions:** Test depth; Control plane; Effect safety
- **Problem:** There are zero property-based tests and no mutation testing. Budget arithmetic, reservation/settlement, ledger recovery, and the reducer are invariant-heavy but tested by examples. Provider, GitHub, and publication failure matrices are incomplete.
- **Scope:**
  - Property tests for: no dispatch without reservation, no settlement without attempt, budget never exceeds ceiling, ledger replay is idempotent, reducer never clears a blocker, stale/unknown never approves.
  - Mutation testing on `reconcile`, reducer/validators, and budget arithmetic; triage surviving mutants.
  - Fault-injection matrix: provider timeout, 4xx/5xx, malformed JSON, truncated stream, duplicate response, GitHub rate limit/redirect/5xx, artifact tamper, publication timeout/ambiguous submit/history pagination.
  - Assert both the terminal state and the absence of forbidden effects.
  - Remove or make tolerant wall-clock assertions that fail under runner contention (for example the elapsed-time assertion in `tests/test_observability.py`); assert ordering and invariants, or use a documented tolerance with a retry-free rationale.
- **Exit criteria:** Property tests run in CI; mutation score ≥70% on the named modules; the fault matrix is parameterized and green; each fault asserts a stable reason code.
- **Verification:** a mutation report artifact; property-test seeds; a fault-matrix table generated from test IDs.
- **Depends on:** CA-1, VD-1.
- **Non-goals:** treating synthetic fault success as live-provider qualification.

---

## VD-3 — Isolate historical pins in a compatibility suite

- **Priority:** P1
- **Dimensions:** Test depth; Architecture
- **Problem:** Historical evidence is protected by 61 hard-coded SHA-256 values and frozen copies of `engine`, `providers`, `cli`, and `selected_model_trial` (26 fixtures, 1.1 MB). A legitimate source change breaks 10+ tests until a fixture is added by hand, as happened with `actions_runtime.py` in PR #138. The friction discourages refactoring and the failure message does not explain the remedy.
- **Scope:**
  - Split "historical compatibility" from ordinary unit/integration tests with an explicit marker or directory.
  - Provide a pin-refresh tool that records: old blob hash, new blob hash, reason, source revision, and timestamp, and refuses to rewrite a pin without that provenance.
  - Replace scattered magic hashes with named fixtures and a single manifest.
  - Make failures actionable: name the module, the historical revision, and the exact remediation command.
  - Document the process in CONTRIBUTING.
- **Exit criteria:** Compatibility tests are identifiable and run separately in CI; the refresh tool exists and is tested; a source change produces an actionable failure; no ad-hoc SHA-256 literals remain outside the compatibility manifest, and the manifest is the only place pins are recorded.
- **Verification:** `pytest -m compatibility`; a dry-run of the refresh tool; a failure-message snapshot test.
- **Depends on:** CA-2 (surface consolidation reduces the pinned set).
- **Non-goals:** deleting historical evidence or silently updating pins.

---

## VD-4 — Enforce static analysis, typing, and formatting

- **Priority:** P1
- **Dimensions:** Test depth; Architecture
- **Problem:** CI runs `ruff check` with only `E4/E7/E9/F/I`; 187 of 267 Python files would be reformatted; there is no type checker. Style and type drift are invisible, and review time is spent on mechanical issues.
- **Scope:**
  - Adopt `ruff format` as the canonical formatter and check it in CI.
  - Expand lint rules incrementally (`B`, `SIM`, `UP`, `C4`, `RUF`, `ASYNC` where applicable), with a documented ignore list.
  - Add `mypy` or `pyright` for the typed core (see CA-4), with a ratchet: new modules must pass.
  - Add a pre-commit configuration matching CI.
  - Add a complexity guard (for example, fail new functions above a threshold) to prevent another 3,000-line function.
- **Exit criteria:** CI enforces format, lint, and types; the repository is formatted; new code cannot add untyped or over-complex functions without an explicit exception.
- **Verification:** `ruff format --check`, expanded `ruff check`, type-check job; a seeded violation failing CI.
- **Depends on:** CA-4.
- **Non-goals:** reformatting history or blocking urgent fixes on style.
- **Status (2026-11-02):** PARTIAL. `ruff format` is canonical and checked in CI
  for every maintained Python file; the sha256-pinned historical compatibility
  fixtures are excluded because reformatting them would break VD-3 evidence.
  A pre-commit configuration matches the CI lint/format gates, and the
  function-length complexity guard enforces a checked 150-line baseline with a
  growth ratchet. The lint rule set is still `E4/E7/E9/F/I`; expanding it and
  adopting a typed core beyond the existing strict `.pyi` boundary checks
  remain open VD-4 work.
