# Theme: Review completeness

**Scorecard dimension:** Review completeness (current: D)
**Target:** ≥90% of required obligations complete on the frozen natural corpus; retrieval truncation ≤5%; `INCOMPLETE` rate ≤15%.
**Why this is first:** the harness's core output is a review. Today most natural reviews are `INCOMPLETE / PARTIAL`; the best observed run completed 27 of 42 required rows. Until this changes, publication and cutover work cannot produce a usable product.

---

## RC-1 — Separate the retrieval envelope from the model-output budget

**Status: Closed 2026-11-05.** Owner approved a test-based receipt because the original PR305 revision was not retained. Evidence: [rc1-retrieval-envelope.json](../evidence/rc1-retrieval-envelope.json). The dedicated `max_retrieval_result_bytes` limit is threaded through retrieval and the isolated invocation, and the 40 KB symbol-at-end test passes. No frozen PR305 rerun is claimed.

- **Priority:** P0
- **Dimensions:** Review completeness; Control plane
- **Problem:** Local context retrieval is sized by `max_output_bytes_per_task` (`engine.py:2771`), which is 16,000 bytes in the shipping limits, while per-task input is 96,000 bytes. Files larger than the envelope are truncated to a **prefix** by `evidence._fit_ipc_envelope`, so a specialist may receive lines 1..N and never see the function under review. In the v17 PR305 run, 8 of 8 retrievals returned `ipc_envelope_truncated`.
- **Scope:**
  - Introduce an explicit retrieval limit (for example `max_retrieval_result_bytes`) distinct from provider output limits, defaulting to the per-task input ceiling.
  - Thread it through `engine.run_review`, `evidence`, and the isolated invocation limits without changing provider response caps.
  - Fail closed with a typed reason when the retrieval *metadata* exceeds the envelope, rather than silently returning a prefix.
  - Add a regression fixture with a 40 KB file whose relevant symbol sits at the end; assert the symbol is present in the retrieved evidence.
- **Exit criteria:** A dedicated retrieval limit exists and is used; the 40 KB symbol-at-end fixture passes; re-running the frozen PR305 case shows zero `ipc_envelope_truncated` results for files under the new cap; larger files must use chunked retrieval or be rejected with a typed reason.
- **Verification:** new test in `tests/test_engine.py` or `tests/test_evidence.py`; a frozen-case run receipt showing retrieval statuses; `rg "max_result_bytes"` shows the retrieval key, not the output key.
- **Depends on:** none.
- **Non-goals:** raising provider output limits, changing budgets, or adding a retry.

---

## RC-2 — Replace prefix retrieval with a retrieval compiler

- **Priority:** P1
- **Dimensions:** Review completeness; Architecture
- **Problem:** Retrieval currently asks for whole paths and degrades to prefixes. It does not reliably deliver the definition under review, its callers, the tests that exercise it, or the configuration that governs it. Observed failures include symbol lookups outside the allowlist contract and repeated unresolved follow-ups. This is a context-selection problem, not a budget problem.
- **Scope:**
  - Build retrieval targets from the diff and profile: changed symbols, enclosing definitions, direct callers/callees, referenced tests, and policy/config paths.
  - Return **line-anchored windows** (definition plus bounded surrounding lines) with explicit path/range/hash provenance, not whole-file prefixes.
  - Support multiple bounded evidence chunks per obligation, deduplicated and deterministically ordered.
  - Add a sufficiency check before dispatch: if required evidence is known missing, record an explicit gap rather than sending an under-contextualized task.
  - Keep the trusted-policy boundary: HEAD content is repository evidence, never policy.
- **Exit criteria:** On the frozen corpus, ≥90% of required context obligations are complete; every retrieved byte is line-anchored; retrieval plans are deterministic and hashable; no whole-file prefix fallback remains above the envelope.
- **Verification:** corpus report by obligation; retrieval-plan fixtures with stable hashes; tests for symbol, caller, test, and policy targeting; a diff of before/after completion reasons on the frozen cases.
- **Depends on:** RC-1, QM-1 (corpus to measure against).
- **Non-goals:** semantic search, embeddings, or model-proposed retrieval as an authority.

---

## RC-3 — Make completeness measurable and regression-gated

**Status: Closed 2026-11-05.** A five-case frozen-corpus baseline and an active CI gate are recorded in [completeness-baseline-v1](../../examples/evaluation/completeness-baseline-v1/README.md); `qm1-slopsearx-pr770` is explicitly excluded for the documented base mismatch. Evidence: [rc3-completeness-baseline.json](../evidence/rc3-completeness-baseline.json).

- **Priority:** P0
- **Dimensions:** Review completeness; Evidence discipline
- **Problem:** Completeness is reported per run but not aggregated or compared. Reason codes (`CONTEXT_GAP_UNRESOLVED`, `ipc_envelope_truncated`, `CHECK_RESULT_UNAVAILABLE`, …) are strings scattered across modules, and no gate prevents a change from making reviews less complete.
- **Scope:**
  - Define one canonical reason taxonomy for incomplete obligations, with stable codes and a documented meaning.
  - Emit a machine-readable completeness summary for every run: required, complete, partial, not-started, and reason distribution.
  - Publish a baseline on the frozen corpus before any change is judged.
  - Add a CI comparison that fails when a change lowers completion beyond an owner-set threshold, or when a known-complete case regresses to truncated.
  - Keep zero-candidate and zero-obligation cases visible in denominators.
- **Exit criteria:** Every review emits the summary; the reason taxonomy is documented and versioned; the frozen-corpus baseline is recorded; the CI gate is active and demonstrably fails on a seeded regression.
- **Verification:** `pr-review stats` (or equivalent) on a stored result; a CI job artifact; a deliberate regression probe showing the gate fails; taxonomy doc linked from the report.
- **Depends on:** none. The taxonomy and baseline can start immediately; the regression gate is finalized alongside the corpus work.
- **Non-goals:** averaging safety invariants into a score, or treating a single clean case as a quality result.
