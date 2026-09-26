# Independent implementation review: snapshot, planner, and engine

**Review date:** 2026-09-26
**Scope:** Read-only source review of snapshot construction, task planning, provider dispatch, evidence reconciliation, coverage, budgets, resume, and reporting. This review is implementation feedback for the pilot; it is not a quality evaluation or release approval.

## Findings and disposition

The review found three material paths that could misstate evidence or weaken the contract. They were raised with the implementation owners and now have regression coverage:

- Semantic reconciliation previously allowed candidate-provided `introducedness` to fill a missing semantic assessment field. The engine now requires a valid assessment `introducedness`, the three support states, and the material-consequence boolean before a supported result can be considered. `test_missing_semantic_introducedness_cannot_fall_back_to_candidate_claim` protects this boundary.
- Candidate locations previously passed when the snapshot had no changed-line ranges. Snapshot collection now derives added/replaced HEAD line ranges from unified-diff hunks, and reconciliation requires a line inside a nonempty range. `test_out_of_hunk_finding_location_cannot_be_accepted` exercises a real Git snapshot and an out-of-hunk candidate. Deletion-only and rename-only file-level locations remain unsupported by the current candidate reconciliation contract; the safe result for an emitted but unverifiable candidate is unresolved coverage, not an accepted finding.
- Splitting an oversized multi-unit task previously risked dropping trusted base context. The planner marks allowlisted base references separately and the engine retains them as budgeted tail context while splitting. `test_trusted_context_is_retained_when_engine_splits_oversized_unit_batch` verifies both chunks receive the base-sourced profile evidence.

Snapshot capture also labels source types, treats generated patterns as review-routing evidence rather than exclusion, marks symlink/submodule and truncated changed content as required gaps, and bounds Git content reads. Required gaps enter the coverage denominator. An optional allowlisted context gap stays visible without automatically making a review incomplete.

## Contract checks

The source and acceptance tests confirm these conservative paths:

- Missing semantic providers, missing or truncated required evidence, invalid evidence references, unresolved semantic results, and unknown/stale PR-head freshness cannot produce `APPROVE`.
- Deterministic project-check tasks are skipped when no check adapter exists. A generic language-model provider is not called for them, and required check coverage remains incomplete.
- Provider calls, retries, context, output, concurrency, and wall-clock time use finite limits. Adjudication and advisory decision calls reserve from the same provider-call ceiling.
- Resume binds the request hash, validates result and event hashes, avoids repeating a completed run, and rejects changed inputs or altered persisted content.
- Trusted context is read from the base commit and is distinguished from untrusted base/head change evidence by source revision and trust class.
- Risk and required-check applicability are frozen before dispatch. An unmatched check pattern is reported as not applicable; an applicable check remains a separate required obligation.

The deterministic check adapter itself is not implemented in this pilot. Therefore configured checks remain skipped and can keep a result `INCOMPLETE`; no build, test, hook, or reviewed executable is run by the snapshot, planner, or engine.

## Verification and limits

The focused snapshot, CLI, and acceptance tests passed in the local fixture repository. Tests exercise the installed command path and temporary Git repositories; they do not use code from SlopSearX. Provider adapter tests require a local HTTP listener, which is denied by this execution sandbox, so their result must come from an environment where loopback binding is allowed. No hosted inference, external GitHub mutation, or target-repository code execution was part of this review.

A complete output-quality evaluation still needs independently adjudicated real review cases and owner-selected error, latency, and cost bounds. A successful empty specialist response, a complete coverage ledger, or a completed smoke run is advisory evidence only; it does not establish missed-blocker or false-approval rates.
