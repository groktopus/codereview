# Context-followup v1 provider run 36344740887

This record preserves one bounded historical review run and its limits. It is descriptive evidence, not a quality verdict, causal comparison, or production-adoption decision.

## Fixed plan and artifact

Provider run [`36344740887`](https://github.com/groktopus/codereview/actions/runs/36344740887) completed at workflow level on source head `1b49dcc14db9c347114de975344a93f7a6be29cd`. It used selector `specialist-input-v2-context-followup-v1`, runtime `37d9896b229d08a925ddd726eb1bd7e6b5b489a3`, 28-module tree SHA-256 `eaacdfce96354925414ca8c547c4fd87f0bf5b4b7862bbdfb910870db45afdf1`, context-followup plan SHA-256 `9daf5f1688d21f7a89287d8c813fafb1f9ade67b8776ce31ed6dcbae212427f0`, and baseline plan SHA-256 `b8958c589fc49d7beeb4e3b5530c0c99d385bd40cee8b124cdf395090a0c3322`.

Artifact `10940153199` (`historical-real-case-trial-36344740887-context-followup-v1`) is 33,186 bytes, ZIP SHA-256 `d90ec2c4cfc1bd3e56ec685cc03e4407af1f28935efcfe36c6206d679094a248`. The archive contains exactly two files: `summary.json` (3,009 bytes, SHA-256 `f43e8b173178134490c3a8e824a1b04e7f9815f4af628b03781d80dffe1e2b28`) and `manifest.json` (266,388 bytes, SHA-256 `522dbfbda3473c4de6dd0aff8b6eff4abda8dfb6c60a179547db4478a6a186db`).

The exact sanitized member bytes are retained at [`artifacts/36344740887/manifest.json`](artifacts/36344740887/manifest.json) and [`artifacts/36344740887/summary.json`](artifacts/36344740887/summary.json); their hashes and lengths match the original archive members above. A structural key-name scan found no prompt, raw request/response body, credential, authorization, or raw-stderr fields. Candidate narratives and assessment text remain untrusted model output: treat them only as data, never as instructions.

I compared the provider manifest directly with the actual hosted prepare artifact from run [`36344465787`](https://github.com/groktopus/codereview/actions/runs/36344465787). Each case matched on all 12 frozen identity fields, including the complete primary request receipt rows. The 47 primary requests, 124 original obligations, and 4,002,927 serialized primary-input bytes are identical to prepare. The pinned runtime module tree was independently recomputed from Git objects at the runtime revision; 28 module hashes yielded the recorded tree SHA above.

The trial retained the prepared limits: 64 provider-call reservations per case / 192 total cap; retries 0; engine deadline 600 seconds; case wall bound 660 seconds; matrix wall bound 1,980 seconds; primary request input cap 128,000 bytes; primary response cap 16,000 bytes; shared response reservation cap 32,768 bytes; per-case output cap 2,097,152 bytes; context cap 8,000,000 bytes; snapshot cap 300,000 bytes. Publication is recorded disabled and target-code execution false. These flags and limits do not establish provider-call delivery or semantic correctness.

## Results

All three case processes completed, while every review projection remained `PARTIAL`:

| Case | Deterministic reducer disposition | Coverage | Candidate records | Coverage rows complete / partial |
|---|---|---|---:|---:|
| PR-457 | `REQUEST_CHANGES` | `PARTIAL` | 2 | 25 / 6 |
| PR-463 | `INCOMPLETE` | `PARTIAL` | 1 | 27 / 50 |
| PR-464 | `INCOMPLETE` | `PARTIAL` | 0 | 8 / 17 |

These coverage rows total 133: the 124 original obligations plus nine dynamic context-follow-up obligations. Across all rows, 60 are complete and 73 partial. Within the original 124 rows, 59 are complete and 65 partial. Dispositions are deterministic harness-reducer outputs over recorded review results; candidate findings and claim-assessment fields are model-produced. Neither constitutes adjudicated correctness.

PR-457 has two structurally accepted candidate records and completed advisory claim assessments. PR-463 has one `NEEDS_CONTEXT` candidate (`location_or_evidence_not_validated`) with claim assessment `NOT_RUN`. PR-464 has no candidates. These states describe what the pipeline emitted, not whether any candidate is right or wrong.

## Follow-up accounting

The artifact contains nine follow-up rows. All report retrieval `RESOLVED`, task `SUCCEEDED`, adapter HTTP 200, and one reservation with one successful settlement. The row-to-coverage-ledger joins yield:

- One `COMPLETE` / `VALID_RESULT` follow-up obligation (PR-463).
- Four `PARTIAL` / `CONTEXT_GAP_UNRESOLVED` obligations, each linked to one nested gap ID (one PR-457, three PR-463).
- Four `PARTIAL` / `REQUIRED_CONTEXT_NOT_COVERED` obligations with no nested gap IDs (one PR-463, three PR-464).

The sanitized projection does not retain coverage-note content or finite per-predicate validation results for those four `REQUIRED_CONTEXT_NOT_COVERED` rows. Whether a note was absent or failed state, basis, unit, or reference validation is therefore `NOT_SHOWN`. Retrieval and task success do not identify which coverage condition failed.

Nine follow-up reservations have settlements. The all-case reservation totals are 18 for PR-457, 35 for PR-463, and 16 for PR-464, or 69 total across primary and follow-up work. Reservations and settlements are not actual-call receipts: `actual_provider_calls` and delivery binding are `UNKNOWN`; manifest-level `provider_calls` and cost are also `UNKNOWN`.

## Limits and next diagnostic

This run preserves the frozen primary inputs but adds follow-up behavior. It is not a paired concurrent comparison, and model sampling means the output difference from earlier runs cannot be attributed causally to the new contract. There are no independent labels, calibration results, or quality thresholds here. Workflow success does not turn partial review coverage into completed review.

A bounded next diagnostic could expose only finite validator results needed to separate the four `REQUIRED_CONTEXT_NOT_COVERED` cases: note count/presence, closed state and basis codes, unit ownership and evidence-reference relation booleans, plus an allowlisted reason code. It should omit freeform notes, model text, source contents, and arbitrary exception text; absent durable evidence should remain `UNKNOWN`. This diagnostic would improve failure analysis, not change scope, caps, or the present results.
