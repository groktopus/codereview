# Context-followup v3 live run 36360197573

This record describes one hosted three-case run. It records transport, handoff, and coverage observations; it is not a finding-quality verdict, model comparison, causal estimate, or production-adoption decision. No human labels or independently validated quality labels are present in this evidence.

## Source, plan, and artifact identity

Hosted run [`36360197573`](https://github.com/groktopus/codereview/actions/runs/36360197573) reports `PROCESS_COMPLETED` on source/runner revision `890349511756ec60b87dc1ab5c96fc9935528d13` (`origin/main` at the recorded revision). The runtime was revision `7c89ad17327b8f0ed4fc381bf5c93255fd4e548e`, with 28 installed modules matching source and module-tree SHA-256 `c5b7c4e43aeddfad55bbcfdcb9e07c4a89fd0b6a3a263a31f046c8852dd8838a`; runtime wheel SHA-256 was `033a6a3002b0020af223da6e99d46339c5fdc3da2aadc185b6ce68eeac2a0f0d`.

The selector was `specialist-input-v2-context-followup-v3`. The frozen v3 plan manifest SHA-256 was `fccc745fade50066d12a2173af987b13d548ac214861f8e99b3a8d3078694857`. The fixed-case manifest SHA-256 and baseline plan SHA-256 were both `b8958c589fc49d7beeb4e3b5530c0c99d385bd40cee8b124cdf395090a0c3322`; the primary parent plan SHA-256 was `65faf40b36fd065a6e7b943d8150ac64c9b707c3bf8ba106aca445d385ff40fb`.

The downloaded sanitized run artifact contains `manifest.json` (272,387 bytes; SHA-256 `43fb6154319c0bb30f28d2353adab2e3016c1844abee2068e69f1621d4d0904b`) and `summary.json` (3,010 bytes; SHA-256 `aa96be6d19f1d073635fbd2168d1644972551f117258eb8573ef6eeff0901a53`). The summary schema is `historical-real-case-trial-manifest.context-followup.v3`. Only hashes and finite structured results are recorded here; raw source, prompts, model responses, candidate prose, and credentials are omitted.

The artifact says the 47 frozen primary requests, 124 required obligations, and 4,002,927 serialized primary-input bytes matched the v2 primary descriptors (`MATCHED_ALL_FROZEN_V2_PRIMARY_DESCRIPTORS`). This is input identity evidence, not evidence that every planned request reached or was consumed by a remote model.

## Case results

All three case processes completed, but each projection remained `PARTIAL` and each deterministic reducer disposition was `INCOMPLETE`:

| Case | Frozen scopes | Coverage rows complete / partial | Candidate records | Reducer disposition | Projection coverage |
|---|---:|---:|---:|---|---|
| PR-457 | 30 | 23 / 9 | 1 | `INCOMPLETE` | `PARTIAL` |
| PR-463 | 72 | 24 / 52 | 0 | `INCOMPLETE` | `PARTIAL` |
| PR-464 | 22 | 6 / 21 | 0 | `INCOMPLETE` | `PARTIAL` |
| **Total** | **124** | **53 / 82** | **1** | — | — |

The 135 coverage rows comprise the 124 planned obligations plus 11 dynamic follow-up obligations. The one PR-457 candidate is structurally `NEEDS_CONTEXT` with reconciliation `NEEDS_EVIDENCE`; its semantic assessment is `UNKNOWN` and claim assessment is `NOT_RUN` (`PRIMARY_CANDIDATE_INVALID`). These are pipeline states, not judgments about whether the candidate is correct. No candidate was emitted for PR-463 or PR-464.

## Follow-up handoff and closure

The artifact projects 11 follow-up rows: two for PR-457, four for PR-463, and five for PR-464. Every row records a `VERIFIED` retrieved-evidence handoff, persisted retrieval IDs matching, persisted obligation/gap-task/metadata/unit records matching, valid metadata contract, adapter HTTP 200, one reservation with one `SUCCEEDED` settlement, and 64-character adapter request and response hashes. This establishes the recorded local adapter exchange and evidence handoff for those 11 rows only.

| Case | Follow-up rows | Handoff verified | Adapter HTTP 200 | Successful settlements | Coverage-ledger outcome for follow-up obligations |
|---|---:|---:|---:|---:|---|
| PR-457 | 2 | 2 | 2 | 2 | 2 `PARTIAL` / `REQUIRED_CONTEXT_NOT_COVERED` |
| PR-463 | 4 | 4 | 4 | 4 | 1 `PARTIAL` / `CONTEXT_GAP_UNRESOLVED`; 3 `PARTIAL` / `REQUIRED_CONTEXT_NOT_COVERED` |
| PR-464 | 5 | 5 | 5 | 5 | 5 `PARTIAL` / `REQUIRED_CONTEXT_NOT_COVERED` |
| **Total** | **11** | **11** | **11** | **11** | **11 partial** |

All 11 closure diagnostic records report `NO_COVERING_NOTE`; their examined coverage notes fail the `STATE_NOT_COVERED` predicate (12 notes total, because one follow-up examined two notes). This explains the missing closure evidence at the recorded validator level. It does not show that evidence retrieval itself failed: all 11 rows report retrieval `RESOLVED` and task `SUCCEEDED`.

The manifest reports `provider_calls: UNKNOWN`, `cost: UNKNOWN`, provider execution state `UNKNOWN_UNLESS_REPORTED_BY_PROVIDER`, per-row actual provider calls `UNKNOWN`, and delivery binding `UNKNOWN`. Reservation settlement and local HTTP success do not prove remote model consumption, billed calls, cost, or external review delivery. Publication was disabled, target-code execution was false, and current PR state was not checked.

## Interpretation and limit

This run verifies frozen-input identity and finite local transport/handoff observations. It does not supply human-labeled quality evidence, a prediction-blind teacher-label set, reciprocal LLM/zero-shot adjudication, held-out error or abstention analysis, calibration, or an independently validated acceptance threshold. Therefore it supports no model-quality, Droid-replacement, or production-readiness claim. The three deterministic outcomes remain incomplete; this record should remain a historical experiment entry in the failure/experiment ledger.
