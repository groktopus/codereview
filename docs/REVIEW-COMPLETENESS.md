# Review completeness: taxonomy, summary, and regression gate

Status: active (RC-3, issue #241). Taxonomy version: `review-completeness-taxonomy.v1`.
Summary schema: `review-completeness-summary.v1`. Baseline schema:
`review-completeness-baseline.v1`.

Completeness answers one narrow question: **did every required review obligation
reach a complete, evidence-backed state?** It does not answer whether the review
found the right defects, whether findings are true, or whether a change is safe
to merge. A complete review can still miss a defect; an incomplete review is not
evidence that a change is harmless. Missing and partial obligations stay missing
and partial in every artifact and in the disposition unless a named reviewer
applies an explicit, bounded, unexpired evidence waiver (section 4). A waiver
marks the obligation `WAIVED`; it never marks it `COMPLETE` and never changes a
finding or an existing blocker.

## 1. Canonical reason taxonomy

Coverage rows keep their original `reason_code` verbatim, so existing reports and
consumers do not change. The completeness layer adds a stable
`canonical_code` classification for every incomplete obligation. The mapping is
defined once in `src/pr_review_harness/completeness.py` and exposed by
`taxonomy_document()`.

| Canonical code | Meaning | Existing strings mapped to it |
| --- | --- | --- |
| `CONTEXT_EVIDENCE_MISSING` | Required repository context could not be retrieved because the target was absent, unallowlisted, unbound, or otherwise unavailable. | `context_target_not_in_trusted_manifest`, `symbol_lookup_not_in_allowlist_contract`, `target_unit_not_in_snapshot`, `target_path_invalid`, `target_path_not_allowlisted`, `source_not_bound_by_exact_trusted_policy_path`, `evidence_not_validated_as_trusted_policy`, `source_inventory_incomplete`, `source_content_unavailable`, `validated_source_changed`, `heading_occurrence_not_found`, `binary_context_not_retrieved`, `context_target_source_identity_mismatch`, `retrieval_evidence_encoding_invalid`, `required_context_missing`, `REQUIRED_CONTEXT_MISSING`, `UNIT_OUT_OF_SCOPE` |
| `CONTEXT_EVIDENCE_TRUNCATED` | Required context was cut short by an input, output, retrieval, or IPC envelope limit, so the obligation was assessed without all of the requested evidence. | `ipc_envelope_truncated`, `retrieval_metadata_exceeds_ipc_limit`, `OUTPUT_BYTE_LIMIT_EXCEEDED`, `OUTPUT_BYTE_BUDGET_EXHAUSTED`, `INPUT_BYTE_LIMIT_EXCEEDED`, `REQUIRED_CONTEXT_OMITTED_BY_INPUT_LIMIT`, `UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT`, `UNIT_EVIDENCE_EXCEEDS_INPUT_LIMIT`, `CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED`, `section_byte_limit_exceeded`, `source_byte_limit_exceeded`, `diff_truncated`, `IPC_OUTPUT_LIMIT_EXCEEDED` |
| `CONTEXT_GAP_UNRESOLVED` | A required evidence or follow-up gap linked to the obligation remained unresolved. | `CONTEXT_GAP_UNRESOLVED` |
| `CONTEXT_NOT_COVERED` | A required-context obligation did not receive a covering static-review note. | `REQUIRED_CONTEXT_NOT_COVERED` |
| `CHECK_EVIDENCE_UNAVAILABLE` | A required project check result could not be observed from bound, complete evidence. | `CHECK_RESULT_UNAVAILABLE`, `CHECK_ADAPTER_UNAVAILABLE`, `github_check_name_not_configured`, `app_identity_not_configured`, `check_run_listing_incomplete`, `check_run_missing_or_ambiguous`, `check_run_identity_or_status_invalid`, `check_run_not_complete_or_conclusion_unknown` |
| `CHECK_EVIDENCE_INVALID` | A project check result was observed but its evidence was unbound, mismatched, or structurally invalid. | `CHECK_RESULT_EVIDENCE_INVALID` |
| `SPECIALIST_COVERAGE_PARTIAL` | The specialist reported valid static-review coverage for only part of the changed unit scope. | `PARTIAL_REVIEW_COVERAGE` |
| `COVERAGE_NOTE_MISSING` | The required coverage-note contract was absent from the specialist output. | `COVERAGE_NOTE_MISSING` |
| `COVERAGE_NOTE_INVALID` | Coverage notes were present but their evidence references or states violated the contract. | `COVERAGE_NOTE_EVIDENCE_INVALID` |
| `REQUIRED_OUTPUT_QUARANTINED` | Output needed for the obligation was quarantined as invalid or unsafe to use. | `REQUIRED_OUTPUT_QUARANTINED` |
| `PROVIDER_UNAVAILABLE` | No configured provider was available to perform the required obligation. | `PROVIDER_UNAVAILABLE`, `NOT_SUPPORTED`, `NOT_CONFIGURED` |
| `BUDGET_EXHAUSTED` | A bounded budget prevented the required obligation from running or completing. | `RUN_CONTEXT_BUDGET_EXHAUSTED`, `PROVIDER_CALL_BUDGET_EXHAUSTED`, `CONTEXT_BYTE_BUDGET_EXHAUSTED`, `CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED`, `FOLLOWUP_TASK_BUDGET_EXHAUSTED`, `MONETARY_BUDGET_EXHAUSTED`, `MONETARY_BOUND_UNAVAILABLE`, `REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED`, `REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED`, `CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE`, `CLAIM_ASSESSMENT_CAP_EXHAUSTED`, `context_budget_exhausted` |
| `DEADLINE_EXHAUSTED` | The run or call deadline expired before the required obligation completed. | `DEADLINE_EXHAUSTED`, `DEADLINE_EXCEEDED` |
| `TASK_FAILED` | A dispatch, worker, transport, or provider failure ended the required task without a usable result. | `WORKER_START_FAILED`, `WORKER_CANCELLED`, `WORKER_EXITED_WITHOUT_RESULT`, `INVALID_PROVIDER_RESULT`, `INVALID_PROVIDER_ESTIMATE`, `RESPONSE_SCHEMA_INVALID`, `INTERRUPTED_UNKNOWN`, `TIMED_OUT`, `SHADOW_DISPATCH_UNCERTAIN`, `PRIOR_SHADOW_ATTEMPT_UNSETTLED`, `PRIOR_SHADOW_RESERVATION_EXISTS`, `TRANSPORT_FAILURE`, `HTTP_ERROR_RESPONSE`, `request_exceeds_limit` |
| `CLAIM_RECONCILIATION_INCOMPLETE` | A required typed claim assessment was unavailable, invalid, mismatched, or incomplete, so reconciliation could not complete. | `PRIMARY_CANDIDATE_INVALID`, `PRIMARY_ASSESSMENT_UNAVAILABLE`, `CLAIM_ASSESSMENT_INCOMPLETE`, `PRIMARY_ASSESSMENT_BINDING_MISMATCH`, `CLAIM_ASSESSMENT_INVALID`, `CLAIM_ASSESSMENT_DIMENSION_UNAVAILABLE`, `RECONCILIATION_QUALIFIER_UNSATISFIED`, `CLAIM_ASSESSMENT_DISAGREES` |
| `MISSING_RESULT` | No result row was produced for the required obligation. | `MISSING_RESULT`, `MISSING` |
| `MISSING_REASON` | The obligation is incomplete but no reason code was recorded. | none |
| `UNCLASSIFIED_REASON` | The obligation is incomplete and the reported reason is not yet in this taxonomy version. The original string is preserved unchanged. | none |

`VALID_RESULT` and `CLAIM_ASSESSMENT_AGREES` are complete-outcome reasons and are
not part of the incomplete distribution.

An unknown string never disappears: it is preserved as
`reported_reason_code`/`legacy_codes` and counted as `UNCLASSIFIED_REASON`. That
is deliberate. Taxonomy drift is visible and gated instead of being normalized
away. Provider and contract codes have an explicit, versioned map (`PROVIDER_CODE_MAP`) plus two documented dynamic rules exposed by `taxonomy_document()`: `http_status_<3 digits>` maps to `PROVIDER_UNAVAILABLE`, and `*_exceeds_limit` maps to `BUDGET_EXHAUSTED`. No other prefix or substring heuristics apply; unmatched codes stay `UNCLASSIFIED_REASON`. Adding a new reason string requires either adding it to the table above or
accepting an explicit unclassified count in the baseline.

## 2. Machine-readable summary

Every result produced by `run_review` now contains `completeness_summary`.
Schema `review-completeness-summary.v1`:

```json
{
  "schema": "review-completeness-summary.v1",
  "taxonomy_version": "review-completeness-taxonomy.v1",
  "taxonomy_document": "docs/REVIEW-COMPLETENESS.md",
  "ledger_total": 6,
  "required_total": 5,
  "non_required": 1,
  "complete": 2,
  "partial": 2,
  "not_started": 1,
  "unknown_state": 0,
  "waived": 0,
  "not_applicable": 1,
  "waived_obligations": [],
  "incomplete_total": 3,
  "zero_obligations": false,
  "complete_ratio": 0.4,
  "resolved_ratio": 0.8,
  "reason_distribution_denominator": 3,
  "unclassified_obligations": 0,
  "reason_distribution": [
    {
      "canonical_code": "CONTEXT_EVIDENCE_TRUNCATED",
      "description": "Required context was cut short ...",
      "obligations": 1,
      "share_of_incomplete": 0.333333,
      "share_of_required": 0.2,
      "states": {"COMPLETE": 0, "PARTIAL": 1, "NOT_STARTED": 0, "UNKNOWN": 0},
      "legacy_codes": [{"code": "ipc_envelope_truncated", "obligations": 1}]
    }
  ]
}
```

Rules:

- **Denominators.** `required_total` counts coverage rows with `required: true`
  (the schema default). `complete_ratio = complete / required_total` and
  `resolved_ratio = (complete + partial + waived) / required_total`. Only
  `COMPLETE` counts toward completion; `PARTIAL` and `WAIVED` never do. A waiver
  is an explicit resolution of a named gap, not evidence that the gap was
  filled.
- **Reason denominators.** `reason_distribution_denominator` equals
  `partial + not_started + unknown_state`. Each reason item carries
  `share_of_incomplete` (relative to that denominator) and `share_of_required`.
- **Zero obligations.** A run with no required obligations is explicit:
  `zero_obligations: true`, `complete_ratio: null`, `resolved_ratio: null`,
  an empty reason distribution, and a zero denominator. It is never reported as
  100% complete.
- **Zero candidates.** Candidate absence does not remove obligations. A run that
  produces no findings still reports every required obligation in the
  denominator, so a zero-candidate run cannot look complete by shrinking the
  denominator.
- **Non-required and not-applicable.** Non-required ledger rows and
  `not_applicable` obligations are reported separately and excluded from the
  completion denominator.
- **Unknown state.** A malformed state is counted as `unknown_state`, included
  in the incomplete denominator, and never promoted to complete.
- **Waived state.** `WAIVED` is a distinct state, not a reason. Waived required
  rows are excluded from `incomplete_total` and the reason distribution, but
  remain in `required_total`, are counted in `waived`, and are listed in
  `waived_obligations` with the waiver id, reviewer, reason, expiry, target,
  and original state/reason. `coverage_state` is `COMPLETE` only when every
  required row is `COMPLETE` or `WAIVED`. When at least one required row is
  `WAIVED`, that state is `COMPLETE_WITH_WAIVERS`, not `COMPLETE`; it still
  follows findings, freshness, policy validity, budget breaches, and unresolved
  findings, and the reducer caps a waived review at `COMMENT` (an existing
  blocker still returns `REQUEST_CHANGES`).

The advisory report renders one concise completeness line under `Coverage`,
including counts, denominator, incomplete reasons, taxonomy version, and a link
to this document. It does not add or reorder the four required report sections
(`Blockers`, `Suggested improvements`, `Specific strengths`,
`Future guidance`) and does not change disposition.

## 3. Baseline and CI regression gate

`scripts/check_completeness.py` compares one or more stored result JSON files
against a baseline and exits non-zero on regression.

```bash
# Emit the summary for a stored result (no baseline required to write one)
python scripts/check_completeness.py --result artifacts/run.json --summary-only --json

# Gate one result against the checked-in baseline
python scripts/check_completeness.py \
  --baseline tests/fixtures/completeness/baseline.v1.json \
  --result artifacts/run.json

# Rebuild a baseline from a stored corpus of results
python scripts/check_completeness.py \
  --write-baseline artifacts/completeness-baseline.v1.json \
  --results-dir artifacts/review-results \
  --corpus-name frozen-natural-corpus \
  --min-completion-ratio 0.90
```

The gate recomputes the summary from `coverage_ledger` rather than trusting an
embedded summary. If an embedded `completeness_summary` disagrees with the
ledger, the gate fails with `SUMMARY_INCONSISTENT` (counts, ratios, zero-obligation flag, and totals).

A result fails the gate when any of these hold:

| Finding | Trigger |
| --- | --- |
| `KNOWN_COMPLETE_REGRESSION` | A baseline obligation was `COMPLETE` and is now partial/not-started (for example a known-complete case regresses to `ipc_envelope_truncated`). |
| `COMPLETION_RATIO_REGRESSION` | `complete_ratio` drops by more than `max_completion_drop` (default `0.0`). |
| `BELOW_MIN_COMPLETION_RATIO` | `complete_ratio` is below the owner-set absolute floor. |
| `OBLIGATION_MISSING` | A required obligation present in the baseline is absent from the result. |
| `SUMMARY_INCONSISTENT` | The embedded summary disagrees with the ledger. |
| `UNCLASSIFIED_REASON_INCREASE` | Unclassified incomplete obligations increase beyond the owner-set allowance. |
| `CASE_NOT_IN_BASELINE` | The result's case id has no baseline case. |

Thresholds are owner-set per baseline in the `thresholds` object and can be
overridden on the command line. A zero-obligation baseline is compared
explicitly: zero versus zero passes, and losing obligations to reach zero fails.

### Checked-in baseline

`tests/fixtures/completeness/baseline.v1.json` is a deterministic,
provider-free fixture baseline used by CI. It records 4 required obligations
(2 complete, 1 partial, 1 not started), one non-required row, one not-applicable
obligation, and a 0.5 completion floor. The matching
`good-result.json` passes.

`seeded-regression-result.json` changes one known-complete obligation to
`PARTIAL` with `ipc_envelope_truncated`. The CI job asserts that the gate exits
`1` on that file. This is the deliberate seeded-regression probe required by
RC-3; it proves the gate is not a no-op.

**Honest limitation:** this checked-in baseline is built from a deterministic
fixture, not from the frozen natural corpus, because no frozen-corpus result
receipts are stored in this checkout. The baseline format and the
`--write-baseline --results-dir` path are ready for that corpus; the baseline
must be regenerated from real frozen-corpus results before it is used to make a
quality or adoption judgement. This gate measures completeness only, not review
quality.

## 4. Bounded evidence waiver

`review --waiver FILE` accepts a strict `review-evidence-waiver.v1` JSON object.
No waiver is the default and leaves the behavior above unchanged. A waiver is
bound to one exact repository and 40-hex base/head pair, a named reviewer, a
written reason, an issue time, and an expiry. It must contain at least one
explicit target and cannot contain duplicate or overbroad targets. A target is
either:

- `id`: the exact planned coverage obligation id (for `check`, its exact check
  binding or check id is also accepted), or
- `reason_code`: an exact reason code that classifies into that target kind's
  family and matches exactly one required incomplete obligation. A multi-row
  reason-code match is rejected as overbroad.

Target kinds are `context_gap`, `check`, and `coverage_note`. `context_gap`
covers rows whose canonical reason is `CONTEXT_GAP_UNRESOLVED`; `check` covers
`CHECK_EVIDENCE_UNAVAILABLE`/`CHECK_EVIDENCE_INVALID`; `coverage_note` covers
`COVERAGE_NOTE_MISSING`, `COVERAGE_NOTE_INVALID`, `SPECIALIST_COVERAGE_PARTIAL`,
and `CONTEXT_NOT_COVERED`. A reason code outside its kind's family, a wildcard,
both `id` and `reason_code`, or an empty identifier is rejected. A reason code
that would match more than one incomplete obligation is rejected, so a waiver
never silently clears a 1:N set of gaps.

The file is loaded and validated before provider dispatch. `issued_at` cannot
be in the future, and the lifetime is capped at 90 days. An invalid, expired,
out-of-scope, duplicate, or unknown-target waiver raises
`review_waiver_rejected` (CLI exit `2`) and writes no result. If a valid waiver
expires during a long run, it is reported as `EXPIRED_AT_USE` in
`waivers_not_applied` and is not honored. The exact schema is
[`schemas/review-evidence-waiver.v1.schema.json`](../schemas/review-evidence-waiver.v1.schema.json).

A waived row in `coverage_ledger` keeps `state: "WAIVED"`, the original state and
reason in `waived_from_state`/`waived_from_reason_code`, and a `waiver` object
with the waiver id, reviewer, reason, justification, expiry, target, and source
file SHA-256. The result also carries `waiver_receipt`, `waivers_applied`, and
`waivers_not_applied`. The rendered report prints `Coverage:
COMPLETE_WITH_WAIVERS`, the waived count, and one line per waived obligation.
The deterministic reducer caps a waived review at `COMMENT`; findings still win,
so an accepted blocker still yields `REQUEST_CHANGES`.

## 5. Wiring and tests

- Taxonomy, summary, baseline, and comparison live in
  `src/pr_review_harness/completeness.py`.
- `review_stages.build_and_persist_result` emits the summary into every result.
- `report.render_report` renders the completeness line and falls back to
  computing the summary for older stored results that predate the field.
- `scripts/check_completeness.py` is the provider-free CLI/CI entry point.
- CI runs the gate in `.github/workflows/test.yml` (`completeness-gate` job),
  uploads the JSON verdict, and requires the seeded regression to fail.
- `tests/test_completeness.py` covers counts and denominators, zero
  obligations, reason mapping and unknown fallback, report section presence,
  comparison pass/fail, stale-summary rejection, CLI exit codes, and
  disposition preservation.
- `tests/test_waiver.py` covers valid exact-gap resolution, default deny,
  wrong head/repository, expired-at-load and expired-at-use, future `issued_at`,
  the 90-day TTL, unknown target before provider dispatch,
  duplicate/overbroad targets, schema validation, 1:N reason-code rejection,
  resume waiver-binding mismatches, visibility in the result/summary/report,
  and blocker preservation.



Gate finding `PARTIAL_OBLIGATION_REGRESSION` fires when a baseline `PARTIAL` obligation becomes `NOT_STARTED` or `UNKNOWN` (normalized state). `KNOWN_COMPLETE_REGRESSION` also catches a baseline `COMPLETE` obligation that becomes `WAIVED`, so a waiver cannot silently replace previously complete evidence. Case identity is `case_id`, then top-level `snapshot_id`, then `run_id`; corpus runs should set a stable `case_id`. Baseline schema/taxonomy version must match the current constants.
