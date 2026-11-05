# 0011 — Bounded, expiring evidence waivers

- **Status:** Accepted
- **Date:** 2026-11-04
- **Owner:** @magnus919
- **Decision authority:** Repository owner, exercised through the direct implementation instruction of 2026-11-04 ("owner-approved bounded evidence waiver ... allow a named reviewer to waive specific missing-evidence obligations, default deny, auditable, scoped, expiring. Do not blanket-ignore missing evidence."); [AGENTS.md](../../AGENTS.md) records the standing user authority.
- **Scope:** The `review` CLI's `--waiver FILE` input, the `review-evidence-waiver.v1` contract, its preflight validation, the `WAIVED` coverage state, completeness-summary and result receipts, report rendering, publisher acceptance of sealed waived results, and the corresponding docs/tests.
- **Evidence:** `src/pr_review_harness/waiver.py`; `src/pr_review_harness/review_stages.py`; `src/pr_review_harness/completeness.py`; `src/pr_review_harness/report.py`; `src/pr_review_harness/publisher.py`; [`schemas/review-evidence-waiver.v1.schema.json`](../../schemas/review-evidence-waiver.v1.schema.json); `tests/test_waiver.py`; `tests/test_completeness.py`.
- **Reversal/expiry:** Supersede if the owner removes waiver authority, if a waiver is used to hide a finding or an existing blocker, if the scope/expiry checks cannot be enforced before provider dispatch, or if the receipt cannot be audited from the sealed result. The decision is reviewable before any release or replacement claim.

## Context

The review controller deliberately fails closed: a required obligation that
cannot be backed by complete evidence remains `PARTIAL`/`NOT_STARTED` and the
review stays `INCOMPLETE`. Some evidence sources are genuinely unavailable
outside the review boundary (for example an external check that cannot be
observed, or a repository-controlled context source that is not retrievable
from immutable objects). There was no explicit, auditable way for a named
reviewer to accept one such gap without weakening the default.

A blanket "ignore missing evidence" switch would be unsafe: it could remove
obligations, hide findings, or convert an existing blocker into an approval.
That is not authorized.

## Decision

Adopt a bounded, expiring waiver that is **deny by default**.

### Input contract

`review --waiver FILE` is available on the `review` command only. The file is a
strict `review-evidence-waiver.v1` JSON object with no unknown fields:

```json
{
  "schema": "review-evidence-waiver.v1",
  "reviewer": "named-reviewer",
  "reason": "Owner-approved exception for a specific unavailable source.",
  "repository": "owner/repository",
  "base_sha": "0123456789abcdef0123456789abcdef01234567",
  "head_sha": "89abcdef0123456789abcdef0123456789abcdef",
  "issued_at": "2026-11-04T12:00:00Z",
  "expires_at": "2026-11-05T12:00:00Z",
  "waivers": [
    {
      "kind": "coverage_note",
      "id": "unit:unit-...:lens:correctness",
      "justification": "The exact named source is unavailable outside this boundary."
    }
  ]
}
```

The schema file is authoritative. The loader additionally enforces:

- `reviewer` is non-empty; `reason` is at least 20 characters; every
  justification is at least 10 characters.
- `repository` matches the snapshot repository exactly.
- `base_sha` and `head_sha` are exact 40-character lowercase hex and match the
  snapshot revisions exactly.
- `issued_at`/`expires_at` are timezone-aware, `issued_at <= now` when loaded,
  `expires_at > issued_at`, `expires_at > now` when loaded and again when
  applied, and the lifetime is at most 90 days.
- At least one and at most 64 targets; duplicate targets are rejected.
- Each target has exactly one of `id` or `reason_code`. Supplying both is
  rejected as overbroad; wildcards and empty identifiers are rejected. Every
  target is resolved during preflight to required planned obligation ids:
  `id` uses the exact obligation id plus any matching `check_binding_id`/
  `check_id` aliases; `reason_code` uses the required planned obligations whose
  kind is compatible with that target kind. Exactly one planned obligation must
  match, otherwise the target is rejected as unknown or ambiguous. At
  application the reason target must still match that obligation’s exact
  canonical reason.
- Any two targets that resolve to the same planned obligation are rejected as
  overlapping during preflight, including an `id` plus a `reason_code` and two
  reason targets. Overlap is never resolved by applying whichever target is
  encountered first.
- Target kinds are `context_gap`, `check`, and `coverage_note`. A reason code
  must classify into that kind's exact reason family.
- An `id` target must name a required planned obligation (or, for `check`, its
  exact check binding/check id). Unknown, non-required, or wrong-kind targets
  are rejected before provider dispatch.

### Runtime semantics

- Only required coverage rows in `PARTIAL`, `NOT_STARTED`, or `UNKNOWN` can be
  waived. Optional rows and already-complete rows are never rewritten.
- An applied row becomes `WAIVED`, never `COMPLETE`. Its original state and
  reason are retained in `waived_from_state` and `waived_from_reason_code`, and
  the row carries the waiver id, reviewer, reason, justification, expiry, target,
  and source file SHA-256.
- A reason-code target applies only to the single row whose exact canonical
  reason is in that target kind's family. More than one match is an error. ID
  targets are exact to one obligation.
- No waiver changes `findings`, a finding's status or blocking class, the
  deterministic reducer, freshness, policy validity, budget breaches, or
  unresolved findings. An existing accepted blocker still produces
  `REQUEST_CHANGES`.
- `coverage_state` is `COMPLETE` only when every required obligation is
  `COMPLETE`; it is `COMPLETE_WITH_WAIVERS` when every required obligation is
  `COMPLETE` or `WAIVED` and at least one is `WAIVED`. Waivers are recorded as a
  non-zero `waived` count and listed in
  `completeness_summary.waived_obligations`; `complete_ratio` still counts only
  `COMPLETE`, so a waiver cannot be reported as complete evidence.
  `resolved_ratio` includes `WAIVED` because the obligation is explicitly
  resolved by the named waiver. The deterministic reducer caps a waived review
  at `COMMENT`; an existing accepted blocker still returns `REQUEST_CHANGES`.
- The result carries `waiver_receipt`, `waivers_applied`, and
  `waivers_not_applied`. A waiver that expires during a long run is reported as
  `EXPIRED_AT_USE` and is not applied; the obligation stays incomplete.
- Resume is allowed only when the same waiver presence and source digest are
  supplied. A changed presence or digest is rejected as
  `resume_state_invalid`; a resumed result is never silently re-interpreted
  under a new waiver.

### Failure behavior

An invalid schema, missing field, non-empty violation, mismatched
repository/revision, expired waiver, duplicate/overbroad target, or unknown
planned target is an `EnginePreflightError("review_waiver_rejected")`. The CLI
exits `2` before provider dispatch and writes no result. With no `--waiver`,
behavior is unchanged: missing evidence remains incomplete.

## Source-line budget consequence

This feature adds 709 physical source lines after review fixes: the strict waiver
loader/validator/applier and receipt builder, plus integration in review
preflight, coverage reduction, completeness, metrics, report, publisher, CLI,
and typed records. The measured `src/pr_review_harness` tree is 32,434 lines
(−20.28% against the 40,686 CA-2 base). The prior ceiling was 31,869 lines, so
565 lines must be explicitly allowed; the owner approved a one-time 565-line
allowance, with the other 144 lines coming from the prior headroom and no further
headroom remaining.

[ADR 0001](0001-post-ca2-feature-budget.md) permits further growth only through a
new decision record. This record therefore adds a separate, one-time
`waiver_feature_allowance_lines: 565` to `docs/public-surface.json`; the test
gate includes that term and records the honest live measurement. This allowance
is scoped to the bounded-waiver feature, does not renew the 500-line general
feature budget, and is not available for unrelated growth. The resulting
one-time ceiling is 32,434 lines, with no further headroom.

## Consequences

- A reviewer can resolve one exact missing-evidence gap without weakening the
  broader coverage contract, and the exception is visible in the result,
  completeness summary, and rendered report.
- Waivers are deliberately inconvenient: exact revisions, exact repository,
  exact target, named reviewer, written reason, issue/expiry, and a source
  hash. This is the intended safety/cost tradeoff.
- A waived obligation is not evidence. `waived > 0` is an explicit annotation,
  not a quality signal, and the run still says `complete_ratio = 0` when every
  obligation was waived. Such a run is `coverage_state:
  COMPLETE_WITH_WAIVERS` and cannot use `APPROVE`; the reducer caps it at
  `COMMENT`.
- The publisher accepts sealed `WAIVED` rows only after revalidating the
  receipt schema, source SHA-256, counts, reviewer/reason/expiry/repository/
  revision identity, and the exact row-to-applied-record mapping, including the target and justification.
  Fabricated rows or targets, missing/extra/duplicate records, and mismatched
  counts are rejected even when the result has been rehashed. It still rejects inconsistent coverage
  state, stale freshness, and non-current dispositions.
- The completeness regression gate treats a baseline `COMPLETE` obligation that
  becomes `WAIVED` as a regression (`KNOWN_COMPLETE_REGRESSION`), so a waiver
  cannot silently replace previously complete evidence.

## Alternatives considered

- **Global "ignore missing evidence" flag.** Rejected: it is a blanket
  weakening, can hide findings, and cannot be scoped or audited.
- **Mark waived obligations `COMPLETE`.** Rejected: it would falsify the
  completeness denominator and make `complete_ratio` lie.
- **Waive an entire obligation kind or every occurrence of a reason without a
  named target.** Rejected: reason-code targets are still constrained to one
  exact kind family and required incomplete rows, and ID targets are exact.
- **Use an environment variable or profile setting.** Rejected: those are
  durable policy surfaces that cannot bind a named reviewer, a reason, and an
  expiry to one base/head pair.
- **Apply waivers after disposition.** Rejected: coverage and the sealed result
  would diverge. Waivers are applied while coverage is reduced, before the
  deterministic disposition is computed.

## Confirmation

`PYTHONPATH=src python3 -m pytest -q tests/test_waiver.py tests/test_completeness.py tests/test_completeness_cli.py tests/test_publisher.py tests/test_run_metrics.py`
exercises valid exact-gap resolution, default deny, wrong head/repository,
expired-at-load and expired-at-use, unknown targets before provider dispatch,
duplicate/overbroad targets, reason-code scoping, visible `WAIVED` rows, the
SUMMARY/report/result receipts, and preservation of findings and blockers.
`tests/test_surface_consolidation.py` verifies the recorded source measurement,
the 565-line waiver-feature allowance, and the resulting ceiling.
Schema validation uses `Draft202012Validator`, including both the exact-`id` and
`reason_code` target shapes. `scripts/check_decision_records.py` validates this
record and its index row.
