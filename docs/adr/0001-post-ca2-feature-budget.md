# 0001 — Post-CA-2 feature budget

- **Status:** Accepted
- **Date:** 2026-11-01
- **Decision authority:** Repository owner (explicit approval in the coordinating session)
- **Scope:** Integrated source-line guard for `src/pr_review_harness/` after CA-2

## Context

CA-2's exit criterion was a one-time `≥25%` reduction against the `7d550b6`
baseline (40,686 lines), met at 30,030 lines (−26.19%). Feature work after CA-2
adds code. OE-2 adds an operator cost model, taking the package to 30,870 lines
(−24.13%), below the one-time 25% ratio even though the original reduction is
preserved.

## Decision

Keep `required_reduction: 0.25` as the CA-2 outcome and add an explicit
`post_ca2_feature_budget_lines: 500` to `docs/public-surface.json`. The gate is:

```
current_src_lines <= base_src_lines * (1 - required_reduction) + feature_budget
```

i.e. 31,014 lines at this budget. Every source addition must update the recorded
measurement; the test asserts the live count and reduction match the manifest.
Unused budget is not permission to grow without review.

## Consequences

- OE-2 can ship without deleting working code or falsifying the CA-2 result.
- The original 25% outcome remains recorded and is not relabeled as met.
- Remaining headroom is visible (144 lines at 30,870); further features require
  a new decision record or real reduction elsewhere.
- The budget is one-time for this migration period, not a permanent growth
  allowance.

## Confirmation

`tests/test_surface_consolidation.py` checks the manifest measurements, the
ceiling, and the one-orchestrator/public-surface invariants in CI.

## Alternatives considered

- Shred/delete working code to keep 25%: rejected as quality-negative.
- Lower `required_reduction` to 0.24: rejected because it rewrites the CA-2
  acceptance result instead of recording a bounded exception.
- Defer OE-2: rejected by the owner; the cost feature is wanted now.
