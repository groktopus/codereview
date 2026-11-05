# 0001 — Post-CA-2 feature budget

- **Status:** Accepted
- **Date:** 2026-11-01
- **Owner:** Repository owner (`@magnus919`; `.github/CODEOWNERS`).
- **Decision authority:** Repository owner (explicit approval in the coordinating session)
- **Scope:** Integrated source-line guard for `src/pr_review_harness/` after CA-2
- **Evidence:** Merged pull request [#291](https://github.com/groktopus/codereview/pull/291); commits `be9556c` and `c026176`; [public-surface.json](../public-surface.json); [test_surface_consolidation.py](../../tests/test_surface_consolidation.py).
- **Reversal/expiry:** One-time for the CA-2 migration period. Further source growth requires a new decision record or real reduction elsewhere; it does not renew this budget automatically.
- **Supersedes:** None. **Superseded by:** None.
- **Related:** [ADR 0002](0002-production-architecture.md) records the consolidated production surface this budget guards.

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

i.e. 31,014 lines at this budget before the VD-4 formatter addendum below. Every source addition must update the recorded
measurement; the test asserts the live count and reduction match the manifest.
Unused budget is not permission to grow without review.

## VD-4 formatter normalization addendum (2026-11-03)

VD-4 adopts `ruff format` at the existing 120-column line length as the
canonical formatter. Formatting is behavior-preserving but changes physical line
counts: wrapping long signatures and calls took `src/pr_review_harness` from
30,870 to 31,725 lines (+855). The source-line guard measures physical lines, so
leaving the manifest at the pre-format count would fail CI for a whitespace-only
change.

The recorded measurement is therefore re-baselined to 31,725 lines
(−22.02%, still short of the one-time 25% outcome). The owner approved a
one-time formatting allowance of up to 900 lines; because the measured delta is
exactly 855 lines, the manifest records
`formatting_normalization_allowance_lines: 855` as a **one-time formatter
allowance, not feature headroom**. The 500-line feature budget is unchanged and
remains a separate allowance. The gate becomes:

```
current_src_lines <= base_src_lines * (1 - required_reduction)
                     + feature_budget + formatting_normalization_allowance
```

i.e. 31,869 lines. After normalization, 144 physical lines remain against that
ceiling; the unused feature budget was also 144 lines before formatting and is
not renewed or enlarged by this addendum. Further feature growth still requires
a new decision record or real reduction elsewhere.

This addendum records a measurement change required by VD-4. The owner approved
the one-time formatting allowance and the observation-revision refresh; the
allowance does not relabel the CA-2 result.

### Bounded-evidence-waiver feature allowance (2026-11-04)

The owner-approved bounded evidence waiver in [ADR 0011](0011-bounded-evidence-waiver.md)
adds a new strict waiver contract, preflight/application logic, result receipts,
completeness state, report rendering, publisher acceptance, and tests. It adds
**708 physical source lines** after review fixes, taking the measured tree from
31,725 to 32,433 lines (−20.28%). The owner approved a one-time **565-line
allowance**; 143 of the 144 prior-headroom lines were also used. The new
measurement exceeds the prior 31,869 ceiling by 564 lines.

Because ADR 0001 requires a new decision record for further growth, ADR 0011
records a separate, one-time `waiver_feature_allowance_lines: 565` in
`docs/public-surface.json`. It is scoped to this feature, is not a renewal or
increase of the 500-line general feature budget, and does not relabel the CA-2
result. The gate becomes:

```
current_src_lines <= base_src_lines * (1 - required_reduction)
                     + feature_budget
                     + formatting_normalization_allowance
                     + waiver_feature_allowance
```

i.e. 32,434 lines. The recorded measurement is updated to the honest live count
(32,433), and `tests/test_surface_consolidation.py` checks all four terms. One
line remains under that one-time ceiling; unrelated growth requires a new
decision or real reduction.

### Observation revision refresh

The formatting commit is behavior-preserving, but it rewrites physical bytes in
three files that `docs/STATUS.md` names as freshness sources. The checked-in
owner handoff manifest (`scripts/documentation-truth-evidence.v1.json`) therefore
records its evidence revision as the formatting commit, while `docs/STATUS.md`
keeps its 2026-11-01 review date and prose. The generated
`docs/STATUS-EVIDENCE.md` reports the handoff verdict rather than asserting a new
owner review. The handoff manifest is no longer listed among the derived page's
own freshness sources because this evidence refresh changes it in the same
commit; the documentation-truth job checks its freshness directly.

## Consequences

- OE-2 can ship without deleting working code or falsifying the CA-2 result.
- The original 25% outcome remains recorded and is not relabeled as met.
- Headroom is nearly exhausted (32,433 lines against the 32,434
  effective ceiling after the bounded-waiver allowance); further features
  require a new decision record or real reduction elsewhere.
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
