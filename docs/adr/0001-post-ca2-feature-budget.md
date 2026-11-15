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
**709 physical source lines** after review fixes, taking the measured tree from
31,725 to 32,434 lines (−20.28%). The owner approved a one-time **565-line
allowance**; all 144 prior-headroom lines were also used. The new measurement
exceeds the prior 31,869 ceiling by 565 lines.

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
(32,434), and `tests/test_surface_consolidation.py` checks all four terms. No
headroom remains under that one-time ceiling; unrelated growth requires a new
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
- No headroom remains (32,434 lines against the 32,434
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


## Addendum: RC-2 retrieval compiler allowance (2026-11-06)

The owner authorized the quality-preserving choice for RC-2. The measured
decomposition of the **229** net source lines is: `retrieval_plan.py` 316 lines,
stage/state integration 9 lines, a 3-line current-side anchor/source-window
correction, and 69 replacement/import lines from the consolidation pass, minus
168 removed or replaced lines (dead functions,
duplicate `_canonical` helpers, duplicate writer-pin validation, and a shared
unified-diff range parser). A one-time
`rc2_retrieval_compiler_allowance_lines: 229` is recorded in
`docs/public-surface.json`; the effective ceiling is
`base*(1-required)+feature budget+formatting+waiver+execution-failure+execution-reason+RC-2`.
The slice is measured at exactly 32781 lines, so the allowance is fully
consumed. This is feature headroom for the compiler slice, not a renewal of the
500-line budget.

## Addendum: canonical compatibility resource (2026-11-15)

The user directed the coordinating root to work through the remaining roadmap
and merge verified source pull requests, with root responsible for contract
decisions. Under that implementation authority, root selects a single installed
compatibility-pin resource and a shared standard-library loader for VD-3. This
is a root implementation decision under that directive, not a separately
recorded owner approval of a numeric allowance.

The loader replaces duplicated test/script validation and makes the same
provenance authority available to installed runtime consumers without importing
tests. Its measured source cost is recorded as
`compatibility_manifest_allowance_lines` in [public-surface.json](../public-surface.json).
This slice adds 172 production lines, for 32,953 total lines and 43 modules.
The allowance equals this slice's added production lines; it is not general
feature headroom, and it does not change the original CA-2 reduction, any
provider/input budget, or any historical digest. Moving validation into the
installed package increases the production-only count even while duplicated
repository code is removed.

The surface test includes this named allowance and verifies the actual source
count and module inventory. Confirmation also requires the unchanged pin and
provenance map, malformed-resource rejection, atomic section-preserving refresh,
and installed-wheel resource loading. These checks are delivery gates; this
decision alone does not establish that they passed or that VD-3 is complete.

Revert this loader/resource migration and its scoped allowance together if the
shared authority cannot preserve historical semantics. Unrelated source growth
requires its own decision or a real reduction.

## Addendum: installed runtime pin consumers (2026-11-15)

Under the same user-directed roadmap and delegated contract authority, root
extends the scoped compatibility migration to the current-source capture and
CLI shadow-policy consumers. Five unchanged PR-457 values join the canonical
resource; PR-464 reuses its existing named value. Explicit private accessors
return fresh ordinary dictionaries with the original keys and values. Typed
shapes preserve those fields without import-time resource reads or lazy proxy
objects. Historical fixtures, digests, provider limits and effect policy remain
unchanged.

The measured production delta is 36 lines: 13 in `cli.py` and 23 in
`current_source_capture.py`. The cumulative compatibility allowance is therefore
208 lines (172 for the loader plus 36 for these consumers), with 32,989 total
source lines and 43 modules. This is a measured root implementation decision,
not a separately recorded owner approval of that number. It covers these
accessors and their typed shapes only, creates no general feature headroom,
and does not alter the original CA-2 result or the other scoped allowances.

Acceptance requires immutable prior-source parity for both serialized mappings,
resource access only at explicit use, malformed-resource rejection, installed
wheel loading, and inclusion of the resource in the current-source runtime
inventory. Six resolved CLI typing diagnostics and one test lint finding are
retired. Two existing `_run_one` signature-debt identities (seven diagnostics)
retain their counts with updated containing-function AST fingerprints; the
signature is unchanged. These are targeted retirements and identity mappings,
not permission for new typing or lint debt. Other script-family pins remain
separate follow-up work, so this slice does not close VD-3 or VD-4.

Revert this consumer migration and its additional 36-line allowance together
if the shared resource cannot preserve the existing case and policy identity.


## Addendum: remaining SYNTH-001 pin consumers (2026-11-15)

Under the same roadmap implementation authority, root records the measured
ten-line `file_pin` accessor in the installed compatibility loader. The
preflight, writer, package and finalizer scripts resolve named identities from
the existing canonical resource at explicit use. All prior resource values
remain unchanged; six semantic values and four file identities are added with
provenance. The finalizer requires the selected pins to match before writes,
never refreshes the canonical resource, and preserves frozen verification.

The source total is 32,999 physical Python lines across 43 modules. The scoped
compatibility allowance becomes 218 lines (208 previously measured plus ten
for this accessor). This root implementation decision grants no general
headroom and changes no provider limits or historical evidence. Acceptance
requires original-value parity, missing or malformed resource rejection, lazy
imports, standalone CLI checks and zero-write finalizer refusal tests, together
with the required repository gates and independent review. Those are evidence
requirements, not assertions that this decision alone satisfies them.

Revert the accessor and its ten-line allowance together if the migration cannot
preserve the named identities and finalizer boundaries. Other script families
remain outside this slice; VD-3 is not complete.
