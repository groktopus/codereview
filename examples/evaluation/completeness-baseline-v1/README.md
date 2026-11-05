# Comparable-subset completeness baseline v1

Five natural cases from `qm2-labeling-pilot-v1`:

- `qm1-codereview-pr112` — `COMPLETE`, `APPROVE`
- `qm1-codereview-pr285` — `COMPLETE`, `REQUEST_CHANGES`
- `qm1-codereview-pr289` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`
- `qm1-slopsearx-pr759` — `COMPLETE_WITH_WAIVERS`, `COMMENT`
- `qm1-slopsearx-pr745` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`

## Not included

`qm1-slopsearx-pr770` is disclosed but not included. The stored #770 result is a
38-unit rerun with `change_base_sha: null`; the frozen case is 31 units on the
frozen comparison base. It is a different workload, so using it would mislabel
the baseline.

## Gate

The operative control is **zero completion drop per case**
(`max_completion_drop: 0.0`). The absolute floor is `0.0` because the subset
contains a waived case at 28.6% `complete_ratio`; the floor does not mask a
per-case drop. CI checks the stored results with `scripts/check_completeness.py`
and retains the verdict; the seeded-regression step proves failure behavior.
