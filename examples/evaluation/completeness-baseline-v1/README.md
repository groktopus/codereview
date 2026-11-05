# Frozen-corpus completeness baseline v1

Six natural cases from `qm2-labeling-pilot-v1`, including the incomplete case:

- `qm1-codereview-pr112` — `COMPLETE`, `APPROVE`
- `qm1-codereview-pr285` — `COMPLETE`, `REQUEST_CHANGES`
- `qm1-codereview-pr289` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`
- `qm1-slopsearx-pr759` — `COMPLETE_WITH_WAIVERS`, `COMMENT`
- `qm1-slopsearx-pr745` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`
- `qm1-slopsearx-pr770` — `INCOMPLETE` (30.3% complete, 274 required obligations)

The incomplete case is included on purpose: excluding it would make the baseline a
subset of clean cases and hide the observed truncation. The gate is therefore
**zero completion drop per case** (`max_completion_drop: 0.0`). The absolute floor
is `0.0` because one baseline case is legitimately incomplete; the per-case
zero-drop check is the operative regression control.

The baseline is provider-free to check. CI gates it with
`scripts/check_completeness.py` against `manifest.json`; the seeded regression
probe remains the proof that the gate fails closed.
