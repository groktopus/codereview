# Frozen-corpus completeness baseline v1

Five complete natural cases from `qm2-labeling-pilot-v1`:

- `qm1-codereview-pr112` — `COMPLETE`, `APPROVE`
- `qm1-codereview-pr285` — `COMPLETE`, `REQUEST_CHANGES`
- `qm1-codereview-pr289` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`
- `qm1-slopsearx-pr759` — `COMPLETE_WITH_WAIVERS`, `COMMENT`
- `qm1-slopsearx-pr745` — `COMPLETE_WITH_WAIVERS`, `REQUEST_CHANGES`

`qm1-slopsearx-pr770` is explicitly excluded: its frozen corpus merge-base
(`282cf846…`) does not match the live PR base (`dfcb164a…`), so rerunning it
would change the frozen case identity rather than measure the same case.

The baseline is provider-free to check. CI gates it with
`scripts/check_completeness.py` against `manifest.json`; the seeded regression
probe remains the proof that the gate fails closed.
