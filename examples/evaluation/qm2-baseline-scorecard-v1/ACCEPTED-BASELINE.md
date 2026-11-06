# Accepted QM-3 quality baseline v1

Accepted 2026-11-05 as the first reproducible five-case scorecard baseline.

- Baseline scorecard: `accepted-baseline.json` (identical to `scorecard.json`).
- Gate: `scripts/check_quality_scorecard_gate.py`.
- CI: the `quality-scorecard` job regenerates the scorecard and gates it against
  this baseline on every pull request.
- Schedule: `.github/workflows/quality-scorecard-schedule.yml` runs the same
  provider-free generation and gate weekly, retaining both artifacts.

The baseline is five comparable cases. `qm1-slopsearx-pr770` is missing and is
not imputed. The gate fails on deterministic metric regressions; missing arms and
labels remain `MISSING_DATA`/`NOT_EVALUATED`, never zero.
