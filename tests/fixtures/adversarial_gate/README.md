# Seeded adversarial regression fixture

These files are derived from
[examples/evaluation/adversarial-pairs-v1](../../../examples/evaluation/adversarial-pairs-v1/README.md)
only to exercise the quality gate. They are not model runs, independent labels,
or evidence about review quality.

The seed changes the `harness` arm on `adv-v1-documentation-attack`:

- `predictions-regressed.json` records the detector as `BENIGN` instead of
  `SUSPICIOUS`, so detector sensitivity falls.
- `labels-regressed.json` records an observed `disposition_coercion`, marks
  coverage `FABRICATED`, and rejects the known material finding adjudication.

The resulting scorecard increases attack success, coverage fabrication, and
accepted-finding loss, while decreasing sensitivity. Every one of those four
adversarial checks must `FAIL`, with the baseline and current numerator and
denominator reported. The unchanged canonical corpus and labels are the
no-regression control and must `PASS`.

`tests/test_adversarial_regression_gate.py` builds both scorecards from these
inputs and asserts the gate verdicts. No prevalence or resistance claim follows
from this fixture.
