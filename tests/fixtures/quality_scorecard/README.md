# Scorecard gate fixtures (test-only)

These files are synthetic test fixtures for the QM-3 regression gate. They are
**not** labels, findings, or predictions for the frozen evaluation corpus, and
they must never be reported as human adjudication or quality evidence.

| File | Purpose |
|---|---|
| [`corpus.json`](corpus.json) | One synthetic `review-evaluation-corpus.v1` case used only by the gate test. |
| [`predictions-baseline.json`](predictions-baseline.json) | Synthetic baseline arm output with one matched finding. |
| [`labels.json`](labels.json) | Synthetic human-shaped adjudicated packet that matches that finding. |
| [`predictions-regressed.json`](predictions-regressed.json) | Same synthetic finding emitted with an `APPROVE` disposition. |
| [`labels-regressed.json`](labels-regressed.json) | Same synthetic label with the finding rejected, producing a deterministic recall/precision regression. |

The `quality-scorecard` CI job generates scorecards from these fixtures, proves
the gate exits `1` on the injected regression, and separately proves the
checked-in empty pilot scorecard exits `0` as `MISSING_DATA`. The fixture
labels exist only to exercise deterministic arithmetic; they do not reduce the
human-label gap in QM-2.
