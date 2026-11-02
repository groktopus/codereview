# QM-2 labeling pilot v1

This directory is a fixed six-case subset of
[`frozen-corpus-v1`](../frozen-corpus-v1/corpus.json) for the human labeling and
scorecard infrastructure. Case identities are copied unchanged from the frozen
corpus; the subset contains both repositories and all three splits.

It intentionally contains **no labels and no predictions**:

| File | State |
|---|---|
| [`corpus.json`](corpus.json) | Valid `review-evaluation-corpus.v1` subset (6 cases). |
| [`predictions.json`](predictions.json) | Valid `review-evaluation-predictions.v1` with an empty `runs` list. |
| [`labels.json`](labels.json) | Valid `review-evaluation-labels.v1` with an empty `packets` list, rubric `qm2-labeling-rubric.v1`. |
| [`manifest.json`](manifest.json) | Source-corpus hash, subset rule, content hashes, missing-data state, and relabeling policy. |

The empty packets are not a clean review, a negative label, or zero findings.
They mean that no human independent packet, human adjudicated packet, or
deterministic model-teacher screening run exists yet. The scorecard reports
`MISSING_DATA` and null metrics.

Do not add a model-teacher packet unless an actual offline process produced it
and its provider, model, prompt revision, output hash, and timestamp are
retained. A model-teacher packet is `screening` only and cannot satisfy human
adjudication.

See [the labeling protocol](../../../docs/QUALITY-LABELING-PROTOCOL.md) and
[the scorecard contract](../../../docs/QUALITY-SCORECARD.md).

Relabeling creates a new packet version and a new labels file; it never mutates
this file or the prior report.

```sh
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels.json \
  --json
```
