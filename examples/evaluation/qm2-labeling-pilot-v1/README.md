# QM-2 labeling pilot v1

This directory is a fixed six-case subset of
[`frozen-corpus-v1`](../frozen-corpus-v1/corpus.json) for the human labeling and
scorecard infrastructure. Case identities are copied unchanged from the frozen
corpus; the subset contains both repositories and all three splits.

It intentionally contains **no labels and no predictions**. Synthetic
model-teacher adjudication is the owner-accepted quality method
([ADR 0010](../../../docs/adr/0010-synthetic-model-teacher-adjudication.md));
human packets are optional:

| File | State |
|---|---|
| [`corpus.json`](corpus.json) | Valid `review-evaluation-corpus.v1` subset (6 cases). |
| [`predictions.json`](predictions.json) | Valid `review-evaluation-predictions.v1` with an empty `runs` list. |
| [`labels.json`](labels.json) | Valid `review-evaluation-labels.v1` with an empty `packets` list, rubric `qm2-labeling-rubric.v1`. |
| [`manifest.json`](manifest.json) | Source-corpus hash, subset rule, content hashes, missing-data state, and relabeling policy. |

The empty packets are not a clean review, a negative label, or zero findings.
They mean that no synthetic adjudicated packet, human independent/adjudicated
packet, or model-teacher screening run exists yet. The scorecard reports
`MISSING_DATA` and null metrics in both label arms.

Do not add a synthetic packet unless an actual teacher run produced the retained
output and its provider, model ID/revision, prompt revision, rubric revision, run
ID, output hash, and timestamp are recorded with `synthetic: true`. The frozen
corpus does not check in the reviewed diff bytes, so the first real run must
materialize them from the recorded base/head identity. A `model_teacher`
screening packet remains advisory and cannot be marked `adjudicated`.

See [the labeling protocol](../../../docs/QUALITY-LABELING-PROTOCOL.md) for the
exact synthetic run and provenance fields, and
[the scorecard contract](../../../docs/QUALITY-SCORECARD.md) for the two label
arms.

Relabeling creates a new packet version and a new labels file; it never mutates
this file or the prior report.

```sh
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels.json \
  --json
```
