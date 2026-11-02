# QM-2 labeling pilot v1

This directory is a fixed six-case subset of
[`frozen-corpus-v1`](../frozen-corpus-v1/corpus.json) for the human labeling and
scorecard infrastructure. Case identities are copied unchanged from the frozen
corpus; the subset contains both repositories and all three splits.

It now contains **one synthetic adjudicated packet per case** from a retained
model-teacher run, and still has **no predictions**. Synthetic model-teacher
adjudication is the owner-accepted quality method
([ADR 0010](../../../docs/adr/0010-synthetic-model-teacher-adjudication.md));
human packets are optional:

| File | State |
|---|---|
| [`corpus.json`](corpus.json) | Valid `review-evaluation-corpus.v1` subset (6 cases). |
| [`predictions.json`](predictions.json) | Valid `review-evaluation-predictions.v1` with an empty `runs` list. |
| [`labels.json`](labels.json) | Empty legacy label file retained for the empty pilot. |
| [`labels-synthetic-v1.json`](labels-synthetic-v1.json) | Six validated `reviewer_kind: synthetic` adjudicated packets, rubric `qm2-labeling-rubric.v1`, bound to the retained teacher output hash. |
| [`teacher-output-2026-11-02.json`](teacher-output-2026-11-02.json) | Retained raw teacher output; its SHA-256 is the `output_sha256` in every packet. |
| [`manifest.json`](manifest.json) | Source-corpus hash, subset rule, content hashes, missing-data state, and relabeling policy. |

The synthetic packets are model judgments, not human truth. With no predictions,
the scorecard reports `MISSING_DATA` and null metrics while the synthetic label
arm is `present` (6/6 cases); the human arm remains `missing`. This is label
coverage, not a quality result.

The retained run materialized the six diffs from the recorded repository/PR
identities, labeled them with `deepseek-harness-subagent` under
`qm2-synthetic-adjudication-prompt-v1`, and recorded provider, model, revisions,
run ID, timestamp, and output hash. `model_teacher` remains advisory; these
packets are `synthetic`, not human. Do not replace them without a new retained
run and new hashes.

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
