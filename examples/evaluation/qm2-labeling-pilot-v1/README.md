# QM-2 labeling pilot v1

This directory is a fixed six-case subset of
[`frozen-corpus-v1`](../frozen-corpus-v1/corpus.json) for the synthetic labeling
and scorecard infrastructure. Case identities are copied unchanged from the
frozen corpus; the subset contains both repositories and all three splits.

Synthetic model-teacher adjudication is the owner-accepted quality method
([ADR 0010](../../../docs/adr/0010-synthetic-model-teacher-adjudication.md));
human packets are optional and none exist here. The first retained synthetic
pilot is now present:

| File | State |
|---|---|
| [`corpus.json`](corpus.json) | Valid `review-evaluation-corpus.v1` subset (6 cases). |
| [`predictions.json`](predictions.json) | Valid `review-evaluation-predictions.v1` with an empty `runs` list; no prediction arm exists yet. |
| [`labels.json`](labels.json) | The original empty `review-evaluation-labels.v1` file, retained unchanged. |
| [`labels-synthetic-v1.json`](labels-synthetic-v1.json) | Valid `review-evaluation-labels.v1` with six synthetic adjudicated packets: five `COMPLETE`/`NO_KNOWN_MATERIAL_DEFECTS` and `qm1-slopsearx-pr770` `INCOMPLETE`/`INCONCLUSIVE`. |
| [`teacher-output-2026-11-02.json`](teacher-output-2026-11-02.json) | The six-packet synthetic output record. Its `output_sha256` fields bind [`evidence/teacher-response.txt`](evidence/teacher-response.txt). |
| [`manifest.json`](manifest.json) | Source-corpus hash, subset rule, label state, all content hashes, retained evidence, and relabeling policy. |
| [`evidence/`](evidence/) | The six exact unified diffs, the exact teacher prompt, the request binding prompt/diffs, and the retained teacher response. |

## Retained synthetic run

- Run: `qm2-synthetic-pilot-2026-11-02`
- Labeled at: `2026-11-02T22:26:00Z`
- Provider: `deepseek`
- Model ID and revision: `deepseek-v4.1-flash-1017`
- Prompt revision: `qm2-synthetic-adjudication-prompt-v1`
- Rubric: `qm2-labeling-rubric.v1`

The request records the exact prompt hash, each case's retained diff hash and
byte count, the frozen evidence-completeness value, and the case identity. The
retained response is retained byte-for-byte in
[`evidence/teacher-response.txt`](evidence/teacher-response.txt). Because a
response cannot contain the hash of the file that includes that hash,
`output_sha256` is the SHA-256 of the retained **retained response** file, not of
`teacher-output-2026-11-02.json`; the output record adds that digest to each
packet after the response bytes are fixed.

The teacher adjudicated no material finding labels on the retained diffs. Five
complete cases are `NO_KNOWN_MATERIAL_DEFECTS` with empty `finding_labels`.
`qm1-slopsearx-pr770` is `INCOMPLETE` and `INCONCLUSIVE` because the frozen
manifest records `evidence_completeness: incomplete` (`diff_truncated`,
`changed_hunk_exceeds_window_limit`, `context_truncated`, and unbound context).
`NO_KNOWN_MATERIAL_DEFECTS` is not a clean-review or quality claim; the empty
findings are a conservative adjudication of bounded inputs.

The scorecard currently reports `MISSING_DATA`: no prediction runs exist, and
the synthetic label arm is `partial` because one of six cases is incomplete. The
human label arm is `missing`. No precision, recall, accuracy, quality, or
replacement claim follows from this pilot.

## Reproduce the validation

```sh
python3 scripts/evaluate_reviews.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json \
  --json

python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json \
  --json

python3 -m pytest -q tests/test_qm2_synthetic_pilot.py tests/test_quality_scorecard.py
```

## Boundaries

Do not add a synthetic packet unless a retained model response produced the
labels and its provider, model ID/revision, prompt revision, rubric revision, run
ID, output hash, and timestamp are recorded with `synthetic: true`. The frozen
corpus records case identities and the exact diffs retained here, but not full
repository source context. A `model_teacher` screening packet remains advisory
and cannot be marked `adjudicated`.

See [the labeling protocol](../../../docs/QUALITY-LABELING-PROTOCOL.md) for the
exact synthetic run and provenance fields, and
[the scorecard contract](../../../docs/QUALITY-SCORECARD.md) for the two label
arms. Relabeling creates a new packet version and a new labels file; it never
mutates this file or a prior report.

## Provenance limitation

The retained response is a provenance-corrected normalization of a model output
from the DeepSeek Harness synthetic teacher, not a fresh live provider call.
The checked-in artifacts bind the prompt, diffs, request manifest, retained
response bytes, and output hash; they do not include transport logs or a
provider-side request ID. It is synthetic model judgment, not human truth.
