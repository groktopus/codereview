# Quality scorecards and the regression gate (QM-3)

**Status:** deterministic scorecard and gate infrastructure; **no accepted
quality baseline exists** and no accuracy or release claim is made. Issue
[#244](https://github.com/groktopus/codereview/issues/244) remains open and
blocked by [#241](https://github.com/groktopus/codereview/issues/241) and
[#243](https://github.com/groktopus/codereview/issues/243).

**Contract:** `review-evaluation-scorecard.v1`
**Gate contract:** `review-evaluation-scorecard-gate.v1`
**Evaluator revision:** `pr-review-evaluation-toolkit.v1`
**Generator:** [scripts/generate_quality_scorecard.py](../scripts/generate_quality_scorecard.py)
**Gate:** [scripts/check_quality_scorecard_gate.py](../scripts/check_quality_scorecard_gate.py)
**CI job:** `quality-scorecard` in [.github/workflows/test.yml](../.github/workflows/test.yml)
**Pilot inputs:** [examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)

## What the scorecard is

The generator consumes the same three versioned inputs as the evaluation
toolkit — corpus, predictions, and labels — validates them with the existing
`experiments/harness/evaluation.py` helpers, and emits one deterministic JSON
object. It makes no provider calls, executes no target code, infers no matches
or labels, and writes no files unless `--output` is given.

The scorecard is a measurement report, not a release gate and not a scalar
quality score. `claims.release_gate` is `null`, `claims.accuracy` is `null`, and
`claims.quality_claim` is `false`.

## Required fields

| Field | Meaning |
|---|---|
| `contract_version` | `review-evaluation-scorecard.v1`. |
| `corpus_id`, `dataset_version`, `rubric_version` | Exact input identity. |
| `evaluator_revision` | Evaluator implementation revision. |
| `evaluator_source_sha256` | SHA-256 of `experiments/harness/evaluation.py`. |
| `input_hashes` | SHA-256 of the exact corpus, predictions, and labels bytes. |
| `data_state` | `MISSING_DATA`, `PARTIAL`, or `COMPLETE`, with reasons, label counts, and missing-arm list. |
| `completion` | Expected case-arms, status counts, completed rates, and per-arm missing run IDs. |
| `arms.<arm>.status` | `missing`, `partial`, or `complete`. |
| `arms.<arm>.candidate_findings` | Count for present runs; `null` when the arm is missing. |
| `arms.<arm>.precision` | Resolved precision plus lower/upper bounds, each with numerator, denominator, value, and undefined reason. |
| `arms.<arm>.recall` | Corpus lower/upper bounds and completed-run conditional rate, each with numerator and denominator. |
| `arms.<arm>.abstention` | Adjudicated abstentions, abstained runs, and their denominators. |
| `arms.<arm>.duplicates` | Correlated duplicates excluded from precision and their denominator. |
| `arms.<arm>.unadjudicated` | Findings without a final adjudication and their candidate-finding denominator. |
| `arms.<arm>.approve_with_known_defect` | `APPROVE` dispositions paired with complete human adjudicated material findings, with a denominator. |
| `arms.<arm>.accuracy` | Always `value: null`, `status: refused`, with explicit reasons. |
| `splits` | The same per-arm shape scoped to each split. |
| `missing_data` | Explicit missing-label, missing-run, and missing-arm state. |

All rates carry `numerator`, `denominator`, `value`, and `undefined_reason`.
A zero denominator yields `value: null`; it never yields `0.0`.

## Missing data is not zero

The pilot inputs contain zero labels and zero prediction runs. The generated
scorecard reports:

- `data_state.state: MISSING_DATA`;
- `arms.harness.status: missing` and `arms.droid.status: missing`;
- `candidate_findings: null`, not `0`;
- precision and recall bounds with null values and explicit reasons;
- abstention, duplicate, unadjudicated, and `APPROVE`-with-known-defect counts
  as `null`, not zero;
- `completion.completed_of_expected: null` with `undefined_reason: no_runs`;
- a list of missing case IDs per arm.

A completed run with zero findings is a different case: it is a legitimate
observation and remains in the denominator. The scorecard distinguishes that
from an arm that was never run. If predictions exist but no complete human
labels exist, the arm can be `complete` while its label-derived metrics are
`missing_labels` with null values; `data_state` remains `MISSING_DATA`.

## Precision and recall bounds

- Precision `resolved` uses explicit `MATCHED` and `REJECTED` adjudications.
- Precision `lower_bound` treats abstentions and unadjudicated predictions as
  false positives; `upper_bound` treats them as possible true positives.
  Correlated duplicates are excluded from precision and counted separately.
- Recall `lower_bound` uses confirmed matches of eligible human labels
  (`MATERIAL` and `INTRODUCED`/`REEXPOSED`). `upper_bound` adds unresolved
  labels attributable to missing, noncompleted, or not-fully-adjudicated runs.
- `completed_run_conditional` restricts the denominator to completed runs with
  every emitted finding finally adjudicated; its scope is in the field name.
- A completed zero-finding run with a known material label is a definitive miss
  and stays in the lower bound. An incomplete run does not turn unseen labels
  into misses.

These are bounded counts over the exact frozen subset and label set. They are
not prevalence estimates, calibrated confidence, or a release signal.

## Accuracy refusal

The v1 scorecard never emits accuracy. For every arm, `accuracy.value` is
`null` and `accuracy.status` is `refused`. The reasons include
`accuracy_not_computed_by_review-evaluation-scorecard.v1` and, when
applicable, `no_complete_adjudicated_human_labels`, `no_runs_for_arm`, or
`missing_runs_for_arm`. This is intentional: the existing evaluator defines
counts and bounds, not accuracy, and QM-3 explicitly forbids converting
model-teacher screening into accuracy.

## Regression gate

`scripts/check_quality_scorecard_gate.py` compares an accepted baseline
scorecard with the current scorecard. It fails on:

| Check | Direction |
|---|---|
| `completion` | Completed runs must not decrease. |
| `recall_lower_bound` | Must not decrease. |
| `precision_lower_bound` | Must not decrease. |
| `approve_with_known_defect` | Count must not increase. |
| `unadjudicated_findings` | Count must not increase. |
| `duplicate_findings` | Count must not increase. |
| `abstentions` | Count must not increase. |

Identity checks fail on a corpus, dataset, rubric, evaluator revision, or evaluator source-hash mismatch. A metric that is
missing on either side is `NOT_EVALUATED`; it is not treated as zero. When no
check is evaluable — for example both scorecards are the empty pilot — the gate
returns `MISSING_DATA` and exits `0`. A seed that regresses a present metric
returns `FAIL` and exits `1`. Contract or read failures return `2` with a
stable error code.

The gate does not infer statistical significance. A change that is within
sampling noise would need an owner-set margin before it could become a policy
threshold; no such margin is accepted here.

## CI behavior

The `quality-scorecard` job in [test.yml](../.github/workflows/test.yml):

1. Generates a scorecard for the fixed six-case pilot subset with the
   checked-in empty predictions and labels.
2. Asserts `MISSING_DATA`, missing arm status, null metrics, and no failure.
3. Uploads the scorecard as a workflow artifact.
4. Generates baseline and seeded-regressed scorecards from the test-only
   synthetic fixtures under
   [tests/fixtures/quality_scorecard](../tests/fixtures/quality_scorecard).
   These fixture labels exist only to exercise the gate and are not human
   labels for the frozen corpus.
5. Runs the gate on the empty pilot and on the seeded regression. The empty
   pilot must exit `0` as `MISSING_DATA`; the seeded regression must exit `1`
   as `FAIL`.

The job proves the gate is wired and sensitive to a known injected regression.
It does not prove the corpus has human labels, real predictions, a baseline, or
quality.

## How to run it

```sh
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels.json \
  --output quality-scorecard.json \
  --json

python3 scripts/check_quality_scorecard_gate.py \
  --baseline quality-scorecard.json \
  --current quality-scorecard.json \
  --json
```

## What remains for QM-3

- Real arm predictions for the corpus, not empty or test-only fixtures.
- Human-adjudicated labels from QM-2.
- An owner-accepted baseline scorecard and owner-set regression tolerances.
- A scheduled full-corpus run, not only the fixed pilot subset.
- A published scorecard for a real corpus run with meaningful denominators.
- The RC-3 dependency and the owner decision on what, if anything, constitutes
  a release gate.

The CI job is infrastructure evidence only. QM-3 stays open and blocked.
