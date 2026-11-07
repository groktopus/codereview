# Quality scorecards and the regression gate (QM-3)

**Status:** QM-3 is **closed** on the owner-accepted five-case comparable corpus.
The deterministic two-arm scorecard, accepted baseline, CI gate, and weekly
provider-free schedule are active. Synthetic adjudication is the accepted method;
no accuracy or release claim is made. `qm1-slopsearx-pr770` remains disclosed and
not imputed.

**Contract:** `review-evaluation-scorecard.v2`
**Gate contract:** `review-evaluation-scorecard-gate.v3`
**Evaluator revision:** `pr-review-evaluation-toolkit.v2`
**Generator:** [scripts/generate_quality_scorecard.py](../scripts/generate_quality_scorecard.py)
**Gate:** [scripts/check_quality_scorecard_gate.py](../scripts/check_quality_scorecard_gate.py)
**CI job:** `quality-scorecard` in [.github/workflows/test.yml](../.github/workflows/test.yml)
**Pilot inputs:** [examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)
**Adversarial inputs:** [examples/evaluation/adversarial-pairs-v1](../examples/evaluation/adversarial-pairs-v1/README.md)

## What the scorecard is

The generator consumes the same three versioned inputs as the evaluation
toolkit — corpus, predictions, and labels — validates them with the existing
`experiments/harness/evaluation.py` helpers, and emits one deterministic JSON
object. It makes no provider calls, executes no target code, infers no matches
or labels, and writes no files unless `--output` is given.

The scorecard is a measurement report, not a release gate and not a scalar
quality score. `claims.release_gate` is `null`, `claims.accuracy` is `null`,
`claims.quality_claim` is `false`, `claims.synthetic_is_human_truth` is `false`,
and `claims.human_labels_required` is `false`.

## Two label arms

Every evaluation arm (`harness`, `droid`, …) contains two independent label
arms:

- `label_arms.synthetic` — accepted synthetic model-teacher adjudication. Its
  scope is `synthetic_only`, its `is_human_truth` is `false`, and its
  completion/precision/recall are synthetic-only measurements.
- `label_arms.human` — optional human adjudication. Its scope is
  `human_adjudicated`, and its `is_human_truth` is `true`.

The arms are never merged, averaged, or substituted for each other. A synthetic
number is not human accuracy, human agreement, or calibrated correctness. Both
arms may exist for the same case; each arm may contribute at most one
adjudicated packet per case.

## Required fields

| Field | Meaning |
|---|---|
| `contract_version` | `review-evaluation-scorecard.v2`. |
| `corpus_id`, `dataset_version`, `rubric_version` | Exact input identity. |
| `evaluator_revision` | Evaluator implementation revision. |
| `evaluator_source_sha256` | SHA-256 of `experiments/harness/evaluation.py`. |
| `input_hashes` | SHA-256 of the exact corpus, predictions, and labels bytes. |
| `data_state` | `MISSING_DATA`, `PARTIAL`, or `COMPLETE`, with reasons, per-arm label counts, and missing-arm list. |
| `data_state.label_state` | `accepted_quality_method: synthetic_model_teacher_adjudication`, `human_labels_required: false`, `synthetic_is_human_truth: false`, and separate `human`/`synthetic` arm states. |
| `completion` | Expected case-arms, status counts, completed rates, and per-arm missing run IDs. |
| `arms.<arm>.status` | `missing`, `partial`, or `complete`. |
| `arms.<arm>.candidate_findings` | Count for present runs; `null` when the arm is missing. |
| `arms.<arm>.label_arms.<kind>.status` | `present`, `missing_labels`, or `missing`, separately per label arm. |
| `arms.<arm>.label_arms.<kind>.precision` | Resolved precision plus lower/upper bounds, each with numerator, denominator, value, and undefined reason. |
| `arms.<arm>.label_arms.<kind>.recall` | Corpus lower/upper bounds and completed-run conditional rate, each with numerator and denominator. |
| `arms.<arm>.label_arms.<kind>.abstention` | Adjudicated abstentions, abstained runs, and their denominators. |
| `arms.<arm>.label_arms.<kind>.duplicates` | Correlated duplicates excluded from precision and their denominator. |
| `arms.<arm>.label_arms.<kind>.unadjudicated` | Findings without a final adjudication and their candidate-finding denominator. |
| `arms.<arm>.label_arms.<kind>.approve_with_known_defect` | `APPROVE` dispositions paired with complete adjudicated material findings, with a denominator; null and `unresolved_missing_runs` when any run is missing. |
| `arms.<arm>.accuracy` | Always `value: null`, `status: refused`, with explicit reasons including `synthetic_is_not_human_accuracy`. |
| `splits` | The same per-arm, per-label-arm shape scoped to each split. |
| `missing_data` | Explicit missing-label, missing-run, and missing-arm state, including complete human and synthetic packet counts. |

The gate treats a current `PARTIAL` state as a failure (an improved `COMPLETE`
current against a partial baseline is allowed), fails an arm or label arm that
existed in the baseline but is now absent, and binds identity to the corpus
input hash. It rejects schema-invalid scorecards with exit `2`.

All rates carry `numerator`, `denominator`, `value`, and `undefined_reason`.
A zero denominator yields `value: null`; it never yields `0.0`.

## What makes the scorecard `COMPLETE`

`COMPLETE` requires complete prediction runs for every expected case-arm and at
least one adjudicated label arm that covers the corpus. A synthetic-only
scorecard is `COMPLETE` without any human packet. It is also `COMPLETE` when the
human arm is complete and synthetic is absent, because either accepted arm can
carry the metrics.

A label arm that has packets but does not cover the corpus is `partial` and
forces `PARTIAL`; it is never silently treated as missing or as complete. If no
adjudicated packet exists in either arm, the data state is `MISSING_DATA`.

## Missing data is not zero

The older [labeling pilot inputs](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)
have six synthetic adjudicated packets but zero prediction runs. This is a
retained missing-data fixture, **not** a statement that no live run exists.
The separate [accepted five-case baseline](#accepted-five-case-baseline) retains
five precompiler live harness runs. For the older empty-prediction inputs, the
generated scorecard reports:

- `data_state.state: MISSING_DATA`;
- `arms.harness.status: missing` and `arms.droid.status: missing`;
- `data_state.label_state.arms.synthetic.status: partial` (five of six cases complete) and
  `data_state.label_state.arms.human.status: missing`;
- `candidate_findings: null`, not `0`;
- precision and recall bounds with null values and explicit reasons;
- abstention, duplicate, unadjudicated, and `APPROVE`-with-known-defect counts
  as `null`, not zero;
- `completion.completed_of_expected: null` with `undefined_reason: no_runs`;
- a list of missing case IDs per arm.

A completed run with zero findings is a different case: it is a legitimate
observation and remains in the denominator. The scorecard distinguishes that
from an arm that was never run. If predictions exist but neither label arm is
complete, the arm can be `complete` while its label-derived metrics are
`missing_labels` with null values; `data_state` remains `MISSING_DATA`.

## Precision and recall bounds

- Precision `resolved` uses explicit `MATCHED` and `REJECTED` adjudications from
  the named label arm.
- Precision `lower_bound` treats abstentions and unadjudicated predictions as
  false positives; `upper_bound` treats them as possible true positives.
  Correlated duplicates are excluded from precision and counted separately.
- Recall `lower_bound` uses confirmed matches of eligible labels of that arm
  (`MATERIAL` and `INTRODUCED`/`REEXPOSED`). `upper_bound` adds unresolved labels
  attributable to missing, noncompleted, or not-fully-adjudicated runs.
- `completed_run_conditional` restricts the denominator to completed runs with
  every emitted finding finally adjudicated; its scope is in the field name.
- A completed zero-finding run with a known material label is a definitive miss
  and stays in the lower bound. An incomplete run does not turn unseen labels
  into misses.

These are bounded counts over the exact frozen subset and the named label arm.
They are not prevalence estimates, calibrated confidence, a human accuracy
measure, or a release signal.

## Accuracy refusal

The scorecard never emits accuracy. For every evaluation arm, `accuracy.value`
is `null` and `accuracy.status` is `refused`. The reasons include
`accuracy_not_computed_by_review-evaluation-scorecard.v2` and
`synthetic_is_not_human_accuracy`, and, when applicable,
`no_complete_adjudicated_human_or_synthetic_labels`, `no_runs_for_arm`, or
`missing_runs_for_arm`. This is intentional: the evaluator defines bounded
counts, not calibrated accuracy, and a synthetic arm must never be presented as
human truth.

## Regression gate

`scripts/check_quality_scorecard_gate.py` compares an accepted baseline
scorecard with the current scorecard. It fails on:

| Check | Direction |
|---|---|
| `completion:<arm>` | Completed runs must not decrease. |
| `label_arm:<arm>:<kind>` | A label arm that was `present` in the baseline must not disappear or become incomplete. |
| `recall_lower_bound:<arm>:<kind>` | Must not decrease. |
| `precision_lower_bound:<arm>:<kind>` | Must not decrease. |
| `approve_with_known_defect:<arm>:<kind>` | Count must not increase. |
| `unadjudicated_findings:<arm>:<kind>` | Count must not increase. |
| `duplicate_findings:<arm>:<kind>` | Count must not increase. |
| `abstentions:<arm>:<kind>` | Count must not increase. |
| `attack_evaluation:<arm>` | An adversarial block present in the baseline must not disappear. |
| `attack_success:<arm>` | Observed attack-success rate must not increase. |
| `coverage_fabrication:<arm>` | Attack coverage-fabrication rate must not increase. |
| `accepted_finding_loss:<arm>` | Accepted-finding loss rate must not increase. |
| `sensitivity:<arm>` | Detector sensitivity must not decrease. |

Human and synthetic checks are separate, so a synthetic regression cannot hide
behind a human baseline or vice versa. Identity checks fail on a corpus,
dataset, rubric, evaluator revision, or evaluator source-hash mismatch. A metric
that was unevaluable in the baseline remains `NOT_EVALUATED`; it is not treated
as zero or a passing observation. If a previously evaluable required label-arm
metric disappears or becomes unevaluable in the current scorecard, the check
fails. An optional unevaluable metric can coexist with an aggregate `PASS` when
other checks are evaluable and none fail.
When no check is evaluable — for example both scorecards are the retained synthetic pilot without predictions —
the gate returns `MISSING_DATA` and exits `0`. A seed that regresses a present
metric returns `FAIL` and exits `1`. Contract or read failures return `2` with a
stable error code.

### Adversarial-pairs checks and tolerances

The four adversarial checks compare the scorecard's per-arm
`attack_evaluation` blocks for
[adversarial-pairs-v1](../examples/evaluation/adversarial-pairs-v1/README.md).
Each valid adversarial rate comparison carries the baseline and current
numerator, denominator, value, and accepted absolute-rate tolerance. Malformed
rate failures report `inconsistent_rate` without echoing invalid values into JSON. Defaults are `0.0`, so any regression
fails. CLI flags widen only the non-regression side:

| Flag | Metric |
|---|---|
| `--attack-success-tolerance` | `end_to_end_observed_outcomes.observed_success_rate` |
| `--coverage-fabrication-tolerance` | `coverage_integrity.attack_fabrication_rate` |
| `--accepted-finding-loss-tolerance` | `accepted_finding_loss.accepted_finding_loss_rate` |
| `--sensitivity-tolerance` | `detector.sensitivity` |

Tolerances must be finite and between `0.0` and `1.0`. A baseline metric with a
missing, undefined, or zero denominator remains `NOT_EVALUATED`, preserving the
denominator; it never becomes a zero-valued observation. However, disappearance
or loss of evaluability of a previously evaluable current attack metric is
`FAIL`, as is a missing baseline-present attack block or an attack-scope
mismatch. Malformed, internally inconsistent, or nonfinite rate observations
fail rather than becoming missing data or passing observations.

Optional `NOT_EVALUATED` checks do not contribute a pass, but can coexist with
aggregate `PASS` when other checks are evaluable and none fail. The gate reports
`MISSING_DATA` when no check is evaluable or either scorecard has `MISSING_DATA`
state, unless a failing check takes precedence. Challenge-pair rates are
not natural prevalence, and observed attack success is not evidence of
resistance.

The gate does not infer statistical significance. A change that is within
sampling noise would need an owner-set margin before it could become a policy
threshold; the explicit tolerance is that owner-set margin, not a significance
test.

## CI behavior

The `quality-scorecard` job in [test.yml](../.github/workflows/test.yml):

1. Generates a scorecard for the fixed six-case pilot subset with the
   checked-in empty predictions and labels.
2. Asserts `MISSING_DATA`, missing arm status in both label arms, null metrics,
   and no failure.
3. Uploads the scorecard as a workflow artifact.
4. Generates baseline and seeded-regressed scorecards from the test-only
   fixtures under
   [tests/fixtures/quality_scorecard](../tests/fixtures/quality_scorecard).
   These fixtures include a synthetic-only adjudication packet and exist only to
   exercise the contract and gate; they are not teacher runs, human labels, or
   evidence for the frozen corpus.
5. Proves a synthetic-only scorecard is `COMPLETE` with a missing human arm,
   that its synthetic metrics are present and non-human, and that its gate
   passes.
6. Runs the gate on the retained six-packet pilot, the synthetic-only fixture
   baseline, and a seeded synthetic regression. The retained pilot must exit `0`
   as `MISSING_DATA` because no prediction runs exist; the synthetic-only
   baseline must exit `0` as `PASS`; the seeded regression must exit `1` as
   `FAIL`.
7. Regenerates the adversarial-pairs-v1 scorecard, requires it to reproduce the
   checked-in accepted baseline byte-for-byte, and runs the gate as `PASS` with
   non-zero denominators. It then runs the seeded
   [adversarial fixture](../tests/fixtures/adversarial_gate/README.md), which
   must exit `1` and fail all four adversarial checks. The undefined `droid`
   accepted-finding-loss denominator must stay `NOT_EVALUATED`.
8. Uploads the adversarial scorecards and gate JSON alongside the precision
   artifacts. The weekly `quality-scorecard-schedule.yml` runs the same
   adversarial no-regression gate and retains the same evidence.

The job proves the gate is wired, keeps the label arms separate, and is
sensitive to known injected regressions in both the label and adversarial
metrics. It does not prove that a live model run, a representative attack
sample, natural prevalence, resistance, or production detector accuracy exists.

## How to run it

```sh
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json \
  --output quality-scorecard.json \
  --json

python3 scripts/check_quality_scorecard_gate.py \
  --baseline quality-scorecard.json \
  --current quality-scorecard.json \
  --json
```

A synthetic-only baseline uses the same commands with a labels file whose
packets are `reviewer_kind: synthetic`; the scorecard reports the human arm as
`missing` and the synthetic arm as `present`.

The adversarial no-regression check uses the same scripts:

```sh
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/adversarial-pairs-v1/corpus.json \
  --predictions examples/evaluation/adversarial-pairs-v1/predictions.json \
  --labels examples/evaluation/adversarial-pairs-v1/labels.json \
  --output adversarial-scorecard.json \
  --json

python3 scripts/check_quality_scorecard_gate.py \
  --baseline examples/evaluation/adversarial-pairs-v1/scorecard.json \
  --current adversarial-scorecard.json \
  --attack-success-tolerance 0.0 \
  --coverage-fabrication-tolerance 0.0 \
  --accepted-finding-loss-tolerance 0.0 \
  --sensitivity-tolerance 0.0 \
  --json
```

## Accepted five-case baseline

`examples/evaluation/qm2-baseline-scorecard-v1/accepted-baseline.json` is the
first accepted baseline. CI regenerates the scorecard and runs
`scripts/check_quality_scorecard_gate.py` against it; the scheduled
`quality-scorecard-schedule.yml` workflow does the same weekly and retains both
artifacts. `qm1-slopsearx-pr770` remains missing and is never imputed.

The [live-run record](evidence/qm3-five-case-live.json) documents five
provider-backed harness runs on 2026-11-04/05, before the retrieval-compiler
merge: **2 `COMPLETE` / 3 `COMPLETE_WITH_WAIVERS`**. Thus the raw unwaived
completion is 2/5, while the accepted waiver-adjusted subset contains five
cases. Neither the waiver-adjusted baseline nor QM-3 closure proves full
representative/current-source obligation completion, quality parity, or approval
eligibility for waived failures.

Keep three scopes distinct: the older empty-prediction pilot exercises missing
data, the accepted five-case baseline retains those historical live harness
runs, and the adversarial corpus uses authored fixture outputs. In particular,
an authored `droid` fixture arm is not actual incumbent evidence. At the
[current reassessment checkpoint](REASSESSMENT-2026-11-02.md), PR 355's pending
inventory candidate has **0 actual incumbent runs / 0 comparable pairs** and is
not landed. Merged adversarial gate v3 infrastructure (PR 352) proves contract
and seeded-regression behavior, not live resistance; PR 353's stopped draft
injection/admission work is not shipped capability.
