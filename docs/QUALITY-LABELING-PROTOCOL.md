# Quality labeling and adjudication protocol (QM-2)

**Status:** owner-accepted protocol. Synthetic model-teacher adjudication is the
accepted quality method ([ADR 0010](adr/0010-synthetic-model-teacher-adjudication.md));
human packets are optional. **A retained six-packet synthetic pilot now exists**
([manifest](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)): five
cases are complete and `qm1-slopsearx-pr770` is incomplete, with no human
packets and no prediction runs. This document does not establish review quality,
accuracy, calibration, or replacement readiness. Issue
[#243](https://github.com/groktopus/codereview/issues/243) remains open because
the pilot has no prediction arm, one incomplete case, and no accepted baseline.

**Rubric revision:** `qm2-labeling-rubric.v1`
**Contract:** `review-evaluation-labels.v1` in
[experiments/harness/evaluation.py](../experiments/harness/evaluation.py)
**Pilot subset:** [examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)
**Owner:** `@magnus919`

## Purpose and non-goals

The protocol defines how a reviewer — a synthetic model teacher or, optionally,
a human — turns a finding candidate into a bounded, evidence-backed label, how
disagreement is preserved, and how the label packet records provenance. It is
intentionally strict about what a label means.

It does not:

- turn a model judgment, a bot comment, a review comment count, or a green test
  run into **human** truth;
- call a single reviewer "inter-rater agreement";
- present synthetic adjudication as human judgment or calibrated accuracy;
- turn model-teacher `screening` output into adjudication;
- infer label values from prose, file names, or the harness's disposition;
- treat an empty packet as a clean review or a negative label;
- treat `NO_KNOWN_MATERIAL_DEFECTS` as proof that the change is clean.

## Severity rubric

Severity answers: *how much does this defect constrain merge or release?*
Materiality answers the narrower evaluator question: *does this count as a
material defect for precision and recall?* The labels contract currently stores
only materiality and introducedness. The four-level severity decision is
recorded in the reviewer's retained worksheet and projected into the packet as
shown below.

| Severity | Definition | Contract `materiality` | Recall eligible? | Minimum evidence |
|---|---|---|---|---|
| `blocking` | The change must not merge or ship until this is fixed: a security, data-loss, authorization, availability, or correctness failure with a credible path to harm. | `MATERIAL` | Yes, when `INTRODUCED` or `REEXPOSED` | Changed source or diff location, a concrete failure mode, and a reproduction, test, trace, or source-to-sink argument. |
| `material` | A non-blocking but substantive defect that should be fixed or explicitly accepted before release: incorrect behavior in an edge case, missing validation, broken contract, or material test/coverage gap. | `MATERIAL` | Yes, when `INTRODUCED` or `REEXPOSED` | The same evidence class as `blocking`, at the lower-impact boundary. State why it is not `blocking`. |
| `non-blocking` | A real improvement opportunity that is not a correctness or security defect: maintainability, clarity, error-message quality, or a bounded test improvement. | `NON_MATERIAL` | No | The affected location and why the impact is non-material. |
| `nit` | Style, naming, formatting, or preference with no demonstrated behavioral impact. | `NON_MATERIAL` | No | The affected location; no failure claim is implied. |

Evidence that cannot support any of the four levels is not a weak label. It is
`UNKNOWN` materiality with an abstention, as described below.

The v1 contract has no separate `severity` field. It preserves the
materiality projection, not the `blocking` versus `material` distinction. A
future labels contract may add the full severity value; until then, the
worksheet and the evidence record retain the four-level decision, and the
scorecard reports only contract-level materiality. Do not encode severity in
`label_id` or other free-form identifiers.

## Introducedness rubric

Introducedness answers: *what is this defect's relationship to the reviewed
change?* It is independent of severity.

| Value | Definition | Required evidence |
|---|---|---|
| `INTRODUCED` | The head change creates the defect, or changes behavior so that previously correct behavior becomes defective. | Base/head diff showing the changed line or changed behavior, plus the failure path. |
| `REEXPOSED` | A pre-existing latent defect becomes reachable or materially more harmful because of the head change. | Base evidence for the latent defect plus head evidence for the new reachability or impact. |
| `PRE_EXISTING` | The defect exists in the base and its reachability or impact is unchanged by the head. | Base evidence and a comparison showing no change in the relevant path. |
| `UNKNOWN` | The available evidence cannot establish the relationship. | The evidence examined and the concrete missing fact. |

Only labels classified `INTRODUCED` or `REEXPOSED` are eligible for the
material-finding recall denominator. `PRE_EXISTING` and `UNKNOWN` labels remain
visible and are counted separately; they are never silently dropped.

## Evidence requirements for every label

A label packet must cite stable evidence references. The evidence store, not
this document, defines how references resolve. At minimum, a material label
records:

1. The exact case identity (case ID, base/head SHAs, snapshot ID, profile, and
   source-manifest hash), which the packet inherits from the corpus.
2. The affected path and changed unit or line range, with diff or source
   evidence. A finding without a location may only be a candidate.
3. The failure mode or contract violated, not just a description of style.
4. The severity rationale: why this level and not the adjacent level.
5. The introducedness evidence: base versus head behavior and the changed
   range that explains the difference.
6. A reproduction, test, trace, or source-to-sink argument for `blocking` or
   `material` labels. A passing unrelated test suite is not evidence for a
   finding.
7. Reviewer provenance, reviewer kind, rubric revision, and label timestamp.

A label with missing required evidence is not downgraded to a `nit`. The
reviewer abstains or records `UNKNOWN`, and the case remains unresolved.

## Abstention

Abstention is a first-class outcome, not a rejection and not a zero.

- `ABSTAINED` on a prediction adjudication means the evidence does not support
  either a match or a rejection after reasonable review.
- `INCONCLUSIVE` on a case assessment means the case cannot support a
  bounded conclusion.
- `INCOMPLETE` or `UNKNOWN` case completeness means the reviewer cannot assert
  that no material defects are known. The contract rejects a packet that claims
  `NO_KNOWN_MATERIAL_DEFECTS` while incomplete.
- A missing or unavailable run is not an abstention by the reviewer. It remains
  a missing run in the scorecard denominator.

Abstentions are counted with their own denominator. They are never folded into
false positives, false negatives, or a clean result.

## Synthetic model-teacher adjudication (accepted method)

Synthetic adjudication is an explicit, non-human arm. A model teacher receives
the frozen case evidence and the `qm2-labeling-rubric.v1` rubric, and emits
exactly one `reviewer_kind: synthetic`, `label_role: adjudicated` packet per
case. The packet must record:

- model identity: `provider_id`, `model_id`, `model_revision`;
- `prompt_revision` for the exact teacher prompt;
- `rubric_revision`, which must equal the labels file `rubric_version`;
- `run_id`, `labeled_at`, and `output_sha256` of the retained model output;
- `synthetic: true`.

The contract enforces an exact field set. A `human` packet carrying synthetic
provenance is rejected with `invalid_reviewer_provenance`; a synthetic packet
with `synthetic: false` or missing fields is rejected with
`invalid_synthetic_provenance`; a mismatch between `rubric_revision` and the
labels file is rejected with `synthetic_rubric_mismatch`. A synthetic packet may
adjudicate finding labels, matches, rejections, abstentions, and duplicates. It
may not supply `attack_outcomes`; forbidden-effect and integrity observations
remain deterministic-observer or human evidence.

**Synthetic adjudication is model judgment, not human truth, not calibrated
accuracy, and not a release gate.** It is accepted as the project's quality
method by owner decision, not because agreement with the harness proves
correctness. Correlated model error, prompt sensitivity, and training-data
contamination remain unresolved limitations.

The order of work for a synthetic case is:

1. **Freeze the case.** Use the exact corpus identity; no substitute commit,
   PR, profile, or source manifest.
2. **Build the teacher input.** Use the frozen case content and the recorded
   prompt revision; do not add evidence that is not in the case or the bounded
   context.
3. **Run and retain the output.** Record `run_id`, model identity, prompt
   revision, timestamp, and the output SHA-256 before writing labels. Never
   reconstruct an output hash from memory or prose.
4. **Emit one adjudicated packet per case** with evidence references on every
   finding label and adjudication.
5. **Validate before use.** Run the evaluator and scorecard; a packet that fails
   `review-evaluation-labels.v1` is not evidence.

Multiple synthetic runs may exist as separate retained artifacts, but at most
one `adjudicated` synthetic packet per case enters the metrics. A rerun is a new
packet version or a new labels file, never a mutation of a used packet.

## Independent human packets and adjudication (optional arm)

The human workflow for a case family remains available but is not required:

1. **Freeze the case.** Use the exact corpus identity. The reviewer may not
   substitute a nearby commit, PR, or profile.
2. **Produce two independent human packets.** Each reviewer works without the
   other reviewer's packet, draft labels, scorecard, model-teacher output, or
   prior adjudication. Each packet uses `label_role: independent` and a distinct
   human reviewer identity.
3. **Preserve both packets.** Independent packets are provenance. They are not
   pooled into precision or recall by input order.
4. **Adjudicate separately.** A human adjudicator produces exactly one
   `label_role: adjudicated` packet per case in the human arm. The adjudicator
   may be one of the independent reviewers or a third human, but the role and
   decision are recorded explicitly. The adjudicated packet states the final
   label set, finding matches/rejections/abstentions, duplicates, and attack
   outcomes.
5. **Report disagreement before aggregation.** Record per-case and aggregate
   disagreement counts with the number of independent packets and cases. A
   single reviewer is never described as inter-rater agreement.
6. **Validate before use.** Run the evaluator/scorecard validation. A packet
   that fails `review-evaluation-labels.v1` is not evidence.

The evaluator deliberately does not choose a winner from independent packets.
When only independent packets exist, the case remains without adjudicated truth;
the scorecard reports that state as missing labels. A human adjudicated packet
and a synthetic adjudicated packet for the same case are separate arms; neither
replaces or validates the other.

## Reviewer provenance and `reviewer_kind`

`reviewer_kind` is mandatory and is never defaulted to `human`.

| `reviewer_kind` | Allowed `label_role` | Required provenance | Metric use |
|---|---|---|---|
| `synthetic` | `adjudicated` only | `provider_id`, `model_id`, `model_revision`, `prompt_revision`, `rubric_revision`, `run_id`, `labeled_at`, `output_sha256`, `synthetic: true` | Accepted synthetic-adjudicated precision/recall and completion, reported only under the synthetic arm. Never human accuracy. |
| `human` | `independent` or `adjudicated` | `reviewer_id`, `source_kind`, `labeled_at` | Optional human arm; adjudicated packets populate human-labelled metrics, independent packets remain provenance only. |
| `model_teacher` | `screening` only | `provider_id`, `model_id`, `prompt_revision`, `output_sha256`, `labeled_at` | Advisory screening counts only. No accuracy, precision, recall, or release gate. |
| `unknown` | `unknown` only | explicit `reason` | Preserved as provenance; contributes no quality metric. |

The contract enforces the role/provenance pairing: a `model_teacher` packet with
`label_role: adjudicated` is rejected with `reviewer_role_mismatch`, and a
`synthetic` packet is accepted only as `adjudicated`. This is intentional.
**Model-teacher screening is not adjudication and not truth.** Adding the
synthetic kind does not promote screening output; it creates a separate arm with
its own provenance and its own non-human metric scope.

A missing provenance record becomes `unknown`; it never becomes `human`.
`source_kind` for human labels is one of `tests`, `maintainer`, `incident`,
`independent_reviewer`, or `other`, and is provenance, not proof.

## Provenance, rubric revision, and timestamps

Every labels file records:

- `contract_version: review-evaluation-labels.v1`;
- `corpus_id` and `dataset_version`, which must exactly match the corpus;
- `rubric_version: qm2-labeling-rubric.v1` for this protocol;
- one or more packets with reviewer provenance and `labeled_at` timestamps.

Every human packet records a stable `reviewer_id`, source kind, and timestamp.
Every model-teacher screening packet records provider, exact model ID, prompt
revision, output SHA-256, and timestamp. Every synthetic packet records the full
model identity, prompt and rubric revisions, run ID, timestamp, output SHA-256,
and the explicit `synthetic: true` marker. Every finding label and adjudication
cites evidence references. The scorecard records the input hashes and the
evaluator revision, so a report is bound to the bytes and evaluator that
produced it.

Timestamps are provenance only. They do not establish ordering, freshness, or
independence.

## Relabeling and packet versions

Labels are immutable once used in a report.

- A correction, new reviewer, new rubric revision, or newly available evidence
  creates a **new packet version** in a new labels file (for example
  `labels-v2.json`) with a new `rubric_version` or `dataset_version`.
- The prior labels file and its hash remain retained. It is never edited in
  place, and an old packet is never silently replaced.
- The new packet set must pass the same contract validation and is then used to
  regenerate the scorecard. Reports name the exact input hashes.
- A packet version does not rewrite history: if the prior packet was used in a
  published scorecard, both reports remain visible with their respective
  hashes.

The pilot manifest records `packet_version: labels-pilot-v1` and
`supersedes: null`. A relabel creates a new manifest and packet set.

## Packet shape

The contract accepts exactly these packet fields:

```json
{
  "case_id": "<corpus case id>",
  "reviewer": {
    "reviewer_kind": "human",
    "reviewer_id": "<stable human id>",
    "source_kind": "independent_reviewer",
    "labeled_at": "<ISO-8601 timestamp>"
  },
  "label_role": "independent",
  "case_completeness": "COMPLETE",
  "case_assessment": "MATERIAL_DEFECTS_PRESENT",
  "finding_labels": [
    {
      "label_id": "<stable label id>",
      "materiality": "MATERIAL",
      "introducedness": "INTRODUCED",
      "evidence_refs": ["<evidence id>"]
    }
  ],
  "adjudications": [],
  "attack_outcomes": []
}
```

The example is a shape, not a label. Do not copy it into the pilot corpus as if
it were a human finding. The original [`labels.json`](../examples/evaluation/qm2-labeling-pilot-v1/labels.json)
remains empty; the retained synthetic packets live in
[`labels-synthetic-v1.json`](../examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json).

A synthetic adjudicated packet has this reviewer shape instead of the human
reviewer object (all other packet fields are unchanged):

```json
{
  "reviewer_kind": "synthetic",
  "provider_id": "<configured provider id>",
  "model_id": "<exact model id>",
  "model_revision": "<exact model or weights revision>",
  "prompt_revision": "<prompt revision id>",
  "rubric_revision": "qm2-labeling-rubric.v1",
  "run_id": "<retained run id>",
  "labeled_at": "<ISO-8601 timestamp>",
  "output_sha256": "<sha256 of the retained model output>",
  "synthetic": true
}
```

This shape is also not a label. It becomes evidence only when an actual run
produced the output whose hash it records.

## Current pilot state

The fixed pilot subset is
[examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json):
six cases, both repositories, all three splits, and identities copied unchanged
from `frozen-corpus-v1`. A retained synthetic run is present:

- `run_id`: `qm2-synthetic-pilot-2026-11-02`;
- provider `deepseek`, model ID/revision `deepseek-v4.1-flash-1017`;
- prompt revision `qm2-synthetic-adjudication-prompt-v1`, rubric
  `qm2-labeling-rubric.v1`;
- six synthetically adjudicated packets: five `COMPLETE` /
  `NO_KNOWN_MATERIAL_DEFECTS` with empty `finding_labels`, and
  `qm1-slopsearx-pr770` `INCOMPLETE` / `INCONCLUSIVE` because the frozen
  manifest records `evidence_completeness: incomplete`;
- zero human packets, zero model-teacher screening packets, and zero prediction
  runs.

The evidence is retained under
[`examples/evaluation/qm2-labeling-pilot-v1/evidence/`](../examples/evaluation/qm2-labeling-pilot-v1/evidence/):
the six exact diffs, `prompt.md`, `request.json`, and the raw
`teacher-response.txt`. `request.json` binds the prompt SHA-256 and each case's
diff SHA-256 and byte count. The six packets are in
`labels-synthetic-v1.json`; `teacher-output-2026-11-02.json` records the same
packets and adds `output_sha256`.

`output_sha256` is the SHA-256 of the retained **retained response** file
`teacher-response.txt`, not of `teacher-output-2026-11-02.json`. A response
cannot contain the hash of a file that contains that hash, so the output record
adds the digest only after the response bytes are fixed. Never hash the output
record itself and copy that value into its own packets.

The empty findings are conservative adjudications of bounded inputs, not a
clean-review claim. The **empty pilot fixture** at
`examples/evaluation/qm2-labeling-pilot-v1/predictions.json` still reports
`MISSING_DATA`; it is retained unchanged as a contract fixture.

The **five-case baseline** is separate and is the QM-2 closure evidence:

```sh
python3 scripts/evaluate_reviews.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-baseline-scorecard-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json \
  --json

python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-baseline-scorecard-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json \
  --json
```

That scorecard is `PARTIAL`: the harness arm completed 5 of 6 cases
(`qm1-slopsearx-pr770` missing and not imputed), the synthetic label arm is
`present` with 5 complete adjudicated packets of 6, synthetic precision has a
4/4 denominator with 4 unadjudicated findings, and accuracy is refused. The
human arm is `missing`.

## What remains for QM-3

QM-2 is closed. The remaining quality work belongs to QM-3: a second prediction
arm, an owner-accepted baseline, a decision on the incomplete `pr770` case, and a
scheduled full-corpus run that adjudicates at least one material finding.
## Validation

```sh
python3 -m pytest -q tests/test_qm2_synthetic_pilot.py tests/test_quality_scorecard.py tests/test_evaluation.py tests/test_frozen_corpus.py
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
```

See [QUALITY-SCORECARD.md](QUALITY-SCORECARD.md) for the scorecard fields and
regression-gate behavior.

## Retained pilot limitation

The checked-in synthetic pilot is a provenance-corrected normalization of a
model output from the harness teacher, not a fresh live provider call. Its
prompt, diffs, request manifest, response bytes, and output hash are retained;
transport logs are not. It supports no human-truth or quality claim.
