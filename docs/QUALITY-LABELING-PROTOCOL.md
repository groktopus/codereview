# Quality labeling and adjudication protocol (QM-2)

**Status:** versioned protocol and rubric; **no human labels exist**. This document
does not establish review quality, accuracy, or replacement readiness. Issue
[#243](https://github.com/groktopus/codereview/issues/243) remains open because
the human-adjudication exit criterion is unmet.

**Rubric revision:** `qm2-labeling-rubric.v1`
**Contract:** `review-evaluation-labels.v1` in
[experiments/harness/evaluation.py](../experiments/harness/evaluation.py)
**Pilot subset:** [examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json)
**Owner:** `@magnus919`

## Purpose and non-goals

The protocol tells a human reviewer how to turn a finding candidate into a
bounded, evidence-backed label, how a second human resolves disagreement, and
how the label packet preserves provenance. It is intentionally strict about
what a label means.

It does not:

- turn a model judgment, a bot comment, a review comment count, or a green test
  run into a human label;
- call a single reviewer "inter-rater agreement";
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

## Independent packets and adjudication

The human workflow for a case family is:

1. **Freeze the case.** Use the exact corpus identity. The reviewer may not
   substitute a nearby commit, PR, or profile.
2. **Produce two independent human packets.** Each reviewer works without the
   other reviewer's packet, draft labels, scorecard, model-teacher output, or
   prior adjudication. Each packet uses `label_role: independent` and a distinct
   human reviewer identity.
3. **Preserve both packets.** Independent packets are provenance. They are not
   pooled into precision or recall by input order.
4. **Adjudicate separately.** A human adjudicator produces exactly one
   `label_role: adjudicated` packet per case. The adjudicator may be one of the
   independent reviewers or a third human, but the role and decision are
   recorded explicitly. The adjudicated packet states the final label set,
   finding matches/rejections/abstentions, duplicates, and attack outcomes.
5. **Report disagreement before aggregation.** Record per-case and aggregate
   disagreement counts with the number of independent packets and cases. A
   single reviewer is never described as inter-rater agreement.
6. **Validate before use.** Run the evaluator/scorecard validation. A packet
   that fails `review-evaluation-labels.v1` is not evidence.

The evaluator deliberately does not choose a winner from independent packets.
When only independent packets exist, the case remains without adjudicated truth;
the scorecard reports that state as missing labels.

## Reviewer provenance and `reviewer_kind`

`reviewer_kind` is mandatory and is never defaulted to `human`.

| `reviewer_kind` | Allowed `label_role` | Required provenance | Metric use |
|---|---|---|---|
| `human` | `independent` or `adjudicated` | `reviewer_id`, `source_kind`, `labeled_at` | Adjudicated packets can populate human precision/recall; independent packets remain provenance only. |
| `model_teacher` | `screening` only | `provider_id`, `model_id`, `prompt_revision`, `output_sha256`, `labeled_at` | Advisory screening counts only. No accuracy, precision, recall, or release gate. |
| `unknown` | `unknown` only | explicit `reason` | Preserved as provenance; contributes no human metric. |

The contract enforces the role/provenance pairing: a `model_teacher` packet with
`label_role: adjudicated` is rejected with `reviewer_role_mismatch`. This is
intentional. **Model-teacher screening is not human judgment, not adjudication,
and not truth.** It cannot satisfy the human-adjudication exit criterion, even
when it agrees with a prediction.

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
Every model-teacher packet records provider, exact model ID, prompt revision,
output SHA-256, and timestamp. Every finding label and adjudication cites
evidence references. The scorecard records the input hashes and the evaluator
revision, so a report is bound to the bytes and evaluator that produced it.

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
it were a human finding. The checked-in pilot labels file is deliberately empty.

## Current pilot state and missing data

The fixed pilot subset is
[examples/evaluation/qm2-labeling-pilot-v1](../examples/evaluation/qm2-labeling-pilot-v1/manifest.json):
six cases, both repositories, all three splits, identities copied unchanged from
`frozen-corpus-v1`, and **zero human packets, zero model-teacher packets, and
zero predictions**. The empty files are valid contract inputs and score as
`MISSING_DATA`, not as zero findings, zero precision, or a clean result.

No model-teacher screening packet is checked in. None was generated by an
actual deterministic offline process for this pilot, so inventing one would
fabricate provenance. If a real screening run is added later, it must be
marked `reviewer_kind: model_teacher`, `label_role: screening`, and retain the
provider/model/prompt/hash/timestamp fields. It will still not count as human
or adjudicated truth.

## What remains for QM-2

- Real human independent packets from two reviewers on at least one case family.
- A separate human adjudicated packet.
- Recorded disagreement counts and denominators.
- Labels that validate against `review-evaluation-labels.v1` with non-empty
  human findings.
- A human adjudication record that is not model-teacher output.

Until those exist, QM-2 stays open and the scorecard keeps the
human-adjudication criterion unmet.

## Validation

```sh
python3 -m pytest -q tests/test_quality_scorecard.py tests/test_evaluation.py tests/test_frozen_corpus.py
python3 scripts/generate_quality_scorecard.py \
  --corpus examples/evaluation/qm2-labeling-pilot-v1/corpus.json \
  --predictions examples/evaluation/qm2-labeling-pilot-v1/predictions.json \
  --labels examples/evaluation/qm2-labeling-pilot-v1/labels.json \
  --json
```

See [QUALITY-SCORECARD.md](QUALITY-SCORECARD.md) for the scorecard fields and
regression-gate behavior.
