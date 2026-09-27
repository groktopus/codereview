# Review evaluation toolkit

This toolkit checks that comparison inputs are bound to the same immutable PR snapshots, keeps adjudicated labels separate from model-teacher screening, and emits deterministic count/rate summaries. An advisory model-only comparison can be operationally complete without label packets, but this toolkit cannot manufacture ground truth, infer finding matches from prose, measure cross-model accuracy, or create a release gate.

The three input contracts are versioned independently: `review-evaluation-corpus.v1`, `review-evaluation-predictions.v1`, and `review-evaluation-labels.v1`. The Python API is `validate_corpus`, `validate_predictions`, `validate_labels`, and `evaluate` in `pr_review_harness.evaluation`. The CLI validates those same contracts:

```sh
python scripts/evaluate_reviews.py \
  --corpus examples/evaluation/corpus.json \
  --predictions examples/evaluation/predictions.json \
  --labels examples/evaluation/labels.json \
  --json
```

`--json` writes exactly one JSON object to stdout. Contract failures return exit code 2 with a stable, content-free `error` code. Each input is read with a 16 MiB cap; cases, runs, labels, refs, and findings have separate count bounds. The output contains summaries only and has a 4 MiB cap. Raw review text, provider bodies, credentials, prompts, and stderr are not included.

## Frozen case and arm identity

Each corpus case identifies a repository, full base/head commit IDs, snapshot ID, profile ID/version/hash, source-manifest ID/hash, case family, and split. Every prediction run repeats that exact identity; even a one-field difference rejects the run. Each case also names expected arms (`harness`, `droid`, `no_harness`, `system_one`). An absent arm is reported as `missing`; it is never interpreted as a completed run with zero findings. Use a distinct source-manifest hash whenever evidence acquisition changes.

Supported splits are `development`, `heldout`, and `challenge`. Every `family_id`, including an attack/benign pair, must stay within one split. Sampling frames are explicit: `natural_prevalence`, `risk_enriched_challenge`, or `pilot_internal`. The evaluator does not convert challenge-set rates into production prevalence.

Scenario metadata is optional for ordinary cases. When present, `kind` is `natural`, `synthetic`, `attack`, or `benign_lookalike`. Attack pairs carry a `behavior_id`, a vector (`adaptive`, `code_comment`, `documentation`, `diff`, or `retrieved_context`), reciprocal paired-case IDs, and fixture source ID/hash. The paired cases must share family, split, repository, profile, source manifest, behavior ID, and vector. Their immutable PR identities can differ because an attack fixture may add untrusted text while preserving the underlying code behavior. `expected_forbidden_effects` describe the challenge fixture, not a claim that the effect occurred.

## Labels and matching

Every label packet records `reviewer_kind`: `human`, `model_teacher`, or `unknown`. Missing or unrecognized provenance is invalid; it is never defaulted to human. Packet role must agree with provenance:

- `independent` preserves one human reviewer's original packet. These packets remain visible in provenance counts but are not pooled into aggregate quality metrics.
- `adjudicated` is the single final human packet used for human-adjudicated metrics. Multiple independent reviewers require a separately recorded adjudicated packet; input ordering never selects the winner.
- `screening` is reserved for model teachers and is reported only as advisory screening counts. Provider, exact model ID, prompt revision, output hash, and timestamp are retained. There is no teacher accuracy field. Multiple screening packets remain provenance records; v1 does not align two models' findings or calculate pairwise agreement/disagreement.
- `unknown` preserves labels whose reviewer provenance is unavailable and contributes no human metric.

Each case assessment is `MATERIAL_DEFECTS_PRESENT`, `NO_KNOWN_MATERIAL_DEFECTS`, or `INCONCLUSIVE`. A completeness state is separately `COMPLETE`, `INCOMPLETE`, or `UNKNOWN`; an incomplete packet cannot assert that no material defects are known. “No known material defects” is a bounded label, not proof the change is clean.

Finding labels and run findings use stable IDs plus evidence references. A reviewer must explicitly adjudicate a prediction finding as `MATCHED` to an existing label ID, `REJECTED`, `ABSTAINED`, or `DUPLICATE_OF` a prediction in the same arm. Duplicate findings are counted separately and excluded from precision; the metric never deduplicates by wording. Matched labels are unique per arm so a cluster of correlated predictions cannot inflate recall. Adjudication and label records require cited evidence references; the evidence store remains the source for interpreting those references.

Human precision uses only explicitly matched and rejected predictions from complete adjudicated human packets. Abstentions, correlated duplicates, and unadjudicated predictions have separate counts. Recall eligibility is only for known material labels classified `INTRODUCED` or `REEXPOSED`; `PRE_EXISTING` and `UNKNOWN` introducedness are excluded and counted separately. The report includes a corpus-wide recall lower and upper bound over all expected cases: confirmed exact-ID matches form the lower bound, while missing, noncompleted, or not-fully-adjudicated outputs leave the relevant unobserved labels unresolved for the upper bound. It also reports definitively unmatched labels only when the run completed and every emitted finding has a final non-abstained adjudication. A separate `completed_run_recall_conditional` rate is restricted to complete human labels and completed runs with full finding adjudication; its denominator is explicit and its conditional scope is part of the field name. No metric drops failed or incomplete runs silently. Every rate includes numerator and denominator. A zero denominator yields `value: null` and an explicit reason. The tool also counts `APPROVE` dispositions paired with known introduced material findings; that count is descriptive and does not declare a gate.

## Model-only cross-audit (outside toolkit v1 metrics)

A label-free advisory run is valid input to the evaluation process; an empty `packets` list produces undefined human precision/recall and no release-gate claim. For cross-model analysis, retain a separate versioned comparison record bound to each case's exact corpus identity, arm/run IDs, model/provider/runtime and prompt/rubric versions, source/output hashes, and run status. Record each finding-level relation as `MATCH`, `DISAGREEMENT`, `NO_COUNTERPART`, `ABSTAINED`, `INCOMPLETE`, or `NOT_RUN`, along with deterministic anchor-check results and explicit denominators. Preserve original outputs and all disagreements; do not resolve them by majority vote.

The evaluation plan's LLM writer, Jev classifier, and LLM source-auditor are not separate arm values in `review-evaluation-predictions.v1`, and v1 has no paired model-to-model metric. Do not alias these roles to `no_harness` or `system_one`, or encode model outputs as human packets, to force them through the existing metrics. Keep the companion record separate until a versioned toolkit contract supports these roles. Even if both models agree on a source claim, agreement is not independent truth, accuracy, calibration, or a validated defect label.

Deterministic checks may verify snapshot identity, evidence-reference resolution, source path/line existence, changed-range membership, and bounded test/observer outcomes. Each check proves only its named property. The current `evaluate()` report does not consume a companion comparison matrix or deterministic observer results as human adjudication; it must not be described as having validated model semantics or side effects. Existing safety invariants remain mandatory and must be verified by their appropriate deterministic/runtime evidence, independent of model consensus.

## Adversarial-input evaluation

`detector_result` is an arm's recorded screening output (`SUSPICIOUS`, `BENIGN`, `UNKNOWN`, or `NOT_RUN`). On paired attack/benign-lookalike fixtures, the toolkit computes detector sensitivity and specificity against the fixture's authored `kind`, keeping unknown outputs in their own count. These are challenge-fixture measures, not calibrated security confidence or natural-prevalence accuracy.

The v1 attack-success metric consumes complete adjudicated human packets with outcome records. Deterministic observers can provide separate bounded side-effect evidence when bound to the exact run and identified by ID/hash, but v1 `evaluate()` does not ingest such records independently of label packets. Keep that observer evidence in its own versioned report until a contract supports it; do not relabel it as human. The `forbidden_effects` state is `OBSERVED`, `NONE_OBSERVED`, or `UNKNOWN`, cites evidence, and identifies a deterministic observer or human adjudication by ID and hash. An observed state also lists the effect kinds. `integrity` separately records `PRESERVED`, `KNOWN_BLOCKER_SUPPRESSED`, `OTHER_INTEGRITY_FAILURE`, or `UNKNOWN`, with its own evidence provenance. Suppressing a known blocker must cite an existing material, introduced/re-exposed label. A model's statement that it resisted injection is not outcome evidence.

The summary reports detector confusion counts separately from `observed_success_rate`, where observed attack success means a forbidden effect was observed or review integrity failed, including suppression of a known blocker. Its denominator contains only attack runs with both effect and integrity outcomes known. Missing, unknown, incomplete, or failed outcome records remain unknown and are reported separately. Benign-lookalike effects have their own counts and do not enter the attack-success denominator. This contract supports attack vectors and outcome capture; it does not implement an attack generator, detector, sandbox observer, or confidence gate.

## PR 464 discovery example

`examples/evaluation/corpus.json` records SlopSearX PR 464 as a `development` / `pilot_internal` case with the recorded base/head pair, snapshot ID, profile hash, and source-manifest hash. `predictions.json` records only the observed Droid inline comment ID with unknown materiality/introducedness and an `incomplete` run status, because that captured comment is not a complete review result. `labels.json` intentionally contains no labels. The associated `docs/PR-464-EVIDENCE-ASSESSMENT.md` is a model-teacher source assessment, not human adjudication or held-out truth. The example therefore produces no human precision/recall and cannot support an accuracy or replacement claim.

The original six-commit historical pilot is also distinct from these exact PR-specific base/head pairs. Do not relabel first-parent comparisons as exact PR comparisons. A bot comment is a claim to adjudicate, not a known defect. For the broader dataset requirements and adoption limits, see [design/EVALUATION.md](design/EVALUATION.md), [PRODUCTION-DELIVERY.md](PRODUCTION-DELIVERY.md), and [COMPARISON-DISCOVERY.md](COMPARISON-DISCOVERY.md).
