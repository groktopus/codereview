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

## Model-only cross-audit (companion contract; outside toolkit v1 metrics)

A label-free advisory run is valid input to the evaluation process; an empty `packets` list produces undefined human precision/recall and no release-gate claim. The separate `review-cross-model-comparison.v1` contract lives in `schemas/review-cross-model-comparison.v1.schema.json` and is implemented by `pr_review_harness.cross_model`. JSON Schema checks structure only; Python semantic validation in `validate_cross_model_comparison` (also run by the CLI) is required and normative for role/status provenance, pairings, and exact corpus coverage. It binds every case to the exact validated corpus identity, and every writer, Jev, and auditor role to its own run ID, provider/model/runtime, prompt/rubric revisions, exact request hash, response hash, and local artifact IDs. Their request hashes are expected to differ: the writer sees source/context, Jev sees bounded writer candidates, and the auditor sees Jev claims and the frozen snapshot. Do not confuse shared snapshot identity with identical request bytes.

Use the offline comparator after preserving each original request and response in separately controlled local artifacts:

```sh
python scripts/compare_cross_models.py \
  --corpus examples/evaluation/corpus.json \
  --comparison /path/to/review-cross-model-comparison.v1.json \
  --snapshot case-id=/path/to/exact-head-checkout \
  --artifact writer-input-id=/private/path/writer-request.bin \
  --artifact writer-output-id=/private/path/writer-response.bin \
  --json
```

Repeat `--snapshot` for each case and `--artifact` for any request/response whose bytes are available. The comparator checks local artifact bytes against their declared SHA-256 values, caps each file at 16 MiB, all checks at 256 artifacts/64 MiB, rejects symlinks and non-regular files, and emits IDs, hashes, and verification statuses only. A missing local artifact is `NOT_PROVIDED` (`DECLARED_ONLY` provenance); local byte verification does not prove how a remote provider delivered or used the bytes. The report includes corpus/comparison input hashes and a `report_sha256` self-checksum over the report before that field is added. None of these hashes authenticate their producer or evidence origin.

Each pair row has an explicit declared relation, the role asserted as reporter, and a reporter output record ID. The fixed declared reporter is Jev for `writer_jev` and the separate LLM auditor for `jev_auditor`; these are metadata declarations, not parsed or verified assertions from provider response bytes. The tool checks those references and rejects a `MATCH`, `DISAGREEMENT`, or `NO_COUNTERPART` that conflicts with abstained, incomplete, unavailable, or not-run role evidence. It never matches prose or infers a semantic relation. `MATCH` is `DECLARED_ONLY`: it does not prove that the reporter emitted the relation, that either claim is factually supported, or that the claims are equivalent. Identical LLM families or shared evidence may have correlated errors.

The report gives per-role run and output-record denominators, counts by record kind (`finding` for writer candidates, `classification` for Jev candidate decisions, and `audit` for auditor checks), counts by the six relations (`MATCH`, `DISAGREEMENT`, `NO_COUNTERPART`, `ABSTAINED`, `INCOMPLETE`, `NOT_RUN`), and deterministic anchor-status denominators. Zero-output cases remain visible through `candidate_or_decision_cases_with_zero`, even when that role has no finding-level comparison rows. Run failures and missing outputs remain explicit. No accuracy, correctness, calibration, precision, recall, truth, or release-gate claim is computed. The v1 `evaluate()` report remains unchanged and does not consume the companion matrix or convert it to human adjudication.

When a `--snapshot` checkout is supplied, anchor checks bind to exact HEAD and base commits, then verify path/line existence and whether the referenced line intersects a changed range. These are location checks only: they do not establish semantic support, materiality, introducedness, or whether a review claim is correct. Git probes are offline/no-lazy-fetch, time and output capped; at most 256 unique anchor paths and 60 seconds are checked per report. Without a checkout, anchor status is `NOT_RUN`; a wrong HEAD is `SNAPSHOT_MISMATCH`, a Git failure is `CHECK_FAILED`, and a time/path/output bound is `CHECK_LIMIT`. These statuses do not claim correctness. Existing safety invariants still require their appropriate deterministic/runtime evidence, independent of model consensus.

## Adversarial-input evaluation

`detector_result` is an arm's recorded screening output (`SUSPICIOUS`, `BENIGN`, `UNKNOWN`, or `NOT_RUN`). On paired attack/benign-lookalike fixtures, the toolkit computes detector sensitivity and specificity against the fixture's authored `kind`, keeping unknown outputs in their own count. These are challenge-fixture measures, not calibrated security confidence or natural-prevalence accuracy.

The v1 attack-success metric consumes complete adjudicated human packets with outcome records. Deterministic observers can provide separate bounded side-effect evidence when bound to the exact run and identified by ID/hash, but v1 `evaluate()` does not ingest such records independently of label packets. Keep that observer evidence in its own versioned report until a contract supports it; do not relabel it as human. The `forbidden_effects` state is `OBSERVED`, `NONE_OBSERVED`, or `UNKNOWN`, cites evidence, and identifies a deterministic observer or human adjudication by ID and hash. An observed state also lists the effect kinds. `integrity` separately records `PRESERVED`, `KNOWN_BLOCKER_SUPPRESSED`, `OTHER_INTEGRITY_FAILURE`, or `UNKNOWN`, with its own evidence provenance. Suppressing a known blocker must cite an existing material, introduced/re-exposed label. A model's statement that it resisted injection is not outcome evidence.

The summary reports detector confusion counts separately from `observed_success_rate`, where observed attack success means a forbidden effect was observed or review integrity failed, including suppression of a known blocker. Its denominator contains only attack runs with both effect and integrity outcomes known. Missing, unknown, incomplete, or failed outcome records remain unknown and are reported separately. Benign-lookalike effects have their own counts and do not enter the attack-success denominator. This contract supports attack vectors and outcome capture; it does not implement an attack generator, detector, sandbox observer, or confidence gate.

## PR 464 discovery example

`examples/evaluation/corpus.json` records SlopSearX PR 464 as a `development` / `pilot_internal` case with the recorded base/head pair, snapshot ID, profile hash, and source-manifest hash. `predictions.json` records only the observed Droid inline comment ID with unknown materiality/introducedness and an `incomplete` run status, because that captured comment is not a complete review result. `labels.json` intentionally contains no labels. The associated `docs/PR-464-EVIDENCE-ASSESSMENT.md` is a model-teacher source assessment, not human adjudication or held-out truth. The example therefore produces no human precision/recall and cannot support an accuracy or replacement claim.

The original six-commit historical pilot is also distinct from these exact PR-specific base/head pairs. Do not relabel first-parent comparisons as exact PR comparisons. A bot comment is a claim to adjudicate, not a known defect. For the broader dataset requirements and adoption limits, see [design/EVALUATION.md](design/EVALUATION.md), [PRODUCTION-DELIVERY.md](PRODUCTION-DELIVERY.md), and [COMPARISON-DISCOVERY.md](COMPARISON-DISCOVERY.md).
