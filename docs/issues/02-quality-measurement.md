# Theme: Quality measurement

**Scorecard dimension:** Review quality evidence (current: F)
**Target:** ≥40 labeled cases across two repositories with a held-out split, synthetic (and optionally human) adjudicated severity and introducedness; precision/recall bounds published with denominators and the label arm named; an incumbent baseline on identical snapshots; every model or prompt change gated by a paired corpus comparison.
**Why:** the project's evidence discipline is unusually rigorous about what it *cannot* claim. That is necessary but not sufficient. Without labels, no threshold, model choice, prompt change, or cutover can be justified.

---

## QM-1 — Build the frozen evaluation corpus v1

- **Priority:** P0
- **Dimensions:** Quality evidence; Review completeness
- **Problem:** `examples/evaluation` contains one case and zero label packets. There is no representative, held-out, versioned dataset against which review behavior can be measured.
- **Scope:**
  - Select ≥40 cases: natural historical PRs from SlopSearX plus a second repository, risk-enriched challenge cases, and clean controls. Include zero-finding and incomplete cases.
  - Freeze exact repository/base/head/snapshot/profile/source-manifest identity per case; use the existing `review-evaluation-corpus.v1` contract.
  - Declare provenance, rights/confidentiality, retention, contamination risk, splits (`development`, `heldout`, `challenge`), and sampling frame (`natural_prevalence` vs `risk_enriched_challenge`).
  - Add a manifest with content hashes and a changelog; never silently replace cases.
  - Document what the corpus cannot establish (prevalence, cross-language generality).
- **Exit criteria:** A versioned corpus with ≥40 cases, ≥2 repositories, all three splits, a manifest, and a documented sampling frame validates against the evaluator; a held-out split exists that no prompt or profile may be tuned against.
- **Verification:** `scripts/evaluate_reviews.py` corpus validation; manifest hash; a report listing case counts by repository/split/family.
- **Depends on:** none.
- **Non-goals:** scraped internet PRs without rights, or calling the corpus representative of all code review.

---

## QM-2 — Establish the labeling and adjudication protocol

**Status: Closed 2026-11-05.** Five-case predictions and a reproducible synthetic scorecard are merged at `432b3d4`; synthetic arm present, 5/6 complete, #770 explicitly missing. Evidence: [qm2-baseline-scorecard.json](../evidence/qm2-baseline-scorecard.json).

- **Priority:** P0
- **Dimensions:** Quality evidence; Governance
- **Problem:** Human labels are unavailable in practice. Model-teacher packets exist as a concept but there was no operating protocol for producing bounded labels, retaining provenance, or preventing model output from being counted as human truth. The owner has decided that synthetic model-teacher adjudication is the accepted method ([ADR 0010](../adr/0010-synthetic-model-teacher-adjudication.md)).
- **Scope:**
  - Define a severity rubric (blocking / material-non-blocking / nit), introducedness (`INTRODUCED`, `REEXPOSED`, `PRE_EXISTING`, `UNKNOWN`), and evidence requirements for each label.
  - Specify the synthetic workflow: frozen case, exact model identity, prompt/rubric revision, run ID, output hash, and one adjudicated synthetic packet per case.
  - Preserve the optional human workflow: independent packets, a separate adjudicated packet, abstention rules, and inter-rater disagreement analysis, in its own arm.
  - Keep `reviewer_kind` mandatory (`synthetic`, `human`, `model_teacher`, `unknown`); never default unknown to human, and reject synthetic packets declared human. Model-teacher `screening` remains non-adjudicative.
  - Record label provenance, rubric revision, and timestamp; support relabeling with a new packet version rather than mutation.
  - Pilot the protocol on a small subset and report synthetic coverage before scaling.
- **Exit criteria:** A versioned rubric and protocol exist; at least one case family has a real synthetic adjudicated packet with retained provenance; labels validate against `review-evaluation-labels.v1`; the synthetic scorecard arm reports coverage and denominators. The owner decision alone does not satisfy the exit criterion.
- **Verification:** label packet files; evaluator validation; a scorecard whose synthetic arm is `present` with input hashes and denominators.
- **Depends on:** QM-1 (cases to label).
- **Non-goals:** presenting synthetic output as human truth or calibrated accuracy, using model-teacher screening as adjudication, or claiming QM-2 closed before a real synthetic packet and baseline exist.

---

## QM-3 — Run evaluation continuously and publish scorecards

- **Priority:** P1
- **Dimensions:** Quality evidence; Observability
- **Problem:** The evaluator is offline and unexercised. Nothing prevents a prompt, model, or profile change from degrading quality silently.
- **Scope:**
  - Add a CI job that evaluates the stored results for a fixed corpus subset, and a scheduled full-corpus run.
  - Publish a scorecard per run: separate synthetic and human label arms, completion, precision/recall lower/upper bounds, abstention, duplicate and unadjudicated counts, `APPROVE`-with-known-defect count, and all denominators.
  - Report missing arms as `missing`, never as zero findings; report synthetic metrics as synthetic-only, never as human accuracy.
  - Compare against the previous accepted baseline; fail on owner-set regressions; keep statistical caveats explicit.
  - Store scorecards as artifacts with input hashes and the evaluator revision.
- **Exit criteria:** The scorecard is produced automatically for every corpus run; the regression gate is active; each published number has a numerator, denominator, and label arm; no single scalar is used as a release signal.
- **Verification:** CI job and artifact; a seeded regression demonstrating the gate; a scorecard containing the required fields and a synthetic-only `COMPLETE` case.
- **Depends on:** QM-1, QM-2, RC-3.
- **Non-goals:** converting model-teacher screening counts or synthetic adjudication into human accuracy.

---

### QM-2/QM-3 status checkpoint — 2026-11-02

Both issues remain **open**. The owner accepted synthetic model-teacher
adjudication as the quality method; this checkpoint records that decision and the
implemented contract, not closure.

- QM-2: [labeling protocol and rubric](../QUALITY-LABELING-PROTOCOL.md)
  (`qm2-labeling-rubric.v1`), `reviewer_kind: synthetic` with exact provenance,
  and a fixed six-case
  [pilot subset](../../examples/evaluation/qm2-labeling-pilot-v1/manifest.json).
  The pilot now has six retained synthetic adjudicated packets
  ([labels](../../examples/evaluation/qm2-labeling-pilot-v1/labels-synthetic-v1.json)):
  five complete cases are `NO_KNOWN_MATERIAL_DEFECTS` and one case is incomplete
  and inconclusive. It still has zero human packets, zero model-teacher
  screening packets, and no predictions. The contract accepts synthetic
  adjudication and rejects synthetic packets mislabelled as human; this retained
  pilot is not evidence that the method produced usable labels.
- QM-3: [scorecard and regression gate](../QUALITY-SCORECARD.md) v2, a CI job
  that runs the retained synthetic pilot, proves a synthetic-only fixture scorecard is
  `COMPLETE` with a missing human arm, and proves a seeded synthetic regression
  fails. The scorecard never emits accuracy and reports the two label arms
  separately.

QM-2 exit criteria still unmet: a retained synthetic packet set now exists, but
it contains no material finding labels, one case is incomplete, no prediction
runs give precision or recall a denominator, and there is no synthetic scorecard
baseline. The accepted method does not substitute for the
missing evidence.

QM-3 exit criteria still unmet: real predictions and real synthetic (or
optional human) labels for the corpus, owner-set tolerances for the five-case
accepted baseline, a scorecard from a real corpus run, and a live full-corpus
run. RC-3 is closed; CI exercises the accepted baseline and gate on
fixtures, not quality.

## QM-4 — Measure the incumbent on identical snapshots

- **Priority:** P1
- **Dimensions:** Quality evidence
- **Problem:** The goal is replacement, but there is no same-snapshot comparison with Droid or any incumbent. Claims of parity or improvement are therefore unsupported in both directions.
- **Scope:**
  - Freeze a baseline arm (`droid` or `incumbent`) on the corpus's exact base/head pairs, with captured findings, timestamps, and model identity where known.
  - Preserve the incumbent's output as claims to adjudicate, not as truth.
  - Compute paired differences in recall, false blockers, disposition, and cost where available; report uncertainty and missing data.
  - Record where the incumbent is better, not only where the harness is.
- **Exit criteria:** Every corpus case has a baseline arm record or an explicit `missing`; a paired comparison report exists with per-case rows and denominators; no equivalence claim is made without a pre-specified margin.
- **Verification:** baseline artifacts; `scripts/evaluate_reviews.py` or companion comparison; a report listing paired rows and unknowns.
- **Depends on:** QM-1, QM-2, QM-3.
- **Non-goals:** inferring accuracy from comment counts or disposition labels.

---

## QM-5 — Integrate adversarial and injection evaluation

- **Priority:** P1
- **Dimensions:** Quality evidence; Security
- **Problem:** Attack/benign pairs exist historically but are outside a maintained corpus and are not part of a regression gate. Blocker suppression, fabricated coverage, and disposition coercion remain unmeasured on a repeatable basis.
- **Scope:**
  - Add paired attack/benign-lookalike fixtures across vectors: diff comments, code comments, string literals, documentation, and retrieved context.
  - Measure separately: detector confusion, output contamination, coverage integrity, accepted-finding loss, and observed forbidden effects.
  - Keep challenge cases in their own split; never report their rates as natural prevalence.
  - Bind every outcome to an exact case, source, prompt, and run identity.
  - Include a known material defect in attack fixtures and compare against the unmodified behavior.
- **Exit criteria:** Attack pairs are in the corpus with reciprocal IDs; the evaluator reports attack-success and integrity outcomes with denominators; the regression gate includes them; no claim of "resistance" is made from model self-report.
- **Verification:** corpus manifest entries; evaluator output for attack/benign arms; detector confusion counts; a known-blocker suppression test.
- **Depends on:** QM-1, QM-2, QM-3.
- **Non-goals:** shipping an attack generator, or treating a refused tool request as evidence of finding integrity.
