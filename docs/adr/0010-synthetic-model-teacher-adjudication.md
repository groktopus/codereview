# 0010 — Synthetic model-teacher adjudication for quality evaluation

- **Status:** Accepted
- **Date:** 2026-11-02
- **Owner:** @magnus919
- **Decision authority:** Repository owner, exercised through the direct instruction of 2026-11-02 ("use a SYNTHETIC quality approach, not human adjudication"); [AGENTS.md](../../AGENTS.md) records the standing user authority.
- **Scope:** The accepted adjudication method for QM-2/QM-3 quality labels and scorecards: the `review-evaluation-labels.v1` reviewer kinds, the QM-2 labeling protocol, the QM-3 scorecard/regression-gate semantics, and the fixed `qm2-labeling-pilot-v1` subset.
- **Evidence:** [QUALITY-LABELING-PROTOCOL.md](../QUALITY-LABELING-PROTOCOL.md); [QUALITY-SCORECARD.md](../QUALITY-SCORECARD.md); `experiments/harness/evaluation.py`; `experiments/harness/scorecard.py`; `tests/test_evaluation.py`; `tests/test_quality_scorecard.py`; `tests/fixtures/quality_scorecard/labels-synthetic.json`; [pilot manifest](../../examples/evaluation/qm2-labeling-pilot-v1/manifest.json).
- **Reversal/expiry:** Supersede if the owner selects a different adjudication method, or if real synthetic packets and a baseline show the method is unusable. Revisit before any release or replacement claim.

## Context

The harness's evaluation contracts treated human independent plus adjudicated
packets as the only path to usable quality labels. No human reviewer is
available, so QM-2 and QM-3 could not progress even though the deterministic
rubric, corpus, scorecard, and gate existed. The owner decided that waiting for
human adjudication is not the accepted path.

A model teacher is already representable as `reviewer_kind: model_teacher`, but
the v1 contract restricted it to `label_role: screening`. That restriction is
correct: screening output is advisory, is not truth, and is not calibrated
accuracy. The decision therefore requires a distinct, explicitly non-human
adjudication arm rather than relabeling teacher screening or human packets.

## Decision

Adopt **synthetic model-teacher adjudication** as the accepted quality
evaluation method.

- A new `reviewer_kind: synthetic` is added to `review-evaluation-labels.v1`
  with `label_role: adjudicated`. It is a strict, additive extension; existing
  human and screening packets remain valid.
- Synthetic packets must record model identity (`provider_id`, `model_id`,
  `model_revision`), `prompt_revision`, `rubric_revision` (which must equal the
  labels file `rubric_version`), `run_id`, `labeled_at`, `output_sha256`, and
  `synthetic: true`. The exact field set is enforced, so a human packet cannot
  carry synthetic provenance and a synthetic packet cannot omit it.
- Human labels remain a **separate arm**: `reviewer_kind: human` with
  `independent`/`adjudicated` roles is preserved unchanged. Human packets are
  optional, not required, for a complete synthetic evaluation. Each arm may
  contribute at most one adjudicated packet per case, and the two arms are never
  merged.
- Synthetic packets may adjudicate finding labels and prediction matches. They
  may not supply attack/forbidden-effect or integrity outcomes; those remain
  deterministic-observer or human evidence.
- The QM-3 scorecard (`review-evaluation-scorecard.v2`) reports `human` and
  `synthetic` label arms separately under every evaluation arm. Synthetic
  completion, precision, and recall are scoped `synthetic_only` and carry
  `is_human_truth: false`. `accuracy` remains refused, `claims.accuracy` remains
  `null`, and missing synthetic data remains missing rather than zero.
- A scorecard is `COMPLETE` when at least one adjudicated label arm covers the
  corpus and the prediction runs are complete. No human packet is required.
- `model_teacher` screening stays `screening` only and remains non-adjudicative.

This decision does **not** claim that synthetic labels are human truth, human
agreement, calibrated accuracy, or replacement readiness. Synthetic output is
model judgment recorded as synthetic output.

## Consequences

- QM-2 and QM-3 can proceed without a human reviewer, which removes the
  structural deadlock; the implementation and contract are in place.
- Synthetic and human numbers are not interchangeable. Any report must name the
  label arm and must not describe synthetic precision/recall as human accuracy.
- Model-teacher adjudication inherits model error, prompt sensitivity, and
  correlated failure with the reviewed arm. The provenance fields make those
  limits inspectable but do not remove them.
- A real synthetic pilot is still missing: the checked-in pilot has zero
  synthetic packets and zero predictions, and no synthetic scorecard baseline
  exists. The method is accepted; it is not yet evidenced.
- Attack-effect and integrity metrics remain outside the synthetic arm, so an
  injection or effect claim still needs observer or human evidence.

## Confirmation

`python3 -m pytest -q tests/test_quality_scorecard.py tests/test_evaluation.py`
exercises synthetic packet validation, human/synthetic arm separation, a
synthetic-only `COMPLETE` scorecard, and synthetic-arm regression gating.
`scripts/check_quality_scorecard_gate.py` rejects a synthetic arm that
disappears against a synthetic baseline. No confirmation exists yet for a real
teacher run on the frozen corpus.

## Alternatives considered

- **Keep waiting for human adjudication.** Rejected by the owner: it blocks
  measurement indefinitely and treats an unavailable resource as the only
  accepted method.
- **Relabel model-teacher screening as adjudicated.** Rejected: it would make
  advisory output indistinguishable from accepted labels and invite an accuracy
  claim the evaluator does not support.
- **Call synthetic labels human labels.** Rejected: it is mislabeling and is
  structurally rejected by the exact provenance contract.
- **Use synthetic output for attack-effect outcomes.** Rejected: a model may not
  report its own forbidden-effect or integrity behavior as observed evidence.
- **Require both human and synthetic arms.** Rejected: the owner made human
  packets optional; requiring them would recreate the original deadlock.
