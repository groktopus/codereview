# 0006 — Evaluation gates: no quality or replacement claim without independent evidence

- **Status:** Accepted
- **Date:** 2026-11-01
- **Owner:** Repository owner (`@magnus919`; `.github/CODEOWNERS`).
- **Decision authority:** Owner instruction recorded in [AGENTS.md](../../AGENTS.md) ("No production or replacement claim until the requirement-by-requirement audit proves it") and the current `NOT ACCEPTED` replacement status in [STATUS.md](../STATUS.md).
- **Scope:** Quality claims, model/prompt comparison claims, and readiness to replace Droid or claim a production review capability.
- **Gate status:** Not met at 2026-11-01. Numeric corpus, labeling, and threshold proposals in `docs/issues/02-quality-measurement.md` (issues [#242–#246](https://github.com/groktopus/codereview/issues)) are backlog proposals, not accepted gate values.
- **Evidence:** [STATUS.md](../STATUS.md); [EVALUATION-TOOLKIT.md](../EVALUATION-TOOLKIT.md); [PILOT-EVIDENCE.md](../PILOT-EVIDENCE.md); [COMPLETE-REQUIREMENT-AUDIT-2026-10-01.md](../COMPLETE-REQUIREMENT-AUDIT-2026-10-01.md); [test_evaluation.py](../../tests/test_evaluation.py).
- **Reversal/expiry:** The no-claim rule holds until independent evaluation evidence exists and the owner accepts the remaining risks and thresholds. Meeting the specific numeric targets requires a new or amended record.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0004](0004-publication-authorization.md) separates publication capability from quality.

## Context

The repository has a rigorous evidence discipline but very little independent quality evidence. Source coverage is `PARTIAL`, semantic accuracy and calibration are unmeasured, human labels are unavailable, and the evaluation toolkit can check contracts and denominators but cannot manufacture ground truth. Publication and transport success are capability observations, not review-quality results. A Droid replacement decision would therefore be unsupported even if every engineering check passed.

## Decision

- Do not claim production review quality, parity with Droid, improvement over an incumbent, or replacement readiness without independent, adjudicated quality evidence.
- A quality claim must identify the frozen corpus and split, exact base/head snapshots, profile and model identities, label provenance, denominators, and the comparison arm. Missing or incomplete evidence stays `UNKNOWN`/`INCOMPLETE`; it does not become a zero or a pass.
- Model agreement, a valid JSON envelope, a zero-finding run, a successful publication, and a green transport test are not quality evidence.
- The evaluation toolkit is the measurement instrument, not a release gate that grants approval. The specific corpus size, held-out split, severity/label rules, and numeric thresholds remain proposed in the quality-measurement backlog until the owner accepts them.
- Replacement remains `NOT ACCEPTED` until the owner reviews held-out evidence, accepts residual risk, sets operating thresholds, and records rollback and human-override ownership.

## Consequences

- Feature and packaging work can proceed without implying review quality.
- A future model, prompt, or profile change must be evaluated separately; it invalidates prior model-specific evidence.
- The repository keeps reporting `UNKNOWN` where labels or denominators are absent instead of publishing an unsupported score.
- Closing the quality gap is a separate body of work (corpus, human adjudication, incumbent baseline, continuous evaluation).

## Alternatives considered

- **Treat provider-backed pilot runs as quality evidence.** Rejected: the recorded runs were `PARTIAL`/`INCOMPLETE`, had no human labels, and established transport and reporting behavior only.
- **Use model-only agreement or an advisory classifier as a quality gate.** Rejected: agreement is not truth or calibrated accuracy, and the advisory contract explicitly disclaims release authority.
- **Treat a successful publication or a zero-finding run as evidence of quality.** Rejected: publication is an effect, and zero findings can mean either a clean change or a missed defect.
- **Adopt the backlog's numeric thresholds now.** Rejected: they are proposals without owner acceptance or a corpus capable of measuring them.

## Evidence status

The absence of quality evidence and the `NOT ACCEPTED` replacement state are `OBSERVED` in retained documents at the named date. No review-quality score, accuracy, recall, or replacement claim is made by this record.
