# Reassessment after the A-minus issue program (2026-11-02)

Status: **A− not achieved. 3 of 10 dimensions meet A− (updated 2026-11-06).** This note records the
current judgment after the 33-issue remediation program and the merged
infrastructure PRs. It supersedes the overall judgment in
[`CODEBASE-ASSESSMENT-2026-11-01.md`](CODEBASE-ASSESSMENT-2026-11-01.md) while
keeping that document as the original evidence snapshot.

## Judgment

| Dimension | Grade | Current evidence | What still blocks A− |
|---|---|---|---|
| Evidence discipline | **A** | Immutable Git evidence, contract fingerprints, observed/reported/unknown separation, frozen historical fixtures, exact-byte pins. | None material. |
| Effect safety | **A−** | Default read-only, typed effect boundaries, 11-test publication fault matrix, publication receipts, fail-closed unknown states, least-privilege App token, and one exercised live canary through the narrow one-shot adapter ([receipt](evidence/canary-review-5763357701.json), review 5763357701 on SlopSearX#1097). The general protected runtime is out of scope and remains intentionally unexercised. | None material for the A− gate; the canary proves the external review effect, not general publication. |
| Deterministic control plane | **A−** | Staged `run_review`, `RunState`, budgets, deterministic planning, contract registry, typed boundaries. | No A− blocker; A would require reducing the 38 functions over 150 lines and tightening module cohesion. |
| Test depth | **B+** | 3,800+ tests, compatibility suite, fault/invariant suites, direct reconcile consolidation tests, and a reconcile mutation probe (257 killed / 338 no-tests / 73 survived = 77.9%, no-tests and timeouts excluded; [report](evidence/vd2-mutation-reconcile.json)). | Reconcile clears the 70% gate, but budget and reducer modules remain unmeasured (#252). |
| Review completeness | **C** | A five-case comparable frozen-corpus baseline and active CI gate are recorded; execution/context failures can be waived into `COMPLETE_WITH_WAIVERS` only by an explicit signed, expiring waiver, and never approval. | Baseline is five cases, #770 is disclosed but not included; no live full-corpus run. |
| Review quality evidence | **D** | Five-case predictions, synthetic scorecard with the synthetic arm `present`, accepted baseline, CI/scheduled gate, and no accuracy claim. | No live full-corpus run; one case (`qm1-slopsearx-pr770`) is missing; no second prediction arm (#244/#245). |
| Architecture | **C+/B−** | Typed core boundaries, contract registry, staged pipeline, no runtime dependencies. | Oversized functions remain; `run_review` orchestration is still concentrated; module ownership is documented but not enforced by required review. |
| Operational readiness | **B−/B** | Hash-locked dependencies, install matrix, public API/support matrix, SBOM/provenance tooling, release workflow, active dependency review. | No general production deployment, on-call/runbook exercise, or non-canary publication operation; releases and dependency review are otherwise current. |
| Documentation | **B+** | 180+ indexed documents, 1,200+ links with 0 broken, generated status evidence, ADR index, docs-truth checks. | Owner-reviewed status remains intentionally stale; some operational evidence is CI-defined but unexecuted. |
| Governance | **C+/B−** | CODEOWNERS coverage 40/40, all issues owned/state-labeled, GA-3 closed, review receipts, decision-record enforcement, and branch protection requiring those two checks (admin bypass retained for the sole maintainer). | Branch protection is new and not yet exercised by a non-admin merge; bus factor 1; no second reviewer. |

## What changed since the original assessment

- Dependency and package contract: hash-locked dev set, install matrix, public
  API/support matrix, scheduled audit (#299).
- Review evidence: receipt protocol enforced on merged PRs (#293, #295, #297,
  #298, #300); decision-record links enforced for future safety-invariant
  changes (#300).
- Ownership/backlog: GA-3 closed with the then-current 16-issue snapshot (#301); the board now has 7 open issues.
- Quality measurement: frozen corpus, versioned labeling protocol, retained
  synthetic pilot, deterministic scorecard, missing-data semantics, seeded
  regression gate (#298, #302, #316).
- Release/supply chain: version/changelog policy, SBOM, provenance, reproducible
  build checks, unsigned-attestation limits documented (#294, #296).

## Why A− is not reached

Seven dimensions remain below A−. Effect safety is now A−: the 11-test
publication fault matrix passes and one live canary was exercised and verified
(review 5763357701 on `magnus919/SlopSearX#1097`, reproduced in the retained
receipt). The remaining gaps are:

1. **Quality measurement (QM-2/QM-3).** Five-case predictions and an accepted
   synthetic scorecard exist, but there is no live full-corpus run and no second
   prediction arm.
2. **Completeness baseline (RC-3).** A five-case comparable baseline and gate are
   active; `qm1-slopsearx-pr770` is disclosed but not included.
3. **Mutation/static depth (VD-2/VD-4).** Reconcile now measures **77.9%**
   (257 killed / 73 survived; no-tests and timeouts excluded) against the 70%
   gate. Budget and reducer modules remain unmeasured. The formatting/complexity
   half of VD-4 is merged, but expanded lint rules and broad typing remain open.
4. **Architecture and documentation (C+/B−, B+).** Oversized functions remain,
   `run_review` orchestration is still concentrated, and owner-reviewed status
   evidence is intentionally stale.
5. **Governance (C+/B−).** Branch protection is active, but it has not been
   exercised by a non-admin merge; bus factor remains one.
6. **Operational readiness (B−/B).** Releases, locks, install matrix, and
   dependency review are active, but there is no general production deployment,
   on-call/runbook exercise, or non-canary publication operation.

## Bottom line

The harness is materially stronger than the 2026-11-01 snapshot. Evidence
discipline, the deterministic control plane, and effect safety meet A−. It is
not an A− codebase overall: quality has only a five-case baseline, completeness
is measured on the same five cases, mutation is 77.9% on reconcile but unmeasured
on budget/reducer, typing remains narrow, and architecture, documentation, governance, and
operational readiness have structural gaps. The first release
predates attestation (`v0.1.0` remains unsigned; `v0.1.1` is attested), and branch protection has not been
exercised by a non-admin merge.


## Update 2026-11-06

Closed since the prior reassessment: **RC-1** (retrieval envelope, test-based receipt),
**RC-3** (five-case completeness baseline and gate), and **QM-2** (predictions and
synthetic scorecard). Execution/context failures can now be explicitly waived into
`COMPLETE_WITH_WAIVERS`, still capped at `COMMENT` and never approval. The open
backlog is **6 issues**: RC-2, QM-4, QM-5, VD-2, VD-3, VD-4.

The A− count is unchanged at **3/10**. Review completeness moved to **C** and quality
evidence to **D**, but neither reaches A−. Test depth rose to **B+** because the reconcile mutation score is **77.9%**
(no-tests and timeouts excluded), above the required 70%; budget and reducer
modules remain unmeasured.
