# Reassessment after the A-minus issue program (2026-11-02)

Status: **A− not achieved. 3 of 10 dimensions meet A− (updated 2026-11-04).** This note records the
current judgment after the 33-issue remediation program and the merged
infrastructure PRs. It supersedes the overall judgment in
[`CODEBASE-ASSESSMENT-2026-11-01.md`](CODEBASE-ASSESSMENT-2026-11-01.md) while
keeping that document as the original evidence snapshot.

## Judgment

| Dimension | Grade | Current evidence | What still blocks A− |
|---|---|---|---|
| Evidence discipline | **A** | Immutable Git evidence, contract fingerprints, observed/reported/unknown separation, frozen historical fixtures, exact-byte pins. | None material. |
| Effect safety | **A−** | Default read-only, typed effect boundaries, 11-test publication fault matrix, publication receipts, fail-closed unknown states, least-privilege App token, and one exercised live canary through the narrow one-shot adapter ([receipt](evidence/canary-review-5763357701.json), review 5763357701 on SlopSearX#1097). | The general protected runtime remains intentionally unexercised; the canary proves the external review effect, not general publication. |
| Deterministic control plane | **A−** | Staged `run_review`, `RunState`, budgets, deterministic planning, contract registry, typed boundaries. | No A− blocker; A would require reducing the 35 functions over 150 lines and tightening module cohesion. |
| Test depth | **B+** | 3,600+ tests, 88.48% coverage (CI run 41438939529 at PR #302), compatibility suite, fault/invariant suites. | Mutation score is **not established**: the exploratory probe was discarded and no retained report, mutant count, killed count, or survivor triage exists (#252). |
| Review completeness | **C−/D+** | Canonical `review-completeness-taxonomy.v1`, per-run summary, fixture baseline, and an active seeded-regression CI gate exist; frozen corpus exists. | No frozen-corpus baseline from real review runs (#241); fixture-only gate does not prove corpus completeness. |
| Review quality evidence | **F** | Frozen corpus v1 (41 cases), synthetic labeling rubric (ADR 0010), retained six-packet synthetic pilot, and scorecard/gate infrastructure. | No checked-in predictions or accepted six-case baseline; exploratory runs are not retained, and large PRs still return bounded `INCOMPLETE` on missing evidence/coverage (#243/#244). |
| Architecture | **C+/B−** | Typed core boundaries, contract registry, staged pipeline, no runtime dependencies. | Oversized functions remain; `run_review` orchestration is still concentrated; module ownership is documented but not enforced by required review. |
| Operational readiness | **B−/B** | Hash-locked dependencies, install matrix, public API/support matrix, SBOM/provenance tooling, release workflow, active dependency review. | `v0.1.0` and attested `v0.1.1` releases exist with wheel/sdist, SBOM, checksums, and reproducibility reports; dependency review is active (#262 closed). |
| Documentation | **B+** | 180+ indexed documents, 1,200+ links with 0 broken, generated status evidence, ADR index, docs-truth checks. | Owner-reviewed status remains intentionally stale; some operational evidence is CI-defined but unexecuted. |
| Governance | **C+/B−** | CODEOWNERS coverage 40/40, all issues owned/state-labeled, GA-3 closed, review receipts, decision-record enforcement, and branch protection requiring those two checks (admin bypass retained for the sole maintainer). | Branch protection is new and not yet exercised by a non-admin merge; bus factor 1; no second reviewer. |

## What changed since the original assessment

- Dependency and package contract: hash-locked dev set, install matrix, public
  API/support matrix, scheduled audit (#299).
- Review evidence: receipt protocol enforced on merged PRs (#293, #295, #297,
  #298, #300); decision-record links enforced for future safety-invariant
  changes (#300).
- Ownership/backlog: GA-3 closed with current 16-issue snapshot (#301).
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

1. **Quality measurement (QM-2/QM-3).** The retained synthetic pilot exists, but
   there is no checked-in prediction set, complete six-case baseline, or accepted
   scorecard baseline. Large PRs still return bounded `INCOMPLETE`.
2. **Completeness baseline (RC-1/RC-3).** The taxonomy, summary, and fixture
   gate are active; a frozen-corpus baseline from real review runs is missing.
3. **Mutation/static depth (VD-2/VD-4).** Mutation score is **not established**;
   the formatting/complexity half of VD-4 is merged, but expanded lint rules and
   broad typing remain open.
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
not an A− codebase overall: quality remains unmeasured as a complete baseline,
completeness lacks a frozen-corpus baseline, mutation and typing depth are not
established, and architecture, governance, and operational readiness have
structural gaps. The first release
is unsigned by design (`v0.1.1` is attested), and branch protection has not been
exercised by a non-admin merge.
