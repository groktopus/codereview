# Reassessment after the A-minus issue program (2026-11-02)

Status: **A− not achieved. 2 of 10 dimensions meet A−.** This note records the
current judgment after the 33-issue remediation program and the merged
infrastructure PRs. It supersedes the overall judgment in
[`CODEBASE-ASSESSMENT-2026-11-01.md`](CODEBASE-ASSESSMENT-2026-11-01.md) while
keeping that document as the original evidence snapshot.

## Judgment

| Dimension | Grade | Current evidence | What still blocks A− |
|---|---|---|---|
| Evidence discipline | **A** | Immutable Git evidence, contract fingerprints, observed/reported/unknown separation, frozen historical fixtures, exact-byte pins. | None material. |
| Effect safety | **B+** | Default read-only, typed effect boundaries, fault matrix, publication receipts, fail-closed unknown states. | The documented A− gate requires an exercised canary; the live canary remains NOT EXERCISED (#258), so the fault matrix alone is not enough. |
| Deterministic control plane | **A−** | Staged `run_review`, `RunState`, budgets, deterministic planning, contract registry, typed boundaries. | No A− blocker; A would require reducing the 35 functions over 150 lines and tightening module cohesion. |
| Test depth | **B+** | 3,600+ tests, 88.48% coverage (CI run 41438939529 at PR #302), compatibility suite, fault/invariant suites. | Mutation score is **not established**: the exploratory probe was discarded and no retained report, mutant count, killed count, or survivor triage exists (#252). |
| Review completeness | **C−/D+** | Canonical `review-completeness-taxonomy.v1`, per-run summary, fixture baseline, and an active seeded-regression CI gate exist; frozen corpus exists. | No frozen-corpus baseline from real review runs (#241); fixture-only gate does not prove corpus completeness. |
| Review quality evidence | **F** | Frozen corpus v1 (41 cases), labeling rubric, empty pilot, scorecard/gate infrastructure. | Zero human packets, zero harness predictions, no accepted baseline, no real scorecard run (#243/#244). Quality is unmeasured. |
| Architecture | **C+/B−** | Typed core boundaries, contract registry, staged pipeline, no runtime dependencies. | Oversized functions remain; `run_review` orchestration is still concentrated; module ownership is documented but not enforced by required review. |
| Operational readiness | **C+/B−** | Hash-locked dependencies, install matrix, public API/support matrix, SBOM/provenance tooling, release workflow. | No tagged release or release artifact; provenance unsigned; dependency review inactive (#260/#261/#262). |
| Documentation | **B+** | 180+ indexed documents, 1,200+ links with 0 broken, generated status evidence, ADR index, docs-truth checks. | Owner-reviewed status remains intentionally stale; some operational evidence is CI-defined but unexecuted. |
| Governance | **C+/D+** | CODEOWNERS coverage 40/40, all issues owned/state-labeled, GA-3 closed, review receipts, decision-record enforcement. | Branch protection absent, so review checks are not required; bus factor 1; no second human (#269/#270). |

## What changed since the original assessment

- Dependency and package contract: hash-locked dev set, install matrix, public
  API/support matrix, scheduled audit (#299).
- Review evidence: receipt protocol enforced on merged PRs (#293, #295, #297,
  #298, #300); decision-record links enforced for future safety-invariant
  changes (#300).
- Ownership/backlog: GA-3 closed with current 16-issue snapshot (#301).
- Quality measurement: frozen corpus, versioned labeling protocol, empty pilot,
  deterministic scorecard, missing-data semantics, seeded regression gate
  (#298, #302).
- Release/supply chain: version/changelog policy, SBOM, provenance, reproducible
  build checks, unsigned-attestation limits documented (#294, #296).

## Why A− is not reached

Eight dimensions remain below A−. Five of them cannot be closed by more harness
code alone:

1. **Human labels and adjudication (QM-2/QM-3).** The label contract permits
   `model_teacher` only for screening and rejects it as adjudication. No second
   human exists, so no real precision/recall or accepted baseline can be
   published without a human adjudicator.
2. **Branch protection (GA-1/GA-2).** `main` is unprotected; the review-receipt
   and decision-record checks run and can fail, but an administrator merge can
   bypass them.
3. **Release publication (RS-2/RS-3).** No tag or release exists; publishing one
   and deciding signed versus explicitly-unsigned provenance requires owner
   authorization.
4. **Provider-backed frozen receipts (RC-1).** A real receipt requires an
   authorized provider run against the frozen case; no such receipt exists yet.
5. **Live canary (SE-4).** The live publication path is deliberately disabled;
   exercising it needs explicit publication authorization.

The remaining code-evidence gaps are:

6. **Completeness baseline (RC-3).** The taxonomy, summary, and fixture gate
   are already active; only a frozen-corpus baseline from real review runs is
   missing, and it cannot be invented.
Architecture (C+/B−) and documentation (B+) remain below A− for the structural
and staleness reasons in the table; neither is blocked on external authority.

7. **Mutation/static depth (VD-2/VD-4).** Mutation score is **not established**
   (no retained scoped run); formatting and broad typing enforcement are not
   adopted. Neither closes without substantial test hardening.

## What can still be done without new authority

- Keep the RC-3 fixture gate green; publish the frozen-corpus baseline only
  after real review runs exist.
- Add formatter/pre-commit and a complexity ratchet (VD-4 partial).
- Harden mutation scope and add tests for the highest-risk modules (VD-2
  partial).
- Keep dependency, docs, and security checks green as the codebase changes.

## Bottom line

The harness is materially stronger than the 2026-11-01 snapshot, and its
evidence discipline and deterministic control plane are genuinely strong. It is
not an A− codebase overall: effect safety still lacks an exercised canary,
quality remains unmeasured in human terms, release artifacts do not exist, and
merge governance is advisory rather than required. Those are evidence and
authorization gaps, not omissions that more code can close by itself.
