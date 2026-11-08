# Reassessment after the A-minus issue program (current checkpoint: main e6eb8d1, refreshed after PR374, 2026-11-08)

**Status: A− not achieved. Only 3 of 10 dimensions meet A−.** This is a reassessment judgment, not a formal promotion/acceptance decision. Evidence discipline
is **A−**, test depth is **B+**, documentation is **B**, and no overall A−, quality parity, equivalence,
or replacement claim is supported.

This is the current reassessment, not a new name for the original assessment.
It supersedes earlier reassessment snapshots (the latest was `c205995`, before PR373)
and the overall judgment in
[the 2026-11-01 assessment](CODEBASE-ASSESSMENT-2026-11-01.md), which remains
unchanged as the historical evidence snapshot.

## Source snapshot and limits

The assessed source is current main at
[`e6eb8d1`](https://github.com/groktopus/codereview/commit/e6eb8d10219faafdaf43f9bf8b2b2301fccc4bf1)
(2026-11-08), after PRs373 and374 merged. Six issues remain open; stopped draft PR353
is excluded from landed capability. PR373 adds a bounded offline validator for
public QM4 evidence, not new incumbent observations. Its schema, path containment,
hashes and missingness checks do not authenticate provider execution or create
pairs. PR374 only refreshed this assessment to the current source snapshot. The
live Dependabot API returned zero open alerts after PR357; this is not broad security
certification. Main Harness [42436449857](https://github.com/groktopus/codereview/actions/runs/42436449857)
and Security [42436449856](https://github.com/groktopus/codereview/actions/runs/42436449856)
passed at PR373 merge SHA `67a902c0c830dfdc50f17564d86f7576daf563e0`. Post-merge
Harness [42439182132](https://github.com/groktopus/codereview/actions/runs/42439182132)
and Security [42439182142](https://github.com/groktopus/codereview/actions/runs/42439182142)
passed at exact main SHA `e6eb8d10219faafdaf43f9bf8b2b2301fccc4bf1`. PR373 still has an
unresolved CodeQL review comment about a redundant assignment. That conversation
item is not a CI failure or security certification. The independent judgment remains
3/10 A−; no grade promotion or issue closure is inferred.


Checked-in evidence below has narrower scopes and older execution dates than
this source snapshot. In particular, the five retained live provider-backed runs
predate the retrieval compiler. They are not a representative current-source
corpus evaluation. Pending and stopped PRs are excluded from landed capability.

## Judgment

| Dimension | Grade | Current evidence | What still blocks A− |
|---|---|---|---|
| Evidence discipline | **A−** | Immutable Git evidence, contract fingerprints, observed/reported/unknown separation, historical fixtures, and exact-byte pins; unsupported premature CLEAR receipts were withdrawn during recovery. | Preserve withdrawn receipts as superseded, and require actual completed independent exact-head source review rather than validator-only claims. The receipt incident prevents retaining the former A grade. |
| Effect safety | **A−** | Default read-only and typed effect boundaries; publication fault tests and one exercised live canary through the narrow one-shot adapter ([receipt](evidence/canary-review-5763357701.json)). | Preserve the narrow authority boundary. This is not general publication qualification; the general protected runtime remains unexercised. |
| Deterministic control plane | **A−** | Staged orchestration, `RunState`, budget reservation/replay, deterministic planning, contract registry, and typed boundaries. | Preserve stale/blocker, partial-coverage, budget, and deterministic-control invariants; broader quality claims remain unsupported. |
| Test depth | **B+** | Budget: 1,775/2,185 = **81.24% all generated**; reconcile: 573/656 = **87.35% whole module, all generated**, with 83 survivors and zero no-tests/timeouts; reducer: 103/105 = 98.10% on `_reduce` only; validators: 117/118 causal roles, 69/72 claim choice, 226/228 adjudication. Reports retain no-tests and all survivors. | Scoped function results do not qualify all validators. Six validator survivors include real boundary gaps. The current fault acceptance map is merged and generated from existing/new test IDs, with layered provider, GitHub, and publication outcomes. Full VD-2 remains open because module/function mutation scope, fault-family closure, survivor disposition, and owner acceptance still need resolution. |
| Review completeness | **C** | Five comparable retained live cases and a completeness regression gate; **2 COMPLETE / 3 COMPLETE_WITH_WAIVERS** ([live-run record](evidence/qm3-five-case-live.json), [baseline scope](evidence/rc3-completeness-baseline.json)). | No representative current-source obligation-completion, INCOMPLETE, or truncation measurement. Disclose raw versus waiver-adjusted outcomes; the sixth frozen case, `qm1-slopsearx-pr770`, is missing. |
| Review quality evidence | **D** | QM-3 is closed for the owner-accepted five-case comparable baseline. Synthetic adjudication, scorecard, and provider-free CI/scheduled gates exist ([scorecard scope](QUALITY-SCORECARD.md)). QM-5 gate v3 is merged infrastructure, not live resistance evidence. | Substantive held-out positive/clean adjudicated cases, actual same-snapshot incumbent evidence, and live bounded attack evaluation remain missing. Fixture arms are not incumbent runs. |
| Architecture | **C+/B−** | Typed boundaries, contract registry, staged pipeline, and a measured 32,781-source-line slice ([allowance record](adr/0001-post-ca2-feature-budget.md#addendum-rc-2-retrieval-compiler-allowance-2026-11-06)). | Large staged functions still need cohesive reduction with behavior proof. The reduction from 40,686 lines is **19.43%**, not a current 25%; the approved allowance is fully consumed. |
| Operational readiness | **B−/B** | Hash-locked dependencies, install matrix, support/API contracts, and release/SBOM/provenance tooling. | The uploader dependency repair is merged and the live Dependabot API returned **0 open alerts** at this snapshot. This is meaningful remediation, not a broad security certification. Bounded install/recovery/on-call exercise and exact-head/post-merge CI evidence remain necessary. |
| Documentation | **B** | Indexed documentation, link/index/ownership tooling, and docs-truth checks exist. This refresh corrects stale current claims and distinguishes historical/fixture evidence from current measurement. | Freshness and source-faithful scope still require maintenance; documentation tooling alone cannot establish operational or quality evidence. |
| Governance | **C+/B−** | Ownership and review/decision-record controls exist; the recovery records completed independent review and exact-head pre-merge checks for PRs 354 and 352. | Actual independent exact-head review and post-merge verification must be preserved at every merge. Bus factor one/admin-bypass constraints and exercised backup/reviewer and negative gates remain unresolved. No new governance exercise is claimed here. |

## What is measured, and what is not

### Retained live runs and QM-3 closure

[The five live provider-backed harness runs](evidence/qm3-five-case-live.json)
completed on 2026-11-04/05, before retrieval-compiler merge
[7be8de3](https://github.com/groktopus/codereview/commit/7be8de3).
Their raw states are **2 COMPLETE and 3 COMPLETE_WITH_WAIVERS**: 2/5 unwaived
complete, not 5/5 unwaived complete. The waiver-adjusted five-case baseline does
not erase execution/context failures or qualify them for approval. Signed,
expiring waivers do not establish that the waived obligations were completed.
Known blockers must still survive disposition.

QM-3 is **closed on that accepted comparable subset**, with retained predictions,
synthetic adjudication, an accepted baseline, and CI/scheduled regression checks.
This corrects the former implication that QM-3 was still open or that no live run
had happened. It does **not** supply a full representative/current-source run,
a same-snapshot incumbent comparison, or quality parity. The missing
`qm1-slopsearx-pr770` is [disclosed, not imputed](evidence/rc3-completeness-baseline.json).
The older empty-prediction pilot and authored fixture arms described in
[the scorecard reference](QUALITY-SCORECARD.md) are separate evidence sets.

### Mutation and compatibility depth

- **Budget:** 1,775 killed / 315 survived / 95 no-tests / 0 timeouts;
  1,775/2,185 = **81.24% of all generated mutants** and 84.9% of killed+survived
  ([report](evidence/vd2-mutation-budget.json)). Both denominators are retained;
  `_child_call` mutations are no-tests, not silently excluded from the all-mutant
  score.
- **Reconcile whole module:** 573/656 = **87.35%**, 83 survivors, 0 no-tests or
  timeouts; repeat status maps match. The initial existing-test baseline failed at
  248/656 (37.80%) and is preserved. This is a new report, not the old 77.9%
  tested-only result: the historical 668-mutant universe recorded 257/668 = 38.47%
  all-generated and 77.9% tested-only. Its generation difference from the current
  656 set remains unexplained. See the [full-module record](evidence/vd2-reconcile-module/README.md).
- **Reducer:** `_reduce` only, 103/105 = **98.10%**, 2 survivors retained.
  Validator function probes: causal roles 117/118, claim choice 69/72, adjudication
  226/228. All six survivors remain; several are real boundary gaps. These
  function-only probes do not qualify entire validator modules. Raw/status/source
  hashes are retained in the [validator report](evidence/vd2-mutation-validators-measured.json)
  and [reducer report](evidence/vd2-mutation-reducer-measured.json).
- Thus measured scopes exceed 70%; fault acceptance mapping is expanded in PR366.
  VD-2 remains open: the reconcile history had a different 668-mutant universe,
  and the new all-generated repeat uses 656. Three validator functions are measured,
  not every whole module; budget survivor triage remains limited; provider cases
  map to engine terminal states while publication/GitHub cases retain distinct
  layers in the generated table. Synthetic fault success is not live qualification.

[PR 354](https://github.com/groktopus/codereview/pull/354), merged as
[3474be7](https://github.com/groktopus/codereview/commit/3474be720fff5123c2f0d6b7a947087629a9c778),
fixed value-pin `provenance.reason`, retained old/new refresh history, improved
actionable refresh help, and isolated marker/collection handling
([refresh helper](../scripts/refresh_compatibility_pins.py),
[pin tests](../tests/test_compatibility_pins.py),
[refresh tests](../tests/test_refresh_compatibility_pins.py)). **VD-3 is partial**:
runtime/script canonical pins, remaining bare comparisons, and tree remediation
remain open. A reviewed partial merge is not complete canonical-pin migration.

### Adversarial infrastructure versus live resistance

[PR 352](https://github.com/groktopus/codereview/pull/352), merged as
[fccff85](https://github.com/groktopus/codereview/commit/fccff85f18c598c3a118873949cfbc46c3587128),
hardened adversarial gate v3 against missing/malformed/non-finite rates, scope
mismatch, producer rounding, and byte-comparison regressions. The
[authored adversarial pairs](../examples/evaluation/adversarial-pairs-v1/README.md)
and [gate implementation](../scripts/check_quality_scorecard_gate.py) provide
reproducible contract and seeded-regression checks. Predictions in those pairs
are authored fixture outputs, including the arm named `droid`, not live model or
incumbent observations. **No live resistance or detector-accuracy claim follows.**

### Work outside the landed snapshot

- **PR 355:** merged as
  [928ec17](https://github.com/groktopus/codereview/commit/928ec1733b3c3dc699be6a09fb38501a409cae00).
  The versioned 41-case inventory retains 5 harness outputs and **0 incumbent
  outputs / 0 comparable pairs**. It includes actual public Droid receipts, but
  their exact snapshot/finality audit found no completed full incumbent output:
  one security receipt predates completion, one review has a base mismatch, and
  stale/original-commit mismatches are explicitly not paired. PR373 adds an offline,
  hash/identity/cardinality validator, malformed JSON rejection, and fail-closed
  support-record bounds. PR374 only refreshed this assessment against current main.
  Neither PR adds incumbent evidence or changes the measures. The report remains about missingness,
  not incumbent performance; QM-4 remains open with 0 complete incumbent outputs and
  0 actual pairs. The local hashes are not upstream signatures and do not authenticate
  GitHub capture completeness or provider execution.
- **PR 353:** [draft source](https://github.com/groktopus/codereview/pull/353)
  stopped after nonconvergence, with no CLEAR receipt and genuine
  entrypoint/frozen/wheel failures. The unverified recovery was preserved locally;
  admission architecture needs a decision before further edits, with no new
  source allowance approved. **Never count this injection/admission work as
  shipped capability or successful live attack evaluation.**

## Evidence integrity and verification limits

Earlier recovery discussion issued CLEAR receipts before independent reviews
completed and confused unrelated successful workflow runs with failed harness
checks. Those receipts were withdrawn and review returned to pending. The
independent reassessment therefore recommends **A−, not A, for evidence discipline**.
Later completed independent reviews for PRs 354 and 352 do not retroactively make
the premature receipts valid or prove the protocol was followed earlier.

Local full-suite candidate runs were not full passes: the VD-3 run recorded
4,107 passed / 12 skipped / 35 deselected **and 2 failures**; the QM-5 recovery run
recorded 4,179 passed / 14 skipped **and 2 failures**. Both failure pairs were due
to the missing local `build` module. Hash-locked candidate CI supplied that
dependency and passed before merge; the later root verification confirms post-merge
Harness and Security success for PR373 at merge SHA `67a902c0c830dfdc50f17564d86f7576daf563e0`.
Historical PR352/354 evidence remains as recorded in their delivery receipts.
Documentation checks cannot replace source/CI or live evaluation obligations.

## Bottom line

The harness is materially stronger than the original historical assessment, but
only evidence discipline, effect safety, and deterministic control reach A−.
Five precompiler live runs, two measured mutation modules, partial VD-3 repair,
and merged adversarial gate infrastructure are real progress within those
scopes. They do not close current-source completeness, representative review
quality, actual incumbent pairing, live attack evaluation, remaining mutation
and static depth, architecture, operational/security, documentation, or governance
gaps. The current judgment remains **3/10 A−; not overall A− and not a qualified
replacement**.
