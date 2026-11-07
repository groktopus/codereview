# Reassessment after the A-minus issue program (current checkpoint: main 94f1973, refreshed after PR367, 2026-11-07)

**Status: A− not achieved. Only 3 of 10 dimensions meet A−.** This is a reassessment judgment, not a formal promotion/acceptance decision. Evidence discipline
is **A−**, test depth is **B+**, documentation is **B**, and no overall A−, quality parity, equivalence,
or replacement claim is supported.

This is the current reassessment, not a new name for the original assessment.
It supersedes the overall judgment in
[the 2026-11-01 assessment](CODEBASE-ASSESSMENT-2026-11-01.md), which remains
unchanged as the historical evidence snapshot.

## Source snapshot and limits

The assessed source is current main at
[`94f1973`](https://github.com/groktopus/codereview/commit/94f1973c93a225e148ee3b1f34575a5224bb3827)
(2026-11-07), after PRs 355–367 merged. Six issues remain open; stopped draft
PR353 is excluded from landed capability. The live Dependabot API returned zero
open alerts after PR357; that time-bounded result is not broad security
certification. Current main Harness
[42412775733](https://github.com/groktopus/codereview/actions/runs/42412775733)
and Security
[42412775600](https://github.com/groktopus/codereview/actions/runs/42412775600)
passed at the exact assessed SHA. The independent ten-dimension judgment remains
3/10 A−; no formal grade promotion or issue closure is inferred.


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
| Test depth | **B+** | Budget: 1,775/2,185 = **81.24% all generated**; reconcile: 573/656 = **87.35% whole module, all generated**, with 83 survivors and zero no-tests/timeouts; reducer: 103/105 = 98.10% on `_reduce` only; validators: 117/118 causal roles, 69/72 claim choice, 226/228 adjudication. Reports retain no-tests and all survivors. PR366 maps bounded faults. | Scoped function results do not qualify all validators. Six validator survivors include real boundary gaps. Fault-table scope and remaining VD-2 acceptance still need owner review; full VD-2 remains open. |
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
  stale/original-commit mismatches are explicitly not paired. The report measures
  missingness, not incumbent performance; QM-4 remains open.
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
dependency and passed before merge; the later root verification above confirms
PR 354's post-merge success but leaves PR 352's queued Harness run pending.
Documentation checks cannot replace those
source/CI or live evaluation obligations.

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
