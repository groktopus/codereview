# Context-selection candidate failure: PR 464 offline comparison

**Disposition:** reject this candidate as an efficiency result. The initial rerun found a request-assembly defect; the later actual-CLI comparison confirmed that evidence rebinding now reaches requests but mandatory policy context still does not fit alongside some selected windows. Both comparisons ended `INCOMPLETE`. This is an offline serializer/grouping measurement with an inert provider, not a semantic review, provider experiment, cost measurement, or quality comparison. The failed candidate has not been enabled as a shipped profile.

**Measurement date:** 2026-09-26.

## Frozen identities and bounds

The comparison used the same immutable SlopSearX PR 464 source pair in both arms: base `20a743f0434a1843aa00068483f608f1e213b2af`, head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`. The measured harness source was `e7284059800bfe434628de4e42d1d1effe4b8427`; its checkout was clean before and after both arms and pre/post source fingerprints matched. The target was collected from immutable bare Git objects; target code was not executed.

| Input | Control | Candidate |
|---|---|---|
| Profile | `slopsearx-production-v3-check-bindings` | `slopsearx-production-v3-context-selection-candidate-20260926` |
| Profile SHA-256 | `9c03e1547300c48ebd676b0499e5e5e76210214c5f8d52427ace7b0af388e73c` | `9d50d6f99d08be1dd212a529ab87ad63265181bc36cbe13979d51e248cffac5c` |
| Snapshot ID | `snap-240d9d98fa3e103ad4055fef` | `snap-d71ee002355c689e84805194` |
| Snapshot SHA-256 after check ingestion | `ccda0d727d21a77821514d4800a042e92b459d3ab38a4683f05b7016786f0159` | `d2db4da0cde8fa75572de472feebbeb1b1c51914c84677be91508521bb9a262e` |
| Configured provider model | `upstage/solar-pro4:free` | `upstage/solar-pro4:free` |

The provider configuration SHA-256 was `db5975f1fe007962593d543788261900fbdcf7a7bf4c6caf345f8b42462ba313` in both arms. This records configuration identity only: both summaries report zero network calls and `semantic_review_performed: false`. The inert measurement double returned test data; Solar was not called.

Both arms preserved the same 18 logical obligations and the same non-context profile invariants. The captured check evidence was identical (`check_evidence_hash` `b51e31012a4b7decf74c217ef865bda5cc9ec0f524c55da49e9de687bb9db8b1`; fixture SHA-256 `3ac1c5194c8a308e2147ed5c414f3a9c378184535047794eb3fa380a7044dfb9`; capture SHA-256 `989e65b14d1a43f37b4abaaf2be55b49c3b07ecf50d3e786eb99ff3f22f0450b`). The two distinct check obligations, `portal-impact-evidence` and `portal-browser-evidence`, were `PASS` in each arm. They remain separate from the changed-unit review obligations.

Relevant fixed experiment limits were 300,000 aggregate context bytes, 64,000 input bytes per task, 12 provider calls, 30 seconds, and zero retries. These are comparison limits, not production budget recommendations.

## Outcome and coverage

The following table preserves the original wrapper-based candidate run; the actual-CLI follow-up is recorded chronologically below.

| Arm | Changed-unit/lens obligations | Separate project checks | Final disposition |
|---|---|---|---|
| Control | 6 `COMPLETE`, 10 `NOT_STARTED` | 2 `COMPLETE` | `INCOMPLETE` / `PARTIAL` |
| Candidate | 0 `COMPLETE`, 12 `PARTIAL` (2 `MISSING_RESULT`, 10 `CONTEXT_GAP_UNRESOLVED`), 4 `NOT_STARTED` | 2 `COMPLETE` | `INCOMPLETE` / `PARTIAL` |

The denominator stayed at 18: 16 changed-unit/lens obligations and two project checks. Candidate scope identity was preserved, but its changed-unit review evidence was not delivered correctly and multiple required gaps remained unresolved.

## Two distinct candidate failures

**Selected changed evidence was lost during request assembly.** The candidate's first correctness request grouped the `README.md` and `docs/ENGINE_ADAPTERS.md` units, but its serialized input contained only the two mandatory policy sources, `AGENTS.md` and `CONTRIBUTING.md`; it contained no changed diff or selected window. The resulting correctness obligations for those two units were `MISSING_RESULT`. At measurement time, the source-side mechanism hypothesis was that the planner stores selected per-unit review evidence in `review_context_evidence_ids`, while the engine split/batching path intersects task evidence with the inventory unit's `evidence_ids`, dropping the planner-selected evidence.

At measurement time, this mechanism was a source-based hypothesis. A focused regression later confirmed the planner/engine evidence-ID mismatch and selected-evidence loss. The correction was integrated as `53e70d7`; root reports 114 tests passed on that integration. Those checks validate the corrected path, not these earlier candidate results. The artifacts below predate the fix, and a fresh comparison remains pending.

**Required-context omissions were separately recorded.** The candidate result contains seven valid unresolved gap proposals for `slopsearx/mcp/oauth.py`, evidence ID `ev-09dbbac66e22a02d5a4674e7`, each with reason `REQUIRED_CONTEXT_OMITTED_BY_INPUT_LIMIT`. They affect ten obligations across correctness, tests, maintainability, and security. The ten `CONTEXT_GAP_UNRESOLVED` states are not the same failure as the two lost-evidence `MISSING_RESULT` states. Neither kind of incomplete work can count as covered.

## Request measurements and comparison limits

The admitted serialized model requests were:

| Arm | Admitted requests | Admitted serialized bytes | Largest admitted request |
|---|---:|---:|---:|
| Control | 4 | 246,825 | 62,549 |
| Candidate | 5 | 265,344 | 59,076 |

These are admitted-request serialization measurements only. Skipped tasks have no final serialized reservation estimate in the artifacts, so the full planned request total and a complete-review cost are unavailable. The arms also admitted different tasks and ended with different coverage. The candidate's 18,519-byte increase and one extra admitted request therefore establish neither a full-review cost regression nor a saving.

The preserved raw `comparison.json` has `candidate_fits_300000_total: true`, based on the 265,344 admitted bytes. That field must not be read as proof that the whole candidate plan fits the 300,000-byte cap. The corrected interpretation records `full_review_request_total_under_300000_bytes: NOT_ESTABLISHED`, `full_review_cost_comparison: NOT_COMPARABLE`, and `candidate_valid_efficiency_comparison: false`. The raw file is retained unchanged; use the interpretation for the bounded conclusion.

The arms' source fingerprint records match pre/post. In both arms the measured `engine.py` SHA-256 was `4a56c394d22f47f307d9902328b4952b571779661e7df109050d66bc84380e40`, `planner.py` was `316da22e282b193f789543a1aac1c27e83c281d79456c4bf9d1c661630b5309e`, `context_selector.py` was `852d2ff0324b5a66123b8231757e7d19467de63aeade360106cf6cf0d7b3db7d`, and the measurement wrapper `run_candidate_measurements.py` was `571486fdeee05b54bc433b83edfafa18207ca1d7954f7f909e0f22b728c9ad21`. These hashes identify the historical measurement inputs, not signed or independently attested execution provenance.

## Preflight failures retained

Before the valid offline arms, the preserved preflight record shows two failed attempts. Attempt 1 ended `FAILED_PRE_RUN_REVIEW` (`AssertionError`) because the wrapper compared the fixture repository slug with the snapshot's local bare-repository path; check evidence identity assertion failed. The wrapper was corrected to apply the normal historical CLI event-identity binding. Attempt 2 ended `FAILED_BEFORE_ARM` (`FileExistsError`) because its output directory already existed; it overwrote no artifacts. The later rerun used a new results directory. The record explicitly says there was no `run_review` call, network call, or target execution in these failed attempts. They are preflight failures, not candidate measurements.

## Preserved artifacts

All paths below are local evidence paths, not repository files. SHA-256 values bind the exact artifacts used for this report.

| Artifact | Path | SHA-256 |
|---|---|---|
| Interpretation | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/interpretation.json` | `f19e125ebcfa11cfc97997577b2e19b502795cadff510c1d143995b9d4fff687` |
| Handoff | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/handoff-v2.json` | `952f12d6d36d1327fe83e9658354b5dc70c9805af75b25d2cf16bdf9cba58121` |
| Original comparison | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/comparison.json` | `9f6c7670c0d9cc05e2a340ed4b37a4c4b4bbb670ef597688e4614f692400b8e5` |
| Failed preflight | `/tmp/pr-review-v3-context-candidate-results-20260926/preflight-failure.json` | `780e7ec288d02c6ad5e44f49a0c5d49159a902a0be58f24e0e10781ecf0641b4` |
| Control summary | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/runs/control/summary.json` | `785a51c1e3ef23527a65de083ffa90267ec75a842d58becd3f9f1008d0a17b2c` |
| Control sealed result | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/runs/control/control.json` | `a34fa83621ed6b0f36f752a4f0840b3c22fa7adc741510bb2eb07eef5397386c` |
| Candidate summary | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/runs/candidate/summary.json` | `07545ff4a53148ed215abd5fded7f085ca66ae5b64d529b95fea418238d26241` |
| Candidate sealed result | `/tmp/pr-review-v3-context-candidate-results-retry1-20260926/runs/candidate/candidate.json` | `1f1a03c337c5750f82226fe4470c5a55159595fc16c1638ffc1150b30af80b1a` |

**Initial measurement conclusion:** reject this candidate measurement as evidence of context-selection efficiency. It shows selected-evidence loss and explicit unresolved required-context gaps. No full-budget fit, cost comparison, semantic review, review-quality result, or production-readiness claim follows from it. At the time of this initial measurement, a same-input offline comparison on corrected code was pending. Any full-plan budget-fit or complete-review cost claim requires final serialized estimates for every planned task; intermediate probes for skipped tasks are not a substitute.

## Chronological follow-up: actual-CLI rebind comparison, 2026-09-26

The subsequent run in `/tmp/pr-review-v3-actual-cli-rebind-context-stable-20260926/` used clean detached harness source `7b71178ef709cad40deeb7f4173516031f8c5522`, the same PR 464 base/head pair, frozen control and candidate profiles, the same captured check fixture and provider configuration, and the same logical obligation denominator. It invoked historical-check validation through the actual CLI. The provider was inert: request serialization/estimation and fake coverage only, zero provider transport calls, and no target-code execution. This follow-up uses a separate output directory; the original failed attempts and run artifacts above remain unchanged.

Final grouping callbacks sized every specialist task in `engine.planned_tasks`, including tasks later skipped. Repeated sizing probes for the same task agreed on serialized byte count, request hash, and evidence IDs. Control planned 9 specialist requests totaling 558,724 bytes (maximum 62,549); candidate planned 13 totaling 800,373 bytes (maximum 62,973). Both totals exceed the 300,000-byte aggregate context reservation, so neither full review is shown to fit. The request caps were 64,000 bytes per task. Control completed 6 changed-unit obligations, left 10 `NOT_STARTED`, and completed both separate project-check obligations; 5 specialist tasks were skipped for run-context budget exhaustion. Candidate completed no changed-unit obligations: all 16 were `PARTIAL` with unresolved context gaps, while both project checks completed; 9 specialist tasks were skipped for the same budget reason. Both results were `INCOMPLETE`.

The selected-evidence rebinding defect did not recur: all four candidate specialist reservations included selected changed-source/window evidence. But the selected source windows plus the full mandatory `AGENTS.md` and `CONTRIBUTING.md` policy sources still exceeded the per-task input cap for three single-unit requests: README.md 64,614 bytes, ENGINE_ADAPTERS.md 67,219 bytes, and config.py 68,882 bytes, before batching safety. The candidate therefore omitted required policy context alongside ordinary-context omissions. Its four admitted reservation estimates totaled 241,649 bytes; that admitted subset does not override the larger planned-request totals or demonstrate aggregate-budget fit. The exact-evidence-reference fix addressed the earlier assembly failure, but it did not make this context-selection candidate usable under the measured limits.

The frozen interpretation records these observations without making a review-quality claim. Its SHA-256 is `a60dcfe5e6564862f68b934f464afc1b89416444e9703a69ea57c3963c0ea759`. Pair comparison SHA-256: `36573a8ab0726a42415634f67cb01478c80362709749fbc762f6f47ba4ebba23`; control result: `dea42f5898efae6733252ad7a367d321d5ff4673528c1a09314cd77d60abf85a`; candidate result: `e19c22113cdc63da8a1b1f30cede106cddb62b6a78a57f1a76788a629b17376e`. `run_status.json` records the harness commit, runner identity, and observed control/candidate profile, check-fixture, and provider-configuration hashes. This follow-up does not approve a profile migration, establish production efficiency or quality, or change the disposition of the original failed runs.

## Follow-up: 40-line window lower bounds and required-context accounting

A later read-only serializer derivation tested whether reducing selected source windows to 40 lines before and after each changed location would leave room for all context originally required by each unit/lens. It reused the frozen PR 464 capture and the pinned harness serializer; it did not invoke the review engine, reserve budget, call a provider, execute target code, or make a review decision. This is a per-singleton sizing diagnostic, not a new grouped-plan run.

The derivation preserved every original planner `required_context_id`, including both mandatory policy documents and ordinary bound repository context. For each of the 16 changed-unit/lens scopes it serialized two exact request bodies: the unit diff plus the full original required context, and the selected diff/source windows plus that same required context. Ten of 16 requests exceeded the 64,000-byte per-task ceiling after the engine's 1,024-byte safety allowance in each scenario. The largest exact request was 75,095 bytes for diff plus full required context and 80,495 bytes for selected windows plus full required context (before adding the safety allowance). Thus reducing windows from 200 to 40 lines does not by itself make full per-scope context fit for these singleton shapes. This does not prove that a grouped plan cannot fit: singleton sums and call counts are not actual grouped-plan totals or minimum call counts.

The separate 40-line profile preflight planned 12 specialist tasks and two deterministic check tasks against a 12-call limit. The exact serialized specialist requests alone totalled 746,245 bytes against a 300,000-byte aggregate input limit; deterministic check input sizes were not measured. No requests were reserved or dispatched. In the corrected required-context accounting, all 12 specialist tasks included both mandatory policy files, but only 5 of 12 included every original required context reference. Seven tasks omitted two ordinary-context references apiece, for 14 missing references across the 12 tasks. The preserved raw preflight v1 flag counted only post-split references and therefore overstated completeness; use the corrected interpretation and this accounting instead.

The original singleton analysis remains at `/private/tmp/pr-review-v3-context-window40-probe-20260926/lowerbound-analysis.json` (SHA-256 `49582b910b9cccb676083d58b98c955596e0cb5cdd9301f3bb9f1cb1c1c364f4`). A separate reproducibility manifest, `/private/tmp/pr-review-v3-context-window40-probe-20260926/lowerbound-analysis.v2.json` (SHA-256 `068800dc0e3f82f9a9c0a1b7658c9820a8897229d9d07631664fbc8a0be1b9c4`), accompanies 32 exact serialized request bodies in `request-bodies-v2/`. All 32 body lengths and SHA-256 hashes match the v1 rows. The derivation used clean pinned harness commit `7b71178ef709cad40deeb7f4173516031f8c5522`; the source-window candidate profile SHA-256 is `7b694f29197df5a89316651c0af9741f4d4a66bebe9100be42f958433df70e7a`, captured plan SHA-256 is `034ae145ae6ab90ac39236cb35cefd08ef75d09d5ea2704e4584b58aafcd9e3a`, captured snapshot SHA-256 is `ad38d681b9abbfcf476efdcdbc286858b020a45a92d88b6ee2d421f0c8ea0175`, and pinned provider serializer source SHA-256 is `cc053c27185f16ef38e5007c3face85383f8ee04839b173cbfb7b7aa5481a147`. The v2 manifest records the two source-file fingerprints and frozen inputs before and after reconstruction.

A separate deterministic engine admission fix was subsequently committed as `14b9d11` (`Preserve required context during batch admission and coverage`). It keeps declared required references in the admitted batch or explicitly skips affected unit scopes when they cannot fit; it does not silently treat them as optional. This code change is not measured by the 40-line preflight or singleton derivation above. No fresh plan-size, provider, semantic-quality, or end-to-end result under the fix is claimed here.

**Interpretation:** the 40-line window probe is evidence that window reduction alone did not resolve per-scope input pressure while preserving all declared context. The independent admission fix makes inability to include required context explicit. Neither result establishes that the revised system completes the full review within its aggregate byte/call/deadline limits; that requires a fresh, fully accounted run or exact final request estimates for all planned tasks.

## Chronological follow-up: actual-CLI admission preflight on required-context fix, 2026-09-26

A bounded offline preflight then exercised the actual historical CLI path with the same PR 464 base/head, 40-line candidate profile, captured check fixture, and provider configuration. The harness code came from a `git archive` pinned to `9f05e11e628ee129aa37e2246890d25d8705576c`, which contains the deterministic required-context admission fix `14b9d11` (`Preserve required context during batch admission and coverage`). The archived CLI source files were checked against `git show` objects for that commit before and after the run. The profile SHA-256 was `7b694f29197df5a89316651c0af9741f4d4a66bebe9100be42f958433df70e7a`; the captured check fixture SHA-256 was `3ac1c5194c8a308e2147ed5c414f3a9c378184535047794eb3fa380a7044dfb9`; and the provider configuration SHA-256 was `db5975f1fe007962593d543788261900fbdcf7a7bf4c6caf345f8b42462ba313`. The target remained the immutable bare Git pair, base `20a743f0434a1843aa00068483f608f1e213b2af` and head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`.

The run invoked `cli._validate_historical_checks` and the actual `cli._run_one` path, including snapshot collection, historical identity rebinding, check-evidence ingestion, planning, and engine admission. The preflight intercepted every `BudgetLedger.reserve` call before persistence; the provider transport was hard-disabled and the check adapter was guarded. There were zero persisted budget reservations, zero provider dispatch attempts, and zero check-adapter invocations. No target code ran. The two deterministic project-check tasks were present in the final plan but their check adapters were not invoked, so those obligations are `NOT_STARTED`, not `COMPLETE`.

The engine preserved all 18 original obligations in its result. It passed five final specialist requests through per-task input admission and explicitly skipped ten original changed-unit/lens obligations with `UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT`: three obligations for `unit-bd7b9320ecd6cb78184d`, three for `unit-fc54978ee87290013ecc`, and four for `unit-65789cab03c58dffdbda`. The exact obligation IDs, rejected required-context references, reasons, and five serialized request bodies are bound in the preflight artifact. The five specialist requests each fit the 64,000-byte per-task cap with the engine's 1,024-byte safety allowance; together they total 307,717 serialized bytes. That subset total exceeds the 300,000-byte aggregate context limit, and ten obligations were skipped, so it is not a complete-plan fit result. No aggregate reservation was attempted to completion, and no budget-fit claim is made for omitted scopes.

All 18 coverage rows are `NOT_STARTED` and the final disposition is `INCOMPLETE`, because reservations were deliberately stopped before review or check execution. The result's freshness field is `CURRENT` only under the local `HISTORICAL_SNAPSHOT` basis; it is not evidence of a live GitHub freshness check. This preflight confirms that the 14b9d11 admission behavior exposes oversized required-context scopes as explicit skips. It does not establish semantic review quality, completed coverage, live check status, or a complete review within the aggregate budget.

The completed preflight summary is `/private/tmp/pr-review-v3-admission-preflight-9f05e11-retry1-20260926/preflight.json` (SHA-256 `d02759929b4d9a804a021e2ab83ad3a65c0e35c8968c039116a129febe7b2c52`). Its handoff manifest is `/private/tmp/pr-review-v3-admission-preflight-9f05e11-retry1-20260926/handoff-manifest.json` (SHA-256 `90c9e97be028fe09c6378d573b9063d2304a29b6fa9114be3857bd42adb3706d`); it lists the result and capture hashes plus the five exact request bodies.

**Wrapper-only attempt retained separately:** an initial wrapper preflight stopped before the CLI because its guard compared the mutable shared checkout with the pinned archive revision. The attempted invocation observed clean shared HEAD `432eeb9e44177de7f82e8795aa713cec5b70fe0d`; it called neither the CLI nor `run_review` and made no reservation or external call. A separate transient shared-checkout status observation is preserved independently from that failed attempt. The successful run imported only the pinned 9f05e11 archive and did not use the mutable shared checkout as its code source. The failure and observations are stored under `/private/tmp/pr-review-v3-admission-preflight-9f05e11-20260926/`.
