# PR Review Harness — traceability

**Status:** Draft, aligned to `SPEC.md` 0.1.0, `DISCOVERY.md`, `EVALUATION.md`, `PILOT-CONTEXT.md`, `ARCHITECTURE.md`, `CONTRACTS.md`, and `RESEARCH.md`. This matrix identifies how a future implementation can be checked; it does not claim that checks ran or passed.

## Requirement-to-acceptance-criterion trace

Origins are inherited from `DISCOVERY.md`: **SAID** is a direct statement in the supplied brief/reply; **IMPLIED** is a necessary consequence; **INTERPRETED** is a proposed design choice awaiting owner validation. R-016 through R-020 and R-023 are interpreted proposals/observations, not additional sponsor sign-off. ACs that encode an interpretation remain draft targets until validated. Gaps without binding acceptance criteria stay in `DISCOVERY.md` and the open questions in `SPEC.md`.

| Requirement | Origin | Spec coverage | Future verification evidence |
|---|---|---|---|
| R-001 Reusable, project-aware review across repositories | SAID | AC-001, AC-009; NFR-003 | Contract test proving adapter reuse and profile-version isolation. First pilot is only SlopSearX; a second held-out project is required before portability claims. |
| R-002 Apply QA/Programming Principles with trusted project context | SAID | AC-009, AC-011, AC-012 | Profile/lens plan inspection for representative pilot changes; counterexample where a generic preference conflicts with a local rule. |
| R-003 Risk/context depth; LOC alone cannot select effort | SAID | AC-006–AC-008 | Paired routing cases with equal LOC/different risk and high LOC/low-risk vs low LOC/high-risk. Inspect versioned policy inputs and result. |
| R-004 Correctness/tests, design/smells, security, applicable aspects | SAID | AC-009–AC-015 | Per-change obligation matrix, contextual smell cases, and security/functional review fixtures; ensure alert/no-alert cases do not imply truth/safety. |
| R-005 Deterministic control flow owns orchestration/effects | SAID | AC-016, AC-017, AC-033, AC-037; NFR-001 | State-transition trace and adversarial provider-output test; inspect task budget reservations and absence of model-selected commands/effects. |
| R-006 Bounded System One semantic judgments consumed by deterministic policy | SAID | AC-017, AC-022, AC-036; NFR-010 | Native request/response contract review per configured adapter, semantic assessment evidence, and reducer test independent of model output formatting. |
| R-007 Generative reviewer cannot choose workflow or next actions | SAID | AC-017, AC-033; NFR-001 | Prompt/task/result contract inspection plus injected action/tool-instruction responses. |
| R-008 Bounded parallel specialist work and aggregation | SAID | AC-016, AC-018–AC-020; NFR-002, NFR-009 | Concurrency-cap exercise, duplicate/conflict reconciliation cases, and timeout/malformed/late-result replay. |
| R-009 Distinct report categories, evidence, unresolved gaps | SAID | AC-023, AC-024, AC-027, AC-028; NFR-003, NFR-005, NFR-006 | Report-to-ledger consistency check; empty-section, no-finding, missing-scope, and blocker-omission fixtures. |
| R-010 Evidence-based disposition distinct from merge authority | SAID | AC-029–AC-032; NFR-004 | Reducer truth table across blocker/coverage/freshness/profile states; verify merge status is independent and defaults to `NOT_EVALUATED`/`UNKNOWN` absent rule evidence. |
| R-011 Providers/models reportedly available but identity and suitability unverified | SAID | AC-034, AC-036, AC-038; NFR-007, NFR-010 | Names-only workflow/secret metadata inspection, native-provider contract validation, canary-secret artifact scan, no live inference during design; evaluate usefulness on independent held-out cases before claims. |
| R-012 Architecture/spec before implementation | SAID | Artifact status and scope of this document set | Gate review records that this is a draft design package; no implementation authorization or implementation evidence is implied. |
| R-013 CLI + GitHub Actions first usable delivery | SAID | AC-001–AC-005, AC-039; NFR-008 | CLI/Actions contract parity and exit-status tests; report-artifact inspection; workflow permission audit. |
| R-014 SlopSearX first pilot | SAID | AC-002, AC-009–AC-015; NFR-003, NFR-011 | Read-only profile discovery against a recorded base revision; check applicability is validated per PR; no cross-project claim from this pilot. |
| R-015 Failure tolerances, budget, posting, providers, thresholds remain open | IMPLIED | AC-004, AC-036–AC-039; NFR-002, NFR-011, NFR-012; open questions 4–8 | Assert missing numeric adoption bounds remain pending; boundary-test finite config and unsupported providers; record actual cost/time without invented targets. |
| R-016 Canonical disposition semantics | INTERPRETED | AC-029–AC-032; NFR-004 | Gate reviewer/sponsor validates proposed reducer table; test `REQUEST_CHANGES` with `PARTIAL`, `INCOMPLETE` without blocker, stale/unknown denial, and complete no-blocker outcomes. |
| R-017 Local/read-only report pilot; future publishing explicit | INTERPRETED | AC-001, AC-003, AC-037, AC-039; NFR-008 | Inspect CLI/Actions output and audit that no repository/PR write occurs; future publisher remains disabled absent separate authorization. |
| R-018 PR content is untrusted; credentialed analysis never executes it | INTERPRETED | AC-033–AC-035; NFR-007 | Workflow event/permissions review, injected prompt content, sandbox capability audit, canary-secret scan, and test-job artifact bounds. |
| R-019 Candidate/reconciled evidence, uncertainty, dedupe/conflict, synthesis integrity | INTERPRETED | AC-018–AC-020, AC-022, AC-028; NFR-005, NFR-006, NFR-009 | Evidence-source review; supported/unsupported/uncertain/contradicted semantic cases; duplicate, contradiction, blocker-retention, and uncertainty-policy tests. |
| R-020 Versioned deterministic LIGHT/FOCUSED/DEEP routing; unknown cannot reduce obligations | INTERPRETED | AC-006–AC-011; NFR-001, NFR-003 | Policy version and routing boundary cases, including unknown context and unsupported project. No numeric routing threshold is accepted in this draft. |
| R-021 Immutable revisions/profile, final freshness, stale cannot publish | IMPLIED | AC-002, AC-021–AC-026; NFR-004 | Snapshot hash checks, head-change and API-unavailable scenarios, profile-version mismatch, and stale publisher guard. |
| R-022 Finite configurable limits; exhaustion leaves explicit gaps | IMPLIED | AC-004, AC-005, AC-016, AC-020, AC-039; NFR-002, NFR-003 | Preflight invalid-bound cases, zero-retry boundary, concurrency/call/deadline/context exhaustion, checkpoint integrity and resulting coverage/disposition. |
| R-023 Existing pilot provider/secret metadata does not verify Nous/Typesafe inference | INTERPRETED (observed configuration, not user requirement) | AC-038; NFR-010 | Names-only check of repository metadata/workflow as observed on 2026-09-26; no secret values or paid calls. Refresh before implementation because metadata can change. |

## Acceptance-criterion verification matrix

Methods below are plans, not executed tests. **Inspect** means review artifact/configuration and its recorded provenance; **contract** means producer/consumer validation; **scenario** means a deterministic fixture or replay with stated input and observed output; **audit** means permissions/effect/artifact evidence from an authorized pilot. Each AC has an observable outcome and at least one primary verification method.

| AC | Origin / requirement | Primary verification method and pass evidence |
|---|---|---|
| AC-001 | SAID R-013; INTERPRETED R-017 | Contract test invokes CLI and Actions adapter with same request fixture; captured core requests have the same versioned fields and there is one reducer implementation. |
| AC-002 | SAID R-014; IMPLIED R-021 | Snapshot inspection shows canonical repository/PR/event/full-SHA/profile identity and no PR-derived policy source. |
| AC-003 | INTERPRETED R-017 | Pilot audit shows local report and Actions report artifact, with no repository/PR write effect. |
| AC-004 | IMPLIED R-015; INTERPRETED R-020 | Table-driven preflight scenarios reject each invalid required field before dispatch; valid-but-unloadable profile returns explicit unsupported/incomplete status, never generic fallback. |
| AC-005 | IMPLIED R-022 | Replay duplicate event/resume with same keys; ledger contains one logical task result and separate invocations have distinct run IDs. |
| AC-006 | SAID R-003; INTERPRETED R-020 | AUTO-routing table test with trusted profile labels: prose-only change with no examples/policy/generated relationship has minimum LIGHT; any listed auth/trust/security/policy change has minimum FOCUSED plus security/correctness lenses. Record this as proposed policy behavior pending pilot validation. |
| AC-007 | SAID R-003; INTERPRETED R-020 | High-risk narrow and low-risk high-churn cases show LOC does not alone lower/raise depth floor. |
| AC-008 | SAID R-003; INTERPRETED R-020 | Remove caller/profile/generated provenance input; result records unknown and keeps configured risk/lens obligations. |
| AC-009 | SAID R-002, R-004; INTERPRETED R-020 | Planned obligations enumerate each changed-unit/lens and separate project check, or include explicit non-applicability reason before dispatch. |
| AC-010 | SAID R-002, R-004; IMPLIED R-015 | Check plan includes trusted binding and finite limits; a workflow-present but non-required check is not automatically dispatched. |
| AC-011 | SAID R-002, R-004; INTERPRETED R-020 | Representative risk-stratified plan has applicable correctness/test/design/security/project-specific coverage or reason-coded exclusions. |
| AC-012 | SAID R-002; INTERPRETED R-020 | Conflict fixture proves local trusted contract governs and generic style-only preference is not a blocker. |
| AC-013 | SAID R-004; INTERPRETED R-019 | Smell-only fixture without concrete impact/local rule is non-blocking or omitted from blocker set. |
| AC-014 | SAID R-004; IMPLIED R-021 | Base/head scenario labels finding INTRODUCED, REEXPOSED, PRE_EXISTING, or UNKNOWN with corresponding evidence; unrelated base defect is not attributed to PR. |
| AC-015 | SAID R-004; INTERPRETED R-019 | Tool-alert-only candidate lacks blocking acceptance; a separate evidence-supported case can be reconciled independently of alert presence. |
| AC-016 | SAID R-008; IMPLIED R-022 | Scheduler trace never exceeds `max_concurrent_scopes`; workers cannot create scopes/tasks or increase budgets. |
| AC-017 | SAID R-005, R-006; IMPLIED R-022 | Inject result containing a proposed command/next action; task may return only typed assessments/context gaps and trusted controller trace remains unchanged by that text. |
| AC-018 | SAID R-008; INTERPRETED R-019 | Duplicate-finding fixture retains candidate provenance, groups duplicates and preserves distinct location/impact references under one stable result identity. |
| AC-019 | SAID R-008; INTERPRETED R-019 | Opposing specialist fixture emits explicit contradiction record naming each finding/evidence; no confidence average or last-write-wins output. |
| AC-020 | IMPLIED R-015, R-022; INTERPRETED R-019 | Timeout/malformed/unsupported/conflicting-hash cases reject/quarantine the result envelope and leave scope PARTIAL/NOT_STARTED absent valid completion; a malformed individual candidate/proposal is retained as invalid, excluded from acceptance/retrieval, and does not discard valid sibling items. |
| AC-021 | IMPLIED R-021 | Snapshot contract check verifies required fields, hashes, unique changed-file inventory, full SHAs, and immutable payload across context retrieval. |
| AC-022 | IMPLIED R-021; INTERPRETED R-019 | Candidate/evidence contract and semantic-assessment scenarios cover complete provenance, four aggregate outcomes and separate claim-support states, assumptions/gaps, evidence-bound context-gap proposals, controller-owned retrieval decisions, and rejection of confidence-only acceptance. |
| AC-023 | SAID R-009; IMPLIED R-021 | Cross-check all configured unit/lens obligations against ledger entries with state, reason, task IDs, and evidence IDs; project checks are separate obligations. |
| AC-024 | SAID R-009; IMPLIED R-021 | Paired scenarios distinguish valid completed empty result from not-run, invalid, failed, skipped, and exhausted-budget work. |
| AC-025 | IMPLIED R-021; INTERPRETED R-016 | Change remote head after snapshot; terminal report is STALE with both SHAs and publisher rejects it. |
| AC-026 | IMPLIED R-021; INTERPRETED R-016 | Make head query unavailable; report is UNKNOWN and cannot state current/approve/publish. |
| AC-027 | SAID R-009 | Renderer contract test asserts exactly four named sections in order and empty arrays/sections remain empty. |
| AC-028 | SAID R-009; INTERPRETED R-019 | Deliberately omit/downgrade blocker in synthesis; report validation fails or is not terminal, and evidence-ledger blocker survives. |
| AC-029 | SAID R-010; INTERPRETED R-016 | Reducer truth-table case with all approval preconditions; outcome follows configured policy and is not set by model output. |
| AC-030 | SAID R-010; INTERPRETED R-016 | Reducer case with accepted BLOCKING finding plus missing required scope yields REQUEST_CHANGES and PARTIAL together. |
| AC-031 | SAID R-010; INTERPRETED R-016 | Reducer cases distinguish completed nonblocking COMMENT from gap/noncurrent INCOMPLETE; accepted blocker takes precedence as REQUEST_CHANGES. |
| AC-032 | SAID R-010; INTERPRETED R-016 | Merge-state tests show independent field and UNKNOWN/NOT_EVALUATED where branch-rule evidence is absent; no merge API exists in pilot. |
| AC-033 | SAID R-005, R-007; INTERPRETED R-018 | Adversarial untrusted text across title/body/path/diff/output cannot mutate profile, plan, limits, provider/effect policy, or trusted state. |
| AC-034 | SAID R-011; INTERPRETED R-018 | Seed canary (never real) credential and scan prompts, task payloads, logs, errors, ledger, reports/artifacts; workflow review proves credentialed job executes no head code. |
| AC-035 | IMPLIED R-015; INTERPRETED R-018 | Sandbox inspection confirms no secret/write token/shared cache and finite resource/network/process/filesystem limits; returned artifact is type/size bounded. |
| AC-036 | SAID R-006, R-011; IMPLIED R-015 | Unknown binding/primitive rejects; each adapter contract identifies and evaluates its own native capability; Jev is advisory; no equivalence is inferred from a shared interface shape. |
| AC-037 | IMPLIED R-022; INTERPRETED R-017 | Pilot permission/effect audit records zero repository/PR writes; future publisher path is absent or preflight-rejected unless separately authorized. |
| AC-038 | INTERPRETED R-023 | Names-only evidence as-of 2026-09-26 records repository secret metadata; LiteLLM backend remains unverified; synthetic/empty Typesafe key is explicitly not treated as live inference evidence; no values/calls; refresh before implementation. |
| AC-039 | IMPLIED R-015; INTERPRETED R-017 | CLI exit scenarios assert 0 for valid durable terminal report (including INCOMPLETE), 2 for atomic preflight rejection, 1 for runtime failure without terminal report. |

## NFR verification map

| NFR | Evidence | Gate status |
|---|---|---|
| NFR-001 Deterministic control plane | State-transition trace plus hostile provider/task output scenario | Required invariant; no model-quality threshold implied. |
| NFR-002 Finite operating bounds | Preflight boundary matrix plus budget exhaustion trace; explicit zero-retry case | Exact operational ceilings are owner-selected and pending. |
| NFR-003 Coverage denominator | Inventory/profile-plan to unit/lens/check-obligation ledger comparison | Required ledger integrity; the correct project obligations need maintainer/profile validation. |
| NFR-004 Snapshot freshness | Head-mismatch/unavailable replays and publisher guard inspection | Required invariant. |
| NFR-005 Evidence/provenance | Result-to-ledger linkage and semantic uncertainty scenarios | Required evidence contract; model semantic accuracy remains unvalidated until evaluation. |
| NFR-006 Blocker preservation | Blocker-omission synthesis challenge and ID comparison | Required invariant. |
| NFR-007 Secret isolation | Workflow permission review, canary-secret scan, job boundary inspection | Required security gate; no real secret is used for verification. |
| NFR-008 Read-only pilot | Repository/PR API audit; artifact upload allowed | Required pilot boundary; artifacts are workflow delivery, not review publication. |
| NFR-009 Reconciliation integrity | Failure/replay ledger review with conflicts and unsupported items | Required inspectability invariant. |
| NFR-010 Provider honesty | Native adapter provenance and unsupported-model fixtures | Provider support must be independently documented; semantic quality is not inferred. |
| NFR-011 Evaluation/adoption evidence | Evaluation-plan exit check; source-label and held-out split audit | Pending owner-selected numeric bounds; prevents claiming release readiness without them. |
| NFR-012 Latency/cost transparency | Per-run/per-stage metric completeness and usage reconciliation | Record distributions first; no numeric latency/spend limit is selected. |

## Open items that are not acceptance criteria

The following remain gates or discovery questions and must not be turned into silent pass conditions: acceptable missed-blocker, false-approval, false-positive/unsupported-blocker and abstention rates; human review time/adoption; cost/latency ceilings; which provider/checkpoint/credential binding is supported; final risk floors and empty-review APPROVE behavior; retention/privacy ownership; required checks and profile authority; posting authorization; second held-out repository. Until each applicable decision has an owner and evidence, report it as **pending/unknown**. A passing structural check, syntactically valid contract, implementation success, synthetic model output, or single pilot run does not clear these gates.

## Source basis and limits

`RESEARCH.md` links OWASP and Google review practice and bounded review/evaluation studies. Those sources inform risk-sensitive, evidence-oriented review and conservative interpretation of alerts; they do not validate this harness or any provider. `qa-methodology/references/ai-code-quality-gates.md` informs independent verification, evidence, and failure handling. `programming-principles/references/code-assessment-workflow.md` informs context, concrete impact, local conventions, and avoiding noise; its broad human repository-inspection procedure is not itself adopted wholesale into a diff-scoped automated harness. `system-one/SKILL.md` bounds typed model judgments to deterministic policy and keeps model availability/quality claims separate. The assessment methods in this document are proposed future checks, not evidence they were executed.
