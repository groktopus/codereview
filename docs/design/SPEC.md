# PR Review Harness — specification

## Status

- **Author:** Codex, specification workstream
- **Version:** 0.1.0 (draft)
- **Status:** Draft for independent Gate 1 review
- **Reviewed by:** Independent Luna-pinned Codex reviewer; see [REVIEW.md](REVIEW.md)
- **Gate verdict:** CONDITIONS; owner decisions remain pending (see REVIEW.md)
- **Authority:** Draft from one sponsor’s written brief, a confirmed delivery/pilot reply, read-only pilot discovery, and cited research. It is not stakeholder acceptance or release approval.
- **Contract references:** `ARCHITECTURE.md` and `CONTRACTS.md` define the proposed component boundaries and record contracts. They are design inputs, not implementation evidence.

## Problem Statement

Magnus wants a practical, reusable alternative to Droid PR review that applies QA and programming-principles lenses in the context of each project. The harness must spend review effort according to change risk and available context, preserve evidence and uncertainty, and keep workflow and effects under deterministic control. The first delivery is a CLI with GitHub Actions integration, piloted on `magnus919/SlopSearX`; available reviewers, provider bindings, and acceptable quality/cost bounds are not yet verified or selected.

## Success Criteria

The first pilot can be considered for adoption only after the CLI and Actions adapter produce an auditable local/CI report for immutable PR revisions; required review coverage, gaps, provenance, disposition, freshness, and merge-eligibility state are visible; bounded worker or provider failures cannot become a clean approval; and an independent pilot evaluation reports the measures and denominators in `EVALUATION.md`. Magnus must then choose acceptable missed-blocker, false-approval, unsupported-blocker, incomplete-review, latency, cost, and adoption bounds before any quality-based release gate is set. No numerical quality target is selected in this draft. A successful build, one PR, green CI, or model availability does not satisfy adoption criteria by itself.

## Scope

### In Scope — first usable pilot

- A reusable local core invoked by a CLI and a thin GitHub Actions adapter; both use the same review request, policy, result, and reducer contracts.
- Read-only SlopSearX pilot review bound to an immutable base/head snapshot and a trusted, versioned project profile.
- Deterministic risk/depth selection and finite configurable budgets; bounded parallel specialist tasks with a single coordinator.
- QA Methodology and Programming Principles as relevant lenses, plus trusted repository conventions, available checks, and change-specific context.
- Candidate finding capture, evidence validation/reconciliation, coverage and freshness accounting, deterministic disposition, merge-eligibility separation, and a local/CI report artifact.
- Optional semantic decision-provider adapters (including candidates such as hosted Jev, local Laya, or local GLiNER) only through each provider’s documented native supported contract. Provider identity and each requested capability must be established before binding it; a shared adapter shape does not assert cross-provider equivalence.
- Secretless isolated execution for any approved PR-controlled tests/builds, separate from credentialed metadata/evidence analysis.
- An evaluation design that distinguishes known findings, novel human-adjudicated findings, incomplete cases, natural-prevalence observations, and advisory model labels.

### Out of Scope (Explicit)

- Automatic merge, code repair, branch changes, label/comment/review publication, or other GitHub writes in the initial pilot.
- Running PR-controlled code, tests, hooks, builds, or generated executables in a job that has inference credentials or write-capable GitHub access.
- Treating model confidence, provider agreement, static-analysis alerts, line count, or a “no findings” response as proof of correctness or safety.
- Claiming application-wide security assurance from a diff-based review, universal language/project coverage, cross-project effectiveness from the SlopSearX pilot, or parity with Droid.
- Choosing production quality/error thresholds, provider/checkpoint, permanent project home, retention period, or operating cost/latency bounds without the owners and evidence recorded in `DISCOVERY.md` and `EVALUATION.md`.
- Implementing a hosted orchestration service, distributed queue, or multi-tenant worker fleet for the first pilot.

## Terms and decision boundary

- **Required scope:** explicitly planned obligations for changed-unit/lens coverage and separately scoped project checks, selected by the versioned trusted profile and deterministic policy. Checks do not implicitly form a Cartesian product with every lens. Applicability and exclusions must be recorded with a reason.
- **Changed unit:** an inventory item in the immutable snapshot. Each changed file is represented once by current path; renames also preserve old path. Generated or binary status needs trusted rule/provenance or remains unknown.
- **Evidence:** a hash-bound source or result reference attached to the snapshot. Trust class describes source authority, not factual truth.
- **Accepted blocker:** a reconciled finding with status `ACCEPTED` and `blocking_class=BLOCKING` under the versioned policy, supported by evidence of a concrete material consequence tied to changed/re-exposed behavior or an explicit trusted project policy. Severity and blocking classification are separate. A worker candidate alone is not an accepted blocker.
- **“No finding”:** a completed, valid scope result with zero accepted findings. It is different from missing, failed, invalid, skipped, or not-started coverage.
- **Review disposition:** the harness’s evidence-bound review recommendation. **Merge eligibility** is a separate repository-rule assessment. Neither grants merge authority.
- **Model/provider:** a bounded source of typed semantic judgments or candidate findings. It does not select workflow stages, tasks, tools, commands, budgets, policy, disposition, or effects.

## User Stories

### US-001: Run the same review contract locally and in CI

**Priority:** P0
**Description:** As a PR reviewer, I want a local CLI and GitHub Actions entry point to invoke one reusable review core so that pilot behavior does not depend on separate policy implementations.

**Acceptance Criteria:**

1. [AC-001] **Origin: SAID (R-013), INTERPRETED (R-017).** Given a valid explicit review request, when it is invoked through the CLI or Actions adapter, then each adapter submits the same versioned core request fields and neither adapter implements a separate disposition reducer.
2. [AC-002] **Origin: SAID (R-014), IMPLIED (R-021).** Given a SlopSearX PR, when the pilot starts, then the run records the canonical repository identity, PR number, event identity, full base/head SHAs, and trusted project-profile version; it does not infer a repository or profile from PR-controlled text.
3. [AC-003] **Origin: INTERPRETED (R-017).** Given the initial pilot configuration, when a review completes, then the CLI writes a local report and Actions retains a report artifact, and the run creates no GitHub comment, formal review, label, check conclusion, merge, or source modification.
4. [AC-004] **Origin: IMPLIED (R-015), INTERPRETED (R-020).** Given missing/invalid repository identity, revision, profile-version identifier, mode, required finite limit, or unauthorized effect configuration, when preflight runs, then it rejects atomically before worker dispatch or external effects and reports each rejected field without exposing credentials. Given a valid profile-version reference that cannot be loaded or validated, then it returns the configured explicit unsupported/incomplete outcome before dispatch; it cannot silently use an empty or generic profile.
5. [AC-005] **Origin: IMPLIED (R-022).** Given a request with a duplicate event or resumed run, when the same `run_id` and task idempotency keys are presented, then the controller resumes or deduplicates that logical work; a new invocation that is not a resume receives a new `run_id`.
6. [AC-039] **Origin: IMPLIED (R-015), INTERPRETED (R-017).** Given a CLI invocation terminates, when it has durably written a valid terminal result (including disposition `INCOMPLETE`), then exit code is `0`; given invalid request/configuration rejected atomically during preflight, then exit code is `2`; given an internal/runtime failure without a valid durable terminal result, then exit code is `1`.

**Edge Cases:**

- Duplicate Actions delivery versus intentional new run; reused identifier with a different snapshot/profile; malformed or unsupported contract version.
- No trusted profile, unavailable GitHub metadata, unreadable diff, deleted file, rename, binary file, generated file without trusted provenance.
- Actions adapter unavailable; local CLI remains the same contract consumer. Actions event configuration and permissions are repository-specific implementation gates.

### US-002: Choose review effort by risk and context

**Priority:** P0
**Description:** As a reviewer, I want review depth to reflect potential impact and context uncertainty so that a one-line authorization change receives more scrutiny than a low-impact prose correction without relying on line count alone.

**Acceptance Criteria:**

1. [AC-006] **Origin: SAID (R-003), INTERPRETED (R-020).** Given the trusted versioned profile classifies a change as prose/documentation-only with no executable examples, policy effect, or generated-code relationship, when AUTO routing runs, then the minimum mode is LIGHT; given the profile identifies any authentication, authorization, permission, trust-boundary, secret-handling, input-validation, or policy-gate change, then the minimum mode is FOCUSED and the relevant security and correctness lenses are required. These are proposed routing rules pending pilot validation, not calibrated thresholds.
2. [AC-007] **Origin: SAID (R-003), INTERPRETED (R-020).** Given a large mechanical/documentation change and a small trust-boundary or security-sensitive change, when routing selects effort, then changed-line count alone cannot lower the latter’s configured risk floor or make the former automatically deep.
3. [AC-008] **Origin: IMPLIED (R-015), INTERPRETED (R-020).** Given unknown language, missing callers, incomplete profile, uncertain generated provenance, or unavailable risk signal, when routing runs, then unknown information is recorded and cannot silently downgrade a required lens, risk floor, or mode.
4. [AC-009] **Origin: SAID (R-002, R-004), INTERPRETED (R-020).** Given a selected mode and trusted profile, when the scope plan is produced, then every required changed unit and applicable lens/check is listed before dispatch with a stable scope/task identity, or is explicitly listed as not applicable with its rule and reason.
5. [AC-010] **Origin: SAID (R-002, R-004), IMPLIED (R-015).** Given a deterministic check or test is relevant to a changed surface, when its required scope is planned, then its exact trusted binding and finite execution limits are named; a check is never inferred as required solely because it appears in a workflow file.

**Edge Cases:**

- One-line permission change versus prose typo; high-churn refactor versus narrow data-consistency change.
- Profile says a lens is not applicable versus profile is missing; unknown caller map versus verified absence of callers.
- Existing CI job is present but its check is not configured as required for this PR.

### US-003: Review applicable project and software-quality concerns

**Priority:** P0
**Description:** As a reviewer, I want correctness, tests, design, security, reliability, and local rules considered when relevant so that generic principles do not override actual contracts and conventions.

**Acceptance Criteria:**

1. [AC-011] **Origin: SAID (R-002, R-004), INTERPRETED (R-020).** Given a planned scope, when specialist tasks are dispatched, then the review includes applicable correctness and tests, design/code-smell, security, and trusted project-specific lenses; omitted or inapplicable lenses have an explicit reason in the coverage ledger.
2. [AC-012] **Origin: SAID (R-002), INTERPRETED (R-020).** Given a project rule conflicts with a generic programming-principle preference, when a candidate concern is evaluated, then the trusted local contract controls and generic preference alone cannot become a blocker.
3. [AC-013] **Origin: SAID (R-004), INTERPRETED (R-019).** Given a smell or style concern without a concrete behavioral, security, reliability, or stated project-rule impact, when it is reconciled, then it cannot be classified as a blocker; if retained as feedback, it is clearly nonblocking and evidence-linked.
4. [AC-014] **Origin: SAID (R-004), IMPLIED (R-021).** Given a candidate regression, when its relationship to base/head evidence is reconciled, then introduced, re-exposed, pre-existing, and unknown status are distinguishable; a pre-existing concern is not attributed to the PR as introduced.
5. [AC-015] **Origin: SAID (R-004), INTERPRETED (R-019).** Given a static-analysis or tool alert, when it is included in a finding, then the alert is identified as a lead and the finding separately records evidence supporting the claimed behavior and consequence; the alert by itself cannot substantiate a blocker.

**Edge Cases:**

- Existing defect on base; changed code re-exposes it; code moves the defect without changing the displayed line.
- Alert points at adjacent code, no alert exists, or the tool reports a warning without relevant behavior.
- Generic smell conflicts with documented layering, fail-closed policy, adapter contract, or module convention.

### US-004: Bound and reconcile parallel specialist work

**Priority:** P0
**Description:** As a reviewer, I want scoped specialist tasks to run efficiently while a deterministic coordinator retains control and reconciles their evidence.

**Acceptance Criteria:**

1. [AC-016] **Origin: SAID (R-008), IMPLIED (R-022).** Given multiple independent required scopes and remaining configured capacity, when work is scheduled, then only predeclared scopes may run in parallel up to `max_concurrent_scopes`; workers cannot add scopes, tasks, tools, commands, retries, or budget.
2. [AC-017] **Origin: SAID (R-005, R-006), IMPLIED (R-022).** Given any provider response, when controller state advances, then sequence, task selection, retry, escalation, termination, disposition, and effects are selected by deterministic policy; a provider response contains no executable next action and cannot change these policies.
3. [AC-018] **Origin: SAID (R-008), INTERPRETED (R-019).** Given two specialists return the same supported concern, when results are reconciled, then candidate provenance is retained, duplicates are grouped without losing distinct locations/impacts/evidence, and a stable reconciled finding ID is used in the report.
4. [AC-019] **Origin: SAID (R-008), INTERPRETED (R-019).** Given specialists make conflicting claims about one concern, when results are reconciled, then all conflicting finding IDs and evidence are retained with an explicit contradiction/uncertainty record; no model vote, confidence average, or silent last-write-wins rule resolves the conflict.
5. [AC-020] **Origin: IMPLIED (R-015, R-022), INTERPRETED (R-019).** Given a worker result envelope or required assessment is malformed/unsupported, times out, or conflicts with a prior output hash, when the result is processed, then it is rejected or quarantined, bounded retry policy is applied, and the affected scope remains PARTIAL or NOT_STARTED unless a valid result completes it. Given an otherwise valid result contains an invalid candidate or context-gap item, then that item is retained with a typed invalid status and cannot be accepted or trigger retrieval, while unrelated valid items remain eligible for reconciliation.

**Edge Cases:**

- Worker timeout followed by a late result; malformed result repeated to retry limit; identical retry versus conflicting output hash.
- Duplicate/correlated findings with different impacts; contradiction between correctness and security specialists.
- Available budget cannot finish all scopes; no specialist returns a finding but each required task completes.

### US-005: Preserve evidence, gaps, and freshness

**Priority:** P0
**Description:** As a reviewer, I want every outcome tied to immutable revisions and evidence so that incomplete or stale work cannot look like a completed clean review.

**Acceptance Criteria:**

1. [AC-021] **Origin: IMPLIED (R-021).** Given a review begins, when the snapshot is created, then it records `snapshot_id`, `run_id`, repository/PR identity, full `base_sha` and `head_sha`, event ID, project-profile version, changed-unit inventory, trusted-context references, ignored/generated reasons, and a hash; snapshot contents do not change during the run.
2. [AC-022] **Origin: IMPLIED (R-021), INTERPRETED (R-019).** Given any finding candidate, when it enters reconciliation, then it identifies its task, snapshot, changed unit, location, observation, consequence, applicable rule/contract, evidence references, and whether its reasoning is observed or inferred; every evidence reference has source kind, locator, content hash, capture time, and trust class. Structural validation may establish identity, location, and provenance but cannot alone establish truth or materiality. Any semantic assessment is bounded to cited evidence and records its aggregate outcome (`SUPPORTED`, `NOT_SUPPORTED`, `UNCERTAIN`, or `CONTRADICTED`) and separate observation, consequence, rule-connection, and introducedness support states, assumptions, and missing context; `NOT_ESTABLISHED` is not evidence of a negative claim, and model confidence alone cannot establish acceptance. A typed context-gap proposal may name a bounded evidence kind and target with supporting candidate/evidence IDs, but only the deterministic controller decides whether allowlisted retrieval or a new task is permitted and reserves its budget.
3. [AC-023] **Origin: SAID (R-009), IMPLIED (R-021).** Given the review report is rendered, when a reviewer inspects it, then each finding links to stable ID and evidence, and the coverage ledger shows every required unit/lens state, including `COMPLETE`, `PARTIAL`, or `NOT_STARTED`, plus reason and relevant task/evidence IDs.
4. [AC-024] **Origin: SAID (R-009), IMPLIED (R-021).** Given a scope returns no accepted finding, when its ledger entry is emitted, then it is distinguishable from not run, failed, invalid, skipped, or out-of-budget work; the phrase “no finding” is only used for a valid completed scope.
5. [AC-025] **Origin: IMPLIED (R-021), INTERPRETED (R-016).** Given GitHub reports a different current head SHA at final freshness check, when the result is finalized, then `freshness=STALE`, observed and expected SHAs are recorded, the result cannot be published, and a fresh `run_id` is required for a current review.
6. [AC-026] **Origin: IMPLIED (R-021), INTERPRETED (R-016).** Given current head cannot be verified, when the result is finalized, then `freshness=UNKNOWN`; the result cannot be represented as current or eligible for approval/publication.

**Edge Cases:**

- Head changes during worker execution or after rendering; GitHub API unavailable at final check.
- Missing caller/context; unparseable diff; omitted file; generated/binary file has no trusted classification.
- One required task complete and another timed out; no finding versus no task result.

### US-006: Produce a faithful report and distinct decision states

**Priority:** P0
**Description:** As a reviewer, I want a concise report and a review recommendation that preserve blockers and distinguish coverage, freshness, and merge eligibility so that I can decide what to do next without confusing the harness with an approver.

**Acceptance Criteria:**

1. [AC-027] **Origin: SAID (R-009).** Given a terminal report, when it is rendered, then it has exactly four sections in this order: blockers, suggested improvements, specific strengths, and future guidance; any empty section is visibly empty rather than fabricated.
2. [AC-028] **Origin: SAID (R-009), INTERPRETED (R-019).** Given at least one accepted blocker, when editorial synthesis finishes, then every accepted blocker’s stable finding ID and evidence link remains in the blockers section; synthesis cannot delete, downgrade, or add unsupported positives to the structured reconciled findings.
3. [AC-029] **Origin: SAID (R-010), INTERPRETED (R-016).** Given `freshness=CURRENT`, `coverage_state=COMPLETE`, valid policy/profile, no accepted blocker, and no unresolved required gap, when the deterministic reducer evaluates the result, then disposition is `APPROVE` only if the configured policy permits an empty/nonblocking review to use APPROVE.
4. [AC-030] **Origin: SAID (R-010), INTERPRETED (R-016).** Given one or more accepted blockers, when the deterministic reducer evaluates the result, then disposition is `REQUEST_CHANGES` even if coverage is PARTIAL, and the incomplete coverage is disclosed alongside the blocker.
5. [AC-031] **Origin: SAID (R-010), INTERPRETED (R-016).** Given current coverage is complete with no accepted blocker but nonblocking actionable feedback exists, when the reducer evaluates the result, then disposition may be `COMMENT`; given no blocker and a required gap or noncurrent freshness, disposition is `INCOMPLETE` unless an accepted blocker requires `REQUEST_CHANGES`.
6. [AC-032] **Origin: SAID (R-010), INTERPRETED (R-016).** Given any review result, when merge eligibility is reported, then it is a separate field with `UNKNOWN`, `ELIGIBLE`, `INELIGIBLE`, or `NOT_EVALUATED`; absent configured rule evidence, it is never inferred as `ELIGIBLE`, and no disposition authorizes merge.

**Edge Cases:**

- Accepted blocker coexists with missing critical coverage; preserve `REQUEST_CHANGES` and `PARTIAL`.
- Current complete review has no findings; policy does not allow clean-empty approval; use `COMMENT` or configured permitted `APPROVE` semantics.
- Editorial renderer omits a blocker or asserts a passed check not present in ledger; output validation fails or report is incomplete.

### US-007: Keep providers, execution, and effects within explicit boundaries

**Priority:** P0
**Description:** As a project/security owner, I want untrusted PR content, credentials, model adapters, and side effects isolated so that a review cannot rewrite policy, leak a secret, execute an unsafe action, or claim unverified provider behavior.

**Acceptance Criteria:**

1. [AC-033] **Origin: SAID (R-005, R-007), INTERPRETED (R-018).** Given a title, body, comment, filename, diff, commit message, generated file, or worker result includes instructions, when it is consumed, then it is treated as untrusted evidence and cannot alter trusted profile, allowed tools/commands, budgets, provider plan, workflow, secrets policy, or effects.
2. [AC-034] **Origin: SAID (R-011), INTERPRETED (R-018).** Given credentialed analysis reads PR data, when it calls a configured provider, then credential values are available only to the transport adapter and are absent from prompts, task payloads, reports, artifacts, logs, and crash output; untrusted code is not executed in that credentialed job.
3. [AC-035] **Origin: IMPLIED (R-015), INTERPRETED (R-018).** Given the implementation runs an approved PR-controlled test/build check, when it executes, then it uses a disposable isolated job with no secrets, no write-capable token, no shared writable cache, and finite CPU, memory, process, filesystem, network, and time limits; the check result returns as bounded typed data with provenance.
4. [AC-036] **Origin: SAID (R-006, R-011), INTERPRETED (R-015).** Given a configured provider or model primitive is unknown, unsupported, or lacks verified binding, when preflight runs, then it rejects before dispatch and does not substitute another provider. Hosted Jev comparison is optional/advisory; local Laya and GLiNER use their native contracts. Each adapter must document and evaluate its own capability; a shared interface shape does not imply equivalent semantics or quality.
5. [AC-037] **Origin: IMPLIED (R-022), INTERPRETED (R-017).** Given initial pilot effect policy is `READ_ONLY`, when any publisher or write path is requested, then preflight rejects it; future `PUBLISH_REVIEW` requires a separately authorized least-privilege design, a current-head recheck, result-hash binding, and idempotent effect reconciliation. No path performs auto-merge or code repair.
6. [AC-038] **Origin: INTERPRETED (R-023).** Given provider availability or a credential binding is considered for implementation, when repository metadata and committed workflow evidence observed on 2026-09-26 are consulted, then `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY` are treated only as repository-secret metadata; the existing `general` Droid alias’s OpenAI-like LiteLLM endpoint is not attributed to a verified Nous backend; an empty or synthetic `TYPESAFE_API_KEY` CI value is not live Jev credential/inference evidence. Credential values remain uninspected, and names-only metadata must be refreshed before implementation.

**Edge Cases:**

- Prompt injection in PR title, body, code comment, path, test output, or provider response.
- Local provider unreachable from hosted Actions; secret expected by stakeholder but absent from repository metadata; Actions receives empty test-only placeholder.
- Unsupported primitive or changed provider response shape; no silent model fallback.
- Test job attempts network access, writes to shared cache, reads secrets, or returns oversized/malformed artifacts.

## Non-Functional Requirements

No latency, cost, availability, accuracy, recall, precision, or adoption threshold is known. The measurable requirements below are invariants and bounded-operation checks; they do not create an unapproved model-quality release gate. Numeric operating ceilings must be finite and configured by the pilot owner before execution; actual values are a pending product decision.

| ID | Requirement | Threshold | Verification Method |
|---|---|---|---|
| NFR-001 | Deterministic control plane | 0 workflow, next-action, command, retry, termination, disposition, permission, or effect choices delegated to a probabilistic response | Contract inspection plus adversarial adapter tests; trace every state transition to trusted deterministic policy or external observed state. |
| NFR-002 | Finite operating bounds | 100% of potentially repeated/concurrent/provider/check operations has a finite configured ceiling before dispatch; all ceilings are positive except retry count, which is a finite integer ≥0; observed reservations and completions never exceed them | Preflight boundary inspection and instrumented run proving each ceiling rejects further work; missing, non-finite, negative, zero where disallowed, or fractional integer limits reject before dispatch. Verify `max_retries_per_task=0` makes no retry. Required limits: deadline, concurrency, provider calls, per-task retries, per-task input/output bytes, total context bytes, plus monetary cap where known pricing/policy requires it. |
| NFR-003 | Coverage denominator and failure honesty | 100% of snapshot changed units and configured required lenses appear in unit/lens coverage; 100% of required project checks, required context, security, and policy obligations appear as separately scoped entries with result/provenance; 0 failed/unknown required obligations represented as COMPLETE | Compare snapshot inventory and trusted profile plan to each frozen `obligation_kind`/`obligation_id` ledger entry; inject timeout, malformed result, unavailable provider, omitted context, exhausted budget, and no-finding responses. |
| NFR-004 | Snapshot freshness | 100% of terminal reports identify full base/head SHAs and profile version; 0 stale/unknown results published or represented as current/APPROVE | Contract check and head-mutation/API-unavailable scenarios; inspect output fields and publisher guard. |
| NFR-005 | Evidence and finding provenance | 100% of accepted findings link stable ID, snapshot, changed unit/location, evidence hashes/locators, task, and reconciliation status; 100% of generated strengths have positive evidence | Result-schema inspection and report-to-ledger consistency check; use missing, invalid, stale-location, unsupported, contradictory, and duplicate candidates. |
| NFR-006 | Blocker preservation | 100% of accepted blocker IDs survive rendering with status, location, and evidence; no editorial stage changes reducer input or result fields | Property/contract check on synthesized output, including a fixture that omits or downgrades a blocker. |
| NFR-007 | Secret isolation | 0 credential values in prompts, requests, logs, ledger, reports, artifacts, or crash output; 0 PR-controlled execution in credentialed analysis | Security boundary inspection, seeded canary-secret scan of all emitted artifacts/logs, and workflow permission/job review. Never use real secret values in the test. |
| NFR-008 | Read-only pilot effects | 0 repository/PR write effects and 0 repository mutations during initial pilot; report artifact upload is permitted as workflow delivery | Workflow permission review and audit of GitHub API calls/repository state for pilot runs. This is a required pilot constraint, not a later publishing guarantee. |
| NFR-009 | Reconciliation integrity | 100% of unsupported, contradicted, duplicate, needs-evidence, timeout, invalid, skipped, and budget-exhausted outcomes remain inspectable with provenance; conflicting hashes are never last-write-wins | Ledger consistency inspection and duplicate/conflict/failure replay scenarios. |
| NFR-010 | Provider boundary honesty | 100% of semantic task results name actual provider/model/runtime/native contract and input/output/question hashes or explicitly record unavailable provenance; 0 implicit substitutions or equivalence claims | Adapter contract inspection; unknown provider, unsupported primitive, changed model identity, and missing metadata scenarios. |
| NFR-011 | Evaluation and adoption evidence | Human labels are currently unavailable. No quantified quality-based release/adoption claim or quality-based Droid replacement until the evaluation report has denominators, frozen splits/provenance, independent labels/adjudication for novel findings, error/abstention analysis, and sponsor-selected quality bounds. Labels are not required to qualify an owner-authorized, read-only advisory shadow while the incumbent remains authoritative, all case/role outcomes and deterministic checks are accounted for, and the operational hard thresholds in `EVALUATION.md` pass. This operational qualification is not a quality gate, publication authorization, or replacement decision. A future non-blocking publication canary additionally requires the deterministic publication controls and complete, role-separated LLM/Jev evidence in `../model-only-shadow-audit-v1.md`, plus separate owner authorization; model agreement cannot satisfy an accuracy gate. A reversible cutover requires the operational evidence and explicit owner acceptance that semantic accuracy remains unknown. | Review `EVALUATION.md` and `../model-only-shadow-audit-v1.md` against the decision gates. For shadow qualification, verify exact snapshot/provenance, explicit terminal/unknown states, zero deterministic safety/control regressions or configured-limit overruns, no unauthorized effects, and a stop/rollback condition. For publication/cutover, verify all role outcomes and deterministic checks, least privilege, recovery evidence, owner authorization, and explicit retention of unknown semantic error rates. Do not claim calibration, ground truth, or quality-based adoption without independent labels. |
| NFR-012 | Latency/cost transparency | Per-run and per-stage elapsed time, retries, provider/tool calls, known provider spend, budget exhaustion, and unavailable cost values are recorded; no universal numeric threshold until selected | Inspect result/ledger metrics against a controlled run and compare provider usage when returned; unknown price is reported as unknown, not zero. |

## Data Contracts & Interfaces

The canonical field/type contracts are documented in [`CONTRACTS.md`](CONTRACTS.md); this spec uses that document rather than duplicating its schemas. Producer/consumer boundaries include:

- `ReviewRequest` → CLI or Actions adapter → deterministic controller; explicit repository, PR, full SHAs, event ID, profile version, mode, provider plan, finite limits, and effect policy.
- `ReviewSnapshot` → immutable evidence basis; snapshot identity/hash, changed-unit inventory, trusted context references, generated/ignored reasons, and full revisions.
- `ScopeTask` / `TaskResult` → fixed bounded task and typed result; task scope, lens, provider/check binding, attempt/idempotency key, provenance, and explicit failure status.
- `EvidenceRef` / `FindingCandidate` → `AcceptedFinding`; evidence is hash-bound and trust-labelled; reconciliation keeps unsupported, contradictory, duplicate, and needs-evidence items visible.
- Coverage ledger + reconciled findings → deterministic `ReviewResult`; independent fields for coverage, freshness, disposition, and merge eligibility.
- `ReviewResult` → four-section local/CI report and durable per-run ledger; artifact delivery in the pilot, with publication disabled.

Unknown fields/enums in strict records, invalid required references, unsupported provider primitives, absent required input, and invalid limits reject the whole request/result atomically. The candidate/proposal item-level exception is narrow: a valid result wrapper may retain an individual invalid candidate/proposal with a typed item error, exclude it from acceptance/retrieval, and continue unrelated valid items. No secret value enters any contract. Any contract change is versioned and requires compatibility review before consumers depend on it. The CLI accepts explicit repository, PR, expected SHAs, profile version, mode, provider plan, finite limits, and effect policy. Exit status is `0` only when a valid terminal report is durably written (including disposition `INCOMPLETE`), `2` for atomic preflight rejection before dispatch, and `1` for internal/runtime failure without a valid terminal report. When a diagnostic report path is available on failure, the CLI returns it through its defined diagnostic channel. The exact CLI flags/file format, Actions event and permissions, repository profile serialization, report presentation, and credential reference name remain implementation/discovery decisions; they are not silently inferred by this spec.

## Assumptions & Open Questions

| # | Assumption / Question | Impact if Wrong | Resolution |
|---|---|---|---|
| 1 | Magnus’s confirmed CLI + GitHub Actions and SlopSearX choices are sufficient authority to define the initial pilot surface. | If the pilot needs another entry point or repository, interfaces and discovery change. | Record as confirmed in `DISCOVERY.md`; verify affected maintainers’ needs before broader adoption. |
| 2 | The initial pilot can use a read-only report artifact and local CLI without writing to the PR. | If inline or formal review publication is required, publisher security/idempotency and authority contracts are missing. | Keep write effects disabled; obtain explicit product/owner authorization and Gate review before a future publication design. |
| 3 | SlopSearX’s committed guidance/configuration is a candidate trusted profile source. | Guidance may be stale, incomplete, or not authoritative for every owner; wrong rules can misroute or misclassify review. | Re-discover current base revision and confirm profile sources with repository maintainers; encode selected revision/provenance. |
| 4 | Credentialed analysis can inspect bounded PR evidence without executing PR code. | Provider data-handling, repository permissions, or Actions event path may violate isolation. | Verify actual event, permissions, endpoint, secret-name binding, and provider retention before integration; no values or calls in this phase. |
| 5 | Hosted generative inference, Jev, Laya, and GLiNER may be candidates, but provider/runtime availability and useful code-review judgments are unverified. | Native contract, latency/cost, language, output quality, and hosted-network reachability may prevent or change an adapter. | Discovery first, then native contract checks and held-out evaluation; no fallback/equivalence assumed. |
| 6 | Named `APPROVE`, `REQUEST_CHANGES`, `COMMENT`, and `INCOMPLETE` semantics in R-016 are a proposed consistent reducer contract. | A sponsor or repository’s desired “empty complete review” behavior may differ. | Treat reducer criteria as proposed until sponsor/maintainer validates; revise before implementation gate. |
| 7 | A finite configurable budget contract can be defined before exact budget values are selected. | Missing values could block any run; too-small limits could create frequent incomplete results; high limits could incur unacceptable cost. | Require explicit finite values and record them per run; owner selects values using pilot cost/latency observations before any deployment. |
| 8 | First-pilot output-quality and operating thresholds are deliberately unknown. | Without explicit bounds, no quality/release/adoption claim is defensible. | Run `EVALUATION.md`; Magnus selects bounds after seeing labeled results, denominators, uncertainty, and cost tradeoffs. Until then a release/adoption gate is pending. |
| 9 | At least some PR-controlled tests may be useful if isolated. | Isolation restrictions may make tests unavailable or flaky; absent test execution must not appear as successful test coverage. | Keep secretless sandbox contract; record not run/failure and corresponding coverage gap. |
| 10 | The architecture and contract drafts express a feasible initial single-process core. | Implementation may reveal durability, recovery, API, or Actions constraints that conflict with proposals. | Independent architecture/Gate 1 review; revise this spec/contract set before implementation. |

## Revision History

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1.0 | 2026-09-26 | Codex | Initial specification draft aligned to R-001–R-022 and proposed architecture/contracts. |
