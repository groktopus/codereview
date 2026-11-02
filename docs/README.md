# Documentation index

This is the entry point for the repository's documentation. It classifies every
Markdown document under `docs/` other than this index into one of four sections: current guidance,
reference contracts, history/evidence, or archive. The root [README](../README.md)
is the user-facing install and CLI guide; `docs/STATUS.md` is the
authoritative statement of what the harness does and does not do.

Current documents are the only ones presented as living guidance. Everything
else is dated, scoped to a named revision or run, or explicitly superseded. A
historical document is not deleted while evidence depends on it; the full
archive policy is in `docs/history/README.md`.

`scripts/check_docs_index.py` fails when a document is unindexed, listed in more
than one section, linked to a missing file, or when the Current section exceeds
ten documents. `scripts/check_relative_links.py` checks relative links in this
index, the root README, and `docs/` (including `docs/issues/`). `scripts/check_docs_truth.py`
checks claims and explicit revision provenance only in this Current set, plus the
root README. Historical issue records and run evidence are not natural-language
lint targets.

## Current

The small living set. Read these first. Dated evidence inside them remains
scoped to the revision and date it names.

| Document | What it records |
|---|---|
| [Status — PR Review Harness](STATUS.md) | Authoritative per-surface status: local CLI, central Actions, target-local route, publication, and replacement readiness. |
| [Current delivery plan — 2026-10-11](CURRENT-EXECUTION-PLAN.md) | Current delivery plan, next bounded work, and retained checkpoints. Dates its evidence; not a quality claim. |
| [Current production-requirement trace](CURRENT-DELIVERY-TRACE.md) | Canonical 39-AC, 12-NFR, six-milestone trace plus the 2026-10-11 operational supplement. |
| [Current rollout update — 2026-10-11](CURRENT-STATUS.md) | Dated rollout and evidence log for the harness source and the reported target-local deployment. |
| [Operations guide](OPERATIONS.md) | Safe local and Actions operation, evidence handling, failure diagnostics, and recovery. |
| [Deployment configuration](DEPLOYMENT-CONFIGURATION.md) | Trusted provider/profile configuration boundaries and secret-handling rules. |
| [Contract and version registry](CONTRACT-REGISTRY.md) | Supported, deprecated, and archived contract/version identifiers. |
| [Review completeness: taxonomy, summary, and regression gate](REVIEW-COMPLETENESS.md) | Canonical incomplete-reason taxonomy, per-run summary, and fixture regression gate. |
| [Production replacement delivery contract](PRODUCTION-DELIVERY.md) | Production replacement contract, six milestones, invariants, and the stateless publication correction. |
| [CLI publication preview migration](CLI-PUBLISH-PREVIEW-MIGRATION.md) | Preview-only `publish` surface; documents the deliberate absence of live publication. |

## Reference contracts

| Document | What it records |
|---|---|
| [Documentation truth checks](DOCUMENTATION-TRUTH-CHECKS.md) | DT-3 source-only link, claim, revision, contract-label, and OE-3 freshness-check contract. |
| [Status evidence (generated)](STATUS-EVIDENCE.md) | Derived revision, run, contract, publication, and owner-review staleness evidence generated from checked-in artifacts; not an owner review. |

Contracts, schemas, policies, and operating references that current work relies
on. A "proposed" label is meaningful: it is not acceptance or evidence of
implementation.

| Document | What it records |
|---|---|
| [Typed boundaries](TYPED-BOUNDARIES.md) | Stable record contracts, typed stage interfaces, and the strict-check scope and migration limits. |
| [Decision records (ADR index)](adr/README.md) | Status, owner, date, and evidence for each recorded decision, plus the safety-invariant change requirement and legacy-proposal reconciliation. |
| [Ownership, review authority, and access record](OWNERSHIP.md) | GA-3: path ownership, module map, second-reviewer protocol and limits, publication incident/rollback ownership, credentials, and the honest bus-factor-1 fallback. |
| [Backlog triage](BACKLOG.md) | GA-3: issue states, labels, owners, closure-evidence rules, issue forms, and the proposed owner/state mapping for the open issues. |
| [ADR 0001: post-CA-2 feature budget](adr/0001-post-ca2-feature-budget.md) | Accepted bounded source-line exception preserving the one-time CA-2 reduction. |
| [ADR 0002: production architecture](adr/0002-production-architecture.md) | Accepted: one modular core with typed deterministic stages and one production review path. |
| [ADR 0003: transport and credential policy](adr/0003-transport-security-policy.md) | Accepted: HTTPS for remote endpoints, exact loopback HTTP only, no redirects. |
| [ADR 0004: publication authorization](adr/0004-publication-authorization.md) | Accepted: READ_ONLY by default; live effects disabled on the CLI and central route. |
| [ADR 0005: model and provider boundary](adr/0005-provider-boundary.md) | Accepted: configured providers only, no new providers; production model remains unresolved. |
| [ADR 0006: evaluation gates](adr/0006-evaluation-gates.md) | Accepted no-claim rule; quality evidence and replacement readiness are not established. |
| [ADR 0007: license](adr/0007-license.md) | Accepted: MIT for original code and documentation, with third-party terms excluded. |
| [ADR 0008: release and version policy](adr/0008-release-version-policy.md) | Accepted: package SemVer plus independent contract versions, changelog, and tag-gated release. |
| [ADR 0009: ownership and second review](adr/0009-ownership-and-second-review.md) | Accepted: path-specific ownership, agent second path, bus-factor-1 limits, and triage states. |
| [Exception audit](EXCEPTION-AUDIT.md) | Typed error taxonomy, narrowed vs retained broad handlers, and defect-propagation rules. |
| [Review evidence receipts](REVIEW-EVIDENCE.md) | Required merge-review receipt fields including `decision_records` for safety-invariant changes, receipt rules, both CI checks and exit codes, owner action, and enforcement limits. |
| [Run metrics and stats](RUN-METRICS.md) | Versioned run-summary record, local aggregation/JSONL export, denominators, and honesty rules for unknown values. |
| [Provenance and evidence](PROVENANCE.md) | License/evidence boundary, retained snapshots, third-party content, and AI-assistance disclosure. |
| [Cost model and ceilings](COST-MODEL.md) | Operator price tables, estimated vs billed cost, currency ceilings, and unknown-value rules. |
| [Current package architecture](ARCHITECTURE.md) | Production module boundaries, package surface, and the experiments split. |
| [PR Review Harness contracts](design/CONTRACTS.md) | Proposed canonical records and envelopes used by the design package. Field names are canonical; runtime support varies. |
| [PR Review Harness — specification](design/SPEC.md) | Proposed behavior and independently testable acceptance criteria (the 39-AC/12-NFR baseline). |
| [PR Review Harness — traceability](design/TRACEABILITY.md) | Requirement-to-acceptance mapping and unresolved interpretations. |
| [Architecture decisions](design/adrs/README.md) | Index of proposed legacy design ADRs. None is recorded as accepted; the decision-record index reconciles them with the accepted production decisions. |
| [ADR-001: Keep a reusable modular core behind CLI and Actions adapters](design/adrs/001-modular-core-and-adapters.md) | Legacy design ADR-001, proposed and not accepted. The production modular-core decision is recorded as accepted in [ADR 0002](adr/0002-production-architecture.md). |
| [ADR-002: Keep review workflow and disposition deterministic](design/adrs/002-deterministic-review-controller.md) | Legacy design ADR-002, proposed and not accepted. Deterministic stages are recorded as accepted in [ADR 0002](adr/0002-production-architecture.md). |
| [ADR-003: Persist run evidence and make recovery and effects idempotent](design/adrs/003-durable-ledger-and-idempotent-effects.md) | Legacy design ADR-003, proposed and not accepted. Its storage shape is superseded by the current stateless direction; recovery and effect rationale is retained. |
| [ADR-004: Separate credentialed analysis from untrusted head-code execution](design/adrs/004-isolate-untrusted-pr-execution.md) | Legacy design ADR-004, proposed and not accepted. The implemented trust boundary is recorded in [ADR 0002](adr/0002-production-architecture.md), [ADR 0003](adr/0003-transport-security-policy.md), and [ADR 0004](adr/0004-publication-authorization.md). |
| [Threat model — PR Review Harness](THREAT-MODEL.md) | Threat model, trust boundaries, and effect controls. References current status for the target-local route. |
| [Production core contract](CORE-PRODUCTION.md) | Production core contract: budgets, provider-call accounting, durable resume, and coverage. |
| [Test and production model policy](TEST-MODEL-POLICY.md) | Test-versus-production model policy and rotation boundaries. |
| [Bounded free-model test matrix](TEST-MATRIX.md) | Bounded free-model test matrix. |
| [Coverage gates](COVERAGE-GATES.md) | Coverage-gate requirements and incomplete-coverage handling. |
| [Publication artifact intake boundary](ARTIFACT-INTAKE.md) | Publication artifact intake boundary compatible with stateless execution. |
| [OpenAI-compatible review provider](OPENAI-COMPATIBLE-PROVIDER.md) | OpenAI-compatible provider adapter contract. |
| [GitHub App credential provider](GITHUB-APP-CREDENTIAL-PROVIDER.md) | GitHub App credential-provider contract. |
| [Linux external effect observer v3](EXTERNAL-EFFECT-OBSERVER.md) | Linux external-effect observer v3 event, aggregate, and coverage contract. |
| [Context target manifest v1](CONTEXT-TARGET-MANIFEST.md) | Context target manifest v1 schema and identity rules. |
| [Bounded context selection](CONTEXT-SELECTION.md) | Bounded context selection and evidence-window rules. |
| [Source-bound dependency context](DEPENDENCY-CONTEXT.md) | Source-bound dependency context. |
| [Claim assessment adapter (advisory)](CLAIM-ASSESSMENT-ADVISORY.md) | Advisory claim-assessment adapter; probabilities do not authorize approval. |
| [Opt-in claim reconciliation](CLAIM-RECONCILIATION.md) | Opt-in claim reconciliation contract. |
| [Native Claim Screen Runner](CLAIM-SCREEN-RUNNER.md) | Native claim-screen runner contract. |
| [Production context profile revision](PROFILE-REVISION.md) | Production context-profile revision. |
| [Provider contract revision](PROVIDER-CONTRACT-REVISION.md) | Provider contract revision. |
| [Review evaluation toolkit](EVALUATION-TOOLKIT.md) | Review evaluation toolkit. |
| [Quality labeling and adjudication protocol](QUALITY-LABELING-PROTOCOL.md) | QM-2 severity/introducedness rubric, evidence, abstention, reviewer-kind, provenance, and relabeling protocol; no human labels exist yet. |
| [Quality scorecards and regression gate](QUALITY-SCORECARD.md) | QM-3 deterministic scorecard fields, missing-data semantics, accuracy refusal, and seeded regression gate. |
| [Frozen evaluation corpus v1](FROZEN-EVALUATION-CORPUS-V1.md) | QM-1 versioned 41-case corpus identity, provenance, splits, hashes, and limits. |
| [GitHub Actions canary runtime](ACTIONS-RUNTIME.md) | GitHub Actions canary runtime contract. |
| [Stateless GitHub Actions publication design](ACTIONS-PUBLICATION-DESIGN.md) | Stateless GitHub Actions publication design. |
| [GitHub review publication readiness](PUBLICATION-READINESS.md) | 2026-09-29 CLI/central-route publication NO-GO decision record, scope-qualified. It does not describe the reported post-2026-10-11 target-local route. |
| [Protected review publication runtime](protected-publication-runtime.md) | Protected review-publication runtime contract. |
| [Opt-in PR analysis publication bundle](pr-analysis-publication-bundle.md) | Opt-in PR-analysis publication bundle. |
| [Protected pull request analysis source](PROTECTED-PUBLICATION-SOURCE.md) | Protected pull-request analysis source boundary. |
| [GitHub App identity canary contract](github-app-identity-canary.md) | GitHub App identity-canary contract. |
| [System One decision strategy](SYSTEM-ONE-STRATEGY.md) | System One decision strategy and advisory-only boundary. |
| [Packaging and CI verification](PACKAGING-VERIFICATION.md) | Wheel, source-distribution, matrix, and installed-entry-point checks. |
| [Release and staged adoption plan](RELEASE-PLAN.md) | Release and staged-adoption plan; publication remains separately gated. |
| [Versioning policy](VERSIONING.md) | Package semantic versioning plus independent contract versioning, promised surfaces, and breaking-change rules. |
| [Release procedure](RELEASING.md) | Tag creation, release workflow triggers and permissions, verification commands, and rollback. |
| [Supply chain and release evidence](SUPPLY-CHAIN.md) | Release SBOM, unsigned provenance, reproducibility results, asset hashes, and consumer verification commands. |
| [Public API and internal-module policy](PUBLIC-API.md) | RS-4 supported import/CLI surface, internal-module compatibility policy, and zero-runtime-dependency contract. |
| [Support matrix, install matrix, and dependency policy](SUPPORT-MATRIX.md) | RS-4 supported Python/OS combinations, documented install matrix, hash-locked dev environment, dependency review switch, and scheduled vulnerability scan. |

## History and evidence

Dated checkpoints, experiments, trials, audits, reviews, and filed issue records.
They are retained and linked, but they are not current guidance and are not
maintained as such. Documents moved into `docs/history/` carry a prominent
banner; evidence that already lived under `docs/experiments/` or a
`historical-functional-review-*` package remains in place.

### Dated checkpoints

| Document | What it records |
|---|---|
| [Codebase assessment — PR Review Harness](CODEBASE-ASSESSMENT-2026-11-01.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Release notes — 0.1.0](releases/0.1.0.md) | Prepared release notes for the `0.1.0` source release: scope, verification commands, and the unsigned-provenance limit. Not evidence that a tag or GitHub Release exists. |
| [Complete requirement audit — 2026-10-01](COMPLETE-REQUIREMENT-AUDIT-2026-10-01.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Local hard-termination recovery qualification — 2026-10-01](HARD-TERMINATION-LOCAL-RECOVERY-QUALIFICATION-2026-10-01.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [SlopSearX historical pilot — 2026-09-26](PILOT-RESULTS.md) | The initial 2026-09-26 SlopSearX pilot and its limitations. |
| [Delivery reset — 2026-09-29](history/checkpoints/DELIVERY-RESET-2026-09-29.md) | Dated checkpoint moved to the history set; retained evidence, not current guidance. |
| [Hosted recovery drill evidence — 2026-09-27](history/checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-27.md) | Dated checkpoint moved to the history set; retained evidence, not current guidance. |
| [Hosted recovery drill evidence — 2026-09-28](history/checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-28.md) | Dated checkpoint moved to the history set; retained evidence, not current guidance. |
| [PR-464 read-only shadow run, 2026-09-29](history/checkpoints/pr464-shadow-run-2026-09-29.md) | Dated checkpoint moved to the history set; retained evidence, not current guidance. |

### Trials, audits, and evidence notes

| Document | What it records |
|---|---|
| [Adjudication Output-Budget Diagnosis](ADJUDICATION-OUTPUT-BUDGET-DIAGNOSIS.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Actions canary cleanup failure provenance](CANARY-CLEANUP-FAILURE-PROVENANCE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Existing reviewer baseline discovery](COMPARISON-DISCOVERY.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Current production-requirement trace](CURRENT-ACCEPTANCE-TRACE.md) | Earlier variant of the requirement trace. Use `CURRENT-DELIVERY-TRACE.md` as canonical; retained for provenance. |
| [Current-source synthetic paired trial](CURRENT-SOURCE-PAIRED-TRIAL.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Current v3 context baseline](CURRENT-V3-CONTEXT-BASELINE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Production evidence and publishing boundaries](EVIDENCE-PRODUCTION.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [PR464 Full-Context Budget Preflight](FULL-CONTEXT-BUDGET-PREFLIGHT.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Secretless hosted cancellation and resume rehearsal](HOSTED-RECOVERY-REHEARSAL.md) | Secretless hosted cancellation/resume protocol and scope. |
| [Independent implementation review: snapshot, planner, and engine](IMPLEMENTATION-REVIEW-CORE.md) | 2026-09-26 independent source review of snapshot, planner, and engine. |
| [First bounded review-injection trial](INJECTION-TRIAL-49BD559.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Candidate integration review](INTEGRATION-REVIEW.md) | Candidate integration review. |
| [Native claim challenge probe: advisory results](NATIVE-CLAIM-CHALLENGE-PROBE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Native claim screen: e22a085 development baseline](NATIVE-CLAIM-SCREEN-BASELINE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Native claim-to-triage boundary check](NATIVE-CLAIM-TRIAGE-BOUNDARY.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Bounded Nous v3 causal-role trial](NOUS-V3-CAUSAL-TRIAL.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Production pilot evidence and next evaluation](PILOT-EVIDENCE.md) | Pilot evidence, run artifacts, and the bounded evaluation backlog. |
| [PR 464 baseline claim assessment](PR-464-EVIDENCE-ASSESSMENT.md) | PR 464 baseline claim assessment. |
| [Prompt-injection evaluation](PROMPT-INJECTION-EVALUATION.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Prompt-injection shadow challenge](PROMPT-INJECTION-SHADOW-CHALLENGE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Preserved installed recovery rehearsal failure](RECOVERY-REHEARSAL-PR65-FAILURE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Installed CLI Recovery Rehearsal](RECOVERY-REHEARSAL.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Release evidence inventory](RELEASE-EVIDENCE-INVENTORY.md) | Checkpoint-specific release evidence inventory, not a fresh audit. |
| [Reversible Droid cutover qualification](REVERSIBLE-CUTOVER.md) | Pre-cutover DEFER package. Target-local statements describe the pre-2026-10-11 state. |
| [Review Coverage Follow-up](REVIEW-COVERAGE-FOLLOWUP.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Selected-model claim-assessment trial](SELECTED-MODEL-CLAIM-TRIAL.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Selected-pair sensitivity evidence](SELECTED-PAIR-SENSITIVITY-EVIDENCE.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [TypeSafe prompt-injection input screen](TYPESAFE-INPUT-SCREEN-TRIAL.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Hosted v17 selector preparation](V17-HOSTED-SELECTOR.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Verification and implementation status](VERIFICATION.md) | 2026-09-26 acceptance/spec-gap snapshot. Historical, not current implementation status. |
| [Worker readiness wait and Linux comparison](WORKER-READINESS.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Configured Jev synthetic injection classifier trial](configured-jev-injection-classifier-trial.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Cross-model v2 package adapter](cross-model-package-v1.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Context-selection candidate failure: PR 464 offline comparison](history/evidence/CONTEXT-CANDIDATE-FAILURE.md) | Historical evidence note retained for provenance; not a current claim. |
| [Historical SlopSearX trial](history/evidence/HISTORICAL-REAL-CASE-TRIAL.md) | Historical evidence note retained for provenance; not a current claim. |
| [Installed stateless CLI verification](history/evidence/INSTALLED-STATELESS-CLI-VERIFICATION.md) | Historical evidence note retained for provenance; not a current claim. |
| [Model-only shadow audit v1](model-only-shadow-audit-v1.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Shadow stage-local preflight v1](model-only-shadow-stage-preflight-v1.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Model-only shadow workflow status v2](model-only-shadow-workflow-status-v2.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [PR analysis recovery inputs](pr-analysis-recovery-inputs.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Prediction-blind review rubric: SlopSearX PR #477](pr477-prediction-blind-rubric.md) | Dated evidence, audit, trial, or review note; not current guidance. |
| [Selected control HTTP/TLS trace pair](selected-control-transport-pair.md) | Dated evidence, audit, trial, or review note; not current guidance. |

### Experiment and run notes

| Document | What it records |
|---|---|
| [Central pilot admission canary runs — 2026-09-29](experiments/central-pilot-admission-canary-2026-09-29.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Central read-only pilot evidence — 2026-09-29](experiments/central-read-only-pilot-evidence-2026-09-29.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Context follow-up closure diagnostics v2](experiments/context-followup-closure-diagnostics-v2.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Context-followup v1 provider run 36344740887](experiments/context-followup-v1-run-36344740887.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Context-followup v3 live run 36360197573](experiments/context-followup-v3-live-run-36360197573.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Historical SlopSearX PR466 functional diagnostic](experiments/historical-slopsearx-pr466-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Historical SlopSearX PR466 v2 diagnostic](experiments/historical-slopsearx-pr466-v2-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Historical SlopSearX PR466 v3 diagnostic](experiments/historical-slopsearx-pr466-v3-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Historical SlopSearX PR466 v4 diagnostic](experiments/historical-slopsearx-pr466-v4-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Historical PR466 static-assessment diagnostic v5 — 2026-10-01](experiments/historical-slopsearx-pr466-v5-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Hosted recovery cancellation and resume rehearsal](experiments/hosted-recovery-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Model-only shadow hosted runs — 2026-09-28](experiments/model-only-shadow-hosted-runs-2026-09-28.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Model-only shadow run 36517763840](experiments/model-only-shadow-run-36517763840.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Model-only shadow trial run 36543218060](experiments/model-only-shadow-run-36543218060.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Ordinary SlopSearX shadow runs — 2026-10-01](experiments/ordinary-slopsearx-shadow-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [PR305 post-fix review and project-onboarding evidence — 2026-10-07](experiments/pr305-postfix-and-project-onboarding-2026-10-07.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [PR305 and PR676 v17 operational evidence — 2026-10-07](experiments/pr305-pr676-v17-current-evidence-2026-10-07.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [SlopSearX PR305 v16 bounded review — 2026-10-07](experiments/pr305-v16-2026-10-07.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [PR305 v17 event-bound snapshot-reuse diagnosis — 2026-10-07](experiments/pr305-v17-event-rebound-snapshot-reuse-2026-10-07.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Second-repository onboarding and publication prerequisites — 2026-10-01](experiments/second-repository-onboarding-and-publication-prerequisites-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [FastMCP/MCP HTTP API evidence audit](experiments/slopsearx-pr466-sdk-source-audit-2026-10-01.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Installed transport round-trip failure: 36349985500](experiments/transport-installed-roundtrip-3919cf7.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |
| [Transport-pair diagnostic run 36347277922](experiments/transport-pair-run-36347277922.md) | Dated experiment or run evidence; scoped to the named revision, run, or artifact. |

### Historical PR 466 packages

| Document | What it records |
|---|---|
| [Historical PR 466 functional-review diagnostic](historical-functional-review-pr466-v1/README.md) | Historical PR 466 diagnostic package; retained run inputs and evidence. |
| [Historical PR 466 bounded-context trial (v2)](historical-functional-review-pr466-v2/README.md) | Historical PR 466 diagnostic package; retained run inputs and evidence. |
| [Historical PR 466 related implementation context trial (v3)](historical-functional-review-pr466-v3/README.md) | Historical PR 466 diagnostic package; retained run inputs and evidence. |
| [Historical PR 466 dependency-context trial (v4)](historical-functional-review-pr466-v4/README.md) | Historical PR 466 diagnostic package; retained run inputs and evidence. |
| [PR466 static-assessment diagnostic v5](historical-functional-review-pr466-v5/README.md) | Historical PR 466 diagnostic package; retained run inputs and evidence. |

### Issue records

These are the filed issue backlog and theme records. They are current working
intake, but not living guidance; DT-1 owns the status reconciliation.

| Document | What it records |
|---|---|
| [Theme: Review completeness](issues/01-review-completeness.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Quality measurement](issues/02-quality-measurement.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Controller architecture](issues/03-controller-architecture.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Verification depth](issues/04-verification-depth.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [VD-2 invariant and fault-test evidence](issues/vd2-test-evidence.md) | Development evidence note for deterministic properties, provider faults, and verification gaps. |
| [Theme: Security and effect boundaries](issues/05-security-and-effect-boundaries.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Release and supply chain](issues/06-release-and-supply-chain.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Observability and economics](issues/07-observability-and-economics.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Documentation truth](issues/08-documentation-truth.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Theme: Governance and accountability](issues/09-governance-and-accountability.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Filed issues](issues/FILED.md) | Filed issue or backlog record. Intake context, not living guidance. |
| [Issue backlog — path to A−](issues/README.md) | Filed issue or backlog record. Intake context, not living guidance. |

## Archive

Superseded designs and proposals retained for provenance. The proposed design
package below is not an accepted architecture; [design/ARCHITECTURE.md](design/ARCHITECTURE.md)
now says so prominently.

| Document | What it records |
|---|---|
| [Documentation history and archive policy](history/README.md) | Archive policy, historical-banner convention, and the git-mv move log. Read this before moving or deleting documentation. |
| [PR Review Harness design](design/README.md) | Reading order for the proposed design package. Status: proposed; independently reviewed with conditions. |
| [PR review harness — design input, 26 September 2026](design/BRIEF.md) | Drafting input and shared conventions for the design package. |
| [PR Review Harness — discovery record](design/DISCOVERY.md) | Discovery record, user requirements, pilot scope, and open decisions. |
| [PR Review Harness architecture](design/ARCHITECTURE.md) | Historical/proposed architecture. Banner states it is not the shipped system and points to current status/architecture docs. |
| [PR Review Harness — pilot evaluation plan](design/EVALUATION.md) | Prospective pilot evaluation design. |
| [SlopSearX pilot discovery](design/PILOT-CONTEXT.md) | SlopSearX pilot discovery and candidate project rules. |
| [Research-to-design memo: reusable pull-request review harness](design/RESEARCH.md) | Research-to-design memo, external evidence, and limitations. |
| [Gate Decision: PR Review Harness / Gate 1 Spec Review](design/REVIEW.md) | Independent Gate 1 design review and remaining conditions. |
| [Cross-model comparison v2](design/cross-model-comparison-v2.md) | Cross-model comparison v2 design. |
| [Bounded v16 review capacity candidate](history/design/BOUNDED-PRODUCTION-REVIEW.md) | Superseded v16 capacity candidate. |
| [Context selection v2 implementation plan](history/design/CONTEXT-SELECTION-V2-IMPLEMENTATION-PLAN.md) | Superseded context-selection v2 planning artifact; its known broken link was corrected without deleting the note. |
| [Initial implementation interface contract](history/design/IMPLEMENTATION-BOUNDARIES.md) | Initial implementation interface contract, superseded. |
| [Implementation plan — initial read-only pilot](history/design/TASK-PLAN.md) | Initial read-only pilot task plan, superseded. |
| [Offline multi-pass plan prototype](history/design/multipass-plan-prototype.md) | Offline multi-pass plan prototype, retained for provenance. |
| [PR-464 source-audit capacity v3](history/design/model-only-shadow-pr464-capacity-v3-proposal.md) | PR-464 capacity proposal, retained for provenance. |

### Archive policy

Nothing is deleted while evidence depends on it. Superseded material is moved
under `docs/history/` with a historical banner, or left in an evidence
directory and labeled in this index. Deletion requires proof that no retained
document, issue, test, script, or release record depends on the file. The full
policy, layout, and `git mv` move log are in
[history/README.md](history/README.md#archive-policy). The moves in this change
are recorded there and Git reports them as renames, not copies.

- [Reassessment 2026-11-02](REASSESSMENT-2026-11-02.md) — current A-minus judgment and blockers.
