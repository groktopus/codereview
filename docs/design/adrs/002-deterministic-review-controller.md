# ADR-002: Keep review workflow and disposition deterministic

- Status: Proposed; acceptance not recorded
- Scope: scheduling, retries, escalation, termination, coverage, disposition, and effects
- Decision authority: unresolved; product owner and architecture owner must accept policy boundaries
- Primary contact: implementation owner to be assigned
- Evidence: BRIEF.md direct requirement that control flow stays outside probabilistic models; research memo; CONTRACTS.md reducer rules

## Context

The review requires bounded parallel scopes, finite budgets, retries, escalation, context scheduling, reconciliation, synthesis, and final disposition. A generative model that selects the next action would make authority, termination, and evidence coverage difficult to bound or reproduce. A model can still supply useful semantic assessments whose quality is unvalidated.

## Decision

Propose an explicit deterministic state machine and reducer. Models return only bounded, typed assessments and candidate findings against supplied evidence. The controller alone reserves budgets, chooses predeclared tasks, retries, escalates, stops, validates outputs, and computes disposition from reconciled findings plus coverage/freshness.

Unknown configured providers and unsupported requested model primitives reject preflight atomically. Provider outage, timeout, malformed results, and budget exhaustion produce explicit failed or missing coverage; they never turn into an implicit fallback or approval.

## Considered options

- Deterministic controller with bounded semantic judgments: preserves auditable workflow and permits replaceable providers; requires explicit policy and contracts.
- Prompt-driven agent workflow: flexible and quick to prototype; expands model authority to tools/actions, complicates budgets and termination, and conflicts with the stated requirement.
- Single generative review call: simple integration; does not provide independent scope coverage, robust reconciliation, or reliable blocker preservation.

## Consequences

Every transition and decision must be recorded with policy/profile/question versions. Model/provider claims need evidence and provenance. REVIEW disposition remains distinct from merge eligibility. APPROVE is prohibited for stale or incomplete required coverage. Evaluation of models remains advisory until representative independent adjudication exists.

## Confirmation plan

Review state-transition and reducer examples against stale head, missing context, invalid result, contradictory specialists, budget exhaustion, accepted blocker suppression, and no-finding cases. Future implementation should test the reducer independently from model output. These checks are planned; no model quality result is implied.
