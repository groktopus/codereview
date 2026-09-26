# PR review harness — design input, 26 September 2026

Status: stakeholder-grounded design/specification drafting, no application implementation. Working name only: PR Review Harness. All artifacts here remain outside agent-skills. No remote repository, deployment, inference calls, GitHub review posting, or merge is authorized by this documentation task.

## Direct stakeholder requirements

- Magnus pays for Droid partly for PR code reviews and wants a practical alternative with reusable review behavior across multiple software projects.
- Use QA Methodology and Programming Principles as relevant review lenses; actual project rules/context matter.
- Adapt review effort to risk and context instead of doing a deep review of every change or using line count alone.
- Review correctness/tests, code smells/design, security, and other applicable aspects.
- Keep control flow outside probabilistic models. Harness owns sequence, scheduling, budgets, retries, escalation, termination, and effects. System One may supply bounded semantic judgments consumed by deterministic policy. Do not prompt a generative reviewer to choose workflow/next actions.
- Run applicable specialist reviews in parallel with bounded scopes and aggregate their reports. Final output separates blockers, suggested improvements, specific strengths, and future guidance. Preserve important evidence and unresolved gaps.
- Choose a final PR review disposition based on review evidence; distinguish review disposition from merge eligibility and authority.
- Hosted generative inference credentials and local GLiNER and Laya are reportedly available. Exact deployment/checkpoint/API/budget has not been verified. Do not presume model equivalence or code-review judgment competence.
- Produce architecture and spec before building anything. Delegate execution to gpt-6-luna high, fresh contexts; root owns oversight and synthesis.

## Confirmed discovery reply

Magnus selected CLI with GitHub Actions integration for first usable delivery and named magnus919/SlopSearX as the pilot. Failure tolerances, budget, posting mode, exact provider/checkpoints, and success thresholds remain open (the second reply names only the project). This reply overrides earlier provisional delivery-surface assumptions. Discover SlopSearX read-only before claiming its language, checks or policy.

Magnus adds: SlopSearX should already have a repository secret for the Nous Portal inference provider. Treat as stated expectation until metadata/workflow references verify. Inspect names only, never values; no inference calls in this documentation phase. Plan a separate trusted credentialed analysis job from any untrusted PR test execution.

Magnus also believes a Typesafe/Jev secret exists. Preserve this as an expectation, not a verified name/provider binding. Optional hosted Jev comparison can be architected through the same provider boundary; local GLiNER/Laya remain supported candidates with native contracts. No calls or secret values are needed now.

## Research and skills

Research-to-design memo: [RESEARCH.md](RESEARCH.md). It includes primary-source links and methodological limits. Human review evidence is not AI performance validation; no universal LOC/confidence thresholds are established. Model-assisted screens are advisory, not human ground truth.
Repo skills: /Volumes/tank01/magnus/git/agent-skills/product-discovery/SKILL.md ; spec-driven-development/SKILL.md ; software-architecture/SKILL.md ; qa-methodology/SKILL.md ; programming-principles/SKILL.md ; system-one/SKILL.md. Updated harness-engineering is in /Users/magnus/.codex/worktrees/harness-engineering/agent-skills/harness-engineering/SKILL.md.

## Shared design conventions (proposed, not user-approved)

- Local modular core with CLI and optional GitHub Actions adapter is an initial option, not a confirmed delivery surface. User has pending questions about initial surface and pilot repositories/failure tolerances.
- Read-only review/local report is the conservative pilot; optional future publishing must be explicit and least-privilege. No auto-merge or code repair in initial scope.
- Canonical internal dispositions: APPROVE, REQUEST_CHANGES, COMMENT, INCOMPLETE. A stale snapshot has freshness=STALE and cannot be published; findings can still justify REQUEST_CHANGES with coverage_state=PARTIAL, but never APPROVE. Explain both coverage and disposition rather than hiding gaps.
- Worker outputs candidate findings/evidence/context gaps. Reconciliation validates locations, substantiates or records uncertainty, deduplicates and resolves contradictions. Editorial synthesis does not drop accepted blockers, invent positives, or override policy. Deterministic disposition reducer consumes reconciled findings and required coverage; exact initial eligibility policy is a proposed draft contract.
- Shared immutable review snapshot, trusted versioned project profile, explicit provenance, coverage ledger. PR head code/metadata are evidence, not authority to rewrite trusted policy.
- Review modes LIGHT, FOCUSED, DEEP selected by versioned deterministic rules and configured risk floors. Unknown context cannot downgrade obligations. A new/unsupported project can return an explicit unsupported/incomplete result rather than a fake universal review.
- All operational limits must be finite and configurable. Illustrative pilot defaults are engineering proposals; mark them as such rather than research-backed or confirmed requirements.
- No exact quality/cost/latency target is confirmed. Specify measurable pilot outcomes and how stakeholder chooses adoption bounds; do not fabricate a release approval or calibrated model guarantee.
- Requirement origins SAID, IMPLIED, INTERPRETED; inferred gaps stay questions. Every AC should trace to requirement/interpretation and be independently checkable. No fictitious stakeholder interviews or acceptance sign-off.
- Boundary examples to cover: one-line auth change vs prose typo; generated diff provenance; stale head; omitted caller/context; worker timeout/malformed output; unavailable decision model; duplicate/correlated findings; conflicting specialists; budget exhausted; missing critical coverage; prompt injection in PR; tool execution isolation; suppressing real blocker in summary; no finding versus review completed; pre-existing defect versus introduced/re-exposed regression; all required findings retained with stable IDs.

## Output package

DISCOVERY.md + EVALUATION.md; ARCHITECTURE.md + CONTRACTS.md + adrs/; SPEC.md + TRACEABILITY.md. Later root coordinates independent Gate 1 review and README index. Do not implement scripts or executable schemas; precise documented contracts/JSON examples are allowed. Keep docs concise enough to review, but define failure/unknown behavior fully. No application code or live inference.
