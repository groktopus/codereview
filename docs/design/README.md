# PR Review Harness design

An architecture and specification for reusable, evidence-based pull-request review, with SlopSearX as the first pilot and a CLI plus GitHub Actions as the delivery surface.

**Status: proposed design, independently reviewed with CONDITIONS.** Operating/provider/profile choices remain pending before the pilot, and measured quality/adoption bounds remain pending before adoption. No application code, inference experiment, posted review, or deployment is included. This package is outside the Agent Skills repository.

## Reading order

| Document | Purpose |
|---|---|
| [DISCOVERY.md](DISCOVERY.md) | User requirements, their origins, pilot scope, and open decisions. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, deterministic workflow ownership, isolation, recovery, and tradeoffs. |
| [CONTRACTS.md](CONTRACTS.md) | Inputs, evidence, findings, coverage, provider boundaries, and disposition semantics. |
| [SPEC.md](SPEC.md) | Proposed behavior and independently testable acceptance criteria. |
| [TRACEABILITY.md](TRACEABILITY.md) | Requirement-to-acceptance mapping and unresolved interpretations. |
| [EVALUATION.md](EVALUATION.md) | Historical and prospective evaluation, independent labels, comparison arms, and adoption evidence. |
| [REVIEW.md](REVIEW.md) | Independent document review and remaining conditions. |
| [RESEARCH.md](RESEARCH.md) | External evidence, limitations, and the distinction between research and design proposals. |
| [PILOT-CONTEXT.md](PILOT-CONTEXT.md) | Read-only SlopSearX integration observations and candidate project rules. |
| [BRIEF.md](BRIEF.md) | Drafting input and shared conventions; the reconciled documents above take precedence. |

The harness owns scope, scheduling, limits, retries, escalation, and effects. Specialists propose evidence-linked findings; optional System One models answer bounded semantic questions. Reconciliation preserves uncertainty, and deterministic rules produce the final disposition. Editorial synthesis organizes blockers, improvements, strengths, and future guidance without changing the evidence or disposition.

The first proposed pilot retains local/Actions report artifacts. Posting reviews is a later explicit product choice. Approval of a review is separate from permission to merge.

Before implementation, resolve the permanent project location, provider bindings and local-model reachability, runtime limits, profile ownership, and review/adoption policy. Performance targets require measured pilot evidence; they are not established by this design.
