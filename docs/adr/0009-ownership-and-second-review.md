# 0009 — Ownership and second-review path

- **Status:** Accepted
- **Date:** 2026-11-02
- **Owner:** @magnus919
- **Decision authority:** Repository owner, exercised through owner-authorized issue #271 and the direct task instruction to resolve the backlog (2026-11-02); AGENTS.md records the standing user authority.
- **Scope:** CODEOWNERS, ownership/recovery documentation, backlog triage, and the second-reviewer path.
- **Evidence:** [issue #271](https://github.com/groktopus/codereview/issues/271), [AGENTS.md](../../AGENTS.md), PR #297, `.github/CODEOWNERS`, `docs/OWNERSHIP.md`, `docs/BACKLOG.md`, GA-1 receipts in PRs #293/#295/#296.
- **Reversal/expiry:** Supersede if a second human maintainer or different ownership model is adopted.

## Context

The repository has one maintainer, path ownership was a single default rule, and the
backlog had no durable owner/state model. GA-1 established a receipt protocol but
`main` has no branch protection, so CODEOWNERS and receipts route review but do not
technically block a merge.

## Decision

Adopt path-specific CODEOWNERS for core review, publication/effects,
security/credentials, workflows, docs, and release; document bus-factor-1,
credential/access recovery, publication incident/rollback ownership, and
maintainer-unavailable freeze rules; use a five-state backlog with closure evidence.
Agent review is an accepted second path when a receipt records identity, protocol,
scope, exact SHA, and verdict; it is advisory for security, release, credentials,
settings, and live effects. Human review remains preferred when available.

## Consequences

Ownership is inspectable and CODEOWNERS covers every production module. Enforcement
still depends on branch protection/required checks, which remains owner action.
Bus factor is still 1; this record does not invent a successor or second human.

## Confirmation

`scripts/check_ownership.py` verifies module/path coverage, required ownership
sections, and the backlog table against the checked snapshot in CI.

## Alternatives considered

- Keep a single default CODEOWNERS rule: rejected because sensitive paths were
  indistinguishable from ordinary code.
- Name a second human: rejected because none exists; the document states the gap.
