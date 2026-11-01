# Theme: Governance and accountability

**Scorecard dimension:** Governance (current: D)
**Target:** 100% of merges carry recorded review evidence; named owners for cutover, release, and risk acceptance; CODEOWNERS and a second-reviewer path; a triaged issue backlog.
**Why:** the project's standard is "independent review clear at the exact reviewed head", but 0 of the last 20 merged pull requests have a GitHub review record. With one contributor and no issues, the evidence lives in prose and session memory rather than durable artifacts. For a replacement decision, accountability must be inspectable.

---

## GA-1 — Require recorded review evidence for every merge

- **Priority:** P0
- **Dimensions:** Governance; Evidence discipline
- **Problem:** Merges cite review in PR descriptions, but GitHub records no review on 0 of the last 20 merged PRs. There is no branch protection. A later auditor cannot tell who reviewed what revision, what they examined, or whether the review was independent.
- **Scope:**
  - Choose one durable mechanism: a GitHub approving review, or a signed review receipt artifact (reviewer identity, reviewed SHA, scope, verdict, evidence links) attached to the PR.
  - Require it for merge, including self-authored PRs; the reviewer may be an agent only if the protocol and identity are recorded.
  - Verify the recorded head equals the merged head.
  - Record post-merge verification.
  - Enable branch protection or a merge queue that enforces the rule.
- **Exit criteria:** Branch protection (or equivalent) requires review evidence; 100% of new merges carry a record bound to the merged SHA; a merge without evidence is impossible, not merely discouraged.
- **Verification:** protection settings; a sample of 10 merges with matching SHA and verdict; a blocked merge attempt.
- **Depends on:** DT-1 (scope clarity) and an owner decision on reviewer identity.
- **Non-goals:** requiring a human where a documented agent review is permitted, or auto-approving from CI.

---

## GA-2 — Record decisions with named owners and evidence

- **Priority:** P1
- **Dimensions:** Governance; Documentation
- **Problem:** Major decisions (stateless architecture, publication modes, model selection, risk acceptance, cutover) live in chat, PR descriptions, or long status narratives. There is no decision record format with alternatives, owner, evidence, and reversal conditions.
- **Scope:**
  - Adopt a lightweight decision-record format (ADR or decision log): context, options, decision, owner, evidence, consequences, reversal/expiry.
  - Cover at minimum: architecture shape, transport policy, publication authorization, model/provider choice, evaluation gates, license, and release policy.
  - Require a decision record for any change to a safety invariant or an external effect.
  - Link decisions from `STATUS.md` and the affected code/docs.
- **Exit criteria:** A decision log exists; the named decisions have records; every safety-invariant change links to one; owners are identifiable.
- **Verification:** decision index; a sampled change traced to its record.
- **Depends on:** GA-1, DT-1.
- **Non-goals:** documenting every small change.

---

## GA-3 — Address ownership, bus factor, and backlog hygiene

- **Priority:** P1
- **Dimensions:** Governance; Operational readiness
- **Problem:** The repository has one contributor, no CODEOWNERS, no issues, and a 238-PR history with work tracked only in branches and prose. If the maintainer is unavailable, no one owns triage, release, or incident response. The 33 issues in this backlog are the first structured backlog.
- **Scope:**
  - Add CODEOWNERS for core, publication, security, and docs paths.
  - Define a second-reviewer path (human or documented agent protocol) and the limits of agent authority.
  - Adopt this issue backlog: filing, labels, triage states, and closure evidence.
  - Record incident/rollback ownership for publication effects.
  - Document credential and access ownership, rotation, and recovery.
- **Exit criteria:** CODEOWNERS exists and matches the module map; every issue has a state and owner; a second-review path is documented and used at least once; access ownership is recorded.
- **Verification:** CODEOWNERS; issue board/labels; a sampled PR showing the second path; an access-ownership record.
- **Depends on:** GA-1, DT-2.
- **Non-goals:** inventing organizational roles the project does not have.
