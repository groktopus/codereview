# Theme: Documentation truth

**Scorecard dimension:** Documentation (current: C)
**Target:** one authoritative status document; an indexed documentation set; zero contradictions and broken links; historical checkpoints archived and labeled; claims automatically checked.
**Why:** 88 documents on 10 topics of truth is not a documentation set, it is an archive with no index. README, `VERIFICATION.md`, and `PUBLICATION-READINESS.md` contradict `CURRENT-STATUS.md` about publication and completion. The project's product is evidence, so stale or contradictory documents are product defects.

---

## DT-1 — Create one authoritative status document and resolve contradictions

- **Priority:** P0
- **Dimensions:** Documentation; Evidence discipline; Governance
- **Problem:** Four top-level documents disagree:
  - README: publication unavailable.
  - `VERIFICATION.md`: publication rejected, retrieval deferred.
  - `PUBLICATION-READINESS.md`: decision **NO-GO**, publication disabled.
  - `CURRENT-STATUS.md`: target deployment with `DISPOSITION` mode and posted reviews.

  They may be scoped to different surfaces, but no document states the scope boundary, so a reader cannot tell what is true.
- **Scope:**
  - Write `STATUS.md` as the single entry point: per surface (local CLI, source Actions, target deployment, publication), state the decision, the revision, the evidence, and the date of evidence.
  - Reconcile the four documents: keep them only as scoped detail pages linked from `STATUS.md`; remove absolute claims that are false in another scope.
  - State explicitly what "disabled" means in each repository and which effects are permitted where.
  - Record unresolved contradictions rather than hiding them.
- **Exit criteria:** `STATUS.md` exists and is the only place a reader needs to start; each surface has one decision and one evidence link; no top-level document contradicts another without an explicit scope qualifier.
- **Verification:** a contradiction checklist over the five documents; link check; a reviewer walking only `STATUS.md` can state the current decision per surface.
- **Depends on:** OE-3 for automation; content reconciliation can start immediately.
- **Non-goals:** deleting historical evidence or rewriting past decisions.

---

## DT-2 — Index, archive, and retire documentation

- **Priority:** P1
- **Dimensions:** Documentation
- **Problem:** There are 88 markdown documents (4,862 lines), no `docs/README.md` or index, and one broken relative link. Dated checkpoints, designs, evidence notes, and operating guides are mixed together. `design/ARCHITECTURE.md` still describes a proposed architecture (ledger, SQLite-era state) that no longer matches the stateless implementation.
- **Scope:**
  - Add `docs/README.md` with sections: current (≤10 living docs), reference contracts, history/evidence, and archive.
  - Move dated checkpoints and superseded designs under `docs/history/` (or `experiments/`) with a banner stating they are historical.
  - Mark or delete documents superseded by code (for example, an architecture doc that describes an unimplemented shape must say so prominently).
  - Keep one canonical document per topic; link rather than duplicate.
  - Record the archive policy: nothing is deleted if evidence depends on it.
- **Exit criteria:** An index exists and covers every document; every historical document is labeled; no topic has two competing "current" documents; the link checker passes.
- **Verification:** index completeness script; link check; a sample navigation walk.
- **Depends on:** DT-1.
- **Non-goals:** preserving broken links for authenticity.

---

## DT-3 — Automate documentation truth checks

- **Priority:** P1
- **Dimensions:** Documentation; Evidence discipline
- **Problem:** Documentation is maintained by hand and drifts. There is no link check, no status-freshness check, no claim lint, and no check that a document references the current contract set.
- **Scope:**
  - CI link checker for relative links across README, docs, and issue files.
  - Status-freshness check (see OE-3): fail when a "current" document is older than the described revision.
  - Claim lint: a small set of forbidden unqualified phrases (for example "production ready", "replaces", "accurate") must be accompanied by an evidence link.
  - Check that referenced SHAs exist in the repository and that superseded contract identifiers are marked deprecated.
  - Run on PRs and main; keep failures actionable.
- **Exit criteria:** All checks run in CI; a seeded stale link, stale status, and unqualified claim each fail; the checks are documented.
- **Verification:** three seeded violations; CI job; a clean main run.
- **Depends on:** DT-1, DT-2.
- **Non-goals:** natural-language policing of every sentence or blocking legitimate hedging.
