# Documentation history and archive policy

This directory holds dated checkpoints, superseded designs, and historical
evidence that remain part of the record. Moving a document here is a
classification change, not a deletion. Every moved document keeps a
prominent historical banner and its original content, links, and dates.

## Archive policy

1. **Nothing is deleted while evidence depends on it.** A dated checkpoint,
   failed attempt, rejected design, or run receipt is retained even when it is
   no longer current. Current documents may cite it as evidence.
2. **Retirement means reclassification.** A superseded document is moved under
   `docs/history/` (or left in `docs/experiments/` where it already lives) and
   labeled. It is removed from the current set in the [index](../README.md),
   not from the repository.
3. **Deletion requires proof that no evidence depends on it.** A document may
   be deleted only when no retained document, issue, test, script, or release
   record cites it, and the change states that finding. The default is to keep
   and label it.
4. **Historical text is not rewritten to look current.** Scope banners and
   corrected links are allowed; the original claims and dates remain. A
   historical statement stays true only for the revision and date it names.
5. **Current guidance points here explicitly.** A historical document must name
   the current status page in its banner, and the index must place it outside
   the current set. No topic may have two competing "current" documents.
6. **Links are maintained mechanically.** `scripts/check_relative_links.py`
   checks relative links in the root README and `docs/`; moves update the
   inbound and outbound links rather than leaving broken references.

## Layout

| Path | Contents |
|---|---|
| `checkpoints/` | Dated delivery checkpoints and run/evidence snapshots moved out of the current set. |
| `design/` | Superseded implementation plans, interface contracts, prototypes, and capacity proposals. |
| `evidence/` | Historical evidence notes that are neither current guidance nor design proposals. |

`docs/experiments/` and `docs/historical-functional-review-pr466-v*/` already
carry dated run evidence and historical package names; they remain in place and
are indexed in the history/evidence section rather than moved again.

## Move log

| Former path | Current path | Classification |
|---|---|---|
| `docs/DELIVERY-RESET-2026-09-29.md` | [checkpoints/DELIVERY-RESET-2026-09-29.md](checkpoints/DELIVERY-RESET-2026-09-29.md) | Dated delivery checkpoint. |
| `docs/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-27.md` | [checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-27.md](checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-27.md) | Dated recovery-drill evidence. |
| `docs/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-28.md` | [checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-28.md](checkpoints/HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-28.md) | Dated recovery-drill evidence. |
| `docs/pr464-shadow-run-2026-09-29.md` | [checkpoints/pr464-shadow-run-2026-09-29.md](checkpoints/pr464-shadow-run-2026-09-29.md) | Dated shadow-run evidence. |
| `docs/CONTEXT-SELECTION-V2-IMPLEMENTATION-PLAN.md` | [design/CONTEXT-SELECTION-V2-IMPLEMENTATION-PLAN.md](design/CONTEXT-SELECTION-V2-IMPLEMENTATION-PLAN.md) | Superseded implementation plan; also fixes its known broken link. |
| `docs/TASK-PLAN.md` | [design/TASK-PLAN.md](design/TASK-PLAN.md) | Initial pilot plan, superseded. |
| `docs/IMPLEMENTATION-BOUNDARIES.md` | [design/IMPLEMENTATION-BOUNDARIES.md](design/IMPLEMENTATION-BOUNDARIES.md) | Initial interface contract, superseded. |
| `docs/multipass-plan-prototype.md` | [design/multipass-plan-prototype.md](design/multipass-plan-prototype.md) | Offline prototype, retained for provenance. |
| `docs/BOUNDED-PRODUCTION-REVIEW.md` | [design/BOUNDED-PRODUCTION-REVIEW.md](design/BOUNDED-PRODUCTION-REVIEW.md) | Capacity candidate, not current guidance. |
| `docs/model-only-shadow-pr464-capacity-v3-proposal.md` | [design/model-only-shadow-pr464-capacity-v3-proposal.md](design/model-only-shadow-pr464-capacity-v3-proposal.md) | Capacity proposal, retained for provenance. |
| `docs/CONTEXT-CANDIDATE-FAILURE.md` | [evidence/CONTEXT-CANDIDATE-FAILURE.md](evidence/CONTEXT-CANDIDATE-FAILURE.md) | Rejected-candidate evidence. |
| `docs/HISTORICAL-REAL-CASE-TRIAL.md` | [evidence/HISTORICAL-REAL-CASE-TRIAL.md](evidence/HISTORICAL-REAL-CASE-TRIAL.md) | Historical trial protocol and evidence. |
| `docs/INSTALLED-STATELESS-CLI-VERIFICATION.md` | [evidence/INSTALLED-STATELESS-CLI-VERIFICATION.md](evidence/INSTALLED-STATELESS-CLI-VERIFICATION.md) | Historical installed-CLI verification. |

Moves used `git mv`; Git status reports renames rather than delete/add pairs.
No document was deleted by this change.

## Banner convention

Every document under `checkpoints/`, `design/`, and `evidence/` begins with a
blockquote banner stating that it is historical or superseded, naming the
current status page, and linking the archive policy and the
[documentation index](../README.md). A move must add or preserve that banner.

## Checks

```sh
python3 scripts/check_docs_index.py
python3 scripts/check_relative_links.py
```

The first fails when a Markdown file under `docs/` is not indexed or when an
index link is dangling. The second fails on a broken relative link in the root
README or `docs/`.
