# Status — PR Review Harness

**This is the authoritative entry point for what the harness does and does not do.** Other status pages are scoped detail. Reviewed 2026-11-01 against repository revision `8223fd7` (the base of this documentation-only change; no code was modified).

A claim is true only on the surface it names. The four top-level documents previously read as contradictions because they described different surfaces and different dates without saying so.

**Evidence classes used here:** `OBSERVED` means checked in this repository at the bound revision for this page. `REPORTED` means recorded by a dated document or run in another repository and **not re-observed** here. `UNKNOWN` means no retained evidence establishes the fact. "Evidence date" is the date the cited evidence was produced or recorded, not the date this page was edited.

## Truth by surface

| Surface | Current decision / state | Bound to revision | Evidence | Evidence date |
|---|---|---|---|---|
| **Local CLI** (`pr-review`) | `READ-ONLY`. `review` and `--prepare-only` work as documented. `publish` renders a validated `PREVIEW_ONLY` request and performs no GitHub read or write; `--authorize-publish` fails closed. No merge, repair, or live publication path. | `8223fd7` | [cli.py publish implementation](../src/pr_review_harness/cli.py#L1465-L1490) and [test_cli.py](../tests/test_cli.py#L1181-L1215) (`OBSERVED`); [README](../README.md); [VERIFICATION.md](VERIFICATION.md); [CLI-PUBLISH-PREVIEW-MIGRATION.md](CLI-PUBLISH-PREVIEW-MIGRATION.md) | 2026-11-01 (code and test observation) |
| **Source-repository Actions** (`groktopus/codereview`) | `READ-ONLY`. CI, packaging, and the reusable `PR Review Analysis` workflow exist. The self-pilot `analyze` job is hard-disabled (`if: false`); the central publication job is hard-disabled (`false &&`, which a repository variable cannot change). No review writes, target-configuration changes, or auto-merge. | `8223fd7` | [pr-publish.yml publication-disabled job](../.github/workflows/pr-publish.yml#L75-L83) (`OBSERVED`); [codereview-self-pilot.yml analyze job](../.github/workflows/codereview-self-pilot.yml#L110-L115) (`OBSERVED`); [pr-analysis.yml](../.github/workflows/pr-analysis.yml); [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) | 2026-11-01 (workflow observation) |
| **Target deployment** (`magnus919/SlopSearX`) | `REPORTED ACTIVE` in v5 `DISPOSITION` mode. The target-local publisher may emit `COMMENT`, `APPROVE`, or `REQUEST_CHANGES`; only Droid Auto Review is disabled; Droid Tag and Wiki are unchanged; no workflow auto-merges. One `COMMENT` effect was confirmed (review `5481780874`, publisher run `38109625164`, attempt 1; attempt 2 confirmed the same review without a duplicate). No full-`DISPOSITION` post or replay is recorded. Source coverage was `PARTIAL`; semantic accuracy remains unknown. | Source `afe5117c2e6c80de6ef84ca3577a5e8b536d36cc` (PR #236); target `0e486ff95ff086906f309d1c1077a0a5ec2ba94c` (PR #772 merge), after `dfcb164abdf8eef711ce6a447ef78c42ec696021` (PR #768) and `e011f264bc4a16dfab535b4dfd492c014ce0519f` (PR #769) | [CURRENT-STATUS.md](CURRENT-STATUS.md) (`REPORTED`); [CURRENT-EXECUTION-PLAN.md](CURRENT-EXECUTION-PLAN.md); [CURRENT-DELIVERY-TRACE.md](CURRENT-DELIVERY-TRACE.md); [CURRENT-ACCEPTANCE-TRACE.md](CURRENT-ACCEPTANCE-TRACE.md) | 2026-10-11 (record date); exact merge and run timestamps are not retained in this repository (`UNKNOWN`) |
| **Publication — harness CLI route** | `UNAVAILABLE` / preview only. The 2026-09-29 **NO-GO** applies to this route and remains in force: no live POST, no writer credential, no effect store. | `8223fd7` (code); decision record is older | [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) (scope-qualified, retained as the decision record); [cli.py](../src/pr_review_harness/cli.py#L1485) (`OBSERVED`) | 2026-11-01 (code observation); decision recorded 2026-09-29 |
| **Publication — central source-repository route** | `HARD-DISABLED`. The only write-capable job is guarded by literal `false &&`; the read-only canary job can verify bindings but cannot post. | `8223fd7` | [pr-publish.yml](../.github/workflows/pr-publish.yml#L75-L83) (`OBSERVED`); [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) | 2026-11-01 (workflow observation); decision recorded 2026-09-29 |
| **Publication — target-local route** (`magnus919/SlopSearX`) | `REPORTED ENABLED` for `DISPOSITION` after target PR #772. Exactly one `COMMENT`-mode effect is evidenced; `APPROVE` and `REQUEST_CHANGES` effects are not evidenced, and no duplicate/replay result exists for them. This is the only route with a reported production write. | Target `0e486ff`; source `afe5117` | [CURRENT-STATUS.md](CURRENT-STATUS.md); [CURRENT-DELIVERY-TRACE.md](CURRENT-DELIVERY-TRACE.md) | 2026-10-11 (`REPORTED`) |
| **Replacement readiness** | `NOT ACCEPTED` as a Droid replacement. Source coverage remains `PARTIAL`; semantic accuracy, calibration, and defect-detection quality are unmeasured; human labels are unavailable. Publication capability is not a quality result. | `8223fd7` / target documents dated 2026-10-11 | [VERIFICATION.md](VERIFICATION.md) (NFR-011); [CURRENT-STATUS.md](CURRENT-STATUS.md); [COMPLETE-REQUIREMENT-AUDIT-2026-10-01.md](COMPLETE-REQUIREMENT-AUDIT-2026-10-01.md) | 2026-10-11 (latest recorded); 2026-10-01 (requirement audit) |

**Publication is not one surface.** It is at least three independently controlled routes — the harness CLI, the central `groktopus/codereview` workflow, and the separately installed target-local route in `magnus919/SlopSearX`. Treating those routes as one is what made the older documents appear to contradict each other.

## What "disabled" means, per repository

| Repository or surface | "Disabled" applies to | What is still enabled there | Evidence |
|---|---|---|---|
| `groktopus/codereview` — central publication | The `publication-disabled` job in `.github/workflows/pr-publish.yml`. The guard is the literal `false &&`; setting `PR_REVIEW_PUBLICATION_ENABLED=true` cannot enable it. | The read-only canary/binding job, CI, packaging, and read-only analysis when a trusted caller invokes the reusable workflow. | [pr-publish.yml](../.github/workflows/pr-publish.yml#L75-L83) |
| `groktopus/codereview` — self-pilot | The `analyze` job in `codereview-self-pilot.yml` (`if: false`). | The `workflow_dispatch` resolve step; other workflows. | [codereview-self-pilot.yml](../.github/workflows/codereview-self-pilot.yml#L110-L115) |
| Harness CLI (`pr-review`) | Live publication. There is no writer capability and `--authorize-publish` rejects. | Local review, sealed-result preview, and provider-free preparation, subject to the documented limits. | [cli.py](../src/pr_review_harness/cli.py#L1465-L1490) |
| `magnus919/SlopSearX` | **Droid Auto Review is disabled** (reported). This is the incumbent control, not the harness publisher. | The target-local harness publisher in v5 `DISPOSITION` mode is **reported enabled**; Droid Tag and Wiki are unchanged; no auto-merge. | [CURRENT-STATUS.md](CURRENT-STATUS.md); [CURRENT-EXECUTION-PLAN.md](CURRENT-EXECUTION-PLAN.md) |
| Historical use in `PUBLICATION-READINESS.md` | "Publication remains disabled" meant the harness CLI and central route at 2026-09-29; "target-local template hard-disabled" described that date. It was not a statement about the target-local route after the 2026-10-11 cutover record. | As of that record: preview-only CLI, read-only central canary, no target-local installation. | [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) (scope banner added) |

## Why the four documents disagreed

| Document | Scope it is authoritative for | Claims that are true only on that surface | Disposition |
|---|---|---|---|
| [README](../README.md) | User-facing local CLI, packaging, and read-only boundaries. | "Live publication is unavailable" is true for the CLI and central workflow; it is false if read as a statement about the separately installed target-local route. "No production write has been verified" is true for this repository's CLI/central route, not for the target-local `COMMENT` canary. | Qualified in place; links here. |
| [VERIFICATION.md](VERIFICATION.md) | A 2026-09-26 snapshot of spec-gap accounting (39 ACs, 12 NFRs). | "Publication rejected" (AC-037) is scoped to the CLI and central workflow. "Automatic bounded retrieval and expanded follow-up scheduling DEFERRED" was true at that snapshot; later evidence records bounded retrieval and follow-ups being exercised. | Retained as a historical snapshot with a scope banner; no past decisions rewritten. |
| [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) | The 2026-09-29 **NO-GO** decision and its acceptance gates for the CLI and central publisher route, plus the state of hosted writer proof at that date. | "NO-GO", "publication remains disabled", and "target-local template hard-disabled" were correct for that scope and date. They do not describe the reported post-2026-10-11 target-local installation. | Retained as the decision record with a scope/date banner; the central-route conclusions still hold. |
| [CURRENT-STATUS.md](CURRENT-STATUS.md) | The dated evidence log for the harness source and the target-local deployment. | "Target deployment with `DISPOSITION` mode and posted reviews" is a target-local, `REPORTED` observation. It does not establish CLI publication, central-route publication, full-`DISPOSITION` behavior, or review quality. | Scope banner added; historical sections remain dated and labeled. |

## Contradiction checklist (post-reconciliation)

| Absolute claim as previously written | Where it appeared | Scope-qualified truth | How this change addresses it |
|---|---|---|---|
| "Live publication is unavailable." | README | True for the harness CLI and central `groktopus/codereview` route; not true for the target-local route after 2026-10-11. | Qualified in README and here. |
| "Publication rejected." | `VERIFICATION.md` AC-037 | True for the CLI/central route; not a statement about the target-local route. | Scope banner on `VERIFICATION.md`; surface rule here. |
| "Decision: NO-GO. Publication remains disabled." | `PUBLICATION-READINESS.md` | True for the CLI/central route at 2026-09-29 and still true for the central route today; superseded for the target-local route by the 2026-10-11 record. | Decision line qualified by route and date; banner added. |
| "Target deployment with `DISPOSITION` mode and posted reviews." | `CURRENT-STATUS.md` | True only for the target-local route, only as `REPORTED`; one `COMMENT` effect, not a full-`DISPOSITION` result. | Scope banner added; not promoted to a global claim. |
| "Automatic bounded retrieval and expanded follow-up scheduling DEFERRED." | `VERIFICATION.md` | True at the 2026-09-26 snapshot; later runs exercised bounded retrieval and follow-ups. Which parts remain deferred is not established here. | Marked as historical; remaining scope recorded as `UNKNOWN` below. |
| "No production write has been verified." | README | True for this repository's CLI/central route; the target-local `COMMENT` canary is a reported production write on another surface. | Qualified in README and here. |

## Unresolved contradictions and unknowns

1. **Target state is report-only.** `CURRENT-STATUS.md` reports the SlopSearX v5 `DISPOSITION` deployment, the `COMMENT` canary receipt, and the disablement of Droid Auto Review. No artifact from the target repository is retained in this repository, and no network access was used for this page. Whether the target-local publisher, policy `enabled` flag, workflow registrations, or credentials are in that state on 2026-11-01 is `UNKNOWN`.
2. **The 2026-09-29 `PUBLICATION-READINESS.md` record and the 2026-10-11 `CURRENT-STATUS.md` record conflict on the target-local route.** The likely reconciliation is repository scope (central vs target-local) plus time (before vs after target PRs #768/#769/#772), but that is inferred from document dates and content. No independent target-side receipt is linked here, so the contradiction is recorded, not erased.
3. **"Publication is enabled" is only evidenced for one comment.** The canary posted exactly one `COMMENT` review and a replay produced no duplicate. No `APPROVE` or `REQUEST_CHANGES` post, and no full-`DISPOSITION` replay, is recorded. The claim "`DISPOSITION` mode allows three events" therefore describes configuration, not observed behavior.
4. **Exact target evidence dates are document dates, not run timestamps.** PR merge dates and run timestamps for `38109625164`, `38111321188`, and the target PRs are not retained in this repository as immutable records. The evidence date shown is the date the receiving documents recorded the events.
5. **`VERIFICATION.md` is a September snapshot.** It says several capabilities are deferred or not implemented; later documents report some of them exercised (bounded retrieval, follow-ups, hosted read-only runs) while other gaps may remain. This page does not relabel the snapshot; it records that the current status of each deferred item is not established by the retained evidence.
6. **`PUBLICATION-READINESS.md` references an older runner and PR set** (`c05ab8f`, PRs #126/#127) and a target-local template state that predates the cutover record. Its gate analysis remains useful for the central route; its currency for the target route is `UNKNOWN`.

## Historical evidence policy

Past decisions and dated evidence sections are **not rewritten** by this page. The four detail documents keep their original text and dates; where a claim was true only on a scope or a date, a banner or scope line now says so. Historical sections in `CURRENT-STATUS.md` and `CURRENT-EXECUTION-PLAN.md` remain dated and are not current state unless the current section explicitly says otherwise. Prior failed runs and rejected decisions remain part of the record.

## Related pages

- [README](../README.md) — install, CLI, and read-only boundaries.
- [VERIFICATION.md](VERIFICATION.md) — 2026-09-26 spec-gap accounting.
- [PUBLICATION-READINESS.md](PUBLICATION-READINESS.md) — 2026-09-29 publication NO-GO and acceptance gates.
- [CURRENT-STATUS.md](CURRENT-STATUS.md) — dated source and target-deployment evidence log.
- [CURRENT-EXECUTION-PLAN.md](CURRENT-EXECUTION-PLAN.md) — current delivery plan and prior checkpoints.
- [CURRENT-DELIVERY-TRACE.md](CURRENT-DELIVERY-TRACE.md), [CURRENT-ACCEPTANCE-TRACE.md](CURRENT-ACCEPTANCE-TRACE.md) — requirement traces.
- [REVERSIBLE-CUTOVER.md](REVERSIBLE-CUTOVER.md) — pre-cutover DEFER package; its "target-local not installed" statements describe the pre-2026-10-11 state.
- [Issue DT-1](issues/08-documentation-truth.md) — the change this page implements.

**Do not publish, enable the central publisher, change target configuration, or cut over on the basis of this page.** Those remain separate decisions with their own evidence and authority.
