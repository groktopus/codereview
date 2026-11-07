# 0012 — Separate required admission from optional captured-evidence enrichment

- **Status:** Proposed
- **Date:** 2026-11-07
- **Owner:** Repository owner (`@magnus919`); coordinating root agent owns proposal routing, not acceptance.
- **Decision authority:** Acceptance is not recorded. The direct design-only instruction requires independent design review before root chooses any implementation slice. Neither this proposal nor the earlier root scope decision grants implementation or source growth.
- **Scope:** Proposed RC-2 replacement design over source checkpoint `578bfbc478773780de353310a361b134098ce20b`: optional captured-evidence selection, existing required admission, request identity, budgets, resume, scoped follow-ups, and planned acceptance evidence. No runtime, schema, policy, allowance, provider, publication, or fixture changes are made by this record.
- **Evidence:** Source anchors in the checkpoint table below; root-local design inputs and independent-review attribution described under provenance; all acceptance cases below are planned, not observed implementation results.
- **Reversal/expiry:** Re-review before implementation if the source checkpoint, required-context contracts, input shape, trust boundary, or budget changes. Reject or revise if ordinary evidence reuse cannot retain citation and unit-local bindings within existing caps. No automatic acceptance or expiry-based authority.

## Context

RC-2 needs a delivery design, not a universal source-admission rule. A complete,
immutable, bound diff can supply the required input for some review questions.
It does not establish semantic adequacy for every question. Conversely, failure
to infer a Python definition or a referenced test is not itself proof that a
required review input is missing. Prose, YAML, constants, renames, deletions and
unsupported/binary units must not inherit an accidental Python-only prerequisite.

The stopped draft [PR #353](https://github.com/groktopus/codereview/pull/353)
remains stopped and unmergeable under the supplied root instruction. This
proposal does not resume, repair, supersede by implementation, or close it.
It proposes the contract to review before a replacement is selected.

### Provenance and decision boundary

The drafting inputs were read from the repository's common Git directory:
`.git/verified-delivery/rc2-admission-design.md` and
`.git/verified-delivery/rc2-admission-decision.json` in the coordinating checkout.
They are root-local handoff records, not tracked public implementation evidence.
Their recorded source baseline is `fccff85f18c598c3a118873949cfbc46c3587128`;
this ADR independently inspects the newer checkpoint named above. The decision
JSON attributes the read-only admission review to agent
`a615ab4b-078a-49e7-999f-3f6af1f3e93b`. That attribution supports the supplied
scope correction; it is not an independent review of this ADR or a recorded
owner acceptance. The refined scope below takes precedence over the earlier
brief's suggestion of universal changed-source interval admission.

No owner approval, implementation CLEAR, quality grade, recall improvement,
release/replacement readiness, or RC-2 closure is claimed. Existing effect and
waiver decisions remain unchanged: [ADR 0004](0004-publication-authorization.md),
[ADR 0006](0006-evaluation-gates.md), and
[ADR 0011](0011-bounded-evidence-waiver.md).

### Observed source checkpoint

Links are repository-relative views; the line references describe the immutable
checkpoint above and must be rechecked if implementation changes those sources.

| Surface | Observed behavior at the checkpoint | Design consequence |
|---|---|---|
| [Planner](../../src/pr_review_harness/planner.py#L605-L625) | Creates required `CHANGED_UNIT_LENS` obligations and selects unit evidence; it does not impose Python-definition coverage. | Do not reinterpret the obligation kind as a universal interval requirement. |
| [Explicit context bindings](../../src/pr_review_harness/planner.py#L626-L799) | Mandatory/bound policy context, v2 related HEAD evidence and validated dependency projections populate `required_context_ids`; missing related HEAD/dependency rows yield sentinel IDs. | Preserve exact required references and missing sentinels. |
| [Snapshot source selector](../../src/pr_review_harness/snapshot.py#L719-L838) | Opt-in selection distinguishes change-base BASE/old path removals from HEAD/new path additions; v3 publishes only complete lines and records side/range gaps. | Existing selector requirements remain requirements; optional enrichment cannot erase them. |
| [Required snapshot gaps and checks](../../src/pr_review_harness/planner.py#L802-L865) | Required checks become `PROJECT_CHECK`; required snapshot gaps become `REQUIRED_CONTEXT`. | Retain the full obligation denominator, including gaps with no provider task. |
| [Preparation and caps](../../src/pr_review_harness/engine.py#L1197-L1395) | Required refs are authoritative, missing refs skip before invocation, unit chunks retain obligations, required context fits before optional context. | Extend this single preparation path, not a second admission implementation. |
| [Evidence and unit bindings](../../src/pr_review_harness/engine.py#L674-L857) | Evidence is delivered by ID; duplicate-ID merge checks immutable bindings; specialist v2 binds supplied evidence to inventory units. | Preserve ordinary cited rows and existing unit-local evidence relations. |
| [Compiler](../../src/pr_review_harness/retrieval_plan.py#L190-L319) | Compiles metadata-only symbol/test candidates and marks several heuristic misses `REQUIRED`; stores plan/gaps and a boolean. | These compiler severity labels are not new admission authority. |
| [Compiler hash](../../src/pr_review_harness/retrieval_plan.py#L19-L19), [hash/sufficiency functions](../../src/pr_review_harness/retrieval_plan.py#L181-L187) | `plan_hash` covers `_ANCHOR_FIELDS` (including units), but **omits `gaps` and `sufficiency`**; sufficiency merely counts raw `REQUIRED` labels. | A matching v1 hash neither authenticates those fields nor establishes required evidence adequacy. |
| [Plan recording](../../src/pr_review_harness/review_stages.py#L1283-L1296) | Records retrieval metadata after task binding; this recording does not skip on compiler gaps. | Do not replace diagnostic recording with a blanket gap-to-skip rule. |
| [Request identity](../../src/pr_review_harness/review_stages.py#L1063-L1090) | Request basis binds snapshot, plan, profile, limits, providers, primary task inputs and core contract. | Opt-in selection must participate before request identity freezes. |
| [Exact adapter serialization](../../src/pr_review_harness/providers.py#L1266-L1295) | One serializer supplies measured body bytes; outputs are validated against supplied evidence IDs. | All added rows must be cited through that existing channel and included in exact serialization. |
| [Dispatch validation](../../src/pr_review_harness/review_stages.py#L1304-L1338), [attempt validation](../../src/pr_review_harness/review_stages.py#L396-L459) | Bound inputs are validated before reservation/dispatch. | Add content validation at the same boundary; metadata validation alone is insufficient. |
| [Final coverage](../../src/pr_review_harness/review_stages.py#L3360-L3518), [reducer](../../src/pr_review_harness/engine.py#L1173-L1194) | Valid unit-local notes, required-context notes and bound check evidence determine completion; partial notes remain partial; accepted blockers precede incompleteness in disposition. | Delivery is not semantic adequacy; retain partial coverage and supported blockers. |
| [Current follow-up construction](../../src/pr_review_harness/review_stages.py#L2121-L2173), [binding reconstruction](../../src/pr_review_harness/engine.py#L872-L1042) | Scope narrows to the resolved unit (or remains parent scope), but the evidence list currently unions parent evidence and retrieved rows. | Narrowed optional selection must not inherit sibling enrichment. Existing parent evidence inheritance is not proof of isolation. |

Two source caveats matter: the profile validator accepts `head_context_paths`
for v2/v3, but the related HEAD consumer is gated exactly on v2; this proposal
does not silently activate that behavior for v3. Pure removals can retain the
HEAD sentinel range `[0, 0]`; the existing selector's handling is preserved,
not reinterpreted here as a positive HEAD source interval. Existing v3 selector
windows are required where their current contract says so; only the **new**
enrichment selection proposed here is optional.

The existing v1 compiler source-row filter is not the proposed payload validator:
[source rows](../../src/pr_review_harness/retrieval_plan.py#L61-L80) check some
metadata but do not independently authenticate content, snapshot, expected
revision/object, or trust. Existing exact-file
[HEAD reuse validation](../../src/pr_review_harness/engine.py#L742-L801) is a
useful precedent, not a general validator for BASE or partial windows.

## Decision

**Recommend, subject to independent review and root selection:** keep existing
required-context admission and final completeness, and add only optional,
validated selection of already captured evidence through the ordinary evidence
list. Do not make raw compiler gaps an admission gate.

### 1. Required inputs remain explicit

Use immutable captured inventory plus the trusted profile to distinguish:

1. Existing required snapshot diff/source/policy gaps and `REQUIRED_CONTEXT`.
2. Existing opt-in selector BASE-removal/HEAD-addition interval, scan and cap gaps.
3. Mandatory policy, unit/lens `required_context_ids`, related HEAD and dependency
   bindings, including missing sentinels.
4. Scoped dynamic follow-up requirements and their required coverage notes.
5. `PROJECT_CHECK` identity-bound, conclusive check evidence.

These contracts retain their current fail-closed behavior. A complete bound diff
may admit a changed-unit lens when no explicit source requirement applies.
Admission does not promise that the diff answers the question: model-reported
`PARTIAL`/`NOT_COVERED`, unresolved required gaps, quarantined output, missing
results and check `UNKNOWN`/`ERROR` retain existing non-clean outcomes.

Inferred symbols, enclosing definitions, tests and callers are **optional** unless
a separately reviewed trusted profile explicitly requires the corresponding
input. A repository reference, inferred symbol, model suggestion, raw compiler
`REQUIRED` label, or `sufficiency.sufficient` boolean cannot create that authority.
The current compiler infers symbol/test candidates, not a complete call graph;
this slice does not add caller discovery.

No universal interval admission is proposed. Such a change requires a distinct,
versioned trusted requirements policy/profile (proposed identifier
`review-evidence-requirements.v1`) and `retrieval-plan.v2`, with independently
reviewed normalization, side-specific interval-union coverage after selection,
malformed-input rejection, cap outcomes, rename/delete/binary semantics and
migration. These identifiers are proposals, not registered supported contracts.
An arbitrary HEAD anchor cannot satisfy an entire positive required interval.

### 2. Minimal optional evidence-list reuse

Introduce a finite, versioned **opt-in trusted selection setting** in a later
reviewed slice (proposed identifier `captured-evidence-enrichment.v1`; exact
profile schema remains to be reviewed). Absence preserves current requests.
It may select only evidence already in the immutable captured snapshot, within
both the task's unit/lens scope and existing trusted path/side allowlists.
It cannot initiate Git reads, network retrieval, target execution or new paths.

The minimum implementation selects an **existing complete evidence row** by its
existing ID, including an already captured complete-line `source_window`, or an
entire captured file when it fits. It does not synthesize excerpt text, mint
uncited anchors, widen capture, mutate the sealed snapshot, or add
`retrieval_windows` content beside evidence. If no existing row can represent the
candidate within caps, record optional omission and continue with required
inputs. Metadata windows remain diagnostic candidate locators only.

This intentionally trades some enrichment precision for a small verifiable
change. New sub-row excerpts need their own reviewed deterministic ID,
parent-evidence provenance, slicing/newline rules, unit-binding relation and
resume validation; they are deferred, not implicitly authorized here.

Keep `specialist-input.v2` only while its ordinary evidence shape, trust and
unit-binding semantics remain unchanged. Reused rows already delivered are not
sent twice. An optional row belonging only to a sibling unit cannot be relabeled
as local evidence; cross-unit candidate reuse is omitted in this minimum slice
unless the existing trusted task relation already authorizes it. A new parallel
provider-visible window channel or changed input semantics requires
`specialist-input.v3` and an explicit migration, not an unversioned field.
No runtime registry entries change in this design-only proposal.

### 3. Validate payloads, not just anchors

One deterministic verifier is required at provider-free prepare, fresh run,
persisted resume, dispatch before reservation, and narrowed follow-up selection.
For every selected row, verify against the original captured evidence index:

- Unique indexed evidence ID equals the row's ID; snapshot and inventory/task
  relation match; no conflicting duplicate ID or ambiguous parent.
- Expected side, exact path (BASE old path versus HEAD new path), source kind,
  revision (change-base for BASE source in merge-base comparison; base revision
  for BASE policy as applicable), object ID/format and source size match.
- UTF-8 content bytes and SHA-256 match; row content is identical to the captured
  row, not a separately supplied string with copied metadata. Complete files
  additionally recompute Git blob identity when captured metadata permits it.
- Positive, ordered complete-line bounds match the captured byte representation;
  reject truncated/mid-line/invalid-range candidates. Do not clip intervals,
  normalize away a mismatch, or imply that one partial capture authenticates a
  whole file. Partial-window object IDs identify the parent blob, not a blob hash
  of the window bytes; validate their captured parent relation instead.
- Captured trust classification is preserved. HEAD PR evidence stays
  `untrusted_pr_content`; selection never promotes it to `trusted_policy`.

A legitimate absent or over-cap optional candidate is an omission, not a skip.
Malformed or tampered caller/persisted delivery input is rejected before any
reservation/provider effect, even when labeled optional. A raw metadata hash is
not an authenticity mechanism: recompute from trusted captured inputs and never
accept caller edits to gaps/sufficiency because `plan_hash` still matches.
Recomputed diagnostics remain diagnostics. If a future policy makes their
meaning authoritative, version and bind the complete policy/requirement and
admission result; do not silently alter `retrieval-plan.v1` hash semantics.

### 4. Stable identity and bounded accounting

Selection order must be deterministic: preserve required unit evidence and
explicit required references first; consider optional candidates in stable
captured inventory/side/path/range/ID order. Deduplicate exact IDs and equivalent
immutable side/path/revision/object/range/content/trust rows, retaining existing
required IDs and citation/unit relationships. Overlapping but unequal rows are
not automatically interchangeable. Optional entries never displace required
entries or invent new required omissions.

Freeze the selected task/evidence list before request identity and budgeting.
Bind opt-in profile/version, source snapshot, selected IDs and content digests,
input-contract version, obligations, limits and provider identity into the
existing request basis; retain per-task exact serialized-body digest/byte count
using the same adapter serializer as dispatch. Recomputed identical inputs must
produce identical order, hashes and body bytes. Different selected bytes,
selection policy or scope must change the appropriate identity and fail old-run
resume, never borrow a successful cached output. No secret values enter receipts.

Count the **actual complete JSON UTF-8 request body**, including content,
metadata, escaping, citation enums, system/schema overhead and task bindings,
against the minimum runtime/adapter wire ceiling. Existing conservative chunk
measurement (including its 1,024-byte margin) can remain; it is not a replacement
for exact body accounting. Include added content in existing input token,
run-context, cost, call and deadline reservations; no allowance/cap increases.
Reuse is not a new retrieval call, but it is not free provider context.

Drop optional rows in deterministic reverse selection order until wire and
existing token/context reservation limits fit. If required input itself cannot
fit or a required reference is absent, preserve the existing typed skip/gap,
obligation and reason, with zero provider reservation for that affected task.
Do not skip unrelated admitted work, suppress provider-failure probes, or erase
already supported findings. A future insufficient run-wide budget still follows
the existing deterministic failure path, not a silently higher cap.

### 5. Follow-up and resume isolation

Recompute optional selection for the actual narrowed child units, lens,
obligations and authorized context target. Do not copy a batched parent's whole
evidence cache, sibling rows or diagnostic plan into the child. Preserve the
existing parent/proposal/target/retrieval/obligation bindings and required-context
note predicates. Revalidate every retained row against original captured
identity, not a resume-enlarged untrusted evidence map. Keep optional enrichment
separate from newly retrieved follow-up evidence and its current retrieval caps.
A child that cannot validate or fit its required evidence remains incomplete;
optional absence does not resolve the parent's semantic gap.

Preserve immutable historical v2 request receipts, frozen runtime and named pins.
A current-source request can differ after opted-in selection; compare it against
current preparation, not a monkeypatched historical preparation function.
Historical equality proves only the historical runtime/receipt contract.

## Alternatives considered

| Option | Disposition and rationale |
|---|---|
| Skip on every raw compiler gap | Reject: turns Python/test heuristics into universal required inputs, changes the obligation contract and can prevent unrelated provider/reducer fault paths. |
| Deliver window strings authenticated only by v1 plan hash | Reject: gaps/sufficiency are omitted, payload bytes are not authenticated, and anchors need not prove complete interval coverage. |
| Add parallel `retrieval_windows` and specialist v3 immediately | Defer: duplicates evidence/citation, identity, cap and follow-up handling. Justified only if ordinary cited evidence cannot represent an independently approved need. |
| Universal changed-source interval admission | Defer to separate versioned trusted requirements policy and v2 plan. Existing opt-in interval requirements remain intact, but do not justify a new universal gate. |
| Keep metadata-only behavior forever | Safe fallback, but does not deliver optional captured context that could be useful. Prefer bounded row reuse when validated and affordable. |
| Reuse existing validated evidence rows | Recommend: smallest ordinary cited channel, no fresh retrieval or derived text; may omit useful sub-row or cross-unit enrichment rather than widening scope. |

## Consequences

- Required admission remains explicit and transport delivery remains distinct
  from semantic adequacy and measured review quality.
- Metadata diagnostics may still say `REQUIRED` or `sufficient`; consumers must
  not treat those v1 names as new authority. A later naming/schema cleanup is
  separate reviewed work, not a hidden migration.
- Whole-row reuse may be too large or already deduplicated; optional enrichment
  can legitimately add zero bytes. This is not a sufficient-review claim.
- A shared validator and selection path cost source lines. The checkpoint's
  [surface budget](../public-surface.json) records 32,781 measured source lines
  and zero remaining headroom under the supplied root decision. This ADR grants
  **no new source allowance**. Measure the minimal delta and present explicit
  reallocation/allowance choices before implementation growth; no whitespace
  compression, fixture suppression or automatic ceiling update.
- [ADR 0001](0001-post-ca2-feature-budget.md), accepted records and historical
  failed recovery evidence remain unchanged. This Proposed record cannot satisfy
  the accepted-on-base decision-link gate for a later safety-invariant change.

## Confirmation

The following are **nine planned discriminating acceptance cases**, not test
results. Each must run through actual current preparation/engine boundaries
with a secretless recording provider or local adapter serialization; no provider
network call or target-code execution is needed to falsify these contracts.

| ID | Input and adversarial contrast | Required oracle |
|---|---|---|
| A1 — Diff-sufficient non-symbol review | Complete bound prose, YAML and constant-only diffs, no Python definition, selector disabled; contrast missing/truncated required diff. | Ordinary obligations reach the recording provider despite heuristic no-window diagnostics; required diff gaps remain in final incomplete coverage. No universal source gate. |
| A2 — Existing explicit required refs | Missing mandatory policy, unit/lens required ID, v2 related HEAD sentinel or dependency projection; include another valid task and an optional symbol miss. | Only affected tasks skip before reservation with existing required-context reasons; all required obligations remain. Optional misses do not hide the gap or suppress the unrelated provider/failure boundary. |
| A3 — Optional miss, reuse and dedup | Captured allowlisted complete row available, absent, over cap, already supplied or duplicated equivalently; inferred test/caller unavailable. | Available valid rows use ordinary cited IDs and unchanged v2 bindings; duplicates add no repeated content; optional absence/drop does not skip. No new read, derived text or parallel window channel. |
| A4 — Tamper and raw hash omissions | Alter content/hash, indexed ID, snapshot, side/path/revision/object/size/trust or bounds at prepare, resume and dispatch; independently edit raw v1 gaps/sufficiency without changing its hash. | Invalid delivery never reserves or reaches provider. A matching metadata hash does not validate altered verdicts/bytes; trusted recomputation retains the existing admission contract. |
| A5 — Exact request and reservation boundaries | Real adapter JSON/UTF-8 including escaping/multibyte content at ceiling and ceiling + 1; optional addition crosses wire, token or run-context cap; required input alone overflows. | Exact serialized length/digest includes every byte. Optional rows drop first; required overflow keeps stable existing skip/gap and zero affected provider reservation. No cap increase; call/cost/deadline accounting retained. |
| A6 — Narrowed follow-up and persisted resume | Two-unit parent narrowed to one unit; attempt sibling enrichment injection, changed selection/profile, changed persisted bytes and replayed parent binding. | Child includes only authorized local/explicit target evidence; original parent/proposal/retrieval/note constraints hold. Tampered/stale identity rejects before reservation; valid deterministic resume reproduces exact selected bytes. |
| A7 — Side-correct interval contracts | Opt-in selector with BASE old-path deletion and HEAD new-path addition, merge-base divergence, separated changed ranges, partial-line scan, byte/window caps; contrast pure rename. | Existing side/range/scan/cap gaps survive. One HEAD anchor never discharges an uncovered required interval; no fabricated HEAD interval for no-content rename; optional reuse cannot erase selector requirements. |
| A8 — Unsupported and non-clean outcomes | Binary/unsupported unit with zero inferred windows; complete transport plus `PARTIAL`/`NOT_COVERED`; unresolved required follow-up; `PROJECT_CHECK` unknown or wrong-binding evidence; a separate supported blocker. | Zero windows does not imply semantic sufficiency. Partial notes and invalid/inconclusive checks do not become complete; required notes/check binding validation remains. Supported blocker survives and reducer still requests changes. |
| A9 — Historical/current boundary and integration | Preserved historical v2 runtime/receipt tests plus the frozen six-unit case through unmodified actual current prepare and installed CLI/wheel; existing provider/reducer fault matrix. | Historical pins remain unchanged; current six-unit obligations, selected IDs, actual body digests/bytes and cap outcomes are independently reported. No historical monkeypatch substitutes for current engine coverage, and optional misses cannot bypass the fault matrix. |

### Proposed slices and review gates

These are candidate slices for root selection **after independent design
review**, not an implementation instruction or source-budget approval.

1. **Provider-free selection/validation contract:** measure a minimal pure
   existing-row selector/verifier and strict opt-in profile schema. Demonstrate
   A1–A4/A7 without changing dispatch or admission. Show source-line delta and
   omissions; root must decide reallocation/allowance before growth is landed.
2. **Single-path preparation and accounting:** integrate through the shared
   current prepare path, existing v2 binding/citation list, exact adapter
   serialization and request identity; retain required-first order and existing
   admission skips. Demonstrate A2–A5 and replay determinism with local fakes.
3. **Resume/follow-up and full confirmation:** reuse the same validator at
   persisted/dispatch/narrowed boundaries; demonstrate A6–A9, full current and
   separate compatibility suites, pinned-tool CI, installed wheel/CLI and Linux
   observer evidence with zero unintended effects. No closure from unit tests
   alone. Avoid a later gap-to-skip slice unless a separate required policy is
   expressly reviewed and accepted.

Each proposed slice needs an exact source revision, unchanged test denominator,
raw check results, source measurement and independent review before root can
select the next one. Function/test ownership remains to be assigned by root;
no acceptance reviewer or approval is fabricated here. Missing confirmation is
an unresolved gate, not a pass. Checks are change-triggered for every affected
slice; failures return to root for scope/contract correction, never automatic
exceptions or weaker thresholds. Review this confirmation plan when the ADR or
source boundaries change; retain its failed runs if it is superseded.

### Open decisions for the independent design review

- Can existing complete captured rows provide enough useful optional context
  to justify the source delta, or should this remain metadata-only for now?
- What is the smallest strict trusted opt-in schema, finite candidate limit and
  receipt projection that preserves existing profile and v2 semantics?
- Can the shared verifier authenticate the needed captured source-window parent
  relations without new capture/schema authority? If not, restrict the first
  slice to verifiable complete files or defer it; do not silently widen scope.
- Which explicit source reallocation, if any, will root choose after measurement?

The next implementation is selected by root only after that independent review.
Documentation checks can validate this proposal's structure and links, not
answer those decisions or establish review quality.

### Observed documentation-only verification — 2026-11-07

The decision-record, relative-link, documentation-index, documentation-truth,
generated-status reproducibility and whitespace CLI checks passed on this draft.
The focused documentation/decision regression selection returned **50 passed,
1 failed**: [the decision-log count assertion](../../tests/test_decision_records.py#L82-L87)
expects exactly 11 records, whereas registering this Proposed ADR makes 12.
The same test's structural `errors == []` assertion passed. Tests and validators
were not edited under the design-only scope; a reviewed count-test update is an
integration follow-up, not permission to omit registration or suppress a test.
These observations do not execute or confirm acceptance cases A1–A9.
