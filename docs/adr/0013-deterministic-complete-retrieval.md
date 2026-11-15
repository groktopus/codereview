# 0013 — Deterministic complete RC-2 retrieval and evidence contract

- **Status:** Accepted
- **Date:** 2026-11-15
- **Owner:** Repository owner (`@magnus919`); coordinating root agent owns execution and contract integration under the explicit 2026-11-15 roadmap directive.
- **Decision authority:** Coordinating root agent exercising delegated contract authority under the explicit user roadmap directive, within the repository's `AGENTS.md` constraints. This does not attribute a separate repository-owner approval. Any wider scope or policy change requires its own authority.
- **Scope:** Complete deterministic RC-2 retrieval, immutable derived evidence, task admission, exact request serialization/accounting, resume and scoped follow-up, based on source checkpoint `0ede601637721f57f9444e8fbc788d75d174a712`. Existing external-effect policy and target configuration are unchanged.
- **Evidence:** Design synthesis of ADR 0012, [issue #240 brief](../issues/01-review-completeness.md), source inspection at the named checkpoint, roadmap direction, and independent design-only review by `/root/retrieval_contract_review` (model `gpt-6.1-sol`). The review did not validate implementation. No implementation or quality result is claimed.
- **Reversal/expiry:** Re-review if captured evidence identity, task/obligation semantics, provider request serializer, trusted configuration, or source checkpoint changes. Preserve ADR 0012 and its historical evidence; a later record may supersede this one without rewriting it.

## Context

ADR 0012 correctly protects explicit required-context contracts and says compiler heuristics cannot independently create admission authority. Its selected implementation is intentionally limited to reuse of existing whole evidence rows. RC-2 requires a deterministic way to find, validate, identify, and deliver derived source evidence that can satisfy explicitly trusted requirements, including definition bodies and bounded caller/callee or test evidence. Whole-row-only reuse cannot express that contract. Conversely, a source compiler must not turn its own guesses into universal requirements or bypass existing diff, context, check, budget, or trust rules.

The earlier PR #353 remains failed/stopped and unmergeable. This successor design does not repair, resume, or treat it as accepted evidence. ADR 0012 remains unchanged with its historical `Proposed` status and rationale; this decision supersedes its whole-row-only limitation for the complete RC-2 design, while retaining its protections around explicit requirements, fail-closed gaps, ordinary evidence citations, request identity and exact accounting.

### Decision provenance

The user roadmap instruction of 2026-11-15 directs the coordinating root to
work through the roadmap issues; `AGENTS.md` records the root's delegated
source-PR responsibilities and constraints. The coordinating root accepts
this record under its delegated contract authority for that roadmap task; no
separate owner vote or approval date is asserted. An independent design-only
review by `/root/retrieval_contract_review` (model `gpt-6.1-sol`) concluded
that ADR 0012's whole-row-only optional enrichment was insufficient for
complete RC-2 retrieval. That review informed the design only; it did not
accept this ADR or validate implementation. This record is based on source
checkpoint `0ede601637721f57f9444e8fbc788d75d174a712`.

This is a source-contract decision. It does not establish a quality grade, recall improvement, deployment, production readiness, replacement, or RC-2 closure. The frozen evaluation corpus identity and its 18 development, 13 held-out and 10 challenge cases remain unchanged. Any new evaluation artifacts are additive and separately identified; raw, waived and unmeasured outcomes remain distinct.

Issue #240's RC-2 exit criterion remains at least 90% of required context
obligations complete on the frozen corpus, with line-anchored retrieval,
deterministic hashable plans, and no whole-file prefix fallback above the
envelope. The separate proposed 90% required-context delivery target in the
implementation plan measures delivery only. It cannot substitute for measured
obligation completion or close RC-2. RC-2 remains open until completion is
independently measured on the frozen corpus and the issue's exit criteria are
met. Neither this acceptance nor the delivery target claims review quality.

After the custom retrieval-index implementation was stopped as not clear in
the pass-3 review, the coordinating root incorporated the read-only 2026-11-15
contract reassessment into this record. This clarifies the static relationship
contract; it does not resume or clear that implementation review, or claim
implementation evidence.

## Decision

Adopt the following complete contract for implementation in dependency-ordered, reviewable slices, within the bounded scope below. All selector authority is trusted configuration; repository content, compiler output, model output and persisted caller-supplied metadata are untrusted data.

### 1. Trusted compiler policy and deterministic prepared input

Add opt-in `retrieval-compiler.v1`, a finite trusted policy containing:

- a closed set of retrieval roles (changed definitions, direct statically resolvable callers/callees, tests, and policy context);
- explicit path, side and role allowlists; bounded scan/capture limits; and finite explicit requirement declarations;
- a distinction between a candidate (optional) and a declared requirement (authoritative only because the trusted policy says so).

Unknown roles, fields, paths, side values, bounds, ambiguous references, and malformed policy are
rejected. No repository manifest or PR text can supply or widen this authority. Defaults remain
opt-out. Heuristic misses remain optional unless an explicit trusted requirement applies. Existing
required diff, source, context, policy, dependency and project-check contracts remain in force
independently of this compiler. Each explicit relation requirement names the relation-contract
version, exact source side/revision, trusted bounded scan universe, selector and whether it requires
named finite references or exhaustive coverage of that static relation within the universe. A named
reference is satisfied only by its uniquely validated call-site/declaration association and complete
required source evidence. An exhaustive requirement additionally requires complete supported
scanning of its universe; one match or a truncated scan cannot satisfy it. Unresolved relations that
may affect the required selector retain a gap unless deterministic analysis proves them irrelevant.
A runtime relationship requirement is unsupported and remains incomplete; the compiler cannot
substitute a syntactic requirement, make it optional or remove it from the denominator.

Create one pure `PreparedReviewInputs` construction used by both CLI `prepare` and the engine before request identity is frozen. It takes the immutable original captured snapshot plus trusted compiler/profile configuration, derives and validates the selection and gaps, fixes task inputs and obligations, and returns a canonical plan. It performs no provider, network, target-code execution or Git mutation. The original snapshot remains immutable and is stored separately from the derived catalog; derived rows never replace, edit or masquerade as captured source rows. Fresh runs, CLI preview, dispatch validation and resume use the same constructor and validation logic.

### 2. Versioned canonical plan and ordinary evidence delivery

Introduce `retrieval-plan.v2`. Its canonical digest covers the complete normalized content, not just candidate anchors:

- plan and compiler contract versions;
- trusted policy identity/version/digest and effective selection authority;
- repository, PR, base/merge-base/head and immutable source snapshot identity;
- selected evidence identities and exact ranges, source sides/paths/revisions, trust classes and parent relationships;
- every explicit requirement, its obligation binding and outcome;
- all deterministic gaps, omissions and scan/cap limits; and
- canonicalized selected fragments and stable fragment IDs.

Canonical encoding and hash algorithm are fixed in the contract and tested against byte-level vectors. No mutable `sufficient` boolean, caller claim, or model output can override the recomputed requirements and outcomes. Legacy `retrieval-plan.v1` behavior remains unchanged when opt-in is absent; it is not silently reinterpreted or upgraded.

Deliver derived evidence only as ordinary cited evidence in `specialist-input.v3`. There is no parallel content/window channel. A derived row includes exact LF byte-slice content, a stable ID, parent evidence ID and immutable parent binding (snapshot, source side, path, revision, Git object format and object ID, parent size, source byte range, trust class), plus role and bound obligation/unit IDs. Provider-visible citations use these ordinary evidence IDs. The full file can be checked against its Git blob identity when applicable. Partial slices are authenticated by exact comparison to the original captured parent bytes and parent identity; a parent blob hash alone is not claimed to hash or authenticate the slice.

A derived catalog stays separate and immutable from the capture catalog. Request identity binds the canonical plan, all primary derived row IDs/content digests, input-contract version, obligations, trusted limits and provider configuration before any provider reservation. Resume recomputes primary inputs from the original snapshot and trusted policy and separately authenticates persisted derived rows; it never trusts cached plan metadata alone. A narrowed follow-up reconstructs only child-scope evidence and obligations and cannot inherit optional sibling-unit rows.

### 3. Deterministic bounded source analysis and byte preservation

The compiler uses deterministic AST parsing and qualified definitions. It selects complete definition bodies for changed or explicitly required definitions and retrieves direct caller/callee, test and policy evidence through versioned finite static association rules. `static-direct-reference.v1` records a bare-name call site associated with one syntactic definition or explicit import declaration under the compiler's declared namespace, binding and expression-context rules. It asserts a source association, not runtime object identity, callability, execution or dynamic-dispatch resolution. It does not execute target code, import target modules or run tests. Dynamic call expressions, assignment aliases, competing or conditional bindings, unsupported scope mappings and other unsupported relations have explicit unresolved outcomes. Syntax errors, unsupported languages, binary content and over-limit scans have explicit scan gaps. Each gap is required or optional solely according to trusted requirements; no gap is silently treated as complete.

The initial positive relation subset must cover unique bare-name references to same-module definitions, nested lexical definitions and explicit imported-name declarations, with correct local/global/free namespace classification and definition-header versus body context. Imported-name declarations are not claims about the executing object or its implementation file. Each supported scope/context and unresolved reason is enumerated in the compiler contract; unknown constructs fail closed for affected requirements. Static namespace facts do not prove absence of dynamic mutation: namespace access through aliases or arbitrary invoked code cannot be certified harmless by a finite spelling blacklist. Optional lexical candidates may still be retained with their limitations, but no static association may satisfy a requirement for stable runtime binding or runtime-complete callers/callees.

Repository scans operate only over capture-time immutable Git trees/blobs, trusted path/role allowlists, and pinned revisions, with explicit file, byte, node/depth and candidate caps. No live worktree reads, network retrieval, submodules, or post-capture target execution occur. BASE/HEAD/merge-base identity is explicit, including rename sides and removals.

Fragment construction is from exact source byte offsets and preserves the specified LF-delimited bytes exactly; it must handle CRLF source, UTF-8 multibyte boundaries and final lines with or without an EOF newline without normalization. Each fragment has a stable ID binding the original evidence ID, object identity, exact byte range, content digest and trust. No fragment may cross its bound source row or invent an anchor unsupported by the captured source.

### 4. Admission, coverage and deterministic degradation

Compute interval coverage as the union of eligible, validated ranges per required source side, exact path and revision after rename/merge-base mapping. A single anchor or a matching plan hash cannot satisfy a larger interval. Missing, stale, malformed, ambiguous, truncated, out-of-scope or over-cap required evidence fails closed. Optional candidates may be omitted with a recorded gap. Malformed/tampered evidence is rejected even if labeled optional.

Preserve existing required diff/source/context/check requirements. A required retrieval gap skips only the affected task before budget reservation/provider invocation; it does not consume an attempt or disappear from the obligation denominator. Optional gaps do not skip. Required source obligations and large definition bodies may produce bounded fragments linked to the same original obligation IDs. An obligation reaches `COMPLETE` only when every required fragment is delivered and covered; partial fragment coverage remains incomplete. Existing supported blockers remain in final disposition through task failure, incomplete synthesis and resume. Provider output cannot redefine which fragments or obligations were required.

Selection is deterministic and deduplicated by full immutable identity. Required inputs have priority. Optional evidence is dropped first to meet the existing normal request and token caps; no provider cap is raised. Preparation measures the actual bytes and hash emitted by `serialize_review_request`, including schemas and bounds, rather than an estimate of evidence text alone. If required content cannot fit the existing cap, skip the affected task before reservation. Exact cap succeeds; cap-plus-one fails/omits according to required versus optional status, with a stable reason.

### 5. Version migration and evidence boundary

`specialist-input.v3` adds derived evidence and its bound metadata while preserving ordinary evidence citation semantics. `retrieval-plan.v2` and `retrieval-compiler.v1` are new independently versioned contracts. Opt-out compatibility retains the legacy v1 plan and v2 specialist payload byte-for-byte at the existing public boundary. No registered surface is declared supported until its canonical pin and compatibility evidence land in the first required PR. Any later compatibility-pin refresh is a separate reviewable change; frozen identities and corpus contents are not rewritten to accommodate RC-2.

No configuration endpoint, provider account, secret binding, model call policy, external effect, or publication behavior changes under this decision. Provider semantics remain advisory and bounded by existing deterministic control. Delivery coverage measures what required evidence reached the request; it does not establish semantic completion or quality.

## Alternatives considered

1. **Keep ADR 0012's whole-row-only selector.** Small and safer to implement, but cannot represent bounded definitions/callers/tests or prove complete source coverage when the needed evidence is a subrange. It does not satisfy the complete RC-2 contract.
2. **Make all inferred definitions/callers/tests required.** Rejected: heuristic completeness is not authority, and this would create false skips for unsupported or ambiguous code and prose/non-code changes.
3. **Add a side-channel for source windows.** Rejected: duplicates citation, validation, serialization and identity semantics, creating an unbound path for provider-visible content.
4. **Trust plan hashes or cached compiler output.** Rejected: a digest is useful only if it covers canonical requirements, authority, content and gaps and is recomputed from the immutable parent capture.
5. **Raise request/provider budgets for the new evidence.** Rejected: changes cost/control policy and hides failure to select within existing caps. Required evidence must fit or skip before reservation; optional evidence degrades first.

## Staged acceptance and verification

| Slice | Acceptance condition | Required evidence |
|---|---|---|
| A. Canonical contract pins | Register only the exact schemas/versions after byte vectors and compatibility behavior are reviewed. | Tests for canonical normalization/hash, unknown fields, legacy v1/v2 unchanged with opt-out; installed wheel/import surface. |
| B. Immutable derived rows | `PreparedReviewInputs` emits deterministic validated rows from the captured snapshot and trusted policy; captured catalog remains unchanged. | Tamper each identity component (parent ID, snapshot, side, path, revision, object format/ID, size, range, trust, bytes, digest); verify complete-file Git identity and partial-parent validation. |
| C. Source selection | AST-qualified definitions and bounded direct static edges/tests/policy are selected within trusted caps. | CRLF, multibyte UTF-8, EOF newline/no-newline, exact range, BASE/HEAD union, rename/removal/merge-base, unsupported and ambiguous scans, exact cap and cap-plus-one. Positive same-module, nested and imported-name caller/callee selection; named versus exhaustive required queries; scope/header/comprehension/global/nonlocal boundaries; direct and aliased dynamic namespace cases without runtime-certainty claims; unknown-scope and partial-universe gaps; normalized results across supported interpreter hosts. |
| D. Admission and obligations | Required gaps skip only affected tasks before reservation; optional gaps omit; every required fragment is covered before its original obligation completes; blockers survive. | Large unit fragmented across requests, partial fragment coverage, malformed data, provider recorder proves zero calls/reservations on skip. |
| E. Request identity and budget | Exact serializer bytes/hash, schemas, ordinary citations and selected content are frozen before budget reservation; optional rows drop first. | Recording-provider captures `serialize_review_request` output; exact cap/cap-plus-one; request identity changes on any selected content/authority/gap change. |
| F. Recovery and scope | Resume recomputes from original capture and authenticates dynamic rows; child follow-up cannot inherit sibling enrichment. | Resume tamper/regeneration tests, sibling-unit follow-up regression, frozen legacy compatibility tests, installed-wheel execution. |
| G. Evaluation and source envelope | Keep frozen corpus (41: 18 development, 13 held-out, 10 challenge) and identities unchanged; add separately identified RC-2 artifacts. The proposed acceptance target is at least 90% required-context delivery measured per obligation; issue #240 still requires at least 90% required-context obligations complete on the frozen corpus. Report delivery and semantic completion separately; delivery does not establish completion. Keep additional source for the scoped complete RC-2 path within the initial 2,400-line planning bound (superseded by the measured-envelope addendum below), measured at each slice; retire any unused allowance rather than removing working code to meet a smaller count. | Frozen-corpus identity check, separate raw/waived/unmeasured reporting, per-obligation delivery and completion denominators and observed numerators, source-line accounting by slice. |

These are acceptance conditions, not completed checks. The 90% delivery target measures delivery only; it is distinct from semantic completion and the frozen-corpus completion exit criterion, and does not mean 90% correctness or a quality grade. Delivery at 90% alone cannot close RC-2. The initial 2,400-line envelope, revised by the measured-envelope addendum below, is a planning bound for this scoped RC-2 path, not permission to grow unrelated code; unused allowance is retired, and working code is not removed just to hit a lower count. Any required check not run or any failed, pending, skipped-required or unknown gate blocks the corresponding PR's completion under normal review policy.

## Consequences

- Complete RC-2 can represent sub-file evidence without mutating source capture or introducing a second provider content channel.
- Requirements and authority become auditable, canonical request inputs, and missing required evidence has deterministic pre-reservation behavior.
- AST and capture work is larger than ADR 0012's minimal selector; staged PRs must keep implementation and evidence within the bounded source envelope.
- Dynamic language relationships remain unresolved; the contract reports those limits instead of inventing certainty.
- Delivery, semantic completion, evaluation quality and replacement readiness remain separate claims. Passing tests alone cannot establish the latter claims.

## Links and records

- Prior design: [ADR 0012](0012-separate-required-admission-from-optional-enrichment.md), preserved unchanged and `Proposed`.
- Requirement brief: [issue #240 local brief](../issues/01-review-completeness.md).
- Project-specific proposal authority, canonical ADR acceptance workflow, safety invariants and review receipts remain governed by `docs/adr/README.md`, `docs/adr/safety-invariants.json`, `docs/OWNERSHIP.md` and `docs/REVIEW-EVIDENCE.md`.
- Acceptance authority is recorded above. Acceptance authorizes implementation of this bounded design; it is not implementation evidence, quality evidence, a review receipt, or a claim of deployment or RC-2 closure.


## Addendum: measured complete-path planning envelope (2026-11-15)

**Decision authority:** The coordinating root accepts this bounded planning
revision within the user-directed roadmap delivery task. This records a root
implementation and contract decision, not a separate repository-owner approval
of the number. Independent GPT-6.1 Sol reassessment informed the decision; it
neither authorized it nor cleared implementation.

The original **2,400 additional physical Python source lines** above is retained
as the initial estimate. It is superseded for planning by a provisional **3,100
additional lines for the complete RC-2 path**, measured from the accepted
`0ede601637721f57f9444e8fbc788d75d174a712` checkpoint. The 36-line compatibility
consumer migration is separate and is not charged to this envelope. No RC-2
implementation from this work has landed at the inspected main checkpoint
`d0ef89561745ee55924a3ef967e77b9e6796e49f`.

The first isolated source-fact draft measured 842 lines against its estimated
300–430. Its SHA-256 was
`ea17826949934d0b8698bbe6a7ac9304eb1577cc604f43591ef9b250fee91294`;
its 186-line test draft was
`561c999eb0379bc81e8c175ead5009be851fed81f38edb3cf1d6822c12358be5`.
These identify unintegrated draft bytes, not a reviewed source release. The
reassessment found necessary scope, byte-identity, binding and failure-handling
work rather than a demonstrated 400-line surplus. Its complete-path forecast is:

| Scoped work | Additional physical source lines |
|---|---:|
| Measured fact draft, still requiring correction | 842 |
| Fact identity, phase, binder and host-normalization corrections | 70–170 |
| Single static association owner | 160–240 |
| Trusted requirements and complete role selection | 240–360 |
| Derived rows, fragments and canonical plan | 220–330 |
| Coverage, admission, exact serialization and validation | 300–430 |
| Resume authentication and child-scope reconstruction | 220–330 |
| Shared preparation wiring and contract registration | 100–160 |
| Capture-universe/full-parent and interface contingency | 80–160 |
| **Whole-path forecast** | **2,232–3,022** |

The revised ceiling rounds that forecast's upper end to the next 100 lines.
Neither the forecast nor the ceiling proves that the implementation will fit.
Count added physical Python lines under `src`, including changes to existing
modules. Moving production code into experiments, deleting unrelated working
code, or compressing formatting cannot offset growth. Measure the cumulative
scoped delta after each slice. Retire unused allowance; stop and reassess any
further conflict. This addendum creates no general feature headroom and does not
change the installed source ratchet: any integrated slice still needs its
measured surface accounting and independent source review.

### Correctness gates before integrating the fact draft

Independent synthetic AST probes on CPython 3.13.5 found parent-unbound scope
and declaration IDs, missing star-import/escaping-walrus binder facts, incorrect
generator phase, loss of enclosing inert-annotation context, and unnormalized
host comprehension mapping. These direct fact-contract defects block
integration regardless of source size. No target text was executed. The
author-reported 17 passing tests do not establish correctness; the other
supported interpreter hosts were not exercised by that assessment.

Correct the fact/association interface before further integration: source-bound
identity must flow through all descendants; enclosing postponed/nonexecuted
annotation context must remain distinct from inner evaluation phase; exceptional
binders must identify their affected namespace; and one association owner must
apply uniqueness, ordering and barriers without duplicating provisional
fact-stage decisions. A fact-stage `reason=None` is not a resolved association.
Keep exact original token bytes separate from NFKC-normalized compiler names.

Run normalized scope, binding, phase and gap vectors on Python 3.11–3.14 before
claiming host equivalence. Preserve same-module, nested and imported-name
positive cases and explicit failures for unsupported or ambiguous relations.
The earlier stopped index, this failed draft and their failure evidence remain
preserved; this decision does not clear either implementation.

All accepted behavior and evidence requirements remain: every retrieval role,
named versus exhaustive requirements, original obligations and denominator,
immutable source sides and bytes, existing capture/request/provider caps,
exact-cap admission, required-gap rejection before reservation, blocker
preservation, resume regeneration and child isolation. The frozen 41-case
corpus and 18/13/10 split stay unchanged. At least 90% required-context
obligations must still be measured complete; delivery alone is not completion.
No quality, readiness, replacement or issue-closure claim follows from this
planning decision.
