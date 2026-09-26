# Context selection v2 implementation plan

**Status:** planning artifact only. No selector implementation, profile
migration, provider request, or production budget change is authorized or
implied by this plan. The current profile and v1 behavior remain the baseline.

## Current state and evidence boundary

As inspected on 2026-09-26, `profiles/slopsearx.json` is
`slopsearx-production-v3-check-bindings`. It has no `context_selection` field,
so it does not use the opt-in v1 selector. Its six exact `context_paths` are
`AGENTS.md`, `CONTRIBUTING.md`, `pyproject.toml`,
`slopsearx/mcp/security.py`, `slopsearx/mcp/oauth.py`, and
`slopsearx/config.py`. `trusted_policy_paths` names only `AGENTS.md` and
`CONTRIBUTING.md`; the other captured files remain repository evidence.
`retrieval_context_patterns` is a separate read allowlist. It permits bounded
gap retrieval of matching immutable Git objects; it does not cause wildcard
eager reads.

In `snapshot.py`, when selection is absent, `requested_paths` is the exact
`context_paths` list and those files are read from BASE. When selection is
enabled, snapshotting instead collects mandatory policy and explicitly bound
paths plus changed-line BASE/HEAD windows. In `planner.py`, legacy mode adds
all matching trusted-context evidence to each compatible task. Selection mode
uses each unit's selected review-context IDs, mandatory policy IDs, and the
binding paths for that unit and lens. The planner also sends the complete
profile `rules` list on each specialist task and the configured criteria for
the task's lens. Grouping and input splitting affect delivery, not the frozen
required obligation denominator.

The profile's current review scope must remain intact through any context
change:

- Every applicable changed-unit lens, risk floor, and generated-file rule
  remains required. The base profile has correctness, tests, and
  maintainability lenses; its risk rules add security/correctness/tests to MCP
  and filter surfaces, security/correctness to deployment/CI/config surfaces,
  and correctness/tests/performance to snapshot, research, cache, and saved
  state surfaces.
- All six project rules remain present and attributable: adapter error
  classification; MCP fail-closed and atomic sensitive grants; demonstrated
  filter enforcement; Valkey shared-state ownership; portal-impact review; and
  import-linter boundaries.
- Both independently bound portal checks remain in the denominator where
  their configured patterns match: `portal-impact-evidence` and
  `portal-browser-evidence`, each bound to the recorded external check identity.
- `AGENTS.md` and `CONTRIBUTING.md` remain the only profile-declared trusted
  policy sources. Immutable BASE provenance does not promote any other source
  to policy authority.
- Changed-source evidence, location anchors, BASE/HEAD identity, required
  context gaps, and the original coverage ledger remain intact. Context
  selection may change which evidence is delivered, not which evidence exists
  or what a result can claim.

The historical PR 464 full-policy v1 preflight is **not** a measurement of the
currently shipped profile. It recorded 14 specialist calls, 879,012 serialized
request-input bytes, a largest request of 76,847 bytes, six requests above
64 KB, and 238,343 bytes of snapshot evidence. Against the provisional
experiment limits of 12 calls, 64 KB per request, and 300 KB aggregate request
bytes, that preflight fails all three ceilings. A narrower binding sensitivity
run omitted applicable `CONTRIBUTING.md` obligations and was rejected; it is
not a valid savings baseline. These are local preflight measurements, not live
provider usage, quality evidence, or production budget recommendations. See
[`CONTEXT-SELECTION.md`](CONTEXT-SELECTION.md),
[`CONTEXT-SELECTION-V2-DESIGN.md`](CONTEXT-SELECTION-V2-DESIGN.md), and
[`PILOT-RESULTS.md`](PILOT-RESULTS.md).

## Policy inventory without shrinking scope

Start from the exact trusted source set already declared by the profile. A
mechanical extractor can enumerate Markdown headings, paragraphs, list items,
and code blocks into exact byte spans without waiting for a reviewer to
manually transcribe policy. Each extracted span receives a revision-bound
identity and hash. If a parser cannot safely segment a source, retain the
whole source as one span or report an extraction gap; never omit unparsed
content to create a smaller inventory. The empty structure in
[`examples/context-selection-v2/policy-inventory.template.json`](../examples/context-selection-v2/policy-inventory.template.json)
is a schema aid, not a SlopSearX policy inventory.

Applicability is a separate deterministic operation. A trace row is emitted
for **every clause and every planned obligation** with one of:
`APPLICABLE`, `NOT_APPLICABLE`, or `UNRESOLVED`. A reviewed, versioned profile
rule and its evidence may establish either of the first two states. When the
available facts or rule leave applicability ambiguous, retain the clause in
the denominator as `UNRESOLVED`; do not infer non-applicability from absence,
reduce the clause inventory, or let a model choose the state. This supports
mechanical extraction now without pretending that extraction proves a policy
interpretation. Any `UNRESOLVED` required row remains visible and prevents that
policy obligation from being reported complete.

Cross-revision clause matching is explicit. Do not guess that changed wording
is the same clause, or that a missing clause was deleted intentionally. A
profile may supply a stable lineage ID after review; otherwise the old and new
revision-bound clause identities remain distinct and the change is surfaced
for applicability review.

## Bounded implementation sequence

1. **Freeze a comparable baseline.** Record the exact PR 464 base/head SHAs,
   current profile version and SHA-256, harness source fingerprint, selector
   fingerprint, and provider request serializer/configuration identity. Capture
   the unchanged v3 plan, required obligation IDs, trust labels, evidence IDs,
   selected task grouping, per-task serialized request sizes, total bytes,
   largest request, and call count. Use immutable bare Git objects; do not
   checkout or execute the target repository.
2. **Generate a draft inventory offline.** Extract every exact source span from
   the BASE versions of the two declared policy documents. Record source path,
   full Git object ID and object format, revision, exact byte and line ranges,
   selector/parser fingerprint, and excerpt hash. Record full-source SHA-256
   only when the entire blob was read and hashed. Do not assign semantic
   applicability during extraction.
3. **Build the total applicability trace.** Cross every inventory clause with
   every planned obligation, preserving the original obligation IDs. Apply
   only explicit deterministic profile rules. Missing, contradictory, or
   ambiguous applicability becomes `UNRESOLVED`; it does not disappear from
   the count. `NOT_APPLICABLE` requires a declared rule and recorded basis.
4. **Add deterministic selector resolution.** Resolve a selected Markdown
   section by exact heading path and explicit occurrence, or return a typed
   gap. Support only parser/selector behavior with pinned version/fingerprint.
   Hash original bytes and preserve original byte/line coordinates. BASE and
   HEAD selectors resolve independently. Unsupported encoding, source hash
   mismatch, ambiguous match, over-bound section, timeout, or unresolved
   required span remains an explicit gap.
5. **Integrate planning without changing policy.** Select excerpts only after
   obligation and clause applicability are fixed. Preserve all selected
   changed-line windows, deleted/renamed BASE anchors, required check tasks,
   lens criteria, and all applicable project rules. Share excerpt bytes only
   across tasks with identical repository/snapshot, task kind, lens semantics,
   authority, applicability trace, and output contract. Do not merge security
   and correctness scopes merely to reduce calls. Optional repository context
   may be omitted with an explicit optional reason; required evidence may not.
6. **Measure before dispatch.** Serialize each exact request with the same
   adapter used for transmission, then reserve calls, input/output bytes, and
   deadlines before any provider call. Compare v3 and the candidate on the same
   frozen inputs, provider configuration, serializer, and limits. Report
   total and maximum serialized bytes, call count, output reservations,
   required/optional selected and omitted counts, gaps by reason, and clause
   trace completeness. Character counts are not a substitute for serialized
   byte counts.
7. **Run offline boundary and behavior checks.** Use the tests below before
   any provider comparison. A later quality comparison requires independently
   adjudicated cases; PR 464's historical Droid/model materials are challenge
   evidence, not independent truth. Teacher-model agreement, a synthetic
   fixture, or fewer bytes cannot establish review quality.

## Required offline test set

- **Inventory completeness:** exact source bytes are partitioned into stable
  extracted spans with no gaps/overlap loss; every clause has a source object,
  range, and hash. An unrecognized block is retained as whole-source content
  or marked extraction-incomplete.
- **Total trace:** every clause has exactly one state for every obligation;
  missing rule, conflicting facts, and unclear applicability produce
  `UNRESOLVED`. A `NOT_APPLICABLE` row without a deterministic rule and basis is
  rejected. No trace rewrite changes the pre-existing coverage denominator.
- **Selector determinism:** duplicate Markdown headings at different nesting
  levels, repeated exact headings, invalid occurrence, nested sections,
  overlapping selectors, changed source revisions, and parser fingerprint
  changes all resolve deterministically or fail closed.
- **Byte and location fidelity:** LF/CRLF, BOM, tabs, Unicode before selected
  ranges, invalid UTF-8, binary data, empty files, and boundary-sized sections
  preserve original byte hashes and declared line/byte coordinates. BASE and
  HEAD, deleted paths, and rename old/new paths never collapse to one side.
- **Bounded source access:** large blobs are streamed under byte and absolute
  time limits. Deadline, byte-cap, unsafe file type, or object identity failure
  yields a gap without materializing unbounded content or falling back to the
  working tree.
- **Scope preservation:** all current profile risk floors, lenses, six project
  rules, generated-file treatment, and matching portal check obligations are
  unchanged between baseline and candidate. Security/correctness/test scopes
  remain separately attributable. Input truncation cannot mark required
  context covered.
- **Exact budget comparison:** construct requests with the actual serializer;
  compare call count, each request, aggregate request bytes, aggregate snapshot
  bytes, response ceilings, retries, and finite deadlines. Rejected or
  incomplete tasks never count as savings.
- **Integrity and resume:** inventory/profile/source mutation invalidates the
  cached plan; rerunning the same immutable request is deterministic; reused
  IDs with different selector/content hashes are rejected or kept distinct.

## Stop criteria

Keep the current v3 profile and stop the candidate if any of these occurs:

- A trusted source cannot be inventoried completely, or a required clause has
  no trace row.
- Any required clause or changed-source anchor is omitted, ambiguous, silently
  clipped, mislabeled as optional, or attached to the wrong revision.
- Any required clause is `UNRESOLVED`, a mandatory excerpt is missing, or an
  obligation is lost while grouping. Report the actual gap; do not compensate
  by editing the denominator, dropping a lens/check, widening limits, or
  raising provider calls.
- The candidate fails any current comparison ceiling: at most 12 calls,
  64,000 serialized input bytes per call, and 300,000 aggregate serialized
  request-input bytes for the fixed experiment. These values are comparison
  constraints, not recommended production limits. The historical full-policy
  preflight's 14 calls and 879,012 bytes show the scale of reduction needed;
  only a complete, comparable plan can establish whether it is achievable.
- Source/profile/runtime identity changes during the comparison, or the exact
  serializer/provider estimate is unavailable. Mark the arms incomparable and
  stop before dispatch.
- Offline fixtures reveal a changed policy interpretation, lost anchor, or
  behavior change beyond context delivery. Revert the candidate to design-only.

Passing these gates establishes only deterministic context selection and
budget fit for the frozen pair. It does not establish that the profile is
complete, that a model follows excerpts, that findings improve, or that v2 is
ready for SlopSearX. Profile enablement and any live model comparison are
separate decisions with separate evidence.
