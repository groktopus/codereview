# Bounded context selection

`context_selection.v1` is an opt-in transport policy for selecting bounded
evidence to send to a provider. The immutable snapshot still records full
source identity and content evidence when available; selection controls what a
review task receives, not what exists or what the task is allowed to claim.
Profiles without this field retain the legacy context-delivery behavior.

The v1 profile shape is:

```json
{
  "version": "context-selection.v1",
  "mandatory_policy_paths": ["AGENTS.md"],
  "max_total_context_bytes": 64000,
  "window": {
    "before_lines": 20,
    "after_lines": 20,
    "max_bytes": 12000,
    "max_windows_per_unit": 4,
    "max_scan_bytes": 1048576
  },
  "bindings": [
    {
      "unit_patterns": ["src/**/*.py"],
      "lenses": ["correctness", "tests"],
      "context_paths": ["CONTRIBUTING.md"],
      "max_context_bytes": 8000
    }
  ]
}
```

Every path must already be within the trusted profile's exact context or
retrieval allowlist. Mandatory policy paths must also be declared trusted
policy. A policy file must be mandatory or explicitly bound; selection cannot
silently remove applicable policy. Bindings select context for matching units
and lenses. Unbound allowed files are not automatically sent. Source windows
are produced around changed line ranges for both BASE and HEAD, merged when
overlapping, and keep original line coordinates, revision, path, full Git
object identity, and content hash. File-level anchors are emitted only when
the full source object was captured. The bounded scan limit is enforced while
reading the Git object, not after materializing an unbounded blob.

The Git object ID and object format identify the immutable source object even
when its body is not fully read. A full-source SHA-256 is available only when
the complete blob was captured and hashed; it remains unknown for a bounded
prefix/window scan. A window content hash identifies only that window and must
not be presented as a hash of the full source file.

If a source scan cannot reach a changed range, a hunk exceeds a window limit,
required policy cannot fit, or an obligated context reference is omitted from
a provider request, the snapshot/task records an explicit context gap. A gap
cannot be converted to coverage by trimming a decisive range, substituting an
unrelated excerpt, or marking an obligation complete. Optional context omitted
solely by selection is recorded as optional and does not itself make every
task incomplete. The engine separately preserves the required obligation
when input splitting or request limits omit evidence needed by that task.

The immutable `evidence_ids` retain source and anchor provenance. The distinct
`review_context_evidence_ids` list identifies selected diff/window evidence
that can be delivered to review tasks; full BASE/HEAD blobs remain available
for validation and bounded retrieval without being copied into every prompt.
Task grouping is deterministic by unit, lens, and selected context set.

For runtime limits, optional `max_snapshot_context_bytes` bounds aggregate
snapshot capture independently from `max_context_bytes`, which remains the
cumulative provider-input budget. If the optional field is absent, snapshot
capture uses the legacy `max_context_bytes` value. This compatibility fallback
preserves existing configurations; deployments that need separate capture and
inference budgets must set both fields explicitly.

## Measurement and current limitation

### Opt-in related HEAD context (v2)

`context-selection.v2` keeps the v1 envelope and adds a required
`head_context_paths` array to every binding. An empty array retains BASE-only
binding behavior. Each entry is a unique exact relative path within the trusted
profile's existing context or retrieval allowlist; directory and symbol lookup
are not added. V1 profiles retain their existing schema and behavior.

For those paths, the planner selects already-captured changed-HEAD diffs and
complete HEAD source windows, checking their snapshot, revision, path, content
hash and provenance. A complete window is not a complete-file anchor. Related
evidence stays untrusted PR content and does not expand task ownership, lenses
or obligations. BASE policy remains authoritative. No additional Git reads or
target execution occur during this selection.

Both BASE context and related HEAD evidence consume the same binding and
aggregate limits. Missing, malformed, stale, truncated or over-cap required
HEAD context creates an unresolved required-context reference; the engine
cannot treat that task as complete. The opt-in
`profiles/slopsearx-v9-context-candidate.json` is a diagnostic candidate, not a
deployed profile. Its historical PR466 implementation binding exceeds the
unchanged 18,000-byte cap when all existing BASE dependencies and the requested
test/documentation windows are included. That gap remains explicit; the v8
profile and target selection are unchanged. Documentation supplies a declared
contract, not evidence of actual external-client behavior.

### Bounded source-window splitting (v3)

`context-selection.v3` uses the v2 binding envelope, including
`head_context_paths`, and changes only how selected source windows are emitted.
When one merged changed range exceeds `window.max_bytes`, the snapshotter may
split it into contiguous, complete UTF-8 source lines. Each emitted window stays
within `max_bytes` and is bound to its exact path, BASE or HEAD revision, Git
blob ID, line interval, and content hash. The window hash covers that window's
bytes only; it is not a full-file hash. Valid multibyte UTF-8 is counted by
encoded bytes. A line that cannot fit intact or cannot be represented as valid
UTF-8 is omitted with a required line-specific gap rather than clipped or
replacement-decoded as exact evidence.

The existing `max_windows_per_unit`, `max_scan_bytes`, aggregate selector
budget, and snapshot byte budget remain in force. When one stops capture, every
uncovered requested line interval receives a required gap, including the tail
beyond a truncated scan. A truncated CRLF line is not accepted as complete
unless its LF byte was captured. V1 and v2 continue to use their historical
whole-range behavior; a profile must opt into v3 to split an oversized range.

### Symbol-anchored follow-up retrieval

A follow-up gap may name a `target_symbol` instead of a path. Only one
unqualified identifier is accepted; dotted names such as `Client.send` are
rejected as `target_symbol_invalid` rather than resolved by leaf name alone.
Retrieval resolves the owning changed unit only from already-captured inventory
evidence and the trusted allowlist, reads the blob up to the trusted runtime
`max_scan_bytes` scan limit (capped at 1 MiB), locates one `def`/`class`
declaration, and returns a complete-line window bounded by the trusted runtime
`window_before_lines`/`window_after_lines` values (20/20 by default) and the
retrieval byte ceiling. The window carries `line_start`, `line_end`, a content
hash over exactly those bytes, and a line-anchored source URL. Missing, ambiguous,
uninspectable, or scan-truncated symbols are explicit `UNRESOLVED` reasons; they
never become a whole-file prefix. An unanchored retrieval request that exceeds
the ceiling also returns `retrieval_window_required` rather than content from
line 1. A HEAD symbol window remains repository evidence, not policy.

### Deterministic retrieval plans

Before provider dispatch, each specialist task with a changed-unit scope gets a
`retrieval-plan.v1` object built only from already-captured snapshot evidence.
The plan derives added/removed `def`/`class` names from the captured diff in
first-seen order. Added symbols resolve only against captured HEAD source and
removed symbols only against captured BASE source, using `changed_lines` for
HEAD and `old_line_ranges` for BASE. For renamed units, BASE rows and
BASE-scoped snapshot gaps are matched against `old_path`; HEAD rows continue to
use `path`. Each resolved symbol gets a bounded definition window; captured
changed lines also resolve their enclosing definition on the matching side.
Windows carry path, revision, Git object identity, side, line interval, roles,
symbols, and a content hash over exactly the emitted bytes. Plans never re-read
Git or follow provider-supplied targets.

Windows with identical `(path, revision, line_start, line_end, content_hash)`
bytes are merged into one anchor; roles and symbols are unioned so one window
can be both a changed definition and an enclosing definition. Anchors are sorted
HEAD-first with changed-definition anchors ahead of enclosing anchors, then by
path, revision, line interval, and hash. Referenced test paths are additional
targets and must pass the trusted retrieval allowlist; changed-unit paths remain
authorized by the task's own captured scope. Plan anchors are repository
evidence; a HEAD anchor is never policy.

After ordering, anchors are bounded by the existing `max_windows_per_unit`,
window byte, and before/after settings. Dropping any HEAD anchor at that cap is
a `REQUIRED` `window_count_limit` gap; dropping only BASE anchors is
`OPTIONAL`. Unresolved changed symbols are reported per symbol, not as one
aggregate gap, and a modified unit with no current-side (HEAD) anchor is a
`REQUIRED` `current_side_window_unavailable` gap, except deletion units and
deletion-only or removed-only hunks (`changed_lines == [[0, 0]]` or a diff with
no added symbols), which have no current-side changed line to anchor; this is a
deliberate policy, not silent coverage. Required snapshot gaps scoped
to the task's units or paths (for example `diff_truncated`,
`context_truncated`, or `changed_source_unavailable`) are imported as
`snapshot_gap_required`. Empty or truncated diff evidence is a `REQUIRED`
`diff_unavailable` or `diff_truncated` gap.

`plan_hash` covers the plan identity and anchor fields only: schema, task,
snapshot and revision identities, obligation ids, and the unit/anchor rows. It
excludes gaps, sufficiency, wall-clock, and capture timestamps, so equal
captured evidence yields an equal hash even when audit-only gap records differ.

The pre-dispatch check records plans and gaps under `retrieval_plans` and
`retrieval_plan_gaps` in the run ledger. A `REQUIRED` gap makes
`retrieval_sufficient` false. This slice records those gaps for audit; it does
not yet suppress dispatch on them, convert them into coverage rows, or feed the
planned windows into provider input. Those integrations remain RC-2 work and
must not be represented as complete coverage.

### Historical v1 preflight

The PR 464 preflight used the same frozen base/head pair and the current full
applicable policy, with the existing 64 KB per-request and 300 KB per-snapshot
experiment limits. The full-policy selection attempt planned 14 specialist
provider calls, totaling 879,012 serialized request-input bytes; the largest
request was 76,847 bytes, and six requests exceeded 64 KB. Snapshot evidence
was 238,343 bytes, below the 300 KB snapshot limit. The request plan therefore
does not fit the current per-call limit. This is a failed preflight under the
current limits, not a quality result or a production budget recommendation.

A narrower context-binding sensitivity run fit the byte totals, but omitted
applicable CONTRIBUTING.md obligations and is rejected. It is not evidence of
a valid savings or a candidate production profile. No shipped profile adopts
v1 from these measurements. A separately reviewed versioned policy-excerpt
design may use exact-section or syntax-aware selectors, but must retain full
source hashes and line anchors, trace every applicable policy clause to a
selected excerpt or explicit unresolved gap, and pass a complete applicability
review before implementation. That proposal remains design-only.

These are local serialization/preflight measurements against retained
repository evidence. They involve no live provider request, target-code
execution, or finding-quality adjudication. They establish neither improved
coverage nor readiness to replace another review system.

## Retrieval content and result envelope limits

Context retrieval keeps three byte measurements separate: the context
reservation bounds admitted UTF-8 evidence content, the provider output cap
(`max_output_bytes_per_task`) remains unchanged and does not size retrieval, and
the dedicated trusted `max_retrieval_result_bytes` limit bounds the complete
serialized retrieval result, including hashes, provenance, and metadata.

Symbol-target retrieval returns only complete-line windows. It never shortens
unanchored content to a line-1 prefix: if a non-symbol read hits its byte
ceiling, retrieval returns `UNRESOLVED` with `retrieval_window_required`. If
the complete result, including metadata, exceeds `max_retrieval_result_bytes`,
it returns `UNRESOLVED` with
`retrieval_metadata_exceeds_ipc_limit` instead of a shortened result. The budget
settlement continues to count admitted content bytes; the serialized envelope
size is recorded separately. Other retrievers are not automatically trimmed,
and an oversized result remains an IPC failure. None of these behaviors
increases the configured content, output, call, or time caps.
