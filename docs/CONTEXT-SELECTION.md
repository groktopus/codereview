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
