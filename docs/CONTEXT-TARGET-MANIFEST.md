# Context target manifest v1

`context-target-manifest.v1` is an opt-in input contract for a trusted review
profile. It lets a specialist request bounded context from a finite set of
captured changed files when the current output contract has no safe symbol
lookup. Profiles without `context_target_manifest` keep the existing v4 prompt,
schema, and serialized request unchanged.

The profile setting is closed and finite:

```json
{
  "context_target_manifest": {
    "version": "context-target-manifest.v1",
    "max_entries": 256,
    "max_bytes": 16384
  }
}
```

The engine builds each task's manifest from its immutable snapshot inventory,
the profile's trusted retrieval patterns, and captured Git object metadata.
Path targets can refer to any matching captured inventory file. Unit targets
are limited to units already in that task. Trusted policy paths are excluded;
their existing BASE-only handling remains authoritative. Each choice binds an
opaque server-side ID to an exact kind/value pair and captured BASE or HEAD blob
identity. The provider schema exposes only available `{kind, value}` pairs,
never symbols or free-form paths. The engine resolves those pairs back to the
opaque mapping and rechecks evidence kind, revision, path, and blob before
accepting retrieved content.

An invented, cross-kind, or unavailable target becomes an explicit invalid
context-gap record. It does not consume retrieval budget or erase other valid
findings from the same response. Missing or partial retrieved evidence remains
visible in coverage; the manifest itself is not evidence that an obligation was
reviewed. Existing request, retrieval, and follow-up limits are unchanged.

The `slopsearx-v17-context-target-manifest-candidate.json` profile is a
provider-free candidate. It does not alter the v16 profile, enable a workflow,
or establish review quality. The caller must explicitly select the trusted
profile before this input contract is used.
