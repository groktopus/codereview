# Opt-in PR analysis publication bundle

The reusable analysis workflow can emit a second artifact named `pr-review-result` for the existing publication intake contract. It is disabled by default. Callers pinning this workflow revision must grant the reusable workflow `actions: read` even when `emit_publication_bundle` is false, because that permission is part of the workflow's declared permissions. A target-local caller must also explicitly set `emit_publication_bundle: true` to produce the bundle; cross-repository calls skip the producer before the GitHub API read.

The artifact upload contains exactly `review-result.json` and `provenance.json`. Its artifact manifest schema is version 1.0; the sealed engine result contract is version 0.1. The producer and receiver check that the manifest contract version matches the result’s declared version. Legacy 1.0 result fixtures remain explicit and are not accepted as current 0.1 results. The result is copied byte-for-byte from the sealed `artifacts/review/<run-id>.json` checkpoint. The producer does not add wrapper fields or recalculate its result hash. The original recovery artifact and manifest continue to be produced and uploaded separately.

The producer reads the current run attempt through the bounded GitHub API transport and cross-checks its repository, numeric repository/workflow IDs, attempt, workflow path/ref, run head SHA, and attached PR base/head against the workflow inputs and context. The caller workflow file SHA comes from the separate GitHub workflow context field, rather than being inferred from the event run head SHA. The manifest's workflow ref is the Git ref portion (for example, `refs/heads/main`). It binds the trusted profile version and digest and uses the canonical `provider-identity-sha256:<digest>` identity string, which the protected publisher requires to match its policy exactly. The digest is SHA-256 over UTF-8 JSON serialized with sorted keys, compact separators, and `ensure_ascii=False`. The hashed object is the effective provider identity independently derived from the protected primary and decision provider config files using the existing provider constructors and engine identity helper, then compared to the sealed result. This includes both primary and decision provider identity fields; credential values are never included or hashed.

`provenance.json` contains producer claims in the existing intake schema. It is not a GitHub server attestation or proof that the run was authorized. The publication receiver remains responsible for independently fetching and validating run, repository, PR, workflow, harness, and profile identity before admission.

A target-local caller uses these read-only permissions on its reusable-workflow job, whether or not it opts into the additional bundle:

```yaml
permissions:
  actions: read
  contents: read
  checks: read
  pull-requests: read
```

This permission is read-only and is separate from the protected publisher's write permission. The checked-in central pilot caller remains cross-repository and does not opt in.
