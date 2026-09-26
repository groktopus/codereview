# CLI publication preview migration

The `pr-review publish` command is currently a stateless, read-only preview. It validates the sealed result and configured repository/disposition scope, renders the canonical review body, and shows the marker that a future verified publication path would use. It does not read GitHub credentials, query freshness, open a database, write a review, or infer authorization from its environment.

Use a minimal preview policy:

```json
{
  "schema_version": "1.0",
  "allowed_repositories": ["OWNER/REPOSITORY"],
  "allowed_dispositions": ["COMMENT", "REQUEST_CHANGES"],
  "allowed_profile_versions": ["trusted-profile-v2"],
  "max_review_body_bytes": 60000
}
```

Then render a preview:

```sh
pr-review publish \
  --result artifacts/reviews/RUN_ID.json \
  --publisher-config preview-policy.json \
  --json
```

`--dry-run` remains accepted for command compatibility but is unnecessary. `--effect-store` has been removed. Legacy policy fields such as `effect_store_path`, `serialization_mode`, and `allowed_actors` are rejected rather than treated as active protection.

An `INCOMPLETE` result can still be previewed as a GitHub `COMMENT` event when `COMMENT` is allowlisted. The preview and any future receipt preserve the semantic result disposition as `INCOMPLETE`; only the GitHub wire event is mapped to `COMMENT`.

Passing `--authorize-publish` returns `stateless publication capability is unavailable`. There is no local live-publish fallback. The stateless publisher primitive requires typed, independently verified GitHub run/artifact admission, complete bounded receipt/review history, and an acknowledged pre-submission receipt. Read-only GitHub Actions adapters, GitHub publication adapter primitives, and a protected canary workflow are implemented. Verified writer credentials and live write-path wiring are unavailable, and the workflow's publication job remains hard-disabled. `GITHUB_ACTIONS`, `GITHUB_ACTOR`, event JSON, and a command-line authorization flag cannot provide the missing proofs.

This is a migration and preview contract, not a publication-ready release. A future live deployment needs completed protected-workflow write-path wiring, verified writer identity, artifact and run provenance, bounded complete history enumeration, explicit unknown-state recovery, narrowly scoped permissions, and a read-only API compatibility canary before any owner-authorized write can be considered.
