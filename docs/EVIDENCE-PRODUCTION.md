# Production evidence and publishing boundaries

The production evidence path binds local review context, PR identity, source revisions, and check runs before the review core can consume them. It reads immutable Git objects and GitHub metadata through `gh api`; it never checks out, imports, or executes PR-controlled code.

## Trusted review inputs

Profiles are operator-supplied JSON objects with a non-empty `version`. `context_paths` is the allowlist for additional repository context. Optional `repository` (`owner/name`) or `repository_url` sets canonical immutable source links. Repository text cannot extend these rules. Limits accept a JSON object with `schema_version: "1.0"` and finite keys documented by `pr-review review --help`; the version field is removed before core budget validation. Optional `max_snapshot_context_bytes` separates the snapshot evidence-capture ceiling from cumulative provider-input admission in `max_context_bytes`; when omitted, legacy snapshot capture continues to use `max_context_bytes`. This additive optional field does not change the limits envelope version. Provider credentials are referenced by environment variable name and are never included in profiles, review artifacts, or diagnostics.

Profiles may opt into `context_revision_metadata: true` to attach the exact configured context file's Git blob identity at the snapshot HEAD to its `profile_context` evidence. The fields report `UNCHANGED`, `CHANGED`, `MISSING_HEAD`, or `UNKNOWN` relative to the base blob; they identify blob content and do not describe file-mode equality, test execution, or quality. The field must be a JSON boolean. It defaults to false, and absent or false preserves legacy snapshot and request identities. The metadata is serialized with the bounded evidence payload and counts toward existing request-size limits; it reads no extra file contents or paths.

`pr-review review --repo PATH --github-pr OWNER/REPO#NUMBER --profile PROFILE.json` reads current base/head SHAs and PR identity from GitHub. The object database at `PATH` must already contain those revisions. A GitHub Actions event may instead supply `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, and `GITHUB_RUN_ID`; explicit `--base` and `--head` values, when present, must match the event. Historical `--base`/`--head` runs are identified as local immutable snapshots and do not claim current PR freshness.

GitHub API reads use bounded response sizes, timeouts, and argument arrays. Check runs are paginated to a fixed maximum. If the listing is incomplete or unavailable, configured checks remain `UNKNOWN` and review coverage stays incomplete.

## Context-gap retrieval

The core may send one typed proposal at a time to `retrieve_context_gap(repo, snapshot, profile, proposal, limits)`. Retrieval requires exactly one target, a recognized evidence kind and lens, a non-empty rationale, and a target path that matches `profile.context_paths`. It resolves the path at an immutable commit to a Git blob object and streams no more than the remaining configured byte budget. It follows no symlinks, reads no working-tree files, performs no checkout, and never executes repository content.

Base is the default source revision. A trusted profile can opt a specific evidence kind into head-source retrieval with `retrieval_revisions`; this does not widen the path allowlist. Each returned item records snapshot ID, source revision and object ID, captured-byte hash, trust class, and optional source permalink. The response is `RESOLVED`, `PARTIAL`, or `UNRESOLVED`. Retrieval alone never completes a review obligation: the core must schedule and finish the required follow-up scope under the same finite budget.

## External check evidence

The check adapter reads existing GitHub Check Runs through the read-only API. Evidence is eligible to produce `PASS` only when the configured trusted binding contains an exact `github_check_name` and positive `github_app_id`; exactly one run matches; the run has a positive run ID, the same repository, PR, and full head SHA; status is `completed`; conclusion is `success`; and capture/completion timestamps include a timezone. A failure conclusion maps to `FINDINGS`. Missing, duplicate, incomplete, mismatched, unconfigured, or nonterminal runs map to `UNKNOWN`.

For pre-captured data, `--checks-json` accepts schema versions `1.0` and `2.0`, each binding repository, PR number, head SHA, capture timestamp, completeness flag, and check-run provenance. New check documents use v2. Its evidence hash retains run ID, name, status, conclusion, head SHA, app ID, completion time, and capture time while omitting provider-supplied `details_url` and `external_id`; the latter fields are not needed for matching or outcome and may carry sensitive data. Version 1 remains readable with its original hash semantics. The envelope must come from trusted workflow output outside PR-controlled execution. Model output, a profile claim, a workflow file in the PR, or an unverified fixture cannot stand in for GitHub check evidence.

Normal Actions runs retain a bounded `recovery-inputs.json` packet alongside the checkpoint. It binds the original workflow run ID, event repository/PR/base/head, and the exact normalized v2 check document used for snapshot construction. Resume must use the original run ID and packet; packet and check-document hashes are recorded in the v3 recovery manifest. See [PR analysis recovery inputs](pr-analysis-recovery-inputs.md) for the replay and data-retention contract.

The check record proves only the provider-reported run identity, state, and conclusion. It does not establish what tests ran or whether their assertions are sound. The result remains advisory, and merge eligibility is assessed separately.

## Review publication

`publisher.py` supports construction and guarded dispatch for a single pull-request review effect. It has no merge or source-edit operation. Publication is disabled unless a versioned operator configuration explicitly sets `enabled: true`, `effect_policy` is `PUBLISH_REVIEW`, and an authorized caller supplies fresh-head, idempotency lookup, and narrowly scoped review-submit capabilities. Result integrity and head SHA are rechecked before dispatch. The effect hash binds repository, PR number, head SHA, disposition, result hash, and effect type. If a submit response is ambiguous, the publisher looks up that same effect and does not blindly retry.

The normal CLI does not construct an authorized publisher or write capability. This implementation therefore does not publish reviews during local runs, CI, tests, or this delivery.
