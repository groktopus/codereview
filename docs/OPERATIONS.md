# Operations guide

This harness creates evidence-bearing review reports. A completed command or green workflow is not the same as a clean review; inspect the disposition, coverage, freshness, unresolved context, external-check states, and task outcomes together. The pilot is experimental and does not justify replacing Droid yet.

## Local read-only review

Install the built wheel in an isolated environment, clone the target as a bare repository, and select a trusted profile maintained outside the reviewed commit:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install dist/pr_review_harness-*.whl
git clone --bare https://github.com/OWNER/REPOSITORY.git /tmp/target.git
pr-review review --repo /tmp/target.git --base BASE_SHA --head HEAD_SHA \
  --profile profiles/generic.json --provider-config examples/provider.nous.json \
  --output artifacts/reviews --json
```

`--dry-run` previews resolved paths and selected revisions without loading provider credentials or making network calls. Normal live review sends bounded source excerpts to the provider named in the trusted provider configuration. Confirm the repository's data handling rules before doing so. Do not put credentials in configuration files, command arguments, artifacts, or logs.

`review --prepare-only` is a separate provider-free mode for an explicit historical base/head pair. It validates and snapshots the source, plans scopes, and measures exact serialized primary specialist requests using the configured adapter, but it does not dispatch requests, read credential values, write a result artifact, or produce a disposition. Its report keeps skipped scopes and required-context gaps visible. Primary call and serialized-byte totals are exact for the prepared plan; semantic-adjudication calls depend on emitted candidates, and summary, follow-up, and claim-assessment work is dynamic, so the report does not claim total call-cap fit. Unlike `--dry-run`, prepare-only inspects the selected immutable source and profile and requires a provider configuration for exact serialization.

Normal `review` and `recent` commands remain read-only; `--effect-policy PUBLISH_REVIEW` is rejected on those paths. The separate `publish` command is also read-only: it validates and previews a canonical sealed PR review but does not submit it. Live publication remains unavailable. `INCOMPLETE`, `PARTIAL`, `UNKNOWN`, or `STALE` is not a passing review.

### Historical check evidence

For a deliberately historical run, `review --historical-checks-json PATH` accepts a captured check-run document only with explicit full `--base` and `--head` revisions and a trusted profile containing the canonical `repository`. The document must bind the same repository, PR number, and head; if it includes a base SHA, that must match the explicit base too. This mode is mutually exclusive with `--checks-json`, `--github-pr`, and GitHub event inputs. It reads the supplied artifact locally and does not query GitHub for current checks or PR freshness. Results are labeled `HISTORICAL_SNAPSHOT`; the captured checks describe the capture, not current status.

Example using the retained PR #464 fixture:

```sh
PYTHONPATH=src python3 -m pr_review_harness review \
  --repo /path/to/slopsearx \
  --base 20a743f0434a1843aa00068483f608f1e213b2af \
  --head bffc26f9e4bf95aca0c252e88a2396d03ece854c \
  --profile profiles/slopsearx.json \
  --historical-checks-json tests/fixtures/pr464-check-evidence.json \
  --output artifacts/pr464-historical --json
```

The fixture is bound to `magnus919/SlopSearX`, PR 464, and the stated head; it has no captured base SHA, so the explicitly supplied immutable pair identifies the base. In the provider-free smoke run, two matching check obligations had captured evidence while sixteen review lenses remained `NOT_STARTED` and the overall disposition stayed `INCOMPLETE`. This is evidence that the check fixture flows through the interface, not evidence of review completeness or quality. A configured provider can still perform bounded remote inference during `review`; omitting one leaves those stages incomplete. `--dry-run` only previews argument paths and revisions; it does not load or validate the historical check artifact.

## PR-review publication preview

`publish` validates the sealed result and renders a canonical review preview using a repository/disposition policy. It does not call `gh`, query freshness, access SQLite, or perform a remote write. `--dry-run` is accepted for compatibility but is unnecessary:

```sh
pr-review publish --result artifacts/reviews/RUN_ID.json \
  --publisher-config preview-policy.json --json
```

The preview policy needs repository and wire-event allowlists. Profile versions and a maximum body size are optional. A terminal `INCOMPLETE` result previews as a `COMMENT` event while preserving `INCOMPLETE` as its semantic disposition:

```json
{
  "schema_version": "1.0",
  "allowed_repositories": ["OWNER/REPOSITORY"],
  "allowed_dispositions": ["COMMENT", "REQUEST_CHANGES"],
  "allowed_profile_versions": ["trusted-profile-v2"],
  "max_review_body_bytes": 60000
}
```

Review the preview's target, semantic disposition, wire event, full body, and evidence links. The old `--effect-store` option is removed; legacy SQLite configuration fields are rejected rather than presented as effective safeguards. `--authorize-publish` returns `stateless publication capability is unavailable` and does not read GitHub credentials, call GitHub, or create a database. No local live-publish fallback exists. See the [CLI publication preview migration](CLI-PUBLISH-PREVIEW-MIGRATION.md).

The read-only GitHub Actions adapter, GitHub publication adapter primitives, and protected publisher canary workflow are implemented. The canary verifies run and repository identity without creating a review. Verified writer credentials and live write-path wiring are unavailable, and the publication job remains hard-disabled. No production publication or remote write verification is claimed.

The publisher canary is a read-only trust preflight. Its `workflow_run` filter and the canary's `PR_REVIEW_ANALYSIS_WORKFLOW_NAME` must match the trusted caller's workflow name (`PR Review Analysis`); the runtime rejects a differently named event before making API reads. The example caller below uses that name, but the repository's current `.github/workflows/slopsearx-pilot.yml` caller is named `SlopSearX read-only review pilot`, so it does not match the publisher filter and cannot trigger this canary. The reusable analysis workflow's own name is not a substitute for the caller run name. Renaming the pilot would not make it compatible: it is a `workflow_dispatch` run in the harness repository that targets a PR in `magnus919/SlopSearX`, while the canary requires an upstream `pull_request` workflow run with exactly one PR binding in the publisher repository. Thus local canary code and tests do not establish a wired hosted canary path for the current pilot. Do not treat the example name as hosted evidence. The canary itself checks the publisher run ID/attempt, workflow ID/path, protected publisher SHA and repository ID; checks the upstream run ID/attempt, workflow ID/path, repository ID, completion/conclusion and unique PR/base/head binding; and re-reads the open PR to reject a stale head or base. Each read is GET-only, bounded to five calls, 256 KiB per response and a 30-second deadline. There is no retry. The canary uploads only its own bounded receipt through the official Actions artifact client; the bridge binds run ID/attempt and checks the exact local receipt size and SHA-256 before upload. That receipt is not an intake or signature verification of the upstream review artifact, and `READ_ONLY_CONTEXT_VERIFIED` does not authorize or prove publication. The disabled publisher still needs a separately reviewed, authenticated upstream artifact intake and effect/idempotency admission before any write path is considered.

## GitHub Actions analysis

`.github/workflows/pr-analysis.yml` is a reusable workflow. It does not trigger on its own. The target repository supplies a trusted caller workflow, normally on `pull_request_target`, and calls this reusable workflow at a reviewed full commit SHA. The caller passes the trusted harness repository and SHA separately from the target repository and PR revisions. A typical caller job is:

```yaml
name: PR Review Analysis
on:
  pull_request_target:
    types: [opened, reopened, synchronize, ready_for_review]
permissions:
  actions: read
  contents: read
  checks: read
  pull-requests: read
jobs:
  review:
    uses: TRUSTED_HARNESS_REPOSITORY/.github/workflows/pr-analysis.yml@FULL_40_CHARACTER_SHA
    with:
      harness_repository: TRUSTED_HARNESS_REPOSITORY
      harness_sha: FULL_40_CHARACTER_SHA
      target_repository: ${{ github.repository }}
      pull_request_number: ${{ github.event.number }}
      base_ref: ${{ github.event.pull_request.base.ref }}
      base_sha: ${{ github.event.pull_request.base.sha }}
      head_sha: ${{ github.event.pull_request.head.sha }}
    secrets:
      LLM_BASE_URL: ${{ secrets.LLM_BASE_URL }}
      LLM_MODEL: ${{ secrets.LLM_MODEL }}
      LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
      JEV_BASE_URL: ${{ secrets.JEV_BASE_URL }}
      JEV_MODEL: ${{ secrets.JEV_MODEL }}
      JEV_API_KEY: ${{ secrets.JEV_API_KEY }}
      HARNESS_READ_TOKEN: ${{ secrets.HARNESS_READ_TOKEN }}
```

Before enabling the caller:

1. Review the workflow and profile from the protected base branch.
2. Verify the reusable workflow `uses:` revision and `harness_sha` are the same reviewed full commit SHA. The workflow checks their syntax before checkout and checks the checked-out `HEAD` before installing or importing it.
3. Configure the six required provider secrets (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `JEV_BASE_URL`, `JEV_MODEL`, and `JEV_API_KEY`) in the caller repository's Actions settings. The workflow materializes private, short-lived provider configuration from those values; it does not fetch a model catalog. See [Deployment configuration](DEPLOYMENT-CONFIGURATION.md) for endpoint format, secret handling, and the selected deployment defaults. The separate [manual historical model comparison](#manual-historical-model-comparison) retains the fixed free-model/catalog procedure.
4. Keep caller and reusable-workflow permissions at read-only. This workflow revision requires `actions: read`, `contents: read`, `checks: read`, and `pull-requests: read`; the caller must grant `actions: read` even when publication-bundle output is disabled. It does not receive write permission.

The workflow verifies the current PR through the caller's read-only GitHub token, fetches the base ref and `refs/pull/<number>/head` into a bare object store, checks both object IDs against the supplied event identities, and passes a synthetic minimal event to the CLI. It never checks out the PR head or runs its hooks, tests, builds, scripts, or actions. A moved ref or failed API read stops or leaves evidence incomplete. The current bare-fetch adapter supports public target repositories; private target acquisition needs a separately reviewed read-only credential adapter.

The workflow uploads reports as an artifact retained for seven days. Reports can contain source excerpts and model output. Restrict artifact access according to repository policy and download or retain results only when authorized. A failed run may still upload partial diagnostics; check the workflow status and result disposition.

The reusable workflow is inactive until a trusted target-repository caller explicitly invokes it. Invocation authorizes read-only model requests and source transmission to the configured provider, but does not authorize posting results. Publication remains disabled in the CLI and no publishing token is granted.

## Manual historical model comparison

The manual `review-commits.yml` workflow accepts one explicit test-model choice (`solar` or `stepfun`) and only the frozen six-pair `historical-pilot-v1` sample. It fetches the public SlopSearX repository into a bare clone, captures `/models` with a 20 MB bound, checks that the selected model is still listed at zero configured price, and runs at most six read-only calls with fixed time limits. It fails closed if the model is no longer free, credentials are missing, a frozen revision is absent, or the catalog is stale.

The resulting manifest is compatibility and harness-operation evidence only. It has no quality labels, does not establish zero billed cost, and cannot be pooled into a model-quality claim. Each selected model is retained separately. Provider usage is not assumed to be billable usage.

## Troubleshooting and recovery

CLI JSON error envelopes and stable diagnostic codes are versioned in the [CLI diagnostic contract](design/CONTRACTS.md#cli-diagnostic-contract-revision-2).

| Symptom | Meaning and action |
|---|---|
| `preflight_rejected` / exit 2 | A legacy CLI's generic preflight rejection. Correct the CLI/profile/limit inputs; the output does not include configuration contents. |
| `invalid_review_request` / exit 2 | The current CLI rejected a malformed review request before dispatch. Correct the request fields and retry with a new run ID if needed. |
| `run_id_already_exists` / exit 2 | The run ID is already bound to saved state. Choose a new run ID, or resume only the exact matching run. |
| `resume_state_invalid` / exit 2 | Saved state or its resume identity failed validation. Preserve the checkpoint and inspect the stable diagnostic; do not edit the checkpoint to force a resume. |
| `snapshot_preflight_failed` | Verify that the bare repository contains both exact full commit IDs and valid Git objects. Do not check out the target as a workaround. |
| `review_runtime_failed` / exit 1 | Inspect the persisted result/checkpoint and task-level safe diagnostics. A failed task stays incomplete; resume only against the same run identity and immutable input. |
| `STALE` | The PR head changed while review ran. Start a new run for the current event. Never reuse the old report as current evidence. |
| required check `UNKNOWN` | Check identity, GitHub App ID, run completion, repository, SHA, and captured timestamps. Missing/untrusted evidence cannot satisfy the binding. |
| production provider configuration or API unavailable | Verify the six caller secrets and configured endpoints without printing secret values. Preserve the failed/incomplete evidence. For the historical provider trial, first observe the same run ID until it is terminal; a failed status lookup or poll is not evidence that the run ended. Do not redispatch because a poll failed. Once terminal, any new manual dispatch is a separately recorded attempt; the prior attempt's call delivery may remain `UNKNOWN`, not zero. The runner has zero automatic retries. For the separate historical free-model comparison, a missing key or stale/unavailable catalog means no model call; do not switch silently to a paid model. |
| canceled Actions run | For reusable PR-analysis runs canceled by superseding events, use the artifact from the newest current-head run; partial output is not a completed review. For a manually dispatched historical trial, continue observing that same run ID until terminal rather than inferring cancellation from an observation failure. A deliberate later dispatch is a new attempt, and prior call delivery may be `UNKNOWN`. |

If the analysis workflow must be disabled, turn off `REVIEW_ANALYSIS_ENABLED`, preserve existing artifacts, use the prior review process, and keep publication disabled. A bounded synthetic hosted recovery rehearsal has now exercised the orderly cancellation and retained-artifact path in [Run A 36313083348](https://github.com/groktopus/codereview/actions/runs/36313083348), then resumed in [Run B 36313501818](https://github.com/groktopus/codereview/actions/runs/36313501818) with zero new fake-provider requests and an `INCOMPLETE` result preserving the uncertain operation. See [the recovery drill evidence](HOSTED-RECOVERY-DRILL-EVIDENCE-2026-09-27.md); the two failed earlier attempts remain recorded there and in [the rehearsal protocol](HOSTED-RECOVERY-REHEARSAL.md). This verifies only that synthetic orderly-cancellation scenario. It does not cover hard termination, service failure, live-provider recovery, review quality, publication, rollback rehearsal, or cutover.
