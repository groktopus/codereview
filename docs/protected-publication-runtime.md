# Protected review publication runtime

The protected runtime composes the existing GitHub Actions artifact intake, App identity checks, publication admission, receipt uploader, and single-review publisher. It accepts a review result artifact from a completed `pull_request_target` run on the protected default branch. The artifact may identify the PR, but it cannot choose policy, App identity, repository, workflow pins, disposition scope, or whether publishing is enabled.

The current `.github/workflows/pr-publish.yml` remains disabled and does not invoke this module. The runtime expects `.github/pr-review-publisher-policy.json`, but that policy file is not present in this checkout, so a direct invocation currently fails closed. Adding and pinning that file, changing it to `enabled: true`, or adding a workflow caller are separate owner-reviewed activation decisions. This runtime has no live-provider test or deployment qualification.

When enabled by a protected configuration, the runtime verifies its clean checked-out source revision and policy file, then uses the explicit Actions read token to bind the source run and fetch one bounded, digest-checked result artifact. It extracts only the PR number and base/head SHAs as candidate target data. The App identity verifier checks GitHub-reported App, installation, repository, bot, source-run, and PR facts before requesting the private key; its read-only identity check is neither publication authorization nor deployment qualification. Full artifact intake and adapter admission run before any write-scoped App token. The existing publisher requires an uploaded receipt to be re-fetched and verified, checks the PR head again, and makes at most one review POST. Missing, stale, ambiguous, or unacknowledged evidence stops the operation.

The target is restricted to same-repository PRs whose current base is the configured default branch. The runtime currently requires the source manifest's caller workflow SHA to equal the current PR base SHA; that is an explicit fail-closed identity hypothesis being checked against the source-context probe, not a general GitHub guarantee. The source Actions run head is checked separately against the PR head; neither value is inferred from the other. Manual dispatch and cross-repository publication remain outside this runtime.

The policy file is a versioned contract, not an input to the PR analysis. It pins the repository and numeric ID, source and publisher workflow IDs/paths/refs, called harness commit, profile and provider-configuration identities, allowed disposition/event scope, App identity, artifact redirect hosts, and upper bounds for run/page/review counts and wall-clock time. Before this module can run, an owner must add the exact schema-v1 file at `.github/pr-review-publisher-policy.json` on the protected default-branch revision, review every identity and limit against authoritative repository configuration, and keep `enabled` false. The runtime also requires the workflow checkout to be clean and its HEAD to equal `GITHUB_SHA`; it rejects an uncommitted or mismatched policy file.

The installed module entry point is:

```sh
python -m pip install '.[github-app]'
python -m pr_review_harness.protected_publication_runtime
```

Run it only inside a protected GitHub Actions runner that supplies these trusted platform inputs: `GITHUB_WORKSPACE`, `GITHUB_SHA`, `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_WORKFLOW_REF`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, and an absolute `GITHUB_EVENT_PATH` containing the `workflow_run` event. It also needs a read-only `GITHUB_TOKEN`, plus `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_RESULTS_URL`, and `ACTIONS_RUNTIME_URL` for the official artifact uploader. `PR_REVIEW_GITHUB_APP_PRIVATE_KEY` must be available as a protected secret; runtime code requests it lazily only after source and current-PR checks. The GitHub App must be installed on the single target repository with the protected policy's App, installation, bot, and permission identities. Never populate these fields from PR artifacts or command-line arguments.

For local, provider-free verification, run the focused fake-API composition tests with:

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src python3 -m pytest -q \
  tests/test_protected_publication_runtime.py \
  tests/test_actions_publication.py \
  tests/test_github_app_credentials.py \
  tests/test_github_app_canary.py
```

These tests verify control flow and API binding against fakes. They do not establish live GitHub API behavior, provider quality, or permission to enable the workflow.
