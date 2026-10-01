# Protected review publication runtime

The protected runtime composes the existing GitHub Actions artifact intake, App identity checks, publication admission, receipt uploader, and single-review publisher. It accepts a review result artifact from a completed `pull_request_target` run on the protected default branch. The artifact may identify the PR, but it cannot choose policy, App identity, repository, workflow pins, disposition scope, or whether publishing is enabled.

The current `.github/workflows/pr-publish.yml` remains disabled and does not invoke this module. The runtime expects `.github/pr-review-publisher-policy.json`, but that policy file is not present in this checkout, so a direct invocation currently fails closed. Adding and pinning that file, changing it to `enabled: true`, or adding a workflow caller are separate owner-reviewed activation decisions. This runtime has no live-provider test or deployment qualification.

When enabled by a protected configuration, the runtime verifies its clean checked-out source revision and policy file, then uses the explicit Actions read token to bind the source run and fetch one bounded, digest-checked result artifact. It extracts only the PR number and base/head SHAs as candidate target data. The App identity verifier checks GitHub-reported App, installation, repository, bot, source-run, and PR facts before requesting the private key; its read-only identity check is neither publication authorization nor deployment qualification. Full artifact intake and adapter admission run before any write-scoped App token. The existing publisher requires an uploaded receipt to be re-fetched and verified, checks the PR head again, and makes at most one review POST. Missing, stale, ambiguous, or unacknowledged evidence stops the operation.

The target is restricted to same-repository PRs whose current base ref is the configured default branch. Before reading the artifact or App key, the runtime fetches the configured default branch from GitHub's repository API and binds the manifest's caller workflow SHA to that reported tip. It keeps the reviewed PR base/head SHAs separate: an older open PR may have a base commit behind the current default-branch tip. The App identity canary independently re-fetches the branch tip before reading the key. Before receipt persistence and again after receipt acknowledgement, the runtime rechecks that the tip is unchanged and that the PR still has the candidate base/head. These are fail-closed API observations; the source-context probe records `GITHUB_SHA`, `GITHUB_WORKFLOW_SHA`, the default-branch API tip, run API head, and PR base/head separately. Do not assume unobserved context equality or treat the probe as identity proof. The producer must independently bind its caller workflow SHA to the protected source revision. Manual dispatch and cross-repository publication remain outside this runtime.

The policy file is a versioned contract, not an input to the PR analysis. It pins the repository and numeric ID, source and publisher workflow IDs/paths/refs, called harness commit, profile and provider-configuration identities, allowed disposition/event scope, App identity, artifact redirect hosts, and upper bounds for run/page/review counts and wall-clock time. Before this module can run, an owner must add the exact schema-v1 file at `.github/pr-review-publisher-policy.json` on the protected default-branch revision, review every identity and limit against authoritative repository configuration, and keep `enabled` false. The runtime also requires the workflow checkout to be clean and its HEAD to equal `GITHUB_SHA`; it rejects an uncommitted or mismatched policy file.

The writer adapter uses repository-wide concurrency (`pr-review-publish-<repository-id>`) so two PRs in the same repository cannot overlap receipt and review effects. The workflow template queues runs and does not cancel an in-progress publisher. Its named `code-review-publication` environment must be configured in the target repository with an approved protected-default-branch deployment restriction and the App key secret before activation. The environment name in YAML does not prove those settings exist; their configuration remains owner evidence. Keep the App key in that environment rather than as a repository-wide secret.

The writer adapter uses repository-wide concurrency (`pr-review-publish-<repository-id>`) so two PRs in the same repository cannot overlap receipt and review effects. The workflow template queues runs and does not cancel an in-progress publisher. Its named `code-review-publication` environment must be configured in the target repository with an approved protected-default-branch deployment restriction and the App key secret before activation. The environment name in YAML does not prove those settings exist; their configuration remains owner evidence. Keep the App key in that environment rather than as a repository-wide secret.

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
