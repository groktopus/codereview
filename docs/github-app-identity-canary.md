# GitHub App identity canary contract

`pr_review_harness.github_app_canary.verify_github_app_identity_canary` is a
protected-runtime identity check for a future publication entrypoint. It is
disabled by default (`enabled=False`) and has no review or comment API path.
Setting `enabled=True` only enables the read-only identity canary; it does not
authorize publication or make a review write.

The protected entrypoint supplies a `ProtectedCanaryRun` built from GitHub
Actions platform context and fixed trusted workflow policy. It must not build
this object from PR files, command-line values, repository artifacts, or a
previously uploaded `CanaryReceipt`. The canary validates the local shape and
protected publisher and caller-workflow expectations, then verifies the
current publisher run, exact source caller run/attempt, repository, and open
PR head/base with bounded GitHub API GETs. The source path/ref identify the
actual caller workflow in the Actions run API; the reusable harness workflow
and immutable harness SHA are checked separately by the publication
admission/runtime adapter before any write capability is requested.
The writer source event is `pull_request_target` from the protected default
branch. The source workflow revision (`source_workflow_sha`) is the trusted
workflow/source commit and remains distinct from the reviewed pull-request
revision (`pull_request_head_sha`). The source run's reported head branch may
be the PR branch; caller ref and source revision are bound separately by the
protected runtime and API checks. GitHub may omit the source run's
`pull_requests` association for this event. If present, the canary requires
exactly one matching PR/base/head tuple; it always checks the current PR API
record. The publication adapter must still bind the exact PR tuple through
trusted source artifact/API admission before requesting any write capability.
For this selected writer path, the protected caller workflow SHA is required
to equal the current default-base SHA, and the PR must still target the
repository's current default branch. A moved base, nondefault target branch,
or disagreement among the trusted workflow context and API PR base fails
closed. This equality is a deliberately strict selected-source contract; it
has not been live-qualified for every reusable-workflow caller.
The Actions run's `head_sha` is retained separately as `source_run_head_sha`
and checked against the run API record; for the selected target event the
producer also requires it to match the current PR head.
The API run's workflow `path` is checked as the bare workflow path; branch and
SHA are verified in their separate API fields rather than inferred from a
path suffix. This writer path is same-repository only.
Only after these checks pass does it call the protected App-key supplier.

The App phase verifies the GitHub App, installation, target-repository
installation, mints one installation token restricted to that repository with
`actions:read` and `pull_requests:read`, checks the returned permission and
repository scope, and confirms the App bot user through GitHub. Its single API
POST is token issuance. It never creates or edits a PR review/comment. The
Actions token is an explicit read-only input for platform-run and PR GETs; it
is not a fallback writer credential.

On success the function returns an in-memory `VerifiedPublisherIdentity` and a
sanitized `CanaryReceipt`. The identity may be passed directly to the trusted
credential provider in the same protected process. Do not reconstruct it from
receipt JSON or treat the receipt as a signature, authorization, or proof of
publication. The receipt includes a fresh per-invocation nonce, exact run and
source bindings, App/install/repository/actor and bot identity, read-only
permission scope, and an evidence hash; it excludes tokens, private keys, and
raw API responses.

One invocation has a finite deadline, a maximum of nine requests, bounded
response bodies, and no retries. Bad local expectations, platform-run
mismatches, disabled state, or unavailable identity stop before App-key access
where possible. A live App installation, protected secret configuration, and
an explicitly authorized later publication canary remain operator actions;
tests use fake HTTP responses and do not establish those live facts.
