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
branch. The protected source workflow revision (`source_workflow_sha`) is
bound to a separate read of the repository's current default-branch tip; it is
not the reviewed PR's base or head SHA. The producer requires its trusted
`GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` contexts to agree with the independently
read branch tip before emitting the publication bundle. The canary independently
re-reads that branch through the API before requesting the App key and requires
the exact branch name and full commit SHA to match. This selected contract
fail-closes if the default branch advances after analysis; rerun analysis for
the new source revision. Keep PR `base_sha` and `head_sha` as distinct snapshot
identities and recheck them against the current PR API record. Do not infer
branch-rule protection from a branch response; no such branch-protection claim
is made here.

The source run's reported head branch may be the PR branch; caller ref,
protected source revision, source run head, and PR base/head are separate
identities. GitHub may omit the source run's
`pull_requests` association for this event. If present, the canary requires
exactly one matching PR/base/head tuple; it always checks the current PR API
record. The publication adapter must still bind the exact PR tuple through
trusted source artifact/API admission before requesting any write capability.
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

One invocation has a finite deadline, a maximum of ten requests (four
Actions/PR/default-branch GETs and six App/install/token identity requests),
bounded response bodies, and no retries. The added default-branch GET uses the
explicit Actions read token before any App-key access; App-token permissions
remain restricted to the one repository's `actions:read` and
`pull_requests:read`. Bad local expectations, platform-run
mismatches, disabled state, or unavailable identity stop before App-key access
where possible. A live App installation, protected secret configuration, and
an explicitly authorized later publication canary remain operator actions;
tests use fake HTTP responses and do not establish those live facts. The source
context probe remains an observations-only, disabled-by-default tool; its
synthetic unit fixtures do not live-qualify the relationship between runner
context SHAs and the default-branch API tip. That qualification remains
`UNKNOWN` until a real secretless protected-base observation is reviewed.

Before configuring a writer key, bind it only to a dedicated target-local
publisher GitHub Actions Environment with deployment branches restricted to
the protected default branch. Do not expose it to the source analysis job.
This is a required deployment control, not evidence that an environment or
branch restriction currently exists. The actual target workflow and publisher
template still require review before any key is installed or publication is
enabled; the checked-in publisher remains hard-disabled.
