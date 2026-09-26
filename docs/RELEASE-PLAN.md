# Release and staged adoption plan

Status: candidate implementation; no release or cutover approved. Scope is the reusable CLI and GitHub Actions review harness, not automated merging or code repair. Root owns the release evidence and final recommendation; the project owner authorizes deployment and cutover.

## Candidate artifact

Build a wheel and source distribution from the reviewed commit in a clean checkout. Record source revision, Python/build-tool versions, file digests and dependency inventory. Install the wheel into a fresh environment outside the source directory; verify `pr-review --help`, dry-run, provider-free review, safe preflight errors and durable reports there. Editable-install tests do not establish wheel delivery.

The same verified artifact must be used for runtime integration and deployment. CI should cover supported Python versions, lint, deterministic tests, failure/cancellation/recovery probes, package construction and installed-artifact smoke tests. Provider-backed evaluation is a separate explicit job with versioned model configuration and bounded usage, not an implicit call from ordinary tests.

## GitHub integration gates

### Current deployment evidence (updated 2026-09-26)

The earlier read-only `gh repo view magnus919/pr-review-harness` attempt reported that the harness repository could not be resolved. That was a dated observation before the project remote was created; it is not current. The public [`groktopus/codereview`](https://github.com/groktopus/codereview) repository now exists. Its default branch contains bootstrap candidate revision `d1b58c5`, and initial PR #1 has been opened. This establishes remote and PR bootstrap only, not a release or cutover.

Hosted run [`36275645532`](https://github.com/groktopus/codereview/actions/runs/36275645532) terminated with failure. All four Python test-and-lint matrix jobs failed during pytest: Python 3.11 had 19 failures, Python 3.12 had 20, and Python 3.13 and 3.14 each had 21. Nineteen failures in every version came from tests trying to load fixture files absent from the installed wheel. Python 3.12, 3.13, and 3.14 also failed the no-isolation packaging test because `setuptools.build_meta` was unavailable; Python 3.13 and 3.14 additionally failed a descendant-process cancellation test. The separate wheel build and both installed-wheel smoke jobs passed.

Follow-up hosted PR run [`36276954116`](https://github.com/groktopus/codereview/actions/runs/36276954116), for candidate head `009207a71d26ab0faacff5663905d5f2e966ea9d`, completed all seven CI jobs successfully. Each Python 3.11, 3.12, 3.13, and 3.14 test-and-lint job reported 496 passed tests and 13 passed subtests; wheel/source-distribution build and installed-wheel smoke on Python 3.11 and 3.14 also passed. The installed CLI emitted a provider-free `INCOMPLETE` result, as expected; this validates packaging and that smoke path, not review quality. The fixture packaging, missing setuptools backend, and descendant cancellation failures from the earlier run are fixed on this tested candidate. A later output-directory creation change has not been tested in a hosted run and is outside this proof.

NousPortal `openai/gpt-6-luna` is the selected production inference model. All six provider variable/secret names are present in repository metadata; values were not read. The production value of `JEV_MODEL` remains unknown and unverified. `jev-1.13.0` is the pinned model from earlier experiments, not a confirmed production Jev selection. The user has authorized a specific read-only analysis payload for the SlopSearX diff/context with bounded Jev risk classification. Current reusable-workflow source accepts the six names as required workflow-call secrets and materializes private provider config files. The passing CI run validates its tests but did not invoke the hosted workflow-call path or make provider calls. No successful hosted production review is established.

The normal CLI remains stateless. GitHub-backed publication receipt and history adapters are implemented in `actions_publication.py` and `publication_receipts.py`, but fake-transport tests do not establish hosted behavior. `.github/workflows/pr-publish.yml` remains hard-disabled, with no write-capable review credential bound. The six read-only inference/decision configuration names do not provide publication authority. No exactly-once guarantee is claimed: ambiguous submissions and incomplete receipt history must remain unresolved rather than cause an automatic repost. A hosted, separately authorized canary and observed recovery evidence are still required before any write path is enabled.

An earlier names-only inspection of the separate target repository `magnus919/SlopSearX` listed `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`, but no repository-level `NOUS_API_KEY` or `TYPESAFE_API_KEY`. That historical observation reveals neither values nor the inference backend and does not describe the new harness repository's six configured variable/secret names. No secret values were inspected or changed.

SlopSearX remains the selected first pilot target. Remaining owner decisions are acceptable operating and quality thresholds, if and when to authorize review posting, and the evidence required before cutting over from Droid. The remote destination and production model have already been selected.

- Trusted harness code and operational profiles come from a reviewed revision. Target objects are acquired without checking out or executing their code in credentialed analysis.
- Read-only review uses minimal token permissions and immutable action pins. Public-target retrieval must not forward the inference credential.
- Review/check evidence is bound to canonical repository, PR, immutable head and explicitly trusted check application identity.
- New commits supersede prior runs. Publication rechecks the current head immediately before the effect, binds the review to the reviewed commit and prevents replay duplicates.
- Publication is disabled by default. Mock API tests establish controller behavior; only an authorized observed GitHub run establishes live integration.
- Required analysis coverage and supported blockers are reflected in the published disposition. An artifact-producing exit code is not a clean-review signal.

## Evaluation and promotion

Freeze a held-out dataset and criteria before tuning. Run the harness and Droid against identical snapshots and compare independently adjudicated consequential misses, false blockers, unsupported findings, useful findings, incomplete reviews, human review effort, latency and cost. Report denominators and uncertainty; compare models separately. Validate the selected production model even if free-model trials pass.

Start with read-only artifacts, then authorized shadow publication that does not determine merge eligibility. Promote to an advisory reviewer only after the evidence supports the owner's criteria. Replacing Droid requires an explicit cutover decision, an observed normal workflow and a recovery path; it is not implied by packaging or deployment.

## Rollback and recovery

Disable the harness workflow/publication trigger, preserve its artifacts and resume using the previously available review process. Keep Droid available throughout shadow operation until the owner chooses cutover. Pin the previous verified harness artifact and configuration for software rollback. A provider/model change invalidates model-specific quality evidence and requires re-evaluation rather than assuming equivalent behavior.

Rehearse recovery using interrupted-run, stale-head, duplicate-publication, malformed-provider-output and unavailable-provider scenarios. Record expected and observed disposition, retained evidence, usage, side effects and operator steps. No destructive cleanup is required for recovery.

## Exit evidence

A release recommendation includes artifact hashes, installed-artifact checks, CI run links, live integration evidence, security/permission review, retained evaluation reports, owner-approved operating criteria, support/retention ownership and rollback rehearsal. Missing evidence is reported as pending. Production readiness and Droid replacement remain unproven until every applicable gate in `PRODUCTION-DELIVERY.md` and the original specification is satisfied.
