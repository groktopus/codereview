# Release and staged adoption plan

Status: candidate implementation; no release or cutover approved. Scope is the reusable CLI and GitHub Actions review harness, not automated merging or code repair. Root owns the release evidence and final recommendation; the project owner authorizes deployment and cutover.

## Candidate artifact

Build a wheel and source distribution from the reviewed commit in a clean checkout. Record source revision, Python/build-tool versions, file digests and dependency inventory. Install the wheel into a fresh environment outside the source directory; verify `pr-review --help`, dry-run, provider-free review, safe preflight errors and durable reports there. Editable-install tests do not establish wheel delivery.

The same verified artifact must be used for runtime integration and deployment. CI should cover supported Python versions, lint, deterministic tests, failure/cancellation/recovery probes, package construction and installed-artifact smoke tests. Provider-backed evaluation is a separate explicit job with versioned model configuration and bounded usage, not an implicit call from ordinary tests.

## GitHub integration gates

### Current deployment evidence (2026-09-26)

SlopSearX is the selected first pilot target. Read-only `gh repo view magnus919/pr-review-harness` returned that the harness repository could not be resolved. No live workflow run, hosted artifact, or published review is established. The reusable analysis workflow and protected read-only canary are implemented as source artifacts: they pin trusted harness code and read public target Git objects without executing them. The analysis workflow uses a Solar free testing configuration, which is not evidence of a selected production model. The hosted analysis/canary path has not been exercised.

The normal CLI is stateless. GitHub-backed publication receipt and history adapters are implemented in `actions_publication.py` and `publication_receipts.py`; their fake-transport tests do not establish hosted behavior. Verified writer credentials and live write-path wiring are unavailable, and `.github/workflows/pr-publish.yml` keeps the publication job hard-disabled. No exactly-once guarantee is claimed: ambiguous submissions and incomplete receipt history must remain unresolved rather than cause an automatic repost. A hosted, authorized canary and observed recovery evidence are still required before any write path is enabled.

The repository-secret metadata observed on 2026-09-26 for `magnus919/SlopSearX` listed `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`; no repository-level `NOUS_API_KEY` or `TYPESAFE_API_KEY` appeared. This names-only observation does not reveal values or prove the inference backend, and may be stale. Local successful Nous/Jev calls do not establish Actions credential availability. The target workflow credential binding must be configured and verified through an authorized hosted run. No secret values were inspected or changed.

SlopSearX is already selected as the first pilot target. Remaining owner choices include the harness repository's remote visibility/destination, the trusted caller and credential binding, production model, acceptable operating thresholds, and whether/when to enable posting or cut over from Droid.

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
