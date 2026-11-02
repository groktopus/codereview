# 0004 — Publication authorization: READ_ONLY by default, live effects disabled

- **Status:** Accepted
- **Date:** 2026-09-29 (NO-GO decision; revised 2026-10-02 for route scoping)
- **Owner:** Repository owner (`@magnus919`; `.github/CODEOWNERS`).
- **Decision authority:** Owner authority recorded in [AGENTS.md](../../AGENTS.md) on 2026-09-26 ("Default effects remain READ_ONLY") and the 2026-09-29 NO-GO decision retained in [PUBLICATION-READINESS.md](../PUBLICATION-READINESS.md).
- **Scope:** The harness CLI and the central `groktopus/codereview` publisher route. The separately installed target-local route is outside this record and is not authorized by it.
- **Evidence:** [AGENTS.md](../../AGENTS.md); [PUBLICATION-READINESS.md](../PUBLICATION-READINESS.md); [STATUS.md](../STATUS.md); the hard-disabled central job in [pr-publish.yml](../../.github/workflows/pr-publish.yml); the preview-only CLI path in [cli.py](../../src/pr_review_harness/cli.py); [test_publisher.py](../../tests/test_publisher.py); [test_cli.py](../../tests/test_cli.py).
- **Reversal/expiry:** The NO-GO remains in force for the CLI and central route until the owner makes a separate activation decision after the gates in `PUBLICATION-READINESS.md` are evidenced. A reversal requires a new or superseding record and must not be inferred from a passing test or a code merge.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0003](0003-transport-security-policy.md) covers credential transport; [ADR 0006](0006-evaluation-gates.md) separates publication capability from review quality.

## Context

The harness can produce a sealed review result and contains publication code, but publication is an external effect with an uncertain outcome: a timeout can hide an accepted POST, a retry can duplicate a review, and a stale head can misattribute a result. The 2026-09-29 record concluded NO-GO for the CLI and central publisher route. The target-local installation is a different, separately controlled route; later reports describe one `COMMENT` effect there, which this repository does not independently verify.

## Decision

- Default effects remain `READ_ONLY` for every review run.
- The CLI `publish` command renders and validates a `PREVIEW_ONLY` request. It does not read a writer credential and `--authorize-publish` fails closed.
- The central publisher job remains hard-disabled by a literal `false &&` guard, not merely by a repository variable.
- No live POST, writer credential, or effect store is authorized by this record.
- Activating any publication route requires a separate owner decision, a concrete target binding, the evidence gates in `PUBLICATION-READINESS.md`, and a named `UNKNOWN` reconciliation operator.
- The separately installed target-local route is not covered; a reported effect there is not evidence for the CLI or central route.

## Consequences

- Normal review and preview remain safe to run without an external write.
- Publication capability is not a quality result and does not establish replacement readiness.
- The publisher code and fault tests are retained for a future authorized route; their presence is not activation.
- A proposed or reported target-local publication state must not be described as this repository's publication authorization.

## Alternatives considered

- **Enable the central publisher after the fake-transport tests pass.** Rejected: fake tests and read-only admission do not prove hosted writer behavior or exact-effect reconciliation.
- **Require per-result human approval instead of a policy.** Rejected by the publication-readiness record: the selected model is narrow standing authorization bound to an exact committed policy, not per-result approval.
- **Delete the publication code until needed.** Rejected: the guarded effect surface and its fault evidence are needed to evaluate a future route, and deletion would discard historical evidence.
- **Treat the reported target-local `COMMENT` as authority for the central route.** Rejected: the routes have different credentials, workflows, and ownership.

## Evidence status

The policy and current containment are `OBSERVED` in the repository. The target-local deployment is `REPORTED` only in dated documents; its current state is not verified here. No live publication is authorized or claimed.
