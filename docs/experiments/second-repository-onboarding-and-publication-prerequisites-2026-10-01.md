# Second-repository onboarding and publication prerequisites — 2026-10-01

This record adds a provider-free portability observation and summarizes the deployment inputs still missing for protected review publication. It does not authorize a target workflow change or publication. See [publication readiness](../PUBLICATION-READINESS.md), the [Actions publication design](../ACTIONS-PUBLICATION-DESIGN.md), and the [protected-source qualification notes](../PROTECTED-PUBLICATION-SOURCE.md) for the controlling records.

The separate [PR466 SDK source audit](slopsearx-pr466-sdk-source-audit-2026-10-01.md) records the imported-class ambiguity and exact-head CI install evidence. It does not establish the installed target runtime; the failed bounded log request returned no bytes and its discarded stderr does not identify an HTTP error category.

## Provider-free second-repository sizing

The public repository `magnus919/agent-skills` was verified as unarchived with default branch `main`; its observed tip was `54d81f7e02051df2f31130a136dc68f8add42130`. The selected immutable case was merged PR #629, a two-line documentation change adding reciprocal routing between `agent-evals-and-observability` and `system-one`:

- base `f35ed6261afe49e42d6f85d42bbf41b6706ea07f`
- head `240ec7d829f8b895bd1d7245a0b6602d53933962`
- exact-head check runs: 5 succeeded, 3 skipped, 0 failed. `paired-eval-model`, `jev-eval-audit`, and `droid` were skipped; these checks do not provide model-review evidence.

The candidate profile was copied from the Codereview generic profile and bound to this repository. It is **not registered** in `profiles/targets.json`, which currently contains only the SlopSearX mapping. The exact profile SHA-256 was `0b1a72bd6897e6a702ada7c1483c4d9028c5521a13cdce49ef1934182b039680`; the finite limits file SHA-256 was `85b74d1f640b6e6b4d76162fba6bd4a8ea27c23d788e2a62c831581b6806ea51`. The check evidence was captured for the fixed historical head; it does not assert current PR state.

Two prepare-only observations are kept distinct because their serializers differ:

| Harness source | Result | Planned primary work | Context / request sizes | Provider calls / target execution |
|---|---|---|---|---|
| `dd2ffe68f4650f6023de4dd77aac972777269a8c` | `PREPARED_ONLY`, exit 0; stdout SHA-256 `a5f6827a64674394f735747c8e6996989f3dcb8cf33d47a2904dbe61587b5843` | 4 of 4 planned obligations admitted; 4 primary requests, 114,237 serialized bytes | 300,000-byte aggregate context cap; largest request 29,122 bytes | 0 / none |
| `162664076d60d2cb5de70482833c7e6a6f7b5f47` | `PREPARED_ONLY`, exit 0; stdout SHA-256 `464ba6f0b0f3f61e9de4277fe915d79bf49de9db8fdf8b6fe90d5ddfebf2e185` | 4 of 4 planned obligations admitted; 4 primary requests, 114,957 serialized bytes | Same limits; largest request 29,302 bytes | 0 / none |

Both used 8 maximum provider calls, 0 retries, a 120-second run deadline, 64,000 declared bytes per task (effective provider limit 32,768 bytes), 2 concurrent scopes, 8,192 output bytes per task, 16,384 aggregate output bytes, no context retrievals, no follow-up tasks, and zero claim assessments. Both had zero required or optional context gaps. Remaining runtime demand is unknown until primary results exist; the unused call slots are not a completeness prediction. The first sizing attempt at a 65,536-byte aggregate context cap correctly rejected the case because its four primary requests totaled 114,237 bytes. These were source-based CLI invocations (`PYTHONPATH=src`), not installed-wheel runtime qualification.

The current-source snapshot hash was `9c35835ab210b8df5af368d8577da2609f8d47906033282ad690df20a40169c9`; the evidence-index hash was `b88ec38a33784977f619e50238c7d221b47161226c7180a809fb0e422b78df14`. The run used a synthetic `example.invalid` sizing-only endpoint and placeholder model, with no API key value set or read. The local temporary packet was mode `0700`; no raw source, provider payload, or credentials are included in this durable note. These results establish planning and serialization only, not review quality, test execution, or readiness to admit this repository in Actions.

## Publication deployment checklist

The mandatory design properties are least privilege, credential isolation from PR-controlled execution, binding to the exact result and reviewed head, fresh-head validation, and bounded reconciliation of duplicate or ambiguous effects. The specification does not mandate a GitHub App or a specific Actions Environment. Those are the current proposed mechanisms; a substitute would need to demonstrate equivalent identity, scope, isolation, and reconciliation controls. A configured environment name alone is not evidence of its protection rules.

Before considering an enablement change:

1. Verify target repository ID, default branch, allowed event, analysis and publisher workflow IDs/paths, protected-source behavior, and exact pinned harness/profile/check bindings with a secretless target-side probe.
2. Review and register a repository-bound profile and immutable hash in `profiles/targets.json`; pin that harness revision in the target caller.
3. Configure the six explicitly named analysis inputs through trusted target-side secret bindings (repository secrets or a reviewed Actions Environment): `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `JEV_BASE_URL`, `JEV_MODEL`, and `JEV_API_KEY`. Source-repository secrets do not implicitly propagate into the target. The latest names-only metadata observation for SlopSearX listed `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`; it did not show those six names. No secret values were accessed.
4. If retaining the GitHub App mechanism, verify its actual App ID, installation ID, slug/bot identity, target-repository installation, and exact review permission. Keep its private key in a target environment whose restrictions are independently verified. These App values and environment controls remain unknown.
5. Install only the reviewed target-local workflow and inert policy. Keep the writer hard-disabled, `GITHUB_TOKEN` read-only, PR code unexecuted in credentialed jobs, and writer concurrency serialized.
6. Produce hosted read-only proof for current PR/run/artifact/result admission and exact receipt upload acknowledgement before making the one-POST boundary reachable. Missing, stale, ambiguous, or incomplete evidence must remain rejected or `UNKNOWN`; never blindly retry a possibly accepted POST.
7. Name the operator for `UNKNOWN` reconciliation, set artifact retention/access and finite run/page/byte/deadline caps, and document rollback by restoring the hard stop and revoking/removing writer credentials. Obtain a separate approval bound to one exact repo/PR/base/head/artifact/result/body/disposition and one attempt before any comment canary.

As of this snapshot the publisher remains hard-disabled. SlopSearX PR #484 was observed at `5539217e` with the writer disabled; no target changes, credentials, workflow dispatches, or publication occurred in this work.
