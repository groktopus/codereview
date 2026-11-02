# 0005 — Model and provider boundary: configured providers only, no new providers

- **Status:** Accepted
- **Date:** 2026-09-26
- **Owner:** Repository owner (`@magnus919`; `.github/CODEOWNERS`).
- **Decision authority:** Owner instruction recorded in [TEST-MODEL-POLICY.md](../TEST-MODEL-POLICY.md) and the standing read-only test authority in [AGENTS.md](../../AGENTS.md).
- **Scope:** Provider, model, endpoint, account, and credential selection for review, claim-assessment, and decision calls made by the harness.
- **Evidence:** [AGENTS.md](../../AGENTS.md) (two configured providers through `LLM_BASE_URL` and `JEV_BASE_URL`; no new providers or accounts); [TEST-MODEL-POLICY.md](../TEST-MODEL-POLICY.md); [OPENAI-COMPATIBLE-PROVIDER.md](../OPENAI-COMPATIBLE-PROVIDER.md); [DEPLOYMENT-CONFIGURATION.md](../DEPLOYMENT-CONFIGURATION.md); [providers.py](../../src/pr_review_harness/providers.py); [test_providers.py](../../tests/test_providers.py).
- **Reversal/expiry:** The provider boundary holds until the owner explicitly authorizes a new provider, account, endpoint, or credential route. A change requires a new or superseding record; a model rotation inside the configured providers is a configuration change governed by the model policy, not a new provider decision.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0003](0003-transport-security-policy.md) is the transport rule applied to the selected endpoints.

## Context

The harness can speak to OpenAI-compatible endpoints and a native Jev/decision transport, and operators can configure endpoints, models, and credential environment-variable names. That flexibility creates a governance risk: a test or agent could silently start spending against a new provider, account, endpoint, or limit. The production model choice also matters for quality evidence, but selecting a model is not the same decision as permitting a new provider.

## Decision

- Use only the two already configured provider families, reached through the trusted `LLM_BASE_URL` and `JEV_BASE_URL` configuration and their existing trusted URL/model/key environment variables.
- Provider, endpoint, model, and credential names come from trusted operator configuration, never from pull-request content, model output, or repository text.
- Do not add a provider, account, endpoint, credential route, or increased limit without explicit applicable owner authorization.
- Do not add silent model, endpoint, or response-format fallback. An unsupported or failed call is an explicit failure, not a substitution.
- The production model choice is **not settled by this record**. [TEST-MODEL-POLICY.md](../TEST-MODEL-POLICY.md) says the production model is not yet selected; [RELEASE-PLAN.md](../RELEASE-PLAN.md) records a candidate selection. The conflict is retained rather than resolved here; a production model selection needs its own owner decision and model-specific quality evidence.

## Consequences

- Test authority cannot be expanded by editing a configuration file or adding a provider adapter without a recorded decision.
- A model rotation within the configured providers still invalidates model-specific quality evidence and requires re-evaluation.
- Provider outages, timeouts, and malformed outputs remain explicit failures; they cannot become an implicit fallback or approval.
- The unresolved production-model question is visible instead of being inferred from a plan or a test configuration.

## Alternatives considered

- **Allow any OpenAI-compatible endpoint as a drop-in provider.** Rejected: it would let a configuration change spend against a new account or endpoint without owner authorization.
- **Automatic fallback to a second model on failure.** Rejected: it makes quality evidence and cost attribution ambiguous and hides provider failure.
- **Select the production model from the free test rotation.** Rejected: the model policy explicitly prohibits silent promotion from the test rotation.
- **Resolve the production model in this record.** Rejected: there is no owner decision and no model-specific quality evidence to support it.

## Evidence status

The boundary and configuration behavior are `OBSERVED` in the repository and its tests. The production model is `UNKNOWN`/unresolved; this record does not claim otherwise.
