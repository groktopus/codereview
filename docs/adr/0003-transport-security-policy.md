# 0003 — Transport and credential policy: HTTPS or exact loopback

- **Status:** Accepted
- **Date:** 2026-11-01
- **Owner:** Repository maintainers (`groktopus/codereview`; `.github/CODEOWNERS` names `@magnus919`).
- **Decision authority:** Repository owner, through merged pull request [#275](https://github.com/groktopus/codereview/pull/275) (SE-1) and the retained transport-policy statement in the root [README](../../README.md).
- **Scope:** Provider and claim-transport endpoint validation at construction for the OpenAI-compatible adapter and the native/claim transport.
- **Evidence:** Commit `f55a0de` (single policy) and `51ffeeb` (malformed-port correction); `validate_provider_url` in [providers.py](../../src/pr_review_harness/providers.py); [test_providers.py](../../tests/test_providers.py); [test_claim_transport.py](../../tests/test_claim_transport.py); [SE-1](../issues/05-security-and-effect-boundaries.md).
- **Reversal/expiry:** No expiry. Revisit if a trusted local proxy, mTLS, or a different credential-placement model is proposed. A change requires a new or superseding record.
- **Supersedes:** None.
- **Superseded by:** None.
- **Related:** [ADR 0005](0005-provider-boundary.md) constrains which providers may be configured; [ADR 0004](0004-publication-authorization.md) governs the separate publication-download boundary.

## Context

The OpenAI-compatible adapter originally accepted `http://` for any host, while the native claim transport already required HTTPS or loopback and a helper script rejected remote HTTP. That inconsistency meant a hand-written provider configuration could send a bearer credential in cleartext. Endpoint choice remains trusted operator configuration, but the transport rule has to be enforced in code at the point where the credential is attached, not only in a helper.

## Decision

Apply one endpoint policy when a provider or claim transport is constructed:

- Remote endpoints must use HTTPS.
- Plain HTTP is accepted only for the exact loopback hosts `127.0.0.1`, `::1`, and `localhost`.
- Userinfo, query strings, fragments, malformed ports, and non-HTTP(S) schemes are rejected.
- Redirects are not followed, so an `Authorization` header cannot be forwarded to an unvalidated host.
- The rule is identical for the OpenAI-compatible adapter and the native/claim transport; there is no per-entry-point exception.

This is credential-transport policy, not a general network-egress or SSRF guarantee. Artifact-download URLs have their own validation and are covered by the publication records.

## Consequences

- A provider configuration cannot silently downgrade a remote credential to cleartext.
- Loopback HTTP remains available for local test servers and development transports.
- Endpoint choice, DNS behavior, and a compromised trusted configuration remain residual risks; the allowlist is a hostname rule, not a private-address classifier.
- Adding a new provider family requires applying the same policy at construction and recording any exception.

## Alternatives considered

- **Validate only in the configuration helper.** Rejected: hand-written configuration and alternate entry points bypass the helper.
- **Allow remote HTTP for explicitly marked hosts.** Rejected: the marker would be configuration-controlled, so a mistaken or malicious profile could still expose a credential.
- **Follow redirects and re-validate the destination.** Rejected for now: redirect handling expands the attack surface, and the harness has no need for it.
- **Central egress proxy.** Deferred: it adds an operational component without evidence that endpoint selection requires one.

## Evidence status

The policy and its tests are `OBSERVED` in the repository at the named revision. Tests cover remote HTTP rejection for both provider families, HTTPS acceptance, loopback HTTP acceptance, credentials/query/fragment rejection, malformed ports, and redirect non-following. No live external provider call is needed to prove the policy.
