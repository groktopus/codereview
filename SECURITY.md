# Security policy

This repository is the **PR Review Harness**, an experimental, read-only code review CLI and its CI workflows. It reads untrusted pull-request content, sends selected evidence to an operator-chosen inference provider, and produces review reports. It does not run target code, and live publication is unavailable from this CLI and hard-disabled in the central workflow. For what each surface actually does, read [docs/STATUS.md](docs/STATUS.md) first; this policy describes how to report a security problem in the harness itself.

## Supported versions

| Version | Security support |
|---|---|
| `0.1.x` on the default branch (`main`) | Supported: fixes land on `main` |
| Older commits, tags, and forks | Not supported |
| The separately installed target-local deployment (for example `magnus919/SlopSearX`) | Not covered by this policy; its owner controls it |

The project is pre-1.0 and experimental. There are no maintained release branches and no backport commitments. A report should be reproducible against current `main` or a clearly identified commit.

## Reporting a vulnerability

**No private vulnerability reporting channel is currently configured for this repository.** GitHub private vulnerability reporting is disabled in the repository settings (observed 2026-11-01), and there is no published security email address or private advisory intake. This is a known gap, recorded as accepted risk AR-8 in the [threat model](docs/THREAT-MODEL.md#81-accepted-risks).

Until a private channel exists:

- **Do not** put exploit details, credentials, target-repository data, or proof-of-concept code in a public issue, discussion, or pull request.
- Open a **minimal public issue** asking the maintainer to establish a private channel (for example, enable GitHub private vulnerability reporting in repository settings or publish a security contact). Include no technical detail beyond the fact that you have a report.
- Keep the report ready to send once a channel is available.
- If you discover a live credential, do not use it, do not test it against its issuer, and do not paste it anywhere. Report only that a credential appears to be exposed and where.

This policy cannot accept confidential reports until the maintainer configures a channel. That limitation is stated here deliberately rather than inventing an address that does not exist.

## What is in scope

In scope for this repository:

- the harness source under `src/pr_review_harness/`, the `pr-review` CLI, packaging, profiles, schemas, and `scripts/`;
- GitHub Actions workflows in `.github/workflows/`, including permission scope, secret handling, action pinning, and the boundary between trusted harness code and untrusted target content;
- the security properties this repository claims for itself in [README.md](README.md), [docs/STATUS.md](docs/STATUS.md), [docs/ARTIFACT-INTAKE.md](docs/ARTIFACT-INTAKE.md), and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md);
- prompt injection that changes review behavior through repository content;
- artifact tampering, forged or replayed publication bundles, and digest/identity confusion;
- credential exposure through configuration, URLs, redirects, errors, logs, reports, or workflows;
- SSRF and cleartext transport in provider or artifact retrieval paths;
- supply-chain weaknesses in this repository's own build and CI;
- ambiguous or unauthorized publication effects, including duplicate, stale, or wrong-actor effects;
- injection into generated Markdown or report content.

Out of scope:

- the correctness, completeness, or quality of review findings, and model semantic accuracy;
- vulnerabilities in inference providers, model services, GitHub, or third-party actions themselves (report those to their owners);
- the separately installed target-local deployment and any consuming repository;
- denial of service against an operator's own workstation, or compromise of an operator's secret manager or account;
- social engineering, physical access, and spam;
- claims of security certification based on a green scan.

A finding that a control described in the threat model is weaker than documented **is in scope**. A finding that the harness gives a wrong review is a quality issue, not a security vulnerability.

## Authorization and safe harbor

Test only within the authorization below:

- Use **your own fork or a local checkout**. Do not test against the `groktopus/codereview` repository's live Actions, its branch protection, or its secrets.
- Do not test against `magnus919/SlopSearX` or any other third-party repository without that owner's explicit authorization.
- Do not use real provider credentials, and do not make provider calls with credentials you do not own. Prefer loopback fakes and fixtures already in the repository.
- Do not create publication, comment, review, merge, release, or target-configuration effects. The harness is read-only by default; keep it that way.
- Do not access, modify, or retain other people's data, and do not exfiltrate repository content to a new third party.

Good-faith research that stays within this policy will not be pursued by the maintainer, to the extent the maintainer can bind that commitment. This is **not** a legal waiver, and it does not authorize testing against GitHub, any inference provider, or any target repository; those parties have their own rules.

## Operator security expectations

- Credentials belong in environment variables referenced by name, never in provider JSON, command-line arguments, prompts, reports, or fixtures.
- Remote provider endpoints must use HTTPS. Plain HTTP is accepted only for the explicit loopback allowlist documented in the README and enforced in `providers.py`.
- Keep the default read-only effect policy. Do not enable publication or supply a writer credential without a separate reviewed decision and explicit authorization.
- Treat reports and artifacts as confidential target-repository data and apply the target's retention rules.
- Pin consumed actions to full commit SHAs, as this repository does.

## Automated scanning

[`.github/workflows/security.yml`](.github/workflows/security.yml) runs:

- **CodeQL** for Python on pull requests, pushes to `main`, and a weekly schedule;
- **dependency review** on pull requests when the repository dependency graph is enabled, failing on high or critical known vulnerabilities;
- a **secret scan** with a SHA-pinned TruffleHog action on pull requests and pushes to `main` (not on schedule/dispatch, where the action would receive empty ranges), plus a `git grep` compensating check for credential-bearing URLs outside tests.

The dependency-review job is gated on the repository variable `DEPENDENCY_GRAPH_ENABLED=true` and requires the dependency graph under *Settings → Code security and analysis*. Until that is enabled, the job skips rather than failing every pull request.

The workflow is read-only (`contents: read`; `security-events: write` only for the CodeQL SARIF upload), holds no repository secrets, and never checks out or executes a reviewed target repository. A green scan means those detectors found nothing on that revision. It is **not** a security certification and does not establish review quality.

## References

- [Threat model](docs/THREAT-MODEL.md) — trust boundaries, assets, threat/control matrix, residual and accepted risks with owners and expiry.
- [Status](docs/STATUS.md) — the authoritative description of each surface and its evidence limits.
- [Operations](docs/OPERATIONS.md) — safe local and Actions operation, evidence handling, and recovery.
- [Artifact intake](docs/ARTIFACT-INTAKE.md) — publication bundle contract and its current limitations.
- [Security workflow](.github/workflows/security.yml) — the scans described above.
