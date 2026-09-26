# ADR-004: Separate credentialed analysis from untrusted head-code execution

- Status: Proposed; acceptance not recorded
- Scope: GitHub Actions trust boundary and execution of PR-controlled code
- Decision authority: unresolved; repository security owner and maintainers must accept workflow design
- Primary contact: security/CI implementation owner to be assigned
- Evidence: research memo's GitHub workflow security guidance; BRIEF.md requirement for credentialed analysis separate from untrusted tests

## Context

PR-controlled source, metadata, generated artifacts, and tests are untrusted. Hosted provider credentials are reportedly expected in SlopSearX, but names and references are not yet verified and values must not be inspected. A workflow that exposes secrets or write permissions while running PR-controlled code can expose credentials or repository state.

## Decision

Propose two trust domains. Credentialed analysis may read bounded PR metadata and Git objects and invoke an explicitly configured provider through an adapter that excludes credentials from prompts, artifacts, and logs; it executes no head-controlled code. Test/build execution, if enabled, occurs in a disposable secretless sandbox with no write token or shared writable cache, and returns only bounded typed results. Workflow actions and permissions must be pinned and least-privilege. The initial pilot remains report-artifact only with no GitHub review-writing capability.

## Considered options

- Separate credentialed analysis and secretless execution: narrows credential exposure; introduces explicit result handoff and workflow coordination.
- One job with secrets and test execution: operationally simpler; allows untrusted code to reach privileged context and is rejected by the proposed threat boundary.
- No execution of PR checks: safest initial option and acceptable when tests are not essential; leaves test evidence incomplete and must be reported as such.

## Consequences

Project-specific Actions event behavior, cache isolation, permissions, fork policy, action pins, provider secret names, and artifact handling must be verified before implementation. Secret names may be inspected; values may not. Provider output is untrusted and cannot drive tools or workflow. This ADR is a design proposal, not a security review or deployment authorization.

## Confirmation plan

Review workflow permissions and event semantics; inspect names-only secret/workflow references; demonstrate that the credentialed job cannot execute PR code and the test job has no secrets/write access; exercise prompt-injection fixtures and artifact size/type validation. These checks are planned and do not establish provider or model security.
