# Security policy

## Supported versions

The `0.1.x` line is the current supported line. Older snapshots and historical
fixtures are retained as evidence, not as supported releases.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security -> Report a vulnerability). Do not open a public issue for a
suspected vulnerability and do not include credentials, private repository
content, or provider keys in a report.

Include the affected version/commit, a minimal reproduction, the impact, and
whether the issue requires provider access or a target repository. If private
reporting is unavailable, contact the repository owner through their GitHub
profile and ask for a private channel.

## Response

Reports are acknowledged on a best-effort basis. There is no paid support or
response-time guarantee. Confirmed issues are fixed on a private branch when
needed, reviewed, merged, and disclosed after a fix is available.

## Scope

In scope: credential exposure, prompt/evidence injection that changes control
flow, unsafe publication or target effects, archive/path traversal, budget or
approval bypass, and dependency or workflow compromise. Out of scope: findings
that require a compromised operator environment, provider-side outages, or
target repositories the harness is not authorized to access.
