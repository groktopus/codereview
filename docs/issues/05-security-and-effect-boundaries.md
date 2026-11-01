# Theme: Security and effect boundaries

**Scorecard dimension:** Effect safety (current: A−); Evidence discipline (current: A)
**Target:** one transport policy enforced at construction; zero high-severity SAST or secret findings; a documented threat model; publication effect faults covered by tests and canary; no security-relevant exception swallowed.
**Why:** the trust model is the project's best feature. The remaining gaps are narrow but consequential: a cleartext-credential path, no static analysis, and insufficient adversarial testing of effects.

---

## SE-1 — Enforce one transport policy at provider construction

- **Priority:** P0
- **Dimensions:** Effect safety; Security
- **Problem:** `providers._safe_url` accepts `http://` for any host. Only `scripts/provider_config_from_env.py` rejects remote HTTP. A hand-written `provider.json` with `http://remote-host` sends the bearer token in cleartext. Jev's transport already enforces HTTPS or loopback, so the policy is inconsistent across adapters and the README's "remote HTTP is rejected" claim is true only for one entry point.
- **Scope:**
  - Implement one URL policy used by every adapter: HTTPS for any remote host; HTTP only for explicit loopback with a documented allowlist.
  - Apply it when the provider object is constructed, not only in a helper script.
  - Include IP-literal, IPv6, userinfo, query, fragment, and redirect cases.
  - Record the normalized endpoint identity hash in provenance without the URL.
  - Update README and deployment docs to state the exact policy.
- **Exit criteria:** Remote HTTP is rejected on every configuration path; loopback HTTP still works; tests cover both adapters and all documented edge cases; docs match behavior.
- **Verification:** tests for `http://remote`, `https://remote`, loopback, credentials-in-URL, and redirect; `rg "_safe_url"` shows one policy implementation.
- **Depends on:** none.
- **Non-goals:** supporting plaintext HTTP to remote hosts for convenience.

---

## SE-2 — Add a threat model and automated security scans

- **Priority:** P1
- **Dimensions:** Security; Governance
- **Problem:** There is no threat model document and no SAST, secret scanning, dependency review, or CodeQL workflow in this repository. Security reasoning exists in tests and docs but is not systematically challenged.
- **Scope:**
  - Write a threat model covering prompt injection, artifact tampering, credential exfiltration, SSRF, supply chain, and publication effects, with trust boundaries and non-goals.
  - Enable CodeQL (or an equivalent SAST), secret scanning, and dependency review in CI.
  - Run a seeded-secret scan over source, fixtures, reports, logs, and artifacts; fail on any match.
  - Classify findings and record accepted risks with owners and expiry.
  - Keep scans read-only and never send repository content to a new third party without authorization.
- **Exit criteria:** Threat model exists and is linked from SECURITY.md; all scans run on PRs and main; a seeded secret or vulnerability fails the build; accepted risks are recorded.
- **Verification:** workflow runs; a seeded violation; threat-model review record.
- **Depends on:** none (can run in parallel with SE-1).
- **Non-goals:** claiming security certification from green scans.

---

## SE-3 — Remove the pickle proxy and audit exception handling

- **Priority:** P2
- **Dimensions:** Security; Architecture
- **Problem:** `engine.py:560` calls `pickle.dumps` on the claim assessor solely to measure configuration size. It is non-deterministic across versions, requires arbitrary objects to be picklable, and is a dangerous pattern to leave in a security-sensitive codebase. Separately, there are 107 `except Exception` sites; most are intentional fail-closed handling, but some can mask defects or convert programming errors into `UNKNOWN`.
- **Scope:**
  - Replace the pickle size check with a canonical serialization of the declared identity/configuration.
  - Introduce a typed error taxonomy for expected failures.
  - Audit every broad except in security- and effect-relevant paths; narrow or re-raise where the error is not an expected boundary condition.
  - Add a test that a programming error in the assessor is not silently converted to a benign result.
- **Exit criteria:** No `pickle` in the engine; the audit is recorded with a rationale per remaining broad except; security paths distinguish expected failure from defect.
- **Verification:** `rg "pickle"`; an exception-audit table; tests for programming-error propagation.
- **Depends on:** CA-1.
- **Non-goals:** removing intentional fail-closed handlers.

---

## SE-4 — Prove effect-boundary behavior with a fault matrix and canary

- **Priority:** P1
- **Dimensions:** Effect safety; Test depth; Operational readiness
- **Problem:** Publication is hard-disabled in this repository and the target deployment's write behavior is reported, not observed here. Ambiguous submission, duplicate delivery, timeout, history pagination, and artifact tampering are partly fake-tested but not consolidated into a repeatable effect-boundary suite.
- **Scope:**
  - Build a parameterized fault matrix for publication: acknowledged receipt before POST, ambiguous submit, duplicate review, timeout after POST, history pagination failure, stale head, tampered artifact, wrong actor, insufficient scope.
  - Assert for each: terminal state, no retry where forbidden, no second effect, and a reconciliation owner/step.
  - Keep the write path disabled by default; exercise the matrix with fakes and an explicit opt-in canary.
  - Record least-privilege scope expectations and verify them against the workflow declaration.
- **Exit criteria:** The matrix is green in CI; each fault has an asserted effect outcome; a documented canary procedure exists and has been exercised with no unintended effect.
- **Verification:** matrix test IDs; canary receipt; scope-declaration test.
- **Depends on:** SE-2; CA-1.
- **Non-goals:** enabling publication for ordinary PRs or auto-merging.
