# Review Coverage Follow-up

This follow-up defines a small contract clarification for static test and security coverage. It preserves the existing 39 acceptance criteria, 12 nonfunctional requirements, and six milestones in [`design/SPEC.md`](design/SPEC.md). It does not claim production readiness or change historical run records.

## Retained evidence

Read-only pilot run [36779096930](https://github.com/groktopus/codereview/actions/runs/36779096930) reviewed SlopSearX PR 477 at base `c355830512fa5bffc167926a6a167bace93d96c6` and head `c8496b74d8e1da05a2ed654772fc4b1b1fcff56b`, using harness `89122c38988c12c20231435fe662e68dcaac3b95` and profile `slopsearx-production-v7-portal-packaging-check`. The sealed result is `INCOMPLETE` / `PARTIAL`: correctness, maintainability, and the configured portal-contract check are complete; tests and security are partial. It reported no findings.

The change was a development dependency pin in `requirements-dev.txt`. The tests task received the diff and relevant test-source context, including unchanged test files, but no changed test files. Its `PARTIAL` note says `NO_CHANGED_TESTS_OR_EXECUTION_EVIDENCE`; its input evidence IDs include no check-run IDs. The separate, complete checks document is bound to the same repository, PR, and head and records successful `test (3.12)`, `test (3.13)`, and `portal-contract` runs. Only the configured portal-contract check became a project-check obligation. Its pass is execution evidence for that configured check, not evidence about test-source adequacy. The browser check was not applicable to the changed path.

The security task received the dependency diff and base/head file evidence. It requested provenance because no advisory or vulnerability rationale was supplied. The requested full-file retrieval was rejected because `requirements-dev.txt` was outside the profile retrieval allowlist. This identifies a policy boundary; it does not establish that the pin is vulnerable or safe. A dependency manifest can show the declared package and development scope, but cannot establish upstream vulnerability status by itself.

PR #175 merged at main `5586932dab5785b8f27c46fe2b13b561dd096b60`; its head `b7dd71d840b30ac55eb372188eceeb2e483cc2e0` passed all 23 checks. That merge and its CI validate the submitted implementation revision. They do not validate the follow-up behavior specified below.

## Planned contract

Keep static adequacy separate from test execution. A tests-lens result may be `COVERED` with `coverage_basis: STATIC_REVIEW` when the supplied diff and relevant tests or contract sources are sufficient to assess test adequacy. The absence of changed tests or an execution receipt alone must not force `PARTIAL`. Missing relevant test sources, unresolved contradictions, or other material evidence gaps remain partial with a concrete reason. A static result never claims that tests ran.

Represent execution independently. Surface a test check outcome only from a trusted, complete receipt bound to the exact repository, PR, and head, and only when a trusted profile explicitly binds that check. Record `PASS`, `FINDINGS`, or `UNKNOWN`. A successful check cannot replace the static adequacy review or upgrade an inadequate one. Do not infer required checks from whichever checks happened to be captured. Existing required-check obligations remain incomplete when evidence is missing, stale, failed, duplicate, or ambiguous.

Keep dependency-manifest facts separate from vulnerability knowledge. Static review may describe what the base and changed manifests establish, including development-only scope when shown, while leaving vulnerability status unknown. A dependency pin alone does not create a blocking request for an upstream advisory or provenance, and static coverage is not a vulnerability-free certification. When a stated security purpose, material risk, or trusted profile rule depends on such evidence, represent the need as a required-context obligation; leave it unresolved until authoritative evidence is supplied. This step does not add live package-registry access or broaden retrieval destinations.

Keep quality screens advisory. A model teacher or Jev may screen sampled outputs without controlling workflow or disposition. Preserve model and prompt revisions, source and output hashes, disagreements, and abstentions. Quality remains unknown without independent adjudication; no human-label prerequisite, threshold, or release gate is introduced.

## Bounded implementation and proof

The immediate candidate changes specialist instructions and the versioned SlopSearX profile only. Existing deterministic project-check obligations remain separate. A future specialist check channel is deferred: it would need explicit profile routing, byte and identity accounting, and must not allow check receipts to substitute for source-local coverage.

1. Clarify the test-lens coverage contract and the separation between static adequacy and execution evidence, while preserving planner obligations and exact-head check identity.
2. Add deterministic boundary tests for sufficient versus missing test sources; profile-bound exact-head test checks; wrong-repository, stale, incomplete, duplicate, failed, and ambiguous checks; dependency pins with and without a material security purpose; and advisory disagreement or abstention. Tests must prove the contract only, not predict live model behavior.
3. Exercise the implementation from the exact reviewed harness and profile revisions against an exact target head. Retain hashes for requests, results, checks, and profile inputs, then verify obligation identities and rendered coverage. Separately verify which checks branch protection actually requires; captured check outcomes do not prove branch-protection policy.

The candidate implements the instruction clarification and profile routing. Offline tests exercise accepted static coverage without execution evidence, preservation of partial coverage, required source obligations, and unchanged configured-check selection. They do not establish whether the live model follows the clarified instructions. Revision-bound provider proof and any later specialist check channel remain outstanding. The pilot's partial results stay partial, and no accuracy, generalized quality, or production-readiness claim follows from the retained run, contract tests, or advisory screens.
