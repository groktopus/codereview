# PR466 static-assessment diagnostic v5

This packet tests a prompt clarification that separates completing a static review from judging whether existing tests adequately cover changed behavior. It uses the v13 candidate profile and the retained PR466 source and check capture.

## Scope and limits

The case is a read-only diagnostic. The default workflow selection remains `pr466-v1`, and live execution remains disabled by default. The v5 request cap is 80,000 serialized input bytes per primary request, with the existing 600,000-byte context cap, 10-call limit, 600-second review deadline, zero retries, and zero follow-up allowance. Historical checks and limits are copied byte-for-byte from v4.

The prepare observation records seven primary request descriptors covering all 15 planned obligations. It is a sizing and admission record only. It does not show model behavior, test execution, review completeness, runtime dependency resolution, review quality, or cutover readiness. Optional-stage demand is unknown until primary results exist.

The dependency projection is derived from the PR's `pyproject.toml` at the exact reviewed head. It shows declarations, not the installed environment or resolved runtime behavior. The static-assessment wording lets a reviewer report test gaps as findings when the available evidence permits assessment; missing or inadequate source evidence remains incomplete.

## Fixed inputs

The manifest pins the PR number, base and head commits, v13 profile digest, historical checks digest, limits digest, and exact provider-free prepare descriptors. Provider identity remains `UNKNOWN`; the placeholder sizing configuration is not evidence of production endpoint or model identity. The prepare source revision identifies the wrapper revision used for the sizing observation and is distinct from the reviewed PR head.

No target source is checked out or executed by prepare. The target repository must be supplied as a bare Git repository containing the exact base and head objects. The workflow and wrapper validate fixed paths, hashes, request cardinality, serialized sizes, projection bindings, and required-context admission before proceeding.
