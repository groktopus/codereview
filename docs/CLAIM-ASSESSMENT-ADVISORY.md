# Claim assessment adapter (advisory)

`pr_review_harness.claim_assessment.ClaimAssessmentAdapter` defines an
optional, bounded TypeSafe System One boundary using native Choice questions.
The adapter and transport are not connected to the normal review engine or
CLI. They cannot change a review disposition or authorize publication.

`claim-assessment.1` preserves the standalone candidate-and-source-evidence
request. Optional `claim-assessment.2` adds `state.primary_assessment`: a
separately labeled prior judgment normalized under
`semantic-adjudication.v3`. It is advisory model output, not source evidence
or an answer to copy. The serialized candidate retains its original citation
list. Delivered source records are the deduplicated union of candidate
citations and the primary judgment's top-level and causal-role citations; each
reference must resolve to supplied evidence whose content hash validates.
The v2 request keeps that judgment separate from native Choice answers, and
result provenance records its hash. The adapter does not combine them into an
aggregate outcome, materiality decision, disposition, or approval signal.

The v3 validator requires exactly the `behavior`, `consumer`, and `impact`
role keys. Each role contains only `support`, `assessment`, and
`evidence_refs`. Support is `SUPPORTED`, `NOT_ESTABLISHED`, or `CONTRADICTED`;
assessment text is nonempty and at most 2,000 UTF-8 bytes; each role may cite
at most 50 IDs, each at most 256 bytes. `SUPPORTED` and `CONTRADICTED` require
citations; `NOT_ESTABLISHED` may have none. The adapter further requires every
primary and role citation to be present in the delivered source-evidence set.

`prepare(...)` returns a frozen `PreparedClaimAssessment` containing the exact
serialized request bytes, question-ID map, cited-reference list, and hashes.
`estimate_prepared(...)` measures those bytes through
`ClaimTransport.estimate_call(...)`; a caller can reserve the returned one-call
quote and pass the same prepared object to `assess_prepared(...)` once. The
adapter validates the prepared request before both quoting and dispatch; the
quoted deadline cannot exceed the caller's requested deadline. Snapshot,
profile, and base/head identities are serialized into those exact request
bytes. Result provenance keeps the configured model ID separate from the
endpoint-reported model ID; version 2 rejects missing or mismatched model
identity. The exact serialized request is limited to 64,000 bytes; it is
rejected rather than truncated if it exceeds that cap. The transport also
caps configured request and response ceilings at 64,000 bytes.

The input binds snapshot ID/hash, profile ID/hash, and full base/head Git SHAs.
Evidence content hashes are checked before transport. Introducedness is asked
only when immutable evidence `source_revision` values match both supplied
SHAs; otherwise it is `NOT_SHOWN`, and no side label substitutes for revision
evidence. Questions separately assess observation, consequence, rule
connection, materiality, missing context, and (when supported by evidence)
introducedness. Each response preserves its native Choice, probability
distribution, and confidence without thresholding. These are model judgments,
not independently established facts.

Missing or malformed answers are represented per question as `OMITTED` or
`INVALID`; unexpected answers are retained only as hashes, while valid
siblings remain available. Raw response bodies and invalid item text are not
returned. Request/response bytes, question count, JSON depth/node count, and
per-call HTTP deadline are bounded. The transport uses a no-redirect opener,
bounded response reader, environment-only credential reference, and
credential-echo check. The direct constructor permits only the official
TypeSafe endpoint (plus explicit loopback endpoints for tests).

For a trusted generic HTTPS route, `ClaimTransport.from_decision_config(...)`
accepts only the exact operator decision-config schema emitted by
`scripts/provider_config_from_env.py`. Its caller must load that config from a
trusted workflow path; review input cannot choose the endpoint. The config
stores a credential environment-variable name, never a key value. A caller
still needs a killable process boundary to hard-stop non-cooperative adapter
code.

Official native-contract references: [TypeSafe Primitives](https://docs.typesafe.ai/primitives),
[Confidence](https://docs.typesafe.ai/confidence), and
[Quick start/API request and response](https://docs.typesafe.ai/introduction/quickstart).
