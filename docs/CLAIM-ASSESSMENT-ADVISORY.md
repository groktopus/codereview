# Claim assessment adapter (advisory)

`pr_review_harness.claim_assessment.ClaimAssessmentAdapter` provides an
optional, bounded TypeSafe System One assessment using native Choice
questions. The normal `pr-review review` CLI can enable this as a shadow
assessment alongside the deterministic review path. Its model judgments are
advisory and cannot change findings, review disposition, or publication
authority. A real call, byte, or deadline budget breach remains an operational
failure and must keep the overall review incomplete under the shared-budget
guard.

## CLI shadow assessment

The CLI defaults `--max-claim-assessments` to `0`, which leaves the shadow
stage disabled and does not construct its transport. Set it to an integer from
`1` through `4` to request at most that many candidate assessments. A positive
value requires `--decision-config` to point to the trusted operator-generated
Typesafe decision config. The CLI validates the exact config schema before it
constructs either provider; the configured model and credential environment
reference are shared with the existing semantic decision-provider setup. The
credential value is resolved only if an API call is made, and is never accepted
on the command line or read from review input.

The engine subjects enabled assessments to the existing shared call, byte, and
deadline ledger, including time reserved for the final freshness check. It
records this stage separately from the primary semantic adjudication. An
assessment that cannot run within the remaining budget is not treated as a
negative answer or as evidence that a candidate is safe. The deterministic
reducer continues to own blocker acceptance and disposition; a model answer,
probability, or confidence cannot clear a finding, create approval, or replace
freshness and coverage requirements. `--dry-run` reports the requested cap but
does not load provider configuration, resolve credentials, or make a request.
The model's answer cannot alter disposition, but failures in the shared
assessment budget or final freshness check can still make the run incomplete.

With a positive cap, the durable result adds a sorted `claim_assessments` list.
Only valid candidates with a validated `semantic-adjudication.v3` primary
assessment and snapshot-bound citations are eligible. Each row records the
candidate, separate per-dimension answers, status (`COMPLETE`, `PARTIAL`,
`FAILED`, `NOT_RUN`, or `INTERRUPTED_UNKNOWN`), safe provenance and usage,
request/evidence/question hashes, reservation and settlement keys, and timing.
An uncertain interrupted attempt remains unknown on resume rather than being
silently resent under the same reservation. These rows are supplementary
observations; they do not replace the primary assessment or deterministic
result fields.

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
