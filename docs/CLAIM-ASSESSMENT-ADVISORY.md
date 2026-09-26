# Claim assessment adapter (advisory)

`pr_review_harness.claim_assessment.ClaimAssessmentAdapter` defines a bounded,
versioned data boundary for optional Jev/System One claim assessment. Its
serialized request follows the official `POST /v1/systemone` request shape and
uses native Choice questions. `ClaimTransport` provides the bounded HTTP
transport, but the adapter is not connected to the review engine in this
revision. No live call was made while implementing or testing it.

The adapter's `prepare(...)` returns a frozen `PreparedClaimAssessment` with
the exact serialized request bytes, question-ID map, cited-reference list and
content hashes. A caller can measure those exact bytes using
`ClaimTransport.estimate_call(prepared.request_bytes, limits)`, reserve the
call, and pass that same prepared object to `assess_prepared(...)` once. The
quote reports one provider call, bounded output and deadline, and unknown cost.
The caller's per-task input ceiling is reported separately and enforced before
dispatch by `assess_prepared`; the transport also enforces its configured hard
request ceiling.

The input contains one candidate, only the evidence IDs named by that
candidate, and an identity record binding snapshot ID/hash, profile ID/hash,
and full base/head Git SHAs. Evidence content hashes are checked before any
transport call. Introducedness is asked only when the cited records' immutable
`source_revision` values match both supplied SHAs. Otherwise the dimension is
explicitly `NOT_SHOWN` and the provider is not asked to infer it from a side
label.

Questions are separate and candidate-bound: observation support, consequence
support, rule-connection support, materiality, missing context, and (when the
revision evidence exists) introducedness. Each result preserves the native
Choice, probability distribution, and confidence without thresholding. These
fields are model judgments, not independently established facts. They do not
produce an aggregate `outcome`, a boolean materiality decision, a disposition,
or an approval signal. A later integration must define and evaluate any
deterministic mapping to the core semantic-adjudication contract separately.

Missing, malformed, and extra answers are represented per question as
`OMITTED`, `INVALID`, or hashed unexpected-answer records; valid siblings are
retained. Raw response bodies and invalid item text are not returned. Limits
cap serialized request/response bytes, question count, JSON depth/node count,
and an absolute per-call HTTP deadline. The transport uses the project's
no-redirect opener, bounded response reader, environment-only credential
reference, and a credential-echo check. It accepts only the official TypeSafe
endpoint, except for explicit loopback endpoints used by tests. A caller still
needs a killable process boundary for hard termination of any non-cooperative
adapter code.

Official native-contract references: [TypeSafe Primitives](https://docs.typesafe.ai/primitives),
[Confidence](https://docs.typesafe.ai/confidence), and
[Quick start/API request and response](https://docs.typesafe.ai/introduction/quickstart).
