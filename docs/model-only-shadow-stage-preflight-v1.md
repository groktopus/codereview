# Shadow stage-local preflight v1

`AuditDispatchGuard` is a provider-free policy check invoked on the exact serialized request bytes at each dispatch boundary. The runner validates the trusted LLM and Jev endpoint/model identities before creating adapters. The OpenAI adapter then invokes the guard before reading its credential reference; the Jev wrapper invokes it before calling the native transport, which reads its credential only after validating the prepared request.

The guard permits one call per role in this order: `source_auditor`, `jev`, then `claim_auditor`. It rejects repeated or out-of-order calls, requests above 64,000 bytes, LLM token requests above 1,800, deadlines above 90 seconds per call or 270 seconds total, and any nonzero retry budget. Existing transports enforce the same response-byte ceilings. The configured limits remain 64,000 response bytes, zero retries, and at most three provider calls for one selected packet.

The source request is checked when its frozen task and source evidence have been serialized. Jev's request is checked after source-only output is sealed. The claim-facing request is constructed only after Jev returns, then checked as exact bytes immediately before the claim auditor's credential lookup. No pre-Jev hash is asserted for this dynamic request. If a check rejects a stage, that role records a failure and later stages do not run. The source-only auditor's output is never included in the claim-facing request.

This establishes bounded request dispatch and ordering only. It does not establish semantic agreement, accuracy, calibration, ground truth, or readiness for publication. The same-job workflow remains disabled; tests use fake provider transports and perform no live calls.
