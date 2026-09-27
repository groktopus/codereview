# Transport-pair diagnostic run 36347277922

This manual, secretless loopback probe did not produce an accepted transport-pair receipt. The probe step reported success, but the workflow replaced the generated receipt after strict validation failed. The original receipt and validator subpredicate were not retained, so the cause remains `NOT_RETAINED`; this record does not attribute the rejection to a particular field or defect.

The only retained member is [`transport-pair.json`](artifacts/36347277922/transport-pair.json), the bounded `selected-control-transport-not-observed.v1` fallback. It is 492 bytes with SHA-256 `19e9d791e3fcc0a44106279d435ec40a4e40f9238b4920266b9de9e56daea638`. Its typed fields record `NOT_OBSERVED`, the generic `PAIR_RECEIPT_MISSING_OR_REJECTED` reason, the expected/checkout/runtime source identity, a successful probe step, and `actual_provider_calls: UNKNOWN`. It contains no validator rejection subpredicate.

Workflow conclusion was SUCCESS even though it uploaded the fallback. This was a reporting defect: uploading a safe fallback must not turn failed receipt validation into a successful job. The corrected workflow retains a finite validator rejection code in a NOT_OBSERVED receipt, allows that receipt to upload, and fails its terminal acceptance gate. The strict pair predicates and observation caps remain unchanged.

No HTTP/TLS comparison was established, no actual provider-call count or cost is known, and this run makes no claim about transport parity, quality, or semantic correctness. A later diagnostic run is a distinct attempt; this fallback does not justify retrying the lost receipt or treating it as an accepted result.
