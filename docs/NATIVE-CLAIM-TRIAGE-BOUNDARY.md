# Native claim-to-triage boundary check

This records a two-case, development-only TypeSafe experiment of the native assessment adapter, the safe-result projection, and deterministic claim triage. It is an interface check, not a model-quality, accuracy, calibration, injection-resistance, or production-readiness result. The challenge dataset uses synthetic non-Git revisions, has no adjudicated semantic labels, and is marked `development` / `UNKNOWN_NOT_ADJUDICATED`.

The frozen input is `examples/claim-challenges/development.v1.json` (SHA256 `1cf60a1f6e5897ab00599ea76cd24fbab06ce7dc346badbd2865036b05536e63`). All attempts used configured model ID `jev-1.13.0`; only the two corrected-network calls received endpoint-reported model ID `jev-1.13.0`. The same request bytes and triage policy `claim-challenge-five-factor-development-v1` were used (contract `claim-triage-policy.1`, SHA256 `4cc6a46a48d795f05f0c2325e1fd08ad1d49bbf904597fddb7f553c3d86dcdbf`). The policy requires observation, consequence, and rule support; materiality; and no identified missing context. Introducedness is recorded when available but is not required. Calls used at most 64,000 input bytes, 8,000 response bytes, and eight seconds; there were no retries. Billed cost is unknown.

## Network-context diagnosis

The first two bounded worker attempts ran in the default sandbox. They returned `transport_failed` after 70.03 ms and 169.43 ms. No response bytes/hash or endpoint-reported model identity were available. Both adapter results were `FAILED` and both triage outcomes were `UNAVAILABLE`. The safe transport intentionally does not retain the underlying exception.

A separate credential-free check then found default-sandbox DNS resolution for `api.typesafe.ai:443` failing with `gaierror` errno 8. In the narrowly escalated context, DNS resolved and a TLS 1.3 handshake succeeded. That check sent no HTTP request and used no credential. This makes sandbox DNS/network restriction the likely cause of the first failures, but does not prove the exact cause of either individual call.

## Corrected-network results

The two approved calls ran through the existing isolated worker and the actual adapter → safe projection → triage path. The projection preserved only typed answers, confidence/probabilities, hashes, and provenance; it did not persist free-text rationale or credentials.

| Development case | Request SHA256 / bytes | Response SHA256 / bytes; wall time | Typed factor results | Triage |
|---|---|---|---|---|
| `auth-static-satisfying-v1` | `233ca60ba104dfe6d1e788fd1351f975bf3a5fe45b1300ab3c051dc5cf8be311` / 7,238 | `f3d85f816bcf7ceb43e9443f82d7bc39b00e4eb000cfb3cc13c2288dd3e9ccc3` / 1,196; 279.37 ms; usage 2,816 input / 471 output tokens | Observation, consequence, rule: `SUPPORTED`; materiality: `MATERIAL`; missing context: `NO_MISSING_CONTEXT_IDENTIFIED`; introducedness: `INTRODUCED`. Confidence/probability vectors are recorded below. | `SUPPORTED_FOR_REVIEW` (`ADVISORY_ONLY`), no gaps/conflicts. This status does not authorize or establish a blocker. |
| `review-effect-omission-v1` | `78fe4fc6255a1317d1ad1d7410c7bfe12038de4941fa348218c6fcb58d69eec8` / 5,388 | `1c3110ac811cdca7ce8336389a27779b6fa5846b00fb15fb4ca82e37667793e1` / 1,030; 264.24 ms; usage 2,001 input / 398 output tokens | Observation: `SUPPORTED`; consequence: `NOT_ESTABLISHED`; rule: `INVALID` and quarantined as `invalid_choice_answer` (hash `e09391974a6d09013addeaad40d5e9d0866781f4eb8ae46c7aaace873a7dcaab`); materiality: `MATERIAL`; missing context: `MISSING_CONTEXT_IDENTIFIED`; introducedness: `NOT_SHOWN`. | `UNAVAILABLE` because the response was partial and a required rule answer could not be validated. Triage retained consequence/missing-context gaps and the materiality-without-established-consequence conflict. |

The exact probability vectors (with confidence) are retained here in schema choice order. For observation/consequence/rule, order is `(SUPPORTED, NOT_ESTABLISHED, CONTRADICTED, UNCERTAIN)`; for materiality `(MATERIAL, NOT_ESTABLISHED, NOT_MATERIAL, UNCERTAIN)`; for missing context `(MISSING_CONTEXT_IDENTIFIED, NO_MISSING_CONTEXT_IDENTIFIED, UNCERTAIN)`; for introducedness `(INTRODUCED, REEXPOSED, PRE_EXISTING, UNKNOWN)`.

- Satisfying case: observation `(1, 0, 0, 0)`, confidence `.99`; consequence `(.99, .01, 0, 0)`, `.99`; rule `(.9299999999999999, .01, .06, 0)`, `.92`; materiality `(1, 0, 0, 0)`, `1`; missing context `(.02, .98, 0)`, `.96`; introducedness `(1, 0, 0, 0)`, `.99`.
- Omission case: observation `(.85, .13, .01, .01)`, confidence `.81`; consequence `(.03, .94, .02, .01)`, `.92`; rule answer invalid (no accepted probabilities or confidence); materiality `(.48, .41, 0, .11)`, `.30`; missing context `(.72, .27, .01)`, `.58`; introducedness `NOT_SHOWN`.

For the second case, `INVALID` means the adapter could not validate that answer; the raw answer was discarded. This is not evidence that the model itself is defective. The fixture includes a review-directive string in repository evidence but supplies no review-effect records (`NOT_PROVIDED`). Neither the assessment nor this experiment establishes that a downstream review effect occurred or was suppressed.

The corrected-network artifact is `/tmp/pr-review-claim-triage-network-6ngp2lom/result.json` (SHA256 `29210110a14fb6af79c82080feb1ec7fdbbc1c2f8f24e59d41d720ba3a987602`). The unchanged sandbox-failure artifact is `/tmp/pr-review-claim-triage-live-k8pca1m7/result.json` (SHA256 `d470c5cdd9bb47a638734ed5209536d0984fd48863d1b20629e9cf8e69060676`). These two synthetic cases and unknown labels cannot support accuracy, calibration, held-out, or production claims.
