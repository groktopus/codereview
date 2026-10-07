# Hosted v17 selector preparation

`bounded-production-v17` is a closed opt-in choice for the SlopSearX caller.
The default remains `legacy-v14`. The new name resolves only to the exact
`slopsearx-v17-context-target-manifest-candidate.json` bytes and the existing
`ordinary-review-limits-v3.json`; the profile adds the finite
`context-target-manifest.v1` input while retaining the v16 review and capacity
policy. The resolver checks both pinned file hashes, the manifest version and
caps, context-selection version and cap, retrieval revisions, required
security risk rule, and claim limit before writing a profile binding. Unknown
or cross-target names fail before profile or limit files are read.

The local provider-free request measurement in
`tests/test_context_target_manifest.py` serialized a 10,204-byte request with
the manifest and an 8,050-byte request for the same task without it. Its
canonical manifest metadata was 1,555 bytes. A separate offline reconstruction
from the PR 305 snapshot produced 11 available choices in 5,535 bytes of
manifest metadata. Those are bounded serialization measurements, not a live
provider quote or proof that a future task fits its budget; normal quote and
ledger checks still govern dispatch. The v4 default request fixture remains
byte-identical (8,087 bytes, SHA-256
`004df69e267e61f3457099ef2febcadee7bf2378e6f1cc0507f19881adc4e129`).

The selected reusable workflow is pinned to the v17-capable runtime at
`816c3487b8ed5aaf608051400f08d48ca80e871a`. That commit contains the manifest
engine, closed contract registry, and the `anyOf` target schema candidate.
Contract resolution runs from the pinned checkout, so qualification must exercise
that exact resolver as well as CLI preparation. This makes the v17 input
available to the caller; it does not validate the profile's review quality or
establish production behavior. The provider wire quote uses adapter 0.2 and
continues to use the same quote/ledger checks before dispatch. Publication
remains outside this read-only selection path.

The fixed PR 305 schema comparison at run `37684737544` returned an HTTP 400 for
the archived whole-object-enum request: 90,234 request bytes and a 211-byte
response with SHA-256
`63770a1ce1eb574d5791e070af9a4caf18754328f806e076e7d2cac6ae0ccffc`. The
`anyOf` candidate returned a parsed structured response, which is limited
evidence that the endpoint accepted that request shape. Its successful exchange
receipt was nested under `provenance.local_http_exchange`, while the probe
summary reader initially checked only the top level; therefore the saved
artifact does not establish the candidate's HTTP status, request receipt, or
response receipt. The comparison says nothing about review quality or coverage.
The receipt mapping fix is covered by the fake-opener tests and will be reflected
in a future natural run; the prior run was not repeated.
