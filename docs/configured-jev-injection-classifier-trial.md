# Configured Jev synthetic injection classifier trial

This diagnostic compares Jev’s native Choice response on the fixed synthetic
code-comment attack and benign-lookalike texts in
`examples/injection/fixture-suite.v2.json`. It records an advisory fixture
match observation; the two authored labels are not an independent security
ground truth or an accuracy estimate.

The workflow is available from **Actions → Configured Jev synthetic injection
classifier diagnostic** on `main`. Its default is provider-free preparation.
The preparation artifact binds the exact source revision, installed harness
package, fixture suite, profile, Choice question and criteria, and request
templates. Select `run_live_trial` only when a two-request diagnostic is
intended. That step uses the existing `JEV_BASE_URL`, `JEV_MODEL`, and
`JEV_API_KEY` secrets; it does not receive the primary LLM credentials.

The run reserves two provider calls: one for each fixed text, with no retry,
20 seconds per call, and a 60-second aggregate deadline. The live step rebuilds
both request bodies from the actual configured model before making either
request, then verifies each adapter receipt against that body and the pinned
question, criteria, and fixture hashes. `JEV_BASE_URL` may be the API base
(for example, ending in `/v1`) or that base with `/systemone` already appended;
the trial normalizes both forms to one exact endpoint and rejects duplicate or
other path suffixes. A configured `jev-latest` alias must
return a concrete versioned Jev model ID; a missing or mismatched identity
remains unknown or invalid rather than being replaced by another model or
endpoint. The historical `classify_with_jev` helper keeps its existing fixed
`jev-1.13.0` allowlist and behavior.

The artifact stores the selected Choice, configured and reported model
identity, hashed endpoint/request/response identities, bounded HTTP status and
byte counts, and usage only when the adapter reports it. This adapter currently
reports token and cost usage as unknown. It does not retain request text, raw
responses, endpoint URLs, or credentials. The trial does not invoke the review
CLI, execute fixture code, publish a review, or change a review disposition.
