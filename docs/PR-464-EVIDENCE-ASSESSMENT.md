# PR 464 baseline claim assessment

Status: source-grounded model review, not human adjudication or release-grade ground truth. Reviewer kind: `model_teacher`. This case is a development/discovery case already inspected during implementation; it must not subsequently be called held out.

## Exact snapshot and claim

Repository: `magnus919/SlopSearX`; base `20a743f0434a1843aa00068483f608f1e213b2af`; head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`. Objects were acquired through a read-only fetch of PR 464 into the temporary bare pilot repository, without checkout or target execution. The recorded Droid inline comment is ID 4068557444, attached to `docs/ENGINE_ADAPTERS.md` at this head.

Droid claims that the optional Stack Exchange key is sent as `X-API-Key`, which the upstream ignores, and recommends adding a `key` query parameter or qualifying the documentation.

## Observed source

At the exact head, `engines/stackexchange.py` builds the `/2.3/search` URL without a key and places a configured key in `request_headers["X-API-Key"]`. The base/head diff does not change this adapter. The documentation diff adds the explicit environment-variable name to an existing optional-key row. This is an existing implementation behavior with new documentation exposure, not newly introduced adapter code. Whether that exposure is consequential enough for a PR finding requires review policy and independent adjudication.

## Primary-source comparison

The current [Stack Exchange authentication documentation](https://api.stackexchange.com/docs/authentication) says API authentication details use an `Authorization: Bearer ...` request header. This conflicts with treating the proposed query-parameter fix as the documented current authentication mechanism. The [throttling documentation](https://api.stackexchange.com/docs/throttle) still discusses quotas in terms of a passed `key`, without establishing that `X-API-Key` is accepted. These current documents were read on 2026-09-26; no archived review-date documentation or authenticated execution probe was collected.

## Bounded assessment

- The source observation about `X-API-Key` is supported by the immutable adapter code.
- The header differs from the currently documented authentication header.
- The claim that the upstream ignores it and that users receive no benefit was not established by observed execution.
- The suggested query-parameter remedy is not supported by the current authentication page; do not promote the whole comment to a known-correct finding.
- The underlying adapter behavior is pre-existing; documentation exposure and review materiality remain separate questions.

Retain this as a useful challenge case for decomposing observations, consequences, remedies and introducedness. Do not use the bot comment or this model assessment as independent human truth. No SlopSearX source, issue, review or configuration was modified.
