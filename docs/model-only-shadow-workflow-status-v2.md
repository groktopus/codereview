# Model-only shadow workflow status v2

`model-only-shadow-workflow-status.v2` adds source-dispatch evidence to the
bounded workflow status receipt. Consumers that require the exact v1 shape
should reject v2 and add an explicit v2 parser before consuming these receipts.

The `stages` map adds `source_accounting_sanitize` and
`source_accounting_upload`, each using the existing workflow outcome enum. The
top-level `source_http_attempts` field is one of `"0"`, `"1"`, or `"unknown"`.
The projector reports `"0"` or `"1"` only when the receipt passed the dedicated
allowlist sanitizer and its artifact upload succeeded. Missing, invalid,
unuploaded, or otherwise unverified evidence is `"unknown"`.

The separate `source-dispatch-accounting.v1` artifact contains only its schema,
the fixed `PR-464` case ID, and this enum. A durable `unknown` value is created
before source audit dispatch. The provider marks `"1"` after the local HTTP
opener has been entered, including opener errors; known pretransport failures
may finish as `"0"`. This records local transport entry and does not establish
remote receipt or provider consumption.
