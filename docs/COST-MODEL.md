# Cost model: operator prices, estimates, and a currency ceiling

Status: implemented (OE-2, issue #264). Price-table schema:
`review-price-table.v1`. Run-summary schema: `review-run-summary.v1`.
Related: [run metrics](RUN-METRICS.md) (OE-1).

The harness keeps three cost facts apart:

| Fact | Source | Meaning |
| --- | --- | --- |
| **Billed** | Provider invoice or authoritative billing adapter | What was actually charged. No configured adapter supplies this, so every run reports `UNKNOWN`. |
| **Estimate** | Observed token usage × an operator-supplied price row | A bounded, revisioned approximation labelled `PRICE_TABLE_ESTIMATE`. It is not an invoice and is never rendered as billed cost. |
| **Bound** | Request size × price row, before dispatch | A conservative per-call ceiling used only to reserve room under a per-run currency ceiling. |

Two rules are absolute. An estimate is never presented as a billed amount, and
an unknown observation never becomes zero. A provider that reports no usable
token split gets `estimate.known = false`, `microunits = null`; a provider that
reports zero tokens gets a real zero estimate.

## 1. Price table

The price table is trusted external operator configuration. The harness never
fetches prices, contacts an endpoint, or derives a price from a model response.
Schema:
[`schemas/review-price-table.v1.schema.json`](../schemas/review-price-table.v1.schema.json).
Example:
[`examples/price-table.example.json`](../examples/price-table.example.json)
(placeholder provider/model and placeholder zero prices; it is not a real
provider price and grant no authority to use one).

```json
{
  "schema": "review-price-table.v1",
  "revision": "2026-11-01.1",
  "currency": "USD",
  "providers": [
    {
      "provider_id": "openai-compatible",
      "model_id": "configured-model",
      "input_price_microunits_per_million_tokens": 750000,
      "output_price_microunits_per_million_tokens": 4500000
    }
  ]
}
```

- `provider_id` and `model_id` must exactly match the configured provider
  identity (`provider_id`/`model_id`, falling back to `kind`/`model`). There is
  no fuzzy or alias matching: an unpriced call is unknown.
- Prices are integer **microunits of `currency` per million tokens**. One
  microunit is one millionth of a currency unit, so `750000` microunits per
  million tokens is 0.75 USD per million input tokens. Floats, booleans,
  negative values, and oversized integers are rejected.
- `revision` is a stable operator version (1–128 safe characters). It is
  echoed into every estimated run summary and bound into the run request
  identity, so a resume against a different revision/content fails closed.
- `currency` is an explicit three-letter uppercase code. It is never assumed
  to be USD.
- The file is limited to 128,000 bytes (128 kB) and 1,000 rows; duplicate
  `(provider_id, model_id)` rows, duplicate JSON keys, unknown fields, control
  characters, and non-finite numbers are rejected.

Validation happens before provider construction/dispatch. CLI output uses the
stable `price table configuration is invalid` diagnostic without echoing file
contents.

## 2. Estimating observed usage

After each provider call settles, the harness reads the settled usage and the
exact `(provider_id, model_id)` row. Input/output tokens come from
`prompt_tokens`/`completion_tokens`, falling back to `input_tokens`/
`output_tokens`. Both sides must be trusted non-negative integers. A
total-only record cannot be split without inventing the split, so it produces
no estimate.

The arithmetic is integer-only and rounds each component **up** to the next
microunit, so the estimate cannot understate the amount being estimated. The
resulting record is additive on the run summary:

```json
"cost": {
  "currency": "USD",
  "reserved_microunits": 65884,
  "limit_microunits": 1000000000,
  "estimate": {
    "microunits": 4000,
    "known": true,
    "basis": "PRICE_TABLE_ESTIMATE",
    "price_table_revision": "2026-11-01.1"
  },
  "billing": {"microunits": null, "known": false, "basis": "UNKNOWN"},
  "ceiling": {
    "limit_microunits": 1000000000,
    "currency": "USD",
    "enforced_pre_dispatch": true
  }
}
```

`billing` is deliberately separate and remains `UNKNOWN`. No named owner or
actual-billing policy has been ratified, and no configured adapter can
establish an authoritative billed amount. Do not add estimates to it.

The estimate is only `known` when **every** provider settlement has a usable
token split and exact price row. One unknown call makes the run total unknown
rather than a partial total presented as complete.

## 3. Per-run currency ceiling

A ceiling is configured by the existing finite limit `max_cost_microunits`
plus the additive `max_cost_currency`:

```json
{
  "max_cost_microunits": 1000000000,
  "max_cost_currency": "USD"
}
```

`max_cost_currency` is required whenever a price-table bound is used and must
equal the table currency; a numeric ceiling without a currency fails closed
because the harness cannot compare it to a price row.

Before the first provider dispatch, `quote_monetary_budget`:

1. validates the ceiling currency against the table;
2. computes a conservative per-call bound from the exact serialized request
   bytes and the configured output cap (`max_output_tokens`, falling back to
   `max_output_bytes`);
3. sums the bounds for planned provider calls and the optional advisory call;
4. refuses the run with `configured monetary budget is below the bounded
   pre-dispatch estimate` when the sum exceeds the ceiling, before any provider
   call or result artifact.

A per-call bound uses a true upper bound for input tokens: every token is
represented by at least one UTF-8 byte, so serialized bytes ≥ token count. The
output side uses the configured token/byte cap, not a predicted completion. An
exact price row and an output cap are therefore both required; otherwise the
run fails closed with `MONETARY_BOUND_UNAVAILABLE` or the pre-dispatch
rejection rather than dispatching unbounded.

At each reservation the budget ledger also rejects unbounded reservations and
refuses a reservation that would exceed the remaining run ceiling
(`MONETARY_BUDGET_EXHAUSTED`). Required claim-assessment calls and optional
advisory calls go through the same guard; if their adapter cannot be priced
they are refused explicitly and cannot silently spend.

The reserved amount is a ceiling, not a charge. The observed estimate can be
lower and is reported separately.

## 4. Using it

```sh
pr-review review ... \
  --price-table /trusted/pricing/prices.v1.json \
  --limits /trusted/limits-with-ceiling.json \
  --json
```

`--price-table` is optional and unchanged behaviour applies without it: no
estimate and `currency: null`. `pr-review stats` reads the persisted summaries,
so it needs no price table.

Stats keep currencies separate. `cost.currency` is set only when known
estimates share one currency; `cost.currency_mixed` is true and the
cross-currency `microunits_total_known` is `null` when they do not.
`cost.estimate.by_currency` carries per-currency partial totals, and
`cost.estimate.price_table_revisions` shows which revisions contributed.

## 5. Residual gaps

- **No authoritative billing.** Billing stays `UNKNOWN`. No provider adapter
  returns an invoice or an authoritative billed amount, and the owner/actual
  billing policy is unratified.
- **Prices are not verified.** The harness trusts the operator file and does
  no network lookup, contract check, or invoice reconciliation. A stale table
  therefore yields a stale estimate, not a detection.
- **Estimates are not forecasts.** They use observed usage after a call or a
  conservative bound before it; they do not predict provider invoices, taxes,
  discounts, or minimum charges.
- **Currency totals do not convert.** There is no FX source; mixed-currency
  corpora intentionally expose no combined total.
- **Claim/advisory pricing depends on exact identity.** If the decision
  adapter's configured model is absent from the table, those calls are refused
  under a ceiling rather than estimated.
- **A legacy per-call cap carries no currency.** When an operator also sets
  `max_cost_microunits_per_call` on the provider, that authoritative cap wins
  over the price-table bound. It is treated as denominated in the declared
  `max_cost_currency` because the legacy provider field has no currency; do not
  combine it with a differently denominated ceiling.
