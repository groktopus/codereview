# Run metrics: versioned summaries and the local stats surface

Status: implemented (OE-1, issue #263). Run-summary schema:
`review-run-summary.v1`. Aggregate schema: `review-run-metrics.v1`.
Taxonomy: `review-completeness-taxonomy.v1` (RC-3).

Each stored review result already contains the run's identity, coverage ledger,
budget, provider observations, and report. Those fields are rich but
run-specific. OE-1 adds one compact record derived from them, plus a read-only
local aggregation command. It does not add a telemetry service, a network call,
a database, or a background job.

Two invariants govern every number:

1. **Unknown never becomes zero.** A missing token count, an unavailable
   latency sample, an unbilled provider call, and a cost estimate without a
   basis are `null` or `UNKNOWN`. When only part of a population reported, the
   record exposes the partial sum *and* the missing count; it never presents
   the partial sum as a total.
2. **No content.** Summaries retain identity, revisions, hashes, counts, enum
   states, and cost numbers. They never retain prompts, source text, findings,
   evidence bodies, or task payloads.

## 1. Per-run record

Every run persisted after this change contains an additive `run_summary`
member in its result JSON. The record is built after the final elapsed and
budget values are known and before the result hash is sealed. Existing result
fields are unchanged; consumers that ignore `run_summary` are unaffected.

Schema: [`schemas/review-run-summary.v1.schema.json`](../schemas/review-run-summary.v1.schema.json).
The example below abridges repeated token fields and array items; the schema is
authoritative.

```json
{
  "schema": "review-run-summary.v1",
  "identity": {
    "run_id": "pr-7-42",
    "repository": "owner/repository",
    "pull_request_number": 7,
    "snapshot_id": "snap-...",
    "base_sha": "aaaa...",
    "head_sha": "bbbb..."
  },
  "contract": {
    "result_version": "0.1",
    "registration": "registered",
    "registry_name": "contract-registry",
    "registry_version": "contract-registry.v1",
    "registry_sha256": "cccc...",
    "review_contract_name": "review-core",
    "review_contract_version": "review-core.v3",
    "profile_name": "codereview-native-v1-candidate",
    "profile_version": "codereview-native-v1-candidate",
    "limits_name": "ordinary-review-limits-v3",
    "limits_version": "ordinary-review-limits-v3"
  },
  "profile": {"project_profile_version": "codereview-native-v1-candidate"},
  "run": {
    "created_at": "2026-11-01T10:00:00Z",
    "completed_at": "2026-11-01T10:03:00Z",
    "terminal_state": "INCOMPLETE",
    "coverage_state": "PARTIAL",
    "freshness": {"state": "CURRENT", "basis": "GITHUB_API"}
  },
  "obligations": {
    "required_total": 5,
    "complete": 3,
    "partial": 1,
    "not_started": 1,
    "unknown_state": 0,
    "incomplete_total": 2,
    "not_applicable": 0,
    "non_required": 0,
    "ledger_total": 5,
    "zero_obligations": false
  },
  "completion": {
    "completeness_schema": "review-completeness-summary.v1",
    "taxonomy_version": "review-completeness-taxonomy.v1",
    "complete_ratio": 0.6,
    "resolved_ratio": 0.8,
    "reason_distribution_denominator": 2,
    "unclassified_obligations": 0
  },
  "reason_codes": [
    {
      "canonical_code": "CONTEXT_GAP_UNRESOLVED",
      "obligations": 1,
      "share_of_incomplete": 0.5,
      "share_of_required": 0.2,
      "states": {"COMPLETE": 0, "PARTIAL": 1, "NOT_STARTED": 0, "UNKNOWN": 0}
    }
  ],
  "providers": {
    "calls_reserved": 6,
    "calls_settled": 6,
    "retries": 1,
    "tool_calls_reserved": 2,
    "request_attempted": 6,
    "request_not_attempted": 0,
    "request_attempt_unknown": 0
  },
  "tokens": {
    "denominator_calls": 6,
    "usage_states": {"known_calls": 4, "partial_calls": 2, "unknown_calls": 0},
    "fields": {
      "prompt_tokens": {
        "reported_sum": 12000,
        "reported_count": 4,
        "unknown_count": 2,
        "denominator_calls": 6
      }
    }
  },
  "latency": {
    "run_elapsed_ms": 180000.0,
    "by_stage": {
      "primary": {
        "calls": 6,
        "call_elapsed_ms_sum": 96000.0,
        "call_elapsed_known": 6,
        "http_elapsed_ms_sum": 90000.0,
        "http_elapsed_known": 6,
        "retries": 1
      }
    }
  },
  "cost": {
    "currency": null,
    "reserved_microunits": 0,
    "limit_microunits": null,
    "estimate": {"microunits": 120, "known": true, "basis": "PROVIDER_REPORTED_ESTIMATE"},
    "billing": {"microunits": null, "known": false, "basis": "UNKNOWN"}
  }
}
```

Notes on the fields:

- `terminal_state` is the preserved `disposition`. `coverage_state` is retained
  separately because an incomplete obligation ledger can coexist with a
  non-approval disposition (and vice versa for historical snapshots).
- `obligations` and `completion` come from the completeness summary (RC-3).
  `reason_codes` is the incomplete-obligation distribution with its canonical
  taxonomy code, obligation count, state split, and shares.
- `providers` carries the budget ledger's reserved/settled/retry/tool counts.
  Old results without observation receipts leave settled/retry values `null`.
- `tokens` is per token field. `reported_sum` is the sum over calls that
  reported the field; `reported_count`/`unknown_count`/`denominator_calls`
  state its coverage. If nothing reported, `reported_sum` is `null`.
- `latency.by_stage.call_elapsed_ms_sum` is the **sum of per-call durations**
  for that stage, not wall-clock time. `call_elapsed_known` is the sample count.
  `run_elapsed_ms` is the only wall-clock latency in the record.
- `cost.estimate` is only `known` when every provider settlement carried a
  usable estimate. With an operator price table (OE-2) the basis is
  `PRICE_TABLE_ESTIMATE` and the record adds `price_table_revision`; without
  one the usual value is `{"microunits": null, "known": false, "basis":
  "UNKNOWN"}`. `billing` is separate and remains `UNKNOWN` unless an
  authoritative billed amount was reported. An estimate is never billing.
- `currency` is the price table's declared currency when a table was used and
  `null` otherwise. Microunits are not silently assumed to be USD.
- The additive `cost.ceiling` member appears only for runs that configured a
  currency ceiling; it reports the limit, its currency, and whether every
  provider reservation was bounded before dispatch. See
  [the cost model](COST-MODEL.md).

Old results remain usable. When `run_summary` is absent or structurally
invalid, the metrics layer rebuilds the record from the stored result's
coverage ledger and budget. Old results without provider observation receipts
produce a record with `null` latency/token/cost observations and explicit
missing-data counts, never zeros.

## 2. Aggregation and `pr-review stats`

```sh
# Aggregate every stored result under artifacts/ (the review --output default).
pr-review stats --since 2026-10-01 --json

# Explicit corpus, plus a JSON-lines export for a dashboard.
pr-review stats \
  --results-dir artifacts \
  --since 2026-10-01T00:00:00Z \
  --json \
  --jsonl /tmp/run-summaries.jsonl

# One or more explicit result files, or a manifest with relative paths.
pr-review stats --result artifacts/a.json --result artifacts/b.json --json
pr-review stats --results-manifest corpus/results.json --json
```

Text output is a compact human summary; `--json` emits one
`review-run-metrics.v1` object. `--jsonl PATH` additionally writes one
`review-run-summary.v1` record per line in run order, sorted and compact. It
contains no prompts or source, so it is safe to feed to a dashboard or a
notebook without opening individual artifacts.

`runs.summary_records_embedded` / `runs.summary_records_derived` count the
input artifacts by whether their embedded record was usable; they are not
restricted to the selected window. The `missing_data` block describes only the
included runs.

`--since` and `--until` are inclusive ISO-8601 bounds on the result's
`created_at`; a date-only value is interpreted as midnight UTC. A result with no parseable `created_at` cannot be proven to fall
inside a requested window: it is excluded and counted under
`runs.missing_created_at`. Without a window it is included and counted under
`missing_data.created_at_missing`.

### Aggregate shape

The example below is abridged; every field is described by the implementation
and covered by the fixture tests.

```json
{
  "schema": "review-run-metrics.v1",
  "generated_at": "2026-11-01T15:00:00Z",
  "window": {"since": "2026-10-01T00:00:00Z", "until": null},
  "runs": {
    "input": 4,
    "included": 3,
    "excluded": 1,
    "before_since": 0,
    "after_until": 0,
    "missing_created_at": 1,
    "summary_records_embedded": 3,
    "summary_records_derived": 1
  },
  "denominators": {
    "obligations": 5,
    "incomplete_obligations": 2,
    "runs": 3,
    "runs_with_required_obligations": 3,
    "provider_calls": 5
  },
  "completion": {
    "required_obligations_total": 5,
    "complete_obligations": 3,
    "partial_obligations": 1,
    "not_started_obligations": 1,
    "unknown_state_obligations": 0,
    "incomplete_obligations_total": 2,
    "not_applicable_obligations": 0,
    "complete_ratio_by_obligations": 0.6,
    "resolved_ratio_by_obligations": 0.8,
    "runs_with_required_obligations": 3,
    "runs_fully_complete": 1,
    "completion_rate_by_runs": 0.333333,
    "runs_with_zero_obligations": 0
  },
  "reason_distribution": [
    {
      "canonical_code": "CONTEXT_GAP_UNRESOLVED",
      "obligations": 1,
      "runs_affected": 1,
      "states": {"COMPLETE": 0, "PARTIAL": 1, "NOT_STARTED": 0, "UNKNOWN": 0},
      "share_of_incomplete": 0.5
    }
  ],
  "terminal_state_distribution": [{"value": "INCOMPLETE", "runs": 2, "share": 0.666667}],
  "freshness_distribution": [{"value": "CURRENT", "runs": 1, "share": 0.333333}],
  "providers": {
    "calls_reserved": {"total": 5, "known_runs": 3, "missing_runs": 0},
    "calls_settled": {"total": 5, "known_runs": 2, "missing_runs": 1},
    "retries": {"total": 1, "known_runs": 2, "missing_runs": 1},
    "tool_calls_reserved": {"total": 0, "known_runs": 3, "missing_runs": 0}
  },
  "tokens": {
    "denominator_calls": 5,
    "fields": {
      "prompt_tokens": {
        "reported_sum": 1300,
        "reported_count": 3,
        "unknown_count": 2,
        "denominator_calls": 5,
        "runs_with_reports": 2,
        "complete_for_all_calls": false
      }
    }
  },
  "latency": {
    "run_elapsed_ms": {"n": 2, "p50": 1000.0, "p95": 3000.0, "sum": 4000.0},
    "by_stage": {
      "primary": {
        "n_runs": 2,
        "call_observations": 5,
        "call_elapsed_ms_sum": 3000.0,
        "p50_run_stage_ms": 900.0,
        "p95_run_stage_ms": 2100.0
      }
    }
  },
  "cost": {
    "estimate": {
      "known_runs": 1,
      "unknown_runs": 2,
      "microunits_total_known": 120,
      "complete_for_all_runs": false,
      "basis_distribution": [
        {"basis": "PROVIDER_REPORTED_ESTIMATE", "runs": 1},
        {"basis": "UNKNOWN", "runs": 2}
      ]
    },
    "billing": {"known_runs": 0, "unknown_runs": 3, "microunits_total_known": null}
  },
  "missing_data": {
    "run_elapsed_ms_missing": 1,
    "stage_latency_missing": 1,
    "provider_calls_missing": 0,
    "tokens_all_unknown": 0,
    "runs_without_provider_calls": 1,
    "cost_estimate_unknown": 2,
    "cost_billing_unknown": 3,
    "created_at_missing": 0,
    "terminal_state_missing": 0,
    "profile_version_missing": 0,
    "contract_identity_missing": 0,
    "freshness_unknown": 1
  }
}
```

Percentiles use the nearest-rank method over **per-run stage sums**, and the
`n` beside each percentile is the number of runs that contributed a value.
`call_observations` is the number of individual calls behind those sums, which
is why a percentile can have `n_runs=2` and `call_observations=5`. Summed call
latency is not run wall time; do not compare it to `run_elapsed_ms` as if it
were.

`cost.estimate.microunits_total_known` is a partial total whenever
`complete_for_all_runs` is `false`. There is no field that pretends to be the
total estimate in that case.

Costs are never summed across currencies. `cost.estimate.by_currency` carries
one row per currency (with `null` as its own distinct group), and
`cost.currency_mixed` is true with `microunits_total_known: null` when known
estimates span more than one currency. `cost.estimate.price_table_revisions`
lists the contributing table revisions. Billing remains a separate block and
is `UNKNOWN` for every run in this repository's corpus.

## 3. Current gaps

- **Aggregation covers persisted results.** A run that fails before the result
  JSON is sealed has no summary to aggregate; `--dry-run` and `--prepare-only`
  are planning surfaces and intentionally emit none. The stats denominator is
  therefore completed stored results, not every process start.
- **Old runs lack observations.** Results written before provider observation
  receipts existed have no stage latency and no token usage. They aggregate
  with explicit missing counts; the metrics layer does not infer them from
  elapsed time or task results.
- **Prices are operator-supplied and unverified.** OE-2 provides a versioned
  price table, currency-labelled estimates, and a pre-dispatch currency
  ceiling, but the harness never fetches or reconciles provider prices. A
  stale table yields a stale estimate. Billing remains `UNKNOWN` for every run
  in this repository's corpus because no authoritative billed amount exists
  and the owner/billing policy is unratified. See
  [the cost model](COST-MODEL.md).
- **Percentiles are small-sample.** Nearest-rank `p95` over a handful of runs
  is a descriptive statistic, not a calibrated service-level estimate. The
  output always carries `n` so a reader can reject an overconfident trend.
- **Freshness is per-run.** The aggregate reports the freshness distribution,
  not a current live status. A `CURRENT` run can still be stale by the time a
  dashboard reads the export.
- **Zero-obligation runs are visible, not normalized.** They are excluded from
  the run-level completion denominator and counted separately, matching RC-3's
  explicit zero-obligation state.
