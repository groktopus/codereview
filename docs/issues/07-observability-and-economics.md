# Theme: Observability and economics

**Scorecard dimension:** Operational readiness (current: C−); Evidence discipline (current: A)
**Target:** cross-run metrics for completion, reasons, latency, tokens, and cost; a bounded currency cost model; automated freshness for status and evidence claims.
**Why:** each run's artifact is rich, but there is no trend across runs. The project repeatedly reports "cost unknown" and cannot answer whether reviews are getting better, slower, or more expensive.

---

## OE-1 — Aggregate run metrics and expose a stats surface

- **Priority:** P1
- **Dimensions:** Observability; Review completeness
- **Problem:** Metrics exist per run (coverage, calls, tokens, elapsed time) but are not stored or aggregated. There is no way to see completion rate, reason distribution, latency percentiles, or provider failure trends across runs. `pr-review` has no `stats` command.
- **Scope:**
  - Define a versioned run-summary record: contract/profile identity, obligations and completion, reason codes, provider calls, tokens, latency by stage, cost estimate and its basis, terminal state, freshness.
  - Add local aggregation (`pr-review stats --since …`) over stored results, with explicit denominators and missing-data counts.
  - Export metrics in a standard format (OpenTelemetry or JSON lines) for external dashboards.
  - Keep raw source and prompts out of metrics; use hashes and counts.
  - Never convert "unknown" to zero.
- **Exit criteria:** Metrics are emitted for every run and aggregatable; the stats surface reports completion, reasons, latency, tokens, and cost with denominators; a trend can be produced without reading individual artifacts.
- **Verification:** `pr-review stats --json` output; a fixture corpus aggregation; a record schema test.
- **Depends on:** RC-3 (canonical reason taxonomy).
- **Non-goals:** shipping a hosted telemetry service or collecting content by default.

---

## OE-2 — Add a currency cost model and budget guard

- **Priority:** P2
- **Dimensions:** Operational readiness; Governance
- **Problem:** Costs are repeatedly reported as unknown. There is no per-provider price table, no estimated-cost field, and no currency-denominated budget guard. `max_cost_microunits` is validated but not operationalized.
- **Scope:**
  - Maintain a versioned, operator-supplied price table (provider, model, input/output unit price, revision, currency).
  - Compute a bounded estimate from observed usage; label it `ESTIMATED` with basis and revision; keep billed amount separate and `UNKNOWN` unless authoritative.
  - Enforce a per-run currency ceiling before dispatch where the estimate is known; fail closed when it cannot be established under a required cap.
  - Surface cost in run summary and stats.
- **Exit criteria:** Every run with known usage reports an estimated cost and basis; a configured currency ceiling is enforced pre-dispatch; unknown billing remains explicit; price-table changes are versioned.
- **Verification:** a run artifact with estimate; a ceiling test that refuses dispatch; `pr-review stats` cost trend.
- **Depends on:** OE-1.
- **Non-goals:** presenting estimates as billed amounts or predicting provider invoices.

---

## OE-3 — Automate evidence and status freshness

- **Priority:** P1
- **Dimensions:** Documentation; Evidence discipline
- **Problem:** Living documents carry hand-written dates and status claims. `CURRENT-STATUS.md` is dated 2026-10-11, the review core last changed 2026-10-07, and top-level docs disagree about publication state. Freshness is asserted, not verified.
- **Scope:**
  - Generate a status block from evidence artifacts: current revision, last verified run, contract set, publication decision, and the date of the evidence (not of the edit).
  - Fail CI when a status document is older than the core revision it describes, or when it references a superseded contract.
  - Keep historical snapshots immutable; display them as history, not current state.
  - Link every status claim to an artifact or test.
- **Exit criteria:** The status block is generated and checked in CI; a stale status fails; every "current" claim has an artifact link; historical sections are explicitly labeled.
- **Verification:** generated status diff on a no-op run; a seeded stale-date failure; artifact links resolve.
- **Depends on:** DT-1, OE-1.
- **Non-goals:** auto-generating quality claims or rewriting historical evidence.
