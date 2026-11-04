"""OE-2: versioned price table, ESTIMATED cost, and pre-dispatch ceilings."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
from test_engine import LIMITS, EmptyProvider, make_snapshot, profile

from pr_review_harness import cli
from pr_review_harness.cost import (
    PRICE_TABLE_SCHEMA,
    PriceTableError,
    load_price_table,
    price_table_from_document,
    provider_price_identity,
    usage_tokens,
)
from pr_review_harness.engine import run_review
from pr_review_harness.metrics import aggregate_run_summaries, build_run_summary
from pr_review_harness.planner import plan_review

ROOT = Path(__file__).resolve().parents[1]
SUMMARY_SCHEMA = json.loads((ROOT / "schemas/review-run-summary.v1.schema.json").read_text(encoding="utf-8"))
PRICE_SCHEMA = json.loads((ROOT / "schemas/review-price-table.v1.schema.json").read_text(encoding="utf-8"))
EXAMPLE_TABLE = ROOT / "examples/price-table.example.json"

TABLE_DOCUMENT = {
    "schema": PRICE_TABLE_SCHEMA,
    "revision": "rev-1",
    "currency": "USD",
    "providers": [
        {
            "provider_id": "probe",
            "model_id": "probe-model",
            "input_price_microunits_per_million_tokens": 2_000_000,
            "output_price_microunits_per_million_tokens": 4_000_000,
        }
    ],
}


def _table(**overrides):
    document = copy.deepcopy(TABLE_DOCUMENT)
    document.update(overrides)
    return price_table_from_document(document)


class CostProbeProvider(EmptyProvider):
    identity = {"provider_id": "probe", "model_id": "probe-model"}

    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        result["usage"] = {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500, "known": True}
        return result


class UnknownUsageProvider(EmptyProvider):
    identity = {"provider_id": "probe", "model_id": "probe-model"}

    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        result["usage"] = {"total_tokens": 1500, "known": False}
        return result


def _run(tmp_path, provider, *, table=None, limits=None, run_id="cost-run"):
    snapshot = make_snapshot()
    prof = profile()
    plan = plan_review(snapshot, prof, "AUTO")
    return run_review(
        snapshot,
        plan,
        prof,
        provider,
        None,
        limits or LIMITS,
        str(tmp_path),
        run_id,
        price_table=table,
    )


# ---------------------------------------------------------------------------
# Price table validation and arithmetic


def test_example_and_valid_price_table_match_published_schema():
    jsonschema.Draft202012Validator.check_schema(PRICE_SCHEMA)
    validator = jsonschema.Draft202012Validator(PRICE_SCHEMA)
    validator.validate(json.loads(EXAMPLE_TABLE.read_text(encoding="utf-8")))
    validator.validate(TABLE_DOCUMENT)
    table = load_price_table(EXAMPLE_TABLE)
    assert table.currency == "USD"
    assert table.entries_sha256


def test_estimate_and_bound_use_ceiling_integer_microunits():
    table = _table()
    entry = table.lookup("probe", "probe-model")
    assert entry is not None
    estimate = table.estimate("probe", "probe-model", {"prompt_tokens": 1000, "completion_tokens": 500})
    assert estimate == {
        "microunits": 4000,
        "known": True,
        "basis": "PRICE_TABLE_ESTIMATE",
        "currency": "USD",
        "price_table_revision": "rev-1",
    }
    # Bytes are an upper bound on input tokens; output falls back to bytes.
    assert table.bound_call("probe", "probe-model", 1000, 500)["max_cost_microunits"] == 4000
    assert table.bound_call("probe", "probe-model", 1000, None, 500)["max_cost_microunits"] == 4000
    assert table.bound_call("probe", "probe-model", 3, None) is None
    assert table.bound_call("other", "probe-model", 3, 4) is None


def test_zero_usage_is_known_zero_but_missing_usage_is_unknown():
    table = _table()
    assert table.estimate("probe", "probe-model", {"prompt_tokens": 0, "completion_tokens": 0})["microunits"] == 0
    assert table.estimate("probe", "probe-model", {"total_tokens": 1500}) is None
    assert table.estimate("probe", "probe-model", {"prompt_tokens": 5}) is None
    assert usage_tokens({"input_tokens": 5, "output_tokens": 6}) == (5, 6)
    assert usage_tokens({"prompt_tokens": True, "completion_tokens": 6}) is None


def test_provider_identity_reads_configured_fields_without_network():
    assert provider_price_identity(SimpleNamespace(identity={"provider_id": "p", "model_id": "m"})) == ("p", "m")
    assert provider_price_identity(SimpleNamespace(identity={"kind": "p", "model": "m"})) == ("p", "m")
    assert provider_price_identity(SimpleNamespace(identity={"provider_id": "p"}, model="m")) == ("p", "m")
    assert provider_price_identity(object()) == (None, None)


@pytest.mark.parametrize(
    "document",
    [
        {**TABLE_DOCUMENT, "schema": "review-price-table.v2"},
        {**TABLE_DOCUMENT, "revision": ""},
        {**TABLE_DOCUMENT, "revision": "bad revision"},
        {**TABLE_DOCUMENT, "currency": "usd"},
        {**TABLE_DOCUMENT, "currency": "US"},
        {**TABLE_DOCUMENT, "unknown": True},
        {key: value for key, value in TABLE_DOCUMENT.items() if key != "providers"},
        {**TABLE_DOCUMENT, "providers": []},
        {
            **TABLE_DOCUMENT,
            "providers": [{**TABLE_DOCUMENT["providers"][0], "input_price_microunits_per_million_tokens": 1.5}],
        },
        {
            **TABLE_DOCUMENT,
            "providers": [{**TABLE_DOCUMENT["providers"][0], "output_price_microunits_per_million_tokens": True}],
        },
        {**TABLE_DOCUMENT, "providers": [{**TABLE_DOCUMENT["providers"][0], "extra": 1}]},
        {**TABLE_DOCUMENT, "providers": [TABLE_DOCUMENT["providers"][0], TABLE_DOCUMENT["providers"][0]]},
    ],
)
def test_malformed_price_tables_fail_closed(document):
    with pytest.raises(PriceTableError):
        price_table_from_document(document)


def test_price_table_loader_rejects_duplicate_json_fields_and_oversize(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema":"review-price-table.v1","revision":"r","currency":"USD","revision":"r2","providers":[]}',
        encoding="utf-8",
    )
    with pytest.raises(PriceTableError):
        load_price_table(duplicate)
    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b"{" + b" " * 128_001 + b"}")
    with pytest.raises(PriceTableError):
        load_price_table(oversize)
    with pytest.raises(PriceTableError):
        load_price_table(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# Run artifact: estimate, basis, revision, separate billing


def test_run_records_estimated_cost_basis_revision_and_keeps_billing_unknown(tmp_path):
    result = _run(tmp_path, CostProbeProvider(), table=_table())
    summary = result["run_summary"]
    jsonschema.Draft202012Validator(SUMMARY_SCHEMA).validate(summary)
    calls = result["budget"]["provider_calls_reserved"]
    assert calls >= 1
    assert result["budget"]["cost_estimated_microunits"] == calls * 4000
    assert result["budget"]["cost_estimate_known"] is True
    assert result["budget"]["cost_estimate_basis"] == "PRICE_TABLE_ESTIMATE"
    assert result["budget"]["cost_currency"] == "USD"
    assert result["budget"]["cost_price_table_revision"] == "rev-1"
    # No configured adapter supplies an authoritative billed amount.
    assert result["budget"]["cost_billing_known"] is False
    assert result["budget"]["cost_billed_microunits"] == 0
    cost = summary["cost"]
    assert cost["currency"] == "USD"
    assert cost["estimate"] == {
        "microunits": calls * 4000,
        "known": True,
        "basis": "PRICE_TABLE_ESTIMATE",
        "price_table_revision": "rev-1",
    }
    assert cost["billing"]["known"] is False
    assert cost["billing"]["basis"] == "UNKNOWN"
    from pr_review_harness.engine import render_report

    text = render_report(result)
    assert "cost estimate ESTIMATED" in text
    assert "billing UNKNOWN" in text
    assert "revision rev-1" in text


def test_unknown_usage_never_becomes_a_zero_cost(tmp_path):
    result = _run(tmp_path, UnknownUsageProvider(), table=_table())
    budget = result["budget"]
    assert budget["cost_estimated_microunits"] == 0
    assert budget["cost_estimate_known"] is False
    assert result["run_summary"]["cost"]["estimate"]["microunits"] is None
    assert result["run_summary"]["cost"]["estimate"]["known"] is False


def test_resume_with_a_different_price_table_revision_fails_closed(tmp_path):
    result = _run(tmp_path, CostProbeProvider(), table=_table(), run_id="rev-run")
    assert result["run_summary"]["cost"]["estimate"]["price_table_revision"] == "rev-1"
    snapshot = make_snapshot()
    prof = profile()
    plan = plan_review(snapshot, prof, "AUTO")
    with pytest.raises(ValueError):
        run_review(
            snapshot,
            plan,
            prof,
            CostProbeProvider(),
            None,
            LIMITS,
            str(tmp_path),
            "rev-run",
            resume=True,
            price_table=_table(revision="rev-2"),
        )


def test_without_a_price_table_cost_stays_unknown_and_currency_unset(tmp_path):
    result = _run(tmp_path, CostProbeProvider())
    assert result["budget"]["cost_estimated_microunits"] == 0
    assert result["budget"]["cost_estimate_known"] is False
    assert result["run_summary"]["cost"]["currency"] is None


# ---------------------------------------------------------------------------
# Pre-dispatch currency ceiling


def test_currency_ceiling_refuses_run_that_exceeds_bounded_estimate(tmp_path):
    provider = CostProbeProvider()
    with pytest.raises(ValueError, match="below the bounded pre-dispatch estimate"):
        _run(
            tmp_path,
            provider,
            table=_table(),
            limits={**LIMITS, "max_cost_microunits": 1, "max_cost_currency": "USD"},
        )
    assert provider.calls == 0
    assert not (tmp_path / "cost-run.json").exists()


def test_currency_ceiling_allows_run_when_bounds_fit(tmp_path):
    provider = CostProbeProvider()
    result = _run(
        tmp_path,
        provider,
        table=_table(),
        limits={**LIMITS, "max_cost_microunits": 10**9, "max_cost_currency": "USD"},
    )
    assert result["budget"]["provider_calls_reserved"] >= 1
    budget = result["budget"]
    assert budget["cost_reserved_microunits"] <= 10**9
    assert budget["cost_ceiling_basis"] == "PRICE_TABLE_BOUND"
    assert budget["cost_ceiling_enforced_pre_dispatch"] is True
    assert result["run_summary"]["cost"]["ceiling"]["enforced_pre_dispatch"] is True


def test_currency_ceiling_requires_explicit_matching_currency(tmp_path):
    provider = CostProbeProvider()
    with pytest.raises(ValueError, match="max_cost_currency"):
        _run(
            tmp_path,
            provider,
            table=_table(),
            limits={**LIMITS, "max_cost_microunits": 10**9},
        )
    assert provider.calls == 0
    with pytest.raises(ValueError, match="currency does not match"):
        _run(
            tmp_path,
            provider,
            table=_table(),
            limits={**LIMITS, "max_cost_microunits": 10**9, "max_cost_currency": "EUR"},
        )
    assert provider.calls == 0


def test_currency_ceiling_fails_closed_without_an_exact_price_row(tmp_path):
    provider = CostProbeProvider()
    provider.identity = {"provider_id": "unpriced", "model_id": "probe-model"}
    with pytest.raises(ValueError, match="monetary budget reservation is unsupported"):
        _run(
            tmp_path,
            provider,
            table=_table(),
            limits={**LIMITS, "max_cost_microunits": 10**9, "max_cost_currency": "USD"},
        )
    assert provider.calls == 0


def test_cli_price_table_loader_is_fail_closed_and_content_free(tmp_path):
    args = SimpleNamespace(price_table=str(tmp_path / "missing.json"))
    with pytest.raises(ValueError, match="price table configuration is invalid"):
        cli._price_table(args, LIMITS)
    valid = tmp_path / "table.json"
    valid.write_text(json.dumps(TABLE_DOCUMENT), encoding="utf-8")
    loaded = cli._price_table(SimpleNamespace(price_table=str(valid)), LIMITS)
    assert loaded.revision == "rev-1"


# ---------------------------------------------------------------------------
# Stats: no cross-currency total


def _currency_summary(currency: str, microunits: int):
    base = json.loads((ROOT / "tests/fixtures/run-metrics/run-1-complete.json").read_text(encoding="utf-8"))
    base["budget"].update(
        {
            "cost_currency": currency,
            "cost_estimated_microunits": microunits,
            "cost_estimate_known": True,
            "cost_estimate_basis": "PRICE_TABLE_ESTIMATE",
            "cost_price_table_revision": "rev-1",
        }
    )
    return build_run_summary(base)


def test_stats_refuses_to_sum_across_currencies_and_keeps_unknown_explicit():
    usd = _currency_summary("USD", 100)
    eur = _currency_summary("EUR", 200)
    stats = aggregate_run_summaries([usd, eur], since=None)
    cost = stats["cost"]
    assert cost["currency_mixed"] is True
    assert cost["currency"] is None
    assert cost["estimate"]["microunits_total_known"] is None
    assert cost["estimate"]["known_runs"] == 2
    assert {row["currency"]: row["microunits_total_known"] for row in cost["estimate"]["by_currency"]} == {
        "USD": 100,
        "EUR": 200,
    }
    assert cost["estimate"]["price_table_revisions"] == [{"revision": "rev-1", "runs": 2}]
    assert cost["billing"]["known_runs"] == 0
    assert stats["missing_data"]["cost_billing_unknown"] == 2

    single = aggregate_run_summaries([usd], since=None)
    assert single["cost"]["currency"] == "USD"
    assert single["cost"]["currency_mixed"] is False
    assert single["cost"]["estimate"]["microunits_total_known"] == 100


def test_claim_assessment_cost_target_uses_claim_assessor():
    from types import SimpleNamespace

    from pr_review_harness.review_stages import _reservation_cost_target

    state = SimpleNamespace(provider="primary", decision_provider="decision", claim_assessor="claim")
    assert _reservation_cost_target(state, "claim-assessment:run", {"kind": "claim_assessment"}) == "claim"
    assert _reservation_cost_target(state, "system-one:run", {"kind": "advisory"}) == "decision"
