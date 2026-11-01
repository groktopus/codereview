"""OE-1: versioned run summaries, fixture aggregation, and the stats surface."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from test_engine import LIMITS, EmptyProvider, make_snapshot, profile

from pr_review_harness import cli
from pr_review_harness.engine import render_report, run_review
from pr_review_harness.metrics import (
    RUN_METRICS_SCHEMA,
    RUN_SUMMARY_SCHEMA,
    aggregate_run_summaries,
    build_run_summary,
    filter_run_summaries,
    read_results,
    render_stats_text,
    summarize_results,
)
from pr_review_harness.planner import plan_review

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/run-metrics"
SCHEMA = json.loads((ROOT / "schemas/review-run-summary.v1.schema.json").read_text(encoding="utf-8"))
SINCE = "2026-10-01T00:00:00Z"


def _fixture_results() -> list[dict]:
    return read_results(sorted(FIXTURES.glob("*.json")))


def _fixture_stats(*, since: str | None = SINCE) -> tuple[dict, list[dict]]:
    results = _fixture_results()
    summaries, sources = summarize_results(results)
    selected, excluded = filter_run_summaries(summaries, since=since)
    return (
        aggregate_run_summaries(
            selected,
            since=since,
            excluded=excluded,
            input_total=len(results),
            summary_sources=sources,
        ),
        selected,
    )


def test_run_summary_schema_accepts_every_fixture_record():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for result in _fixture_results():
        summary = build_run_summary(result)
        assert summary["schema"] == RUN_SUMMARY_SCHEMA
        validator.validate(summary)
        # The record is content-free: no prompts, source text, findings, or tasks.
        serialized = json.dumps(summary)
        for forbidden in ("coverage_ledger", "task_results", "findings", "report_sections", "evidence_index"):
            assert forbidden not in serialized


def test_fixture_aggregation_reports_denominators_missing_data_and_percentiles():
    stats, selected = _fixture_stats()

    assert stats["schema"] == RUN_METRICS_SCHEMA
    assert len(selected) == 3
    assert stats["runs"] == {
        "input": 4,
        "included": 3,
        "excluded": 1,
        "before_since": 0,
        "after_until": 0,
        "missing_created_at": 1,
        "summary_records_embedded": 0,
        "summary_records_derived": 4,
    }
    assert stats["denominators"] == {
        "obligations": 5,
        "incomplete_obligations": 2,
        "runs": 3,
        "runs_with_required_obligations": 3,
        "provider_calls": 5,
    }

    completion = stats["completion"]
    assert completion["required_obligations_total"] == 5
    assert completion["complete_obligations"] == 3
    assert completion["partial_obligations"] == 1
    assert completion["not_started_obligations"] == 1
    assert completion["incomplete_obligations_total"] == 2
    assert completion["complete_ratio_by_obligations"] == 0.6
    assert completion["resolved_ratio_by_obligations"] == 0.8
    assert completion["runs_fully_complete"] == 1
    assert completion["completion_rate_by_runs"] == pytest.approx(1 / 3, abs=1e-6)

    reasons = {row["canonical_code"]: row for row in stats["reason_distribution"]}
    assert set(reasons) == {"CONTEXT_GAP_UNRESOLVED", "PROVIDER_UNAVAILABLE"}
    assert reasons["CONTEXT_GAP_UNRESOLVED"]["obligations"] == 1
    assert reasons["CONTEXT_GAP_UNRESOLVED"]["share_of_incomplete"] == 0.5
    assert reasons["PROVIDER_UNAVAILABLE"]["obligations"] == 1

    assert {row["value"]: row["runs"] for row in stats["terminal_state_distribution"]} == {
        "APPROVE": 1,
        "INCOMPLETE": 2,
    }
    assert {row["value"]: row["runs"] for row in stats["freshness_distribution"]} == {
        "CURRENT": 1,
        "STALE": 1,
        "UNKNOWN": 1,
    }

    assert stats["providers"]["calls_reserved"] == {"total": 5, "known_runs": 3, "missing_runs": 0}
    assert stats["providers"]["calls_settled"] == {"total": 5, "known_runs": 2, "missing_runs": 1}
    assert stats["providers"]["retries"] == {"total": 1, "known_runs": 2, "missing_runs": 1}

    prompt = stats["tokens"]["fields"]["prompt_tokens"]
    assert prompt["reported_sum"] == 1300
    assert prompt["reported_count"] == 3
    assert prompt["unknown_count"] == 2
    assert prompt["denominator_calls"] == 5
    assert prompt["complete_for_all_calls"] is False
    assert stats["tokens"]["fields"]["input_tokens"]["reported_sum"] is None

    elapsed = stats["latency"]["run_elapsed_ms"]
    assert elapsed["n"] == 2
    assert elapsed["p50"] == 1000.0
    assert elapsed["p95"] == 3000.0
    primary = stats["latency"]["by_stage"]["primary"]
    assert primary["n_runs"] == 2
    assert primary["call_observations"] == 5
    assert primary["p50_run_stage_ms"] == 900.0
    assert primary["p95_run_stage_ms"] == 2100.0

    estimate = stats["cost"]["estimate"]
    assert estimate["known_runs"] == 1
    assert estimate["unknown_runs"] == 2
    assert estimate["microunits_total_known"] == 120
    assert estimate["complete_for_all_runs"] is False
    assert {row["basis"]: row["runs"] for row in estimate["basis_distribution"]} == {
        "PROVIDER_REPORTED_ESTIMATE": 1,
        "UNKNOWN": 2,
    }
    billing = stats["cost"]["billing"]
    assert billing["known_runs"] == 0
    assert billing["microunits_total_known"] is None
    assert billing["unknown_runs"] == 3

    missing = stats["missing_data"]
    assert missing["run_elapsed_ms_missing"] == 1
    assert missing["stage_latency_missing"] == 1
    assert missing["tokens_all_unknown"] == 0
    assert missing["runs_without_provider_calls"] == 1
    assert missing["cost_estimate_unknown"] == 2
    assert missing["cost_billing_unknown"] == 3
    assert missing["freshness_unknown"] == 1

    # The human text names denominators and never claims a missing percentile.
    text = render_stats_text(stats)
    assert "included 3 of 4 results" in text
    assert "3/5 required obligations complete" in text
    assert "run wall p50 1000.0 ms, p95 3000.0 ms (n=2)" in text
    assert "prompt_tokens 1300 (3/5 calls reported)" in text
    assert "estimate 120 microunits known for 1 runs, unknown for 2 runs" in text


def test_unknown_values_stay_null_in_summary_and_aggregate():
    result = {
        "run_id": "unknown-run",
        "created_at": "2026-10-05T00:00:00Z",
        "contract_version": "0.1",
        "coverage_state": "PARTIAL",
        "freshness": "UNKNOWN",
        "disposition": "INCOMPLETE",
        "coverage_ledger": [
            {
                "obligation_id": "unit:u1:lens:correctness",
                "obligation_kind": "CHANGED_UNIT_LENS",
                "required": True,
                "scope_unit_ids": ["u1"],
                "task_ids": ["task-u1"],
                "state": "PARTIAL",
                "reason_code": "TASK_FAILED",
            }
        ],
        "budget": {
            "provider_calls_reserved": 2,
            "cost_estimated_microunits": 0,
            "cost_estimate_known": False,
            "cost_billed_microunits": 0,
            "cost_billing_known": False,
            "provider_observability": {
                "provider_calls_reserved": 2,
                "stages": {
                    "primary": {
                        "provider_calls_reserved": 2,
                        "settled_calls": 2,
                        "usage_known": 0,
                        "usage_partial": 0,
                        "usage_unknown": 2,
                        "usage_fields": {
                            "prompt_tokens": {"reported_count": 0, "reported_sum": 0},
                            "completion_tokens": {"reported_count": 0, "reported_sum": 0},
                            "input_tokens": {"reported_count": 0, "reported_sum": 0},
                            "output_tokens": {"reported_count": 0, "reported_sum": 0},
                            "total_tokens": {"reported_count": 0, "reported_sum": 0},
                        },
                    }
                },
            },
        },
    }
    summary = build_run_summary(result)

    assert summary["tokens"]["fields"]["prompt_tokens"]["reported_sum"] is None
    assert summary["tokens"]["fields"]["prompt_tokens"]["unknown_count"] == 2
    assert summary["cost"]["estimate"] == {"microunits": None, "known": False, "basis": "UNKNOWN"}
    assert summary["cost"]["billing"]["microunits"] is None
    assert summary["latency"]["run_elapsed_ms"] is None

    stats, _selected = _fixture_stats(since=None)
    assert stats["runs"]["included"] == 4
    assert stats["tokens"]["fields"]["input_tokens"]["reported_sum"] is None

    single = aggregate_run_summaries([summary], since=None)
    assert single["tokens"]["fields"]["prompt_tokens"]["reported_sum"] is None
    assert single["cost"]["estimate"]["microunits_total_known"] is None
    assert single["cost"]["billing"]["microunits_total_known"] is None
    assert single["latency"]["run_elapsed_ms"]["p50"] is None
    assert single["latency"]["run_elapsed_ms"]["n"] == 0


def test_ledger_results_rebuild_embedded_summaries(tmp_path, capsys):
    result = json.loads((FIXTURES / "run-1-complete.json").read_text(encoding="utf-8"))
    result["run_summary"] = build_run_summary(result)
    (tmp_path / "embedded.json").write_text(json.dumps(result), encoding="utf-8")

    assert cli.main(["stats", "--results-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"]["included"] == 1
    assert payload["runs"]["summary_records_embedded"] == 0
    assert payload["runs"]["summary_records_derived"] == 1
    assert payload["completion"]["complete_obligations"] == 2


def test_summary_only_input_is_reused(tmp_path, capsys):
    result = json.loads((FIXTURES / "run-1-complete.json").read_text(encoding="utf-8"))
    (tmp_path / "summary-only.json").write_text(
        json.dumps({"run_summary": build_run_summary(result)}), encoding="utf-8"
    )
    assert cli.main(["stats", "--results-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"]["summary_records_embedded"] == 1
    assert payload["runs"]["summary_records_derived"] == 0


def test_malformed_embedded_summary_is_rebuilt_from_the_ledger():
    result = json.loads((FIXTURES / "run-1-complete.json").read_text(encoding="utf-8"))
    result["run_summary"] = {
        "schema": "review-run-summary.v1",
        "identity": {},
        "run": {},
        "obligations": {},
        "tokens": {"fields": {}},
        "latency": {},
        "cost": {"estimate": {}, "billing": {}},
    }
    summaries, sources = summarize_results([result])
    assert sources == {"embedded": 0, "derived": 1}
    assert summaries[0]["obligations"]["required_total"] == 2


def test_resume_rebuilds_the_run_summary():
    from pr_review_harness.review_stages import _reseal_resumed_result

    result = json.loads((FIXTURES / "run-1-complete.json").read_text(encoding="utf-8"))
    result["run_summary"] = build_run_summary(result)
    result["freshness"] = "UNKNOWN"
    result["disposition"] = "INCOMPLETE"
    _reseal_resumed_result(result)
    assert result["run_summary"]["run"]["freshness"]["state"] == "UNKNOWN"
    assert result["run_summary"]["run"]["terminal_state"] == "INCOMPLETE"


def test_duplicate_input_paths_are_one_run(tmp_path, capsys):
    source = FIXTURES / "run-1-complete.json"
    assert cli.main(
        [
            "stats",
            "--result",
            str(source),
            "--results-dir",
            str(FIXTURES),
            "--json",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"]["input"] == 4
    assert payload["runs"]["included"] == 4


def test_jsonl_cannot_overwrite_an_input(tmp_path, capsys):
    source = tmp_path / "a.json"
    source.write_text((FIXTURES / "run-1-complete.json").read_text(), encoding="utf-8")
    before = source.read_text()
    assert cli.main(["stats", "--results-dir", str(tmp_path), "--jsonl", str(source), "--json"]) == 2
    assert source.read_text() == before
    assert "must not overwrite" in capsys.readouterr().err


def test_duplicate_run_ids_fail_closed(tmp_path, capsys):
    data = json.loads((FIXTURES / "run-1-complete.json").read_text(encoding="utf-8"))
    for name in ("a.json", "b.json"):
        (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")
    assert cli.main(["stats", "--results-dir", str(tmp_path), "--json"]) == 2
    assert "duplicate run_id" in capsys.readouterr().err


def test_stats_cli_json_and_jsonl_export(tmp_path, capsys):
    jsonl = tmp_path / "run-summaries.jsonl"
    code = cli.main(
        [
            "stats",
            "--results-dir",
            str(FIXTURES),
            "--since",
            SINCE,
            "--json",
            "--jsonl",
            str(jsonl),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == RUN_METRICS_SCHEMA
    assert payload["runs"]["included"] == 3
    assert payload["jsonl_export"]["records"] == 3
    assert "included 3 of 4 results" in payload["summary"]

    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for line in lines:
        record = json.loads(line)
        assert record["schema"] == RUN_SUMMARY_SCHEMA
        validator.validate(record)


def test_stats_cli_rejects_invalid_inputs(tmp_path, capsys):
    assert cli.main(["stats", "--results-dir", str(tmp_path / "missing"), "--json"]) == 2
    assert "stats_input_invalid" in capsys.readouterr().out

    assert cli.main(["stats", "--results-dir", str(FIXTURES), "--since", "not-a-time", "--json"]) == 2
    assert "invalid --since timestamp" in capsys.readouterr().out


def test_run_review_emits_a_run_summary_and_report_metrics_line(tmp_path):
    snapshot = make_snapshot()
    project_profile = profile()
    result = run_review(
        snapshot,
        plan_review(snapshot, project_profile, "AUTO"),
        project_profile,
        EmptyProvider(),
        None,
        {**LIMITS, "max_provider_calls": 4},
        str(tmp_path),
        "metrics-emission",
    )

    summary = result["run_summary"]
    assert summary["schema"] == RUN_SUMMARY_SCHEMA
    jsonschema.Draft202012Validator(SCHEMA).validate(summary)
    stored = json.loads((tmp_path / "metrics-emission.json").read_text(encoding="utf-8"))
    assert stored["run_summary"] == summary
    assert "Run metrics (review-run-summary.v1)" in render_report(result)
