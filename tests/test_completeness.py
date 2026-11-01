"""Contract tests for the canonical completeness taxonomy, summary, and gate."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pr_review_harness.completeness import (
    BASELINE_SCHEMA,
    COMPLETE_REASON_CODES,
    REASON_TAXONOMY,
    SUMMARY_SCHEMA,
    TAXONOMY_DOC,
    TAXONOMY_VERSION,
    build_baseline,
    build_completeness_summary,
    classify_reason,
    compare_to_baseline,
    render_summary_text,
    summary_from_result,
    taxonomy_document,
)
from pr_review_harness.engine import _reduce, run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.report import render_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/completeness"


def _row(obligation_id, state, reason_code, *, required=True, kind="CHANGED_UNIT_LENS"):
    return {
        "obligation_id": obligation_id,
        "obligation_kind": kind,
        "required": required,
        "scope_unit_ids": [obligation_id.split(":")[1] if ":" in obligation_id else "u0"],
        "task_ids": [f"task-{obligation_id}"],
        "state": state,
        "reason_code": reason_code,
        "context_gap_ids": [],
        "evidence_refs": [],
    }


def test_summary_counts_required_denominator_and_reason_distribution():
    summary = build_completeness_summary(
        [
            _row("unit:u0:lens:correctness", "COMPLETE", "VALID_RESULT"),
            _row("unit:u1:lens:correctness", "COMPLETE", "VALID_RESULT"),
            _row("unit:u2:lens:correctness", "PARTIAL", "CONTEXT_GAP_UNRESOLVED"),
            _row("unit:u3:lens:correctness", "PARTIAL", "ipc_envelope_truncated"),
            _row("unit:u4:lens:correctness", "NOT_STARTED", "CHECK_RESULT_UNAVAILABLE"),
            _row("unit:u5:lens:correctness", "PARTIAL", "PARTIAL_REVIEW_COVERAGE", required=False),
        ],
        [{"obligation_id": "unit:u6:lens:security", "reason": "configured_path_patterns_did_not_match"}],
    )

    assert summary["schema"] == SUMMARY_SCHEMA
    assert summary["taxonomy_version"] == TAXONOMY_VERSION
    assert summary["ledger_total"] == 6
    assert summary["non_required"] == 1
    assert summary["required_total"] == 5
    assert (summary["complete"], summary["partial"], summary["not_started"], summary["unknown_state"]) == (2, 2, 1, 0)
    assert summary["incomplete_total"] == 3
    assert summary["not_applicable"] == 1
    assert summary["zero_obligations"] is False
    assert summary["complete_ratio"] == 0.4
    assert summary["resolved_ratio"] == 0.8
    assert summary["reason_distribution_denominator"] == 3
    assert summary["unclassified_obligations"] == 0

    distribution = {item["canonical_code"]: item for item in summary["reason_distribution"]}
    assert set(distribution) == {
        "CONTEXT_EVIDENCE_TRUNCATED",
        "CONTEXT_GAP_UNRESOLVED",
        "CHECK_EVIDENCE_UNAVAILABLE",
    }
    truncated = distribution["CONTEXT_EVIDENCE_TRUNCATED"]
    assert truncated["obligations"] == 1
    assert truncated["share_of_incomplete"] == pytest.approx(1 / 3, abs=1e-6)
    assert truncated["share_of_required"] == 0.2
    assert truncated["states"]["PARTIAL"] == 1
    assert truncated["legacy_codes"] == [{"code": "ipc_envelope_truncated", "obligations": 1}]


def test_summary_keeps_zero_obligation_runs_explicit():
    summary = build_completeness_summary([], [{"obligation_id": "not-applicable", "reason": "no_match"}])

    assert summary["required_total"] == 0
    assert summary["zero_obligations"] is True
    assert summary["complete_ratio"] is None
    assert summary["resolved_ratio"] is None
    assert summary["reason_distribution"] == []
    assert summary["reason_distribution_denominator"] == 0
    assert summary["not_applicable"] == 1
    assert "zero required obligations" in render_summary_text(summary)


def test_non_required_rows_alone_are_still_a_zero_obligation_denominator():
    summary = build_completeness_summary([_row("unit:u0:lens:correctness", "PARTIAL", "PARTIAL_REVIEW_COVERAGE", required=False)])

    assert summary["ledger_total"] == 1
    assert summary["non_required"] == 1
    assert summary["required_total"] == 0
    assert summary["zero_obligations"] is True
    assert summary["complete_ratio"] is None


def test_reason_mapping_is_versioned_complete_and_preserves_unknown_strings():
    document = taxonomy_document()
    assert document["version"] == TAXONOMY_VERSION
    assert document["documentation"] == TAXONOMY_DOC
    assert len(document["reasons"]) == len(REASON_TAXONOMY)

    canonical_codes = {entry["code"] for entry in REASON_TAXONOMY}
    for entry in REASON_TAXONOMY:
        for legacy in entry["legacy_codes"]:
            assert classify_reason(legacy) == entry["code"]
    assert classify_reason("CONTEXT_GAP_UNRESOLVED") in canonical_codes
    assert classify_reason("ipc_envelope_truncated") == "CONTEXT_EVIDENCE_TRUNCATED"
    assert classify_reason("CHECK_RESULT_UNAVAILABLE") == "CHECK_EVIDENCE_UNAVAILABLE"
    assert classify_reason("VALID_RESULT") == "VALID_RESULT"
    assert "VALID_RESULT" in COMPLETE_REASON_CODES
    assert classify_reason(None) == "MISSING_REASON"
    assert classify_reason("") == "MISSING_REASON"
    assert classify_reason("brand_new_provider_code_that_is_not_mapped") == "UNCLASSIFIED_REASON"


def test_unclassified_reason_stays_visible_in_the_distribution():
    summary = build_completeness_summary(
        [_row("unit:u0:lens:correctness", "PARTIAL", "brand_new_provider_code_that_is_not_mapped")]
    )

    assert summary["unclassified_obligations"] == 1
    assert summary["reason_distribution"][0]["canonical_code"] == "UNCLASSIFIED_REASON"
    assert summary["reason_distribution"][0]["legacy_codes"] == [
        {"code": "brand_new_provider_code_that_is_not_mapped", "obligations": 1}
    ]


def test_unknown_state_is_not_silently_promoted():
    row = _row("unit:u0:lens:correctness", "WEIRD", "CONTEXT_GAP_UNRESOLVED")
    summary = build_completeness_summary([row])

    assert summary["unknown_state"] == 1
    assert summary["complete"] == 0
    assert summary["incomplete_total"] == 1
    assert summary["reason_distribution"][0]["states"]["UNKNOWN"] == 1


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _baseline() -> dict:
    return _fixture("baseline.v1.json")


def test_comparison_passes_the_baseline_fixture_and_fails_the_seeded_regression():
    passed = compare_to_baseline(_fixture("good-result.json"), _baseline())
    assert passed["status"] == "PASS"
    assert passed["findings"] == []
    assert passed["current"]["complete"] == 2
    assert passed["baseline"]["complete"] == 2

    failed = compare_to_baseline(_fixture("seeded-regression-result.json"), _baseline())
    assert failed["status"] == "FAIL"
    codes = {finding["code"] for finding in failed["findings"]}
    assert "KNOWN_COMPLETE_REGRESSION" in codes
    assert "COMPLETION_RATIO_REGRESSION" in codes
    assert any("ipc_envelope_truncated" in finding["message"] for finding in failed["findings"])


def test_comparison_rejects_missing_case_and_absolute_floor():
    missing = compare_to_baseline(_fixture("good-result.json"), _baseline(), case_id="not-in-baseline")
    assert missing["status"] == "FAIL"
    assert [finding["code"] for finding in missing["findings"]] == ["CASE_NOT_IN_BASELINE"]

    floor = compare_to_baseline(_fixture("good-result.json"), _baseline(), min_completion_ratio=0.75)
    assert floor["status"] == "FAIL"
    assert {finding["code"] for finding in floor["findings"]} == {"BELOW_MIN_COMPLETION_RATIO"}


def test_comparison_rejects_stale_embedded_summary_and_missing_obligation():
    good = _fixture("good-result.json")
    good["completeness_summary"] = {
        "schema": SUMMARY_SCHEMA,
        "taxonomy_version": TAXONOMY_VERSION,
        "required_total": 1,
        "complete": 1,
        "partial": 0,
        "not_started": 0,
        "unknown_state": 0,
        "not_applicable": 0,
        "incomplete_total": 0,
        "reason_distribution_denominator": 0,
    }
    stale = compare_to_baseline(good, _baseline())
    assert stale["status"] == "FAIL"
    assert "SUMMARY_INCONSISTENT" in {finding["code"] for finding in stale["findings"]}

    dropped = _fixture("good-result.json")
    dropped["coverage_ledger"] = [
        row for row in dropped["coverage_ledger"] if row["obligation_id"] != "unit:u1:lens:tests"
    ]
    missing_obligation = compare_to_baseline(dropped, _baseline())
    assert missing_obligation["status"] == "FAIL"
    assert "OBLIGATION_MISSING" in {finding["code"] for finding in missing_obligation["findings"]}


def test_baseline_roundtrip_and_zero_obligation_case():
    zero_result = {
        "case_id": "zero-case",
        "coverage_ledger": [],
        "not_applicable": [{"obligation_id": "not-applicable", "reason": "no_match"}],
    }
    baseline = build_baseline([zero_result], corpus={"name": "zero"})
    assert baseline["schema"] == BASELINE_SCHEMA
    assert baseline["cases"]["zero-case"]["zero_obligations"] is True
    verdict = compare_to_baseline(zero_result, baseline)
    assert verdict["status"] == "PASS"
    assert verdict["current"]["complete_ratio"] is None


def test_gate_cli_passes_the_fixture_and_demonstrably_fails_a_seeded_regression():
    script = ROOT / "scripts/check_completeness.py"
    baseline = FIXTURES / "baseline.v1.json"
    passed = subprocess.run(
        [sys.executable, str(script), "--baseline", str(baseline), "--result", str(FIXTURES / "good-result.json")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert passed.returncode == 0, passed.stderr
    assert "[PASS]" in passed.stdout

    failed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--baseline",
            str(baseline),
            "--result",
            str(FIXTURES / "seeded-regression-result.json"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "[FAIL]" in failed.stdout
    assert "KNOWN_COMPLETE_REGRESSION" in failed.stdout


def test_gate_cli_summary_only_emits_the_summary_without_a_baseline():
    script = ROOT / "scripts/check_completeness.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--result",
            str(FIXTURES / "good-result.json"),
            "--summary-only",
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "SUMMARY"
    assert payload["results"][0]["completeness_summary"]["required_total"] == 4


def test_report_renders_completeness_without_changing_sections_or_disposition():
    result = _fixture("good-result.json")
    rendered = render_report(result)

    assert rendered.splitlines()[0] == "PR review completeness-fixture-good: INCOMPLETE"
    assert "Completeness (review-completeness-taxonomy.v1): 2/4 required complete (50.0%)" in rendered
    assert "incomplete reasons (2/4 required)" in rendered
    assert TAXONOMY_DOC in rendered
    assert rendered.count("## ") == 4
    for title in ("Blockers", "Suggested improvements", "Specific strengths", "Future guidance"):
        assert f"## {title}" in rendered
    assert result["disposition"] == "INCOMPLETE"
    assert "2 complete, 2 partial, 1 not started across 5 obligations." in rendered


def test_summary_does_not_change_the_deterministic_disposition():
    result = _fixture("good-result.json")
    without = _reduce(result, result.get("allow_empty_approve", False), result.get("policy_valid", False))
    result["completeness_summary"] = summary_from_result(result)
    with_summary = _reduce(result, result.get("allow_empty_approve", False), result.get("policy_valid", False))
    assert with_summary == without == "INCOMPLETE"


def test_summary_cannot_change_an_approve_or_incomplete_reduction():
    approving = {
        "findings": [],
        "coverage_state": "COMPLETE",
        "freshness": "CURRENT",
        "budget": {},
    }
    before = _reduce(approving, True, True)
    approving["completeness_summary"] = {
        "required_total": 1,
        "partial": 1,
        "complete": 0,
    }
    assert before == _reduce(approving, True, True) == "APPROVE"

    incomplete = _fixture("good-result.json")
    assert _reduce(incomplete, False, False) == "INCOMPLETE"
    incomplete["completeness_summary"] = summary_from_result(incomplete)
    assert _reduce(incomplete, True, True) == "INCOMPLETE"


class _PartialStaticProvider:
    identity = {"kind": "offline-test-double", "model": "completeness-fixture"}

    def review(self, task, _evidence, _limits):
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit_id,
                        "state": "PARTIAL",
                        "reason_code": "STATIC_TEST_CONTEXT_INSUFFICIENT",
                        "coverage_basis": "STATIC_REVIEW",
                        "evidence_refs": list(task["evidence_ids"]),
                    }
                    for unit_id in task["unit_ids"]
                ],
                "specific_strengths": [],
                "future_guidance": [],
            },
            "usage": {},
            "provenance": {"transport": "offline_test_double"},
        }


def test_engine_emits_the_summary_for_a_real_run_and_keeps_disposition(tmp_path):
    base_sha = "b" * 40
    head_sha = "c" * 40
    snapshot = {
        "snapshot_id": "snap-completeness-engine",
        "snapshot_hash": "d" * 64,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "repository": "example/repository",
        "pull_request_number": 7,
        "profile_version": "completeness-engine-v1",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "u0",
                "path": "src/example.py",
                "kind": "human_code",
                "change": "modified",
                "evidence_ids": ["diff:u0"],
            }
        ],
        "evidence": {
            "diff:u0": {
                "evidence_id": "diff:u0",
                "snapshot_id": "snap-completeness-engine",
                "path": "src/example.py",
                "source_revision": head_sha,
                "content": "-old\n+new",
                "content_hash": "1" * 64,
                "source_kind": "diff",
                "trust": "untrusted_pr_content",
            }
        },
        "gaps": [],
    }
    profile = {
        "version": "completeness-engine-v1",
        "required_lenses": ["correctness"],
        "allow_empty_approval": True,
        "review_criteria": {"correctness": "Assess the changed behavior."},
    }
    limits = {
        "deadline_seconds": 2,
        "max_concurrent_scopes": 1,
        "max_provider_calls": 4,
        "max_retries_per_task": 0,
        "max_context_bytes": 20_000,
        "max_input_bytes_per_task": 45_000,
        "max_output_bytes_per_task": 4_000,
        "max_output_bytes": 8_000,
        "max_context_retrievals": 0,
        "max_followup_tasks": 0,
    }
    plan = plan_review(snapshot, profile, "AUTO")
    result = run_review(
        snapshot,
        plan,
        profile,
        _PartialStaticProvider(),
        None,
        limits,
        str(tmp_path),
        "completeness-engine",
    )

    summary = result["completeness_summary"]
    required_rows = [row for row in result["coverage_ledger"] if row.get("required", True)]
    assert summary["schema"] == SUMMARY_SCHEMA
    assert summary["required_total"] == len(required_rows)
    assert summary["complete"] + summary["partial"] + summary["not_started"] + summary["unknown_state"] == len(
        required_rows
    )
    assert summary["partial"] >= 1
    assert summary["reason_distribution"]
    assert result["findings"] == []
    assert summary["required_total"] >= 1
    assert result["disposition"] == "INCOMPLETE"
    assert result["disposition"] == _reduce(
        result,
        result.get("allow_empty_approve", False),
        result.get("policy_valid", False),
    )
    rendered = render_report(result)
    assert "Completeness (review-completeness-taxonomy.v1)" in rendered
    assert rendered.count("## ") == 4


def test_every_provider_and_contract_error_code_is_classified():
    import ast

    codes = set()
    for name in ("providers.py", "contracts.py", "claim_assessment.py", "claim_transport.py"):
        source = Path(__file__).resolve().parents[1] / "src/pr_review_harness" / name
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if func not in {"ProviderError", "ContractIssue"}:
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.replace("_", "").isalnum():
                        codes.add(arg.value)
    assert codes
    unclassified = sorted(code for code in codes if classify_reason(code) == "UNCLASSIFIED_REASON")
    assert unclassified == []
    assert classify_reason("http_status_500") == "PROVIDER_UNAVAILABLE"
    assert classify_reason("cache_unavailable") == "UNCLASSIFIED_REASON"
    assert classify_reason("invalid_future_semantics") == "UNCLASSIFIED_REASON"
