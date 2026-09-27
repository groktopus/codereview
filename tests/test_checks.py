import json
from pathlib import Path

import pytest

from pr_review_harness.checks import CheckEvidenceError, GitHubCheckAdapter, ingest_check_runs, make_check_runs_document
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review

HEAD = "a" * 40
REQUEST = {"repository": "owner/repo", "pull_request_number": 7, "head_sha": HEAD}
BINDINGS = [{"id": "unit-tests", "github_check_name": "unit-tests", "github_app_id": 12}]


def test_check_run_success_is_sha_and_binding_bound_evidence():
    doc = make_check_runs_document(
        "owner/repo",
        7,
        HEAD,
        [
            {
                "id": 88,
                "name": "unit-tests",
                "status": "completed",
                "conclusion": "success",
                "head_sha": HEAD,
                "app_id": 12,
                "completed_at": "2026-09-26T12:00:00Z",
            }
        ],
        captured_at="2026-09-26T12:01:00Z",
    )
    result = ingest_check_runs(doc, REQUEST, BINDINGS)
    assert result["results"]["unit-tests"]["outcome"] == "PASS"
    evidence = result["evidence"][result["results"]["unit-tests"]["evidence_id"]]
    assert evidence["head_sha"] == HEAD
    assert evidence["run_id"] == "88"
    assert evidence["source_kind"] == "github_check_run"
    assert evidence["content_hash"]


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"status": "in_progress", "conclusion": None}, "UNKNOWN"),
        ({"status": "completed", "conclusion": "failure"}, "FINDINGS"),
        ({"status": "completed", "conclusion": "neutral"}, "UNKNOWN"),
    ],
)
def test_check_run_outcomes_fail_closed(changes, expected):
    run = {
        "id": 88,
        "name": "unit-tests",
        "status": changes["status"],
        "conclusion": changes["conclusion"],
        "head_sha": HEAD,
        "app_id": 12,
        "completed_at": "2026-09-26T12:00:00Z" if changes["status"] == "completed" else None,
    }
    doc = make_check_runs_document("owner/repo", 7, HEAD, [run], captured_at="2026-09-26T12:01:00Z")
    assert ingest_check_runs(doc, REQUEST, BINDINGS)["results"]["unit-tests"]["outcome"] == expected


def test_check_evidence_wrong_head_or_ambiguous_runs_never_pass():
    doc = make_check_runs_document(
        "owner/repo",
        7,
        "b" * 40,
        [
            {
                "id": 88,
                "name": "unit-tests",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "b" * 40,
                "app_id": 12,
            }
        ],
        captured_at="2026-09-26T12:01:00Z",
    )
    with pytest.raises(CheckEvidenceError):
        ingest_check_runs(doc, REQUEST, BINDINGS)
    doc = make_check_runs_document("owner/repo", 7, HEAD, [], captured_at="2026-09-26T12:01:00Z")
    assert ingest_check_runs(doc, REQUEST, BINDINGS)["results"]["unit-tests"]["outcome"] == "UNKNOWN"


def test_unconfigured_binding_and_mismatched_app_do_not_pass():
    doc = make_check_runs_document(
        "owner/repo",
        7,
        HEAD,
        [
            {
                "id": 88,
                "name": "unit-tests",
                "status": "completed",
                "conclusion": "success",
                "head_sha": HEAD,
                "app_id": 13,
            }
        ],
        captured_at="2026-09-26T12:01:00Z",
    )
    result = ingest_check_runs(doc, REQUEST, BINDINGS)
    assert result["results"]["unit-tests"]["outcome"] == "UNKNOWN"
    assert ingest_check_runs(doc, REQUEST, [{"id": "x"}])["results"]["x"]["outcome"] == "UNKNOWN"


def test_same_name_duplicate_reruns_and_naive_timestamps_fail_closed():
    run = {
        "id": 88,
        "name": "unit-tests",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "app_id": 12,
        "completed_at": "2026-09-26T12:00:00Z",
    }
    doc = make_check_runs_document("owner/repo", 7, HEAD, [run, {**run, "id": 89}], captured_at="2026-09-26T12:01:00Z")
    result = ingest_check_runs(doc, REQUEST, BINDINGS)
    assert result["results"]["unit-tests"]["outcome"] == "UNKNOWN"
    with pytest.raises(CheckEvidenceError):
        make_check_runs_document("owner/repo", 7, HEAD, [run], captured_at="2026-09-26T12:01:00")


def test_slopsearx_v4_has_separate_exact_pr464_check_bindings():
    root = Path(__file__).resolve().parents[1]
    profile = json.loads((root / "profiles/slopsearx.json").read_text())
    document = json.loads((root / "tests/fixtures/pr464-check-evidence.json").read_text())
    assert profile["version"] == "slopsearx-production-v4-context-selection"
    assert len(document["runs"]) == 20
    assert document["fixture_provenance"]["source_capture_sha256"] == (
        "989e65b14d1a43f37b4abaaf2be55b49c3b07ecf50d3e786eb99ff3f22f0450b"
    )
    bindings = profile["required_checks"]
    assert [(item["id"], item["github_check_name"], item["github_app_id"]) for item in bindings] == [
        ("portal-impact-evidence", "portal-contract", 15368),
        ("portal-browser-evidence", "portal-browser", 15368),
    ]

    request = {
        "repository": document["repository"],
        "pull_request_number": document["pull_request_number"],
        "head_sha": document["head_sha"],
    }
    result = ingest_check_runs(document, request, bindings)
    assert {item["outcome"] for item in result["results"].values()} == {"PASS"}
    assert set(result["results"]) == {"portal-impact-evidence", "portal-browser-evidence"}
    assert len({item["evidence_id"] for item in result["results"].values()}) == 2


def _fixture_engine_inputs():
    root = Path(__file__).resolve().parents[1]
    document = json.loads((root / "tests/fixtures/pr464-check-evidence.json").read_text())
    bindings = [
        {
            "id": "external:portal-contract",
            "check_id": "portal-impact-evidence",
            "github_check_name": "portal-contract",
            "github_app_id": 15368,
            "unit_ids": ["u0"],
        },
        {
            "id": "external:portal-browser",
            "check_id": "portal-browser-evidence",
            "github_check_name": "portal-browser",
            "github_app_id": 15368,
            "unit_ids": ["u0"],
        },
    ]
    request = {
        "repository": document["repository"],
        "pull_request_number": document["pull_request_number"],
        "head_sha": document["head_sha"],
    }
    ingested = ingest_check_runs(document, request, bindings)
    profile = {
        "version": "checks-engine-integration-v1",
        "required_lenses": [],
        "allow_empty_approve": True,
        "required_checks": [
            {
                "id": item["check_id"],
                "unit_ids": item["unit_ids"],
                "binding": item["id"],
                "github_check_name": item["github_check_name"],
                "github_app_id": item["github_app_id"],
            }
            for item in bindings
        ],
    }
    snapshot = {
        "snapshot_id": "snap-pr464-checks-test",
        "snapshot_hash": "e" * 64,
        "base_sha": "2" * 40,
        "head_sha": request["head_sha"],
        "repository": request["repository"],
        "pull_request_number": request["pull_request_number"],
        "profile_version": profile["version"],
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [{"unit_id": "u0", "path": "src/example.py", "kind": "human_code", "evidence_ids": []}],
        "evidence": ingested["evidence"],
        "external_check_results": ingested["results"],
        "gaps": [],
    }
    limits = {
        "deadline_seconds": 2,
        "max_concurrent_scopes": 2,
        "max_provider_calls": 8,
        "max_retries_per_task": 0,
        "max_context_bytes": 120_000,
        "max_input_bytes_per_task": 45_000,
        "max_output_bytes_per_task": 16_000,
        "max_output_bytes": 192_000,
        "max_context_retrievals": 8,
        "max_followup_tasks": 8,
    }
    plan = plan_review(snapshot, profile, "AUTO")
    return snapshot, profile, plan, limits


def _run_engine(snapshot, profile, plan, limits, output_dir):
    return run_review(
        snapshot,
        plan,
        profile,
        None,
        None,
        limits,
        str(output_dir),
        "check-integration",
        check_adapter=GitHubCheckAdapter(),
    )


def test_engine_check_coverage_preserves_actual_ingested_binding_evidence(tmp_path):
    snapshot, profile, plan, limits = _fixture_engine_inputs()

    result = _run_engine(snapshot, profile, plan, limits, tmp_path)

    rows = {row["check_binding_id"]: row for row in result["coverage_ledger"]}
    tasks = {task["check_binding_id"]: result["task_results"][task["task_id"]] for task in plan["tasks"]}
    assert set(rows) == {"external:portal-contract", "external:portal-browser"}
    for binding_id in rows:
        task_result = tasks[binding_id]
        evidence_id = snapshot["external_check_results"][binding_id]["evidence_id"]
        assert task_result["status"] == "SUCCEEDED"
        assert task_result["input_evidence_ids"] == [evidence_id]
        assert task_result["payload"]["evidence_refs"] == [evidence_id]
        assert rows[binding_id]["state"] == "COMPLETE"
        assert rows[binding_id]["evidence_refs"] == [evidence_id]


@pytest.mark.parametrize("mismatch", ["cross_binding", "missing_snapshot_evidence", "missing_reference"])
def test_engine_check_coverage_rejects_unbound_or_missing_ingested_evidence(tmp_path, mismatch):
    snapshot, profile, plan, limits = _fixture_engine_inputs()
    target_binding = "external:portal-contract"
    external_result = snapshot["external_check_results"][target_binding]
    if mismatch == "cross_binding":
        external_result["evidence_id"] = snapshot["external_check_results"]["external:portal-browser"]["evidence_id"]
    elif mismatch == "missing_snapshot_evidence":
        snapshot["evidence"].pop(external_result["evidence_id"])
    else:
        external_result.pop("evidence_id")

    result = _run_engine(snapshot, profile, plan, limits, tmp_path)

    check_row = next(row for row in result["coverage_ledger"] if row["check_binding_id"] == target_binding)
    task = next(task for task in plan["tasks"] if task["check_binding_id"] == target_binding)
    task_result = result["task_results"][task["task_id"]]
    assert check_row["state"] == "PARTIAL"
    assert check_row["evidence_refs"] == []
    assert result["disposition"] == "INCOMPLETE"
    if mismatch == "missing_reference":
        assert task_result["status"] == "INVALID"
    else:
        assert task_result["status"] == "INVALID"
        assert task_result["input_evidence_ids"] == []
