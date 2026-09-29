from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import finalize_model_only_shadow_live_plans_v3 as finalizer  # noqa: E402


def _prepared(case_id: str) -> dict:
    case = finalizer.CASES[case_id]
    proposal_path = ROOT / (
        "experiments/model-only-shadow-live-pr457-plan-v3-proposal.json"
        if case_id == "PR-457" else "experiments/model-only-shadow-live-pr464-plan-v3-proposal.json"
    )
    proposal = json.loads(proposal_path.read_text())
    identity = proposal["case"]
    old_plan = json.loads((ROOT / case["old_plan"]).read_text())
    writer_requests = proposal.get("writer_requests")
    if writer_requests is None:
        writer_requests = old_plan["writer_requests"]
    runtime = proposal.get("runtime", old_plan["runtime"])
    def ident(key):
        return identity.get(key, old_plan["case"].get(key))
    primary = [{**row, "admitted": True} for row in writer_requests]
    source_rows = proposal.get("source_audit_preflight", {}).get("requests")
    if source_rows is None:
        source_rows = [
            {"task_id": row["task_id"], "input_bytes": 113_860 if case_id == "PR-457" and index < 3 else 70_000 + index,
             "input_sha256": hashlib.sha256(f"{case_id}-{index}".encode()).hexdigest(), "admitted": True}
            for index, row in enumerate(primary)
        ]
    else:
        source_rows = [{**row, "admitted": True} for row in source_rows]
    return {
        "command": "review", "status": "PREPARED_ONLY", "no_provider_calls": True,
        "no_target_code_execution": True, "disposition": None,
        "snapshot": {
            "base_sha": identity["base_sha"], "head_sha": identity["head_sha"],
            "snapshot_id": identity["snapshot_id"], "snapshot_hash": identity["snapshot_sha256"],
            "evidence_index_sha256": ident("evidence_index_sha256"),
            "profile_version": ident("profile_version"),
            "profile_file_sha256": ident("profile_file_sha256"),
            "provider_identity_sha256": runtime["provider_identity_sha256"],
        },
        "checks": {
            "historical_check_identity": {"check_document_sha256": ident("historical_checks_sha256")},
            "check_evidence_hash": ident("check_evidence_sha256"),
        },
        "scope": {"coverage_obligations": [{} for _ in range(case["scope_obligations"])]},
        "capacity": {
            "source_audit_preflight": {
                "active_input_limit_bytes": case["audit_cap"], "status": "ADMITTED",
                "request_count": len(source_rows),
                "request_bytes_max": max(row["input_bytes"] for row in source_rows),
                "requests": source_rows,
            },
        },
        "primary_requests": primary,
    }


@pytest.mark.parametrize("case_id", ["PR-457", "PR-464"])
def test_v3_plan_finalizer_binds_provider_free_requests_and_case_budget(case_id: str):
    prepared = _prepared(case_id)
    plan = finalizer._plan(case_id, prepared, "a" * 40, 35, "b" * 64)
    assert plan["schema"] == "model-only-shadow-live-writer-plan.v2"
    assert len(plan["writer_requests"]) == finalizer.CASES[case_id]["calls"]
    assert plan["budget"]["audit_max_input_bytes_per_call"] == finalizer.CASES[case_id]["audit_cap"]
    assert plan["runtime"]["plan_generated_from_revision"] == "a" * 40
    assert plan["runtime"]["module_tree_sha256"] == "b" * 64
    plan_sha = hashlib.sha256(json.dumps(plan, indent=2, ensure_ascii=False).encode() + b"\n").hexdigest()
    corpus_raw, manifest_raw = finalizer._identity_copy(case_id, plan, plan_sha)
    corpus = json.loads(corpus_raw)
    manifest = json.loads(manifest_raw)
    assert corpus["corpus_id"] == f"model-only-shadow-{case_id.replace('-', '').lower()}-v3"
    assert manifest["plan_path"] == finalizer.CASES[case_id]["plan"]
    assert manifest["plan_sha256"] == plan_sha
    assert corpus["cases"][0]["identity"]["source_manifest"]["sha256"] == plan_sha


def test_v3_plan_finalizer_rejects_dispatch_and_over_cap_source_prepares():
    prepared = _prepared("PR-464")
    prepared["no_provider_calls"] = False
    with pytest.raises(finalizer.FinalizeError, match="provider_free_prepare_required"):
        finalizer._plan("PR-464", prepared, "a" * 40, 35, "b" * 64)

    prepared = _prepared("PR-457")
    assert prepared["capacity"]["source_audit_preflight"]["request_bytes_max"] == 113_860
    finalizer._plan("PR-457", prepared, "a" * 40, 35, "b" * 64)
    prepared["capacity"]["source_audit_preflight"]["requests"][0]["input_bytes"] = 120_001
    with pytest.raises(finalizer.FinalizeError, match="source_audit_request_invalid"):
        finalizer._plan("PR-457", prepared, "a" * 40, 35, "b" * 64)
