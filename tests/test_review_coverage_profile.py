from __future__ import annotations

import json
from pathlib import Path

from pr_review_harness.planner import plan_review

ROOT = Path(__file__).resolve().parents[1]


def _profile() -> dict:
    return json.loads((ROOT / "profiles/slopsearx.json").read_text(encoding="utf-8"))


def _dependency_snapshot(profile: dict, *, missing_test_path: str | None = None) -> dict:
    evidence = {
        "diff:dependency": {
            "evidence_id": "diff:dependency",
            "snapshot_id": "snapshot-test",
            "path": "requirements-dev.txt",
            "source_kind": "diff",
            "source_revision": "b" * 40,
            "content_hash": "a" * 64,
            "source_object_id": "a" * 40,
            "trust": "untrusted_pr_content",
            "content": "uvicorn==0.52.4\n",
        }
    }
    refs = []
    for index, path in enumerate(profile["context_paths"]):
        if path == missing_test_path:
            continue
        evidence_id = f"context:{index}"
        evidence[evidence_id] = {
            "evidence_id": evidence_id,
            "snapshot_id": "snapshot-test",
            "path": path,
            "source_kind": "profile_context",
            "source_revision": "a" * 40,
            "content_hash": "b" * 64,
            "source_object_id": "b" * 40,
            "trust": "trusted_policy" if path in profile["trusted_policy_paths"] else "repository_evidence",
            "content": f"source for {path}\n",
        }
        refs.append(evidence_id)
    gaps = []
    if missing_test_path:
        gaps.append({
            "gap_id": "missing-test-source",
            "path": missing_test_path,
            "source_kind": "profile_context",
            "reason": "missing_from_base",
            "required": True,
            "unit_ids": ["dep-unit"],
            "lenses": ["tests"],
        })
    return {
        "snapshot_id": "static-review-test",
        "snapshot_hash": "c" * 64,
        "profile_version": profile["version"],
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "inventory": [{
            "unit_id": "dep-unit",
            "path": "requirements-dev.txt",
            "kind": "config",
            "evidence_ids": ["diff:dependency"],
        }],
        "trusted_context_refs": refs,
        "evidence": evidence,
        "gaps": gaps,
    }


def test_dependency_profile_routes_static_test_security_and_only_the_bound_portal_check():
    profile = _profile()
    snapshot = _dependency_snapshot(profile)
    plan = plan_review(snapshot, profile)

    specialists = {
        task["lens"]: task
        for task in plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS" and "dep-unit" in task["unit_ids"]
    }
    assert {"tests", "security"} <= specialists.keys()
    assert specialists["tests"]["review_criteria"] == profile["review_criteria"]["tests"]
    assert specialists["security"]["review_criteria"] == profile["review_criteria"]["security"]

    test_context_paths = {
        snapshot["evidence"][evidence_id]["path"]
        for evidence_id in specialists["tests"]["required_context_ids"]
    }
    assert {"tests/test_mcp_gateway.py", "tests/test_mcp_harness.py"} <= test_context_paths

    required_check_ids = {
        task["check_id"]
        for task in plan["tasks"]
        if task["task_kind"] == "DETERMINISTIC_CHECK"
    }
    assert required_check_ids == {"portal-impact-evidence"}
    assert {
        row["obligation_id"]
        for row in plan["not_applicable"]
        if row["obligation_kind"] == "PROJECT_CHECK"
    } == {"check:portal-browser-evidence"}


def test_missing_bound_test_source_remains_a_required_context_obligation():
    profile = _profile()
    snapshot = _dependency_snapshot(profile, missing_test_path="tests/test_mcp_harness.py")
    plan = plan_review(snapshot, profile)

    missing = [row for row in plan["coverage_obligations"] if row["obligation_kind"] == "REQUIRED_CONTEXT"]
    assert len(missing) == 1
    assert missing[0]["scope_unit_ids"] == ["dep-unit"]
    assert missing[0]["reason"] == "missing_from_base"
    assert plan["mode"] == "DEEP"
