"""Regression contract for the nondeployed v13 static-test assessment wording."""

from __future__ import annotations

import json
from pathlib import Path

from pr_review_harness.planner import plan_review, validate_profile_lenses

ROOT = Path(__file__).resolve().parents[1]
V12_PATH = ROOT / "profiles/slopsearx-v12-dependency-context-candidate.json"
V13_PATH = ROOT / "profiles/slopsearx-v13-static-assessment-candidate.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _snapshot() -> dict:
    base_sha = "a" * 40
    head_sha = "b" * 40
    return {
        "snapshot_id": "snapshot-static-assessment-candidate",
        "snapshot_hash": "c" * 64,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "repository": "magnus919/SlopSearX",
        "pull_request_number": 466,
        "profile_version": "slopsearx-production-v13-static-assessment-candidate",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "unit-mcp-security",
                "path": "slopsearx/mcp/security.py",
                "kind": "python",
                "change": "modified",
                "evidence_ids": ["diff:security"],
            }
        ],
        "evidence": {
            "diff:security": {
                "evidence_id": "diff:security",
                "snapshot_id": "snapshot-static-assessment-candidate",
                "path": "slopsearx/mcp/security.py",
                "source_kind": "diff",
                "source_revision": head_sha,
                "content_hash": "d" * 64,
                "trust": "untrusted_pr_content",
                "content": "-return server.streamable_http_app()\n+return server.http_app(stateless_http=True)\n",
            }
        },
        "trusted_context_refs": [],
        "gaps": [],
    }


def test_v13_changes_only_version_and_test_assessment_wording():
    v12 = _load(V12_PATH)
    v13 = _load(V13_PATH)

    assert v13["version"] == "slopsearx-production-v13-static-assessment-candidate"
    assert v12["version"] != v13["version"]
    assert v12["review_criteria"]["tests"] != v13["review_criteria"]["tests"]

    prior = json.loads(json.dumps(v13))
    prior["version"] = v12["version"]
    prior["review_criteria"]["tests"] = v12["review_criteria"]["tests"]
    assert prior == v12
    validate_profile_lenses(v13)


def test_v13_forwards_static_assessment_boundary_without_changing_scope():
    v12 = _load(V12_PATH)
    v13 = _load(V13_PATH)
    snapshot = _snapshot()
    plan12 = plan_review(snapshot, v12, "DEEP")
    plan13 = plan_review(snapshot, v13, "DEEP")

    def without_criteria(plan: dict) -> dict:
        copy = json.loads(json.dumps(plan))
        copy.pop("profile_version", None)
        for task in copy["tasks"]:
            task.pop("review_criteria", None)
        return copy

    assert without_criteria(plan13) == without_criteria(plan12)
    tests_task = next(task for task in plan13["tasks"] if task.get("lens") == "tests")
    assert tests_task["review_criteria"] == v13["review_criteria"]["tests"]
    criterion = tests_task["review_criteria"].lower()
    assert "complete the static assessment" in criterion
    assert "test gap" in criterion
    assert "only when missing" in criterion
    assert "does not establish runtime behavior" in criterion
