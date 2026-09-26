import json
from pathlib import Path

import pytest

from pr_review_harness.planner import plan_review


def snapshot(units):
    return {"snapshot_id": "snap-1", "profile_version": "p1", "inventory": units, "gaps": []}


def unit(uid, path, kind="human_code"):
    return {"unit_id": uid, "path": path, "kind": kind, "evidence_ids": [f"diff:{uid}"]}


def test_slopsearx_profile_routes_docs_and_scopes_matching_check():
    profile = {
        "version": "slopsearx-pilot-v1",
        "required_lenses": ["correctness", "tests", "maintainability"],
        "docs_lenses": ["correctness"],
        "risk_rules": [
            {
                "patterns": ["slopsearx/mcp/*"],
                "min_mode": "FOCUSED",
                "lenses": ["security"],
                "reason": "MCP grant boundary",
            }
        ],
        "required_checks": [
            {
                "id": "portal",
                "patterns": ["slopsearx/*.py"],
                "binding": "external:portal",
                "reason": "Portal contract evidence",
            }
        ],
    }
    snap = snapshot([unit("docs", "docs/usage.md", "documentation"), unit("oauth", "slopsearx/mcp/oauth.py")])
    plan = plan_review(snap, profile)
    assert plan["mode"] == "FOCUSED"
    assert "unit:oauth:lens:security" in {o["obligation_id"] for o in plan["coverage_obligations"]}
    assert "unit:docs:lens:correctness" in {o["obligation_id"] for o in plan["coverage_obligations"]}
    assert "check:portal" in {o["obligation_id"] for o in plan["coverage_obligations"]}
    # Related units are batched by lens, while the frozen denominator stays per-unit.
    assert (
        len([t for t in plan["tasks"] if t["lens"] == "correctness" and t["task_kind"] == "SPECIALIST_FINDINGS"]) == 2
    )


def test_profile_check_with_no_matching_path_is_explicitly_not_applicable():
    profile = {
        "version": "p1",
        "required_lenses": ["correctness"],
        "required_checks": [{"id": "portal", "patterns": ["slopsearx/*.py"], "reason": "portal"}],
    }
    plan = plan_review(snapshot([unit("docs", "docs/usage.md", "documentation")]), profile)
    assert "check:portal" not in {o["obligation_id"] for o in plan["coverage_obligations"]}
    assert plan["not_applicable"] == [
        {
            "obligation_id": "check:portal",
            "obligation_kind": "PROJECT_CHECK",
            "reason": "portal",
            "state": "NOT_APPLICABLE",
        }
    ]


def test_unknown_and_unclassified_change_cannot_be_routed_light():
    plan = plan_review(snapshot([unit("unknown", "generated/mystery.bin", "unknown")]), {"version": "p1"}, "LIGHT")
    assert plan["mode"] == "DEEP"
    assert plan["risk_floor"] == "DEEP"
    assert any("unknown_or_generated_provenance_deep_floor" in reason for reason in plan["routing_reasons"])


def test_high_risk_rule_raises_floor_without_line_count_signal():
    plan = plan_review(
        snapshot([unit("oauth", "slopsearx/mcp/oauth.py")]),
        {
            "version": "p1",
            "required_lenses": ["correctness"],
            "risk_rules": [
                {
                    "patterns": ["slopsearx/mcp/*"],
                    "min_mode": "DEEP",
                    "lenses": ["security"],
                    "reason": "authorization boundary",
                }
            ],
        },
        "LIGHT",
    )
    assert plan["mode"] == "DEEP"
    assert plan["risk_floor"] == "DEEP"
    assert "unit:oauth:lens:security" in {o["obligation_id"] for o in plan["coverage_obligations"]}


def test_trusted_base_context_and_lens_criteria_are_passed_in_specialist_task():
    snap = snapshot([unit("u", "src/a.py")])
    snap["trusted_context_refs"] = ["policy:agents"]
    snap["evidence"] = {
        "policy:agents": {
            "evidence_id": "policy:agents",
            "path": "AGENTS.md",
            "trust": "trusted_policy",
            "source_revision": "BASE",
        }
    }
    profile = {
        "version": "p1",
        "context_paths": ["AGENTS.md"],
        "required_lenses": ["correctness"],
        "review_criteria": {"correctness": "Check callers and failure paths."},
        "rules": ["Keep adapters thin."],
    }
    task = plan_review(snap, profile)["tasks"][0]
    assert "policy:agents" in task["evidence_ids"]
    assert task["review_criteria"] == "Check callers and failure paths."
    assert task["project_rules"] == ["Keep adapters thin."]


def test_optional_missing_context_does_not_force_deep_docs_review():
    snapshot = {
        "snapshot_id": "s",
        "inventory": [{"unit_id": "u", "path": "notes.md", "kind": "documentation", "evidence_ids": []}],
        "gaps": [{"path": "optional.md", "required": False, "reason": "missing_from_base"}],
    }
    result = plan_review(snapshot, {"version": "v1", "docs_lenses": ["correctness"]})
    assert result["mode"] == "LIGHT"
    assert len(result["coverage_obligations"]) == 1
    snapshot["gaps"][0]["required"] = True
    required = plan_review(snapshot, {"version": "v1", "docs_lenses": ["correctness"]})
    assert required["mode"] == "DEEP"
    assert any(item["obligation_kind"] == "REQUIRED_CONTEXT" for item in required["coverage_obligations"])


@pytest.mark.parametrize(
    "profile_override",
    [
        {"required_lenses": ["correctnes"]},
        {"default_lenses": ["correctnes"]},
        {"docs_lenses": ["correctnes"]},
        {"documentation_lenses": ["correctnes"]},
        {"security_lenses": ["correctnes"]},
        {"risk_rules": [{"patterns": ["src/*"], "lenses": ["correctnes"]}]},
        {"review_criteria": {"correctnes": "Review callers."}},
    ],
)
def test_unknown_lenses_in_any_configured_profile_field_fail_preflight(profile_override):
    profile = {"version": "p1", **profile_override}
    with pytest.raises(ValueError, match="unsupported lens"):
        plan_review(snapshot([unit("u", "src/a.py")]), profile)


def test_empty_specialist_lenses_preserve_check_only_profiles():
    plan = plan_review(
        snapshot([unit("u", "src/a.py")]),
        {
            "version": "p1",
            "required_lenses": [],
            "required_checks": [{"id": "build", "patterns": ["src/*"]}],
        },
    )

    assert [item["obligation_kind"] for item in plan["coverage_obligations"]] == ["PROJECT_CHECK"]


@pytest.mark.parametrize(
    "profile_override",
    [
        {"required_lenses": "correctness"},
        {"required_lenses": ["correctness", None]},
        {"docs_lenses": None},
        {"risk_rules": "not-a-list"},
        {"risk_rules": ["not-an-object"]},
        {"risk_rules": [{"lenses": "security"}]},
        {"risk_rules": [{"lenses": ["security", 1]}]},
        {"review_criteria": None},
        {"review_criteria": {"correctness": 7}},
    ],
)
def test_malformed_configured_lens_fields_fail_preflight(profile_override):
    profile = {"version": "p1", **profile_override}
    with pytest.raises(ValueError):
        plan_review(snapshot([unit("u", "src/a.py")]), profile)


@pytest.mark.parametrize("name", ["generic.json", "slopsearx.json"])
def test_repository_profiles_keep_their_supported_lens_configuration(name):
    profile_path = Path(__file__).parents[1] / "profiles" / name
    configured_profile = json.loads(profile_path.read_text(encoding="utf-8"))
    plan = plan_review(snapshot([unit("u", "src/a.py")]), configured_profile)

    assert plan["policy_valid"] is True
    assert any(item["obligation_kind"] == "CHANGED_UNIT_LENS" for item in plan["coverage_obligations"])
