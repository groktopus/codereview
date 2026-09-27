import hashlib
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
            "reason": "configured_path_patterns_did_not_match",
            "profile_rationale": "portal",
            "state": "NOT_APPLICABLE",
        }
    ]


def test_slopsearx_lockfile_does_not_match_portal_check_paths():
    profile = json.loads((Path(__file__).resolve().parents[1] / "profiles/slopsearx.json").read_text())
    plan = plan_review(snapshot([unit("requirements", "requirements-dev.txt", "configuration")]), profile)
    assert {row["obligation_id"] for row in plan["not_applicable"]} == {
        "check:portal-impact-evidence",
        "check:portal-browser-evidence",
    }
    assert all(row["reason"] == "configured_path_patterns_did_not_match" for row in plan["not_applicable"])
    assert all(row["profile_rationale"].startswith("Base AGENTS requires portal impact") for row in plan["not_applicable"])


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
    assert result["mode"] == "FOCUSED"
    assert "u:docs_prose_only_unverified_focused_floor" in result["routing_reasons"]
    assert {item.get("lens") for item in result["coverage_obligations"]} == {
        "correctness",
        "tests",
        "design",
        "maintainability",
    }
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


def _document_snapshot(change_type="modify"):
    base_sha, head_sha = "a" * 40, "b" * 40
    path = "docs/new.md" if change_type == "rename" else "docs/guide.md"
    old_path = "docs/old.md" if change_type == "rename" else None
    old_path = old_path or path
    diff_id = "diff:doc"
    unit = {
        "unit_id": "doc",
        "path": path,
        "old_path": old_path if change_type == "rename" else None,
        "change_type": change_type,
        "kind": "documentation",
        "diff": "@@ -1 +1 @@\n-before\n+after\n",
        "evidence_ids": [],
    }
    evidence = {}

    def add_evidence(evidence_id, source_kind, evidence_path, revision, content, object_id=None):
        content_bytes = content.encode("utf-8")
        evidence[evidence_id] = {
            "evidence_id": evidence_id,
            "snapshot_id": "doc-snapshot",
            "source_kind": source_kind,
            "path": evidence_path,
            "source_revision": revision,
            "content": content,
            "content_hash": hashlib.sha256(content_bytes).hexdigest(),
            "content_truncated": False,
            "source_object_id": object_id,
            "source_object_size_bytes": len(content_bytes) if object_id else None,
        }
        unit["evidence_ids"].append(evidence_id)

    add_evidence(diff_id, "diff", path, head_sha, "@@ -1 +1 @@\n-before\n+after\n")
    if change_type in {"modify", "delete", "rename"}:
        add_evidence("base:doc", "base_file", old_path, base_sha, "A prose introduction.\n", "base-blob")
    if change_type in {"modify", "add", "rename"}:
        add_evidence("head:doc", "head_file", path, head_sha, "A prose introduction.\n", "head-blob")
    return {
        "snapshot_id": "doc-snapshot",
        "base_sha": base_sha,
        "head_sha": head_sha,
        "inventory": [unit],
        "evidence": evidence,
        "gaps": [],
    }


def _doc_profile(**overrides):
    return {
        "version": "docs-route-v1",
        "docs_lenses": ["correctness"],
        "required_lenses": ["correctness", "tests"],
        **overrides,
    }


@pytest.mark.parametrize("change_type", ["add", "delete", "modify", "rename"])
def test_complete_plain_documentation_routes_light_for_each_change_side(change_type):
    plan = plan_review(_document_snapshot(change_type), _doc_profile())

    assert plan["mode"] == "LIGHT"
    assert "doc:trusted_docs_only_route" in plan["routing_reasons"]
    assert {item["lens"] for item in plan["coverage_obligations"]} == {"correctness"}


@pytest.mark.parametrize(
    "source_kind,content",
    [
        ("head_file", "```python\nreturn True\n```\n"),
        ("head_file", "Example:\n\n    return True\n"),
        ("head_file", ".. code-block:: python\n\n   return True\n"),
        ("head_file", "<pre><code>return True</code></pre>\n"),
        ("head_file", "Run it like this:\n\n$ python example.py\n"),
        ("diff", "@@ -1 +1 @@\n+```python\n+return True\n+```\n"),
    ],
)
def test_possible_documentation_examples_do_not_route_light(source_kind, content):
    snap = _document_snapshot("modify")
    evidence_id = "head:doc" if source_kind == "head_file" else "diff:doc"
    item = snap["evidence"][evidence_id]
    item["content"] = content
    item["content_hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if source_kind == "head_file":
        item["source_object_size_bytes"] = len(content.encode("utf-8"))

    plan = plan_review(snap, _doc_profile())

    assert plan["mode"] == "FOCUSED"
    assert plan["routing_reasons"][-1] == "doc:docs_prose_only_unverified_focused_floor"


@pytest.mark.parametrize(
    "change_type,missing_id",
    [
        ("add", "head:doc"),
        ("delete", "base:doc"),
        ("modify", "base:doc"),
        ("modify", "head:doc"),
        ("rename", "base:doc"),
        ("rename", "head:doc"),
        ("modify", "diff:doc"),
    ],
)
def test_missing_required_immutable_doc_evidence_cannot_certify_prose(change_type, missing_id):
    snap = _document_snapshot(change_type)
    snap["inventory"][0]["evidence_ids"].remove(missing_id)

    plan = plan_review(snap, _doc_profile())

    assert plan["mode"] == "FOCUSED"
    assert "doc:docs_prose_only_unverified_focused_floor" in plan["routing_reasons"]


def test_truncated_documentation_blob_cannot_certify_prose():
    snap = _document_snapshot("modify")
    snap["evidence"]["head:doc"]["content_truncated"] = True

    plan = plan_review(snap, _doc_profile())

    assert plan["mode"] == "FOCUSED"
    assert "doc:docs_prose_only_unverified_focused_floor" in plan["routing_reasons"]


def test_hash_mismatch_or_unknown_provenance_cannot_certify_light_documentation():
    mismatched_hash = _document_snapshot("modify")
    mismatched_hash["evidence"]["head:doc"]["content_hash"] = "0" * 64
    hash_plan = plan_review(mismatched_hash, _doc_profile())
    assert hash_plan["mode"] == "FOCUSED"
    assert "doc:docs_prose_only_unverified_focused_floor" in hash_plan["routing_reasons"]

    unknown_kind = _document_snapshot("modify")
    unknown_kind["inventory"][0]["kind"] = "unknown"
    unknown_plan = plan_review(unknown_kind, _doc_profile())
    assert unknown_plan["mode"] == "DEEP"
    assert "doc:trusted_docs_only_route" not in unknown_plan["routing_reasons"]


def test_generated_docs_and_mandatory_policy_docs_cannot_route_light():
    generated = plan_review(
        _document_snapshot("modify"),
        _doc_profile(generated_patterns=["docs/*.md"]),
    )
    assert generated["mode"] == "DEEP"

    profile = _doc_profile(
        context_paths=["docs/guide.md"],
        trusted_policy_paths=["docs/guide.md"],
        context_selection={
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["docs/guide.md"],
            "max_total_context_bytes": 1_000,
            "window": {
                "before_lines": 0,
                "after_lines": 0,
                "max_bytes": 1_000,
                "max_windows_per_unit": 1,
                "max_scan_bytes": 1_000,
            },
            "bindings": [],
        },
    )
    policy = plan_review(_document_snapshot("modify"), profile)
    assert policy["mode"] == "FOCUSED"
    assert "doc:docs_mandatory_policy_path_focused_floor" in policy["routing_reasons"]


def test_explicit_non_documentation_profile_classification_overrides_extension():
    plan = plan_review(
        _document_snapshot("modify"),
        _doc_profile(classifications={"docs/guide.md": "human_code"}),
    )

    assert plan["mode"] == "FOCUSED"
    assert "doc:trusted_docs_only_route" not in plan["routing_reasons"]
