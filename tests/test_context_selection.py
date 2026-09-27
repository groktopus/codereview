import json
from pathlib import Path

from pr_review_harness.planner import plan_review

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "profiles" / "slopsearx.json"


def _profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def _snapshot(paths):
    profile = _profile()
    evidence = {}
    trusted_context_refs = []
    for index, path in enumerate(profile["context_paths"]):
        evidence_id = f"context-{index}"
        evidence[evidence_id] = {
            "evidence_id": evidence_id,
            "path": path,
            "source_kind": "profile_context",
            "source_revision": "base-sha",
            "source_object_id": f"git-object-{index}",
            "trust": "trusted_policy" if path in profile["trusted_policy_paths"] else "repository_evidence",
            "content": f"baseline context for {path}\n",
        }
        trusted_context_refs.append(evidence_id)

    inventory = []
    for index, (path, kind) in enumerate(paths):
        evidence_id = f"diff-{index}"
        evidence[evidence_id] = {
            "evidence_id": evidence_id,
            "path": path,
            "source_kind": "diff",
            "source_revision": "head-sha",
            "trust": "repository_evidence",
            "content": f"changed evidence for {path}\n",
        }
        inventory.append(
            {
                "unit_id": f"unit-{index}",
                "path": path,
                "kind": kind,
                "evidence_ids": [evidence_id],
            }
        )
    return {
        "snapshot_id": "snapshot-test",
        "profile_version": profile["version"],
        "base_sha": "base-sha",
        "head_sha": "head-sha",
        "inventory": inventory,
        "trusted_context_refs": trusted_context_refs,
        "evidence": evidence,
        "gaps": [],
    }


def _context_paths(snapshot, plan, unit_id, lens="correctness"):
    task = next(
        task
        for task in plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS" and task["lens"] == lens and unit_id in task["unit_ids"]
    )
    evidence = snapshot["evidence"]
    assert task["required_context_ids"] == task["base_context_ids"]
    return {evidence[evidence_id]["path"] for evidence_id in task["required_context_ids"]}


def test_slopsearx_candidate_keeps_both_trusted_policy_files_mandatory():
    profile = _profile()
    selection = profile["context_selection"]

    assert profile["version"] == "slopsearx-production-v4-context-selection"
    assert selection["version"] == "context-selection.v1"
    assert selection["mandatory_policy_paths"] == ["AGENTS.md", "CONTRIBUTING.md"]
    assert selection["max_total_context_bytes"] == 120000
    assert set(selection["mandatory_policy_paths"]) <= set(profile["context_paths"])
    assert set(selection["mandatory_policy_paths"]) <= set(profile["trusted_policy_paths"])


def test_docs_experiment_reviews_keep_policy_without_unrelated_code_context():
    snapshot = _snapshot(
        [
            ("docs/experiments/EXP-024-call-local-url-memo.md", "documentation"),
            ("docs/experiments/evidence/EXP-024/summary.json", "config"),
        ]
    )
    plan = plan_review(snapshot, _profile())

    for unit_id in ("unit-0", "unit-1"):
        assert _context_paths(snapshot, plan, unit_id) == {"AGENTS.md", "CONTRIBUTING.md"}


def test_dependency_bot_config_receives_dependency_context_not_auth_implementation():
    snapshot = _snapshot([(".github/dependabot.yml", "config")])
    plan = plan_review(snapshot, _profile())

    expected = {"AGENTS.md", "CONTRIBUTING.md", "pyproject.toml"}
    assert _context_paths(snapshot, plan, "unit-0") == expected
    # The .github/* risk floor adds a security lens, but that does not make
    # MCP authentication implementation context relevant to a dependency bot.
    assert _context_paths(snapshot, plan, "unit-0", "security") == expected


def test_mcp_auth_context_is_bound_to_mcp_auth_path_family():
    snapshot = _snapshot([("slopsearx/mcp/oauth_client.py", "human_code")])
    plan = plan_review(snapshot, _profile())

    assert _context_paths(snapshot, plan, "unit-0", "security") == {
        "AGENTS.md",
        "CONTRIBUTING.md",
        "slopsearx/mcp/security.py",
        "slopsearx/mcp/oauth.py",
    }
    assert _context_paths(snapshot, plan, "unit-0", "tests") == {
        "AGENTS.md",
        "CONTRIBUTING.md",
        "slopsearx/mcp/security.py",
        "slopsearx/mcp/oauth.py",
    }


def test_mcp_filter_context_is_scoped_to_tools_that_consume_filter_enforcement():
    snapshot = _snapshot(
        [
            ("slopsearx/mcp/tools.py", "human_code"),
            ("slopsearx/mcp/oauth_client.py", "human_code"),
        ]
    )
    plan = plan_review(snapshot, _profile())

    assert _context_paths(snapshot, plan, "unit-0", "security") == {
        "AGENTS.md",
        "CONTRIBUTING.md",
        "slopsearx/mcp/security.py",
        "slopsearx/mcp/oauth.py",
        "slopsearx/filters.py",
    }
    assert _context_paths(snapshot, plan, "unit-1", "security") == {
        "AGENTS.md",
        "CONTRIBUTING.md",
        "slopsearx/mcp/security.py",
        "slopsearx/mcp/oauth.py",
    }


def test_runtime_config_context_is_not_attached_to_unrelated_security_or_docs():
    snapshot = _snapshot(
        [
            ("slopsearx/config.py", "human_code"),
            ("docs/experiments/README.md", "documentation"),
        ]
    )
    plan = plan_review(snapshot, _profile())

    assert _context_paths(snapshot, plan, "unit-0") == {
        "AGENTS.md",
        "CONTRIBUTING.md",
        "slopsearx/config.py",
    }
    assert _context_paths(snapshot, plan, "unit-1") == {"AGENTS.md", "CONTRIBUTING.md"}
