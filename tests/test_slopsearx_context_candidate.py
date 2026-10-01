"""Focused routing contract for the opt-in SlopSearX v9 profile candidate."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

from pr_review_harness.planner import plan_review, validate_context_selection
from pr_review_harness.snapshot import collect_snapshot

ROOT = Path(__file__).resolve().parents[1]
V8_PATH = ROOT / "profiles" / "slopsearx.json"
CANDIDATE_PATH = ROOT / "profiles" / "slopsearx-v9-context-candidate.json"
MCP_PATHS = {
    "slopsearx/mcp/security.py",
    "tests/test_mcp_security.py",
    "tests/test_mcp_oauth.py",
    "docs/MCP_SERVER.md",
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _profile(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _changed_snapshot(tmp_path: Path, profile: dict) -> dict:
    repo = tmp_path / "target"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    initial = {
        "AGENTS.md": "# Trusted review policy\n",
        "CONTRIBUTING.md": "# Contribution policy\n",
        "slopsearx/mcp/security.py": "def make_http_app():\n    return None\n",
        "slopsearx/mcp/oauth.py": "def callback():\n    return None\n",
        "tests/test_mcp_security.py": "def test_old_security_contract():\n    assert True\n",
        "tests/test_mcp_oauth.py": "def test_old_oauth_contract():\n    assert True\n",
        "docs/MCP_SERVER.md": "# MCP server\nOld contract.\n",
    }
    for relative, content in initial.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")

    changed = {
        "slopsearx/mcp/security.py": "def make_http_app():\n    return validate_origin()\n",
        "tests/test_mcp_security.py": "def test_security_rejects_bad_origin():\n    assert rejected_origin()\n",
        "tests/test_mcp_oauth.py": "def test_revoked_token_is_rejected():\n    assert callback_status() == 401\n",
        "docs/MCP_SERVER.md": "# MCP server\nInvalid bearer tokens fail closed.\n",
    }
    for relative, content in changed.items():
        (repo / relative).write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "head")
    head = _git(repo, "rev-parse", "HEAD")
    limits = {"max_context_bytes": 600_000, "max_input_bytes_per_task": 96_000}
    snapshot = collect_snapshot(str(repo), base, head, profile, limits)
    return snapshot


def test_candidate_preserves_v8_checks_budgets_and_review_effects():
    v8 = _profile(V8_PATH)
    candidate = _profile(CANDIDATE_PATH)

    assert candidate["version"] == "slopsearx-production-v9-exact-context-candidate"
    assert candidate["version"] != v8["version"]
    for key in (
        "required_lenses",
        "docs_lenses",
        "security_lenses",
        "required_checks",
        "effect_policy",
        "allow_empty_approval",
        "trusted_policy_paths",
        "retrieval_context_patterns",
    ):
        assert candidate.get(key) == v8.get(key)
    assert (
        candidate["context_selection"]["max_total_context_bytes"] == v8["context_selection"]["max_total_context_bytes"]
    )
    assert candidate["context_selection"]["window"] == v8["context_selection"]["window"]
    assert candidate["risk_rules"] == v8["risk_rules"]
    assert validate_context_selection(candidate)["version"] == "context-selection.v2"


def test_changed_mcp_test_and_doc_heads_are_in_their_scoped_tasks(tmp_path):
    profile = _profile(CANDIDATE_PATH)
    snapshot = _changed_snapshot(tmp_path, profile)
    plan = plan_review(snapshot, profile)
    units = {unit["path"]: unit["unit_id"] for unit in snapshot["inventory"]}
    assert MCP_PATHS <= units.keys()

    for path, lens in (
        ("slopsearx/mcp/security.py", "security"),
        ("tests/test_mcp_security.py", "tests"),
        ("tests/test_mcp_oauth.py", "tests"),
        ("docs/MCP_SERVER.md", "correctness"),
    ):
        unit_id = units[path]
        task = next(
            task
            for task in plan["tasks"]
            if task["task_kind"] == "SPECIALIST_FINDINGS" and task["lens"] == lens and unit_id in task["unit_ids"]
        )
        supplied = [snapshot["evidence"][eid] for eid in task["evidence_ids"] if eid in snapshot["evidence"]]
        changed_head = [
            item
            for item in supplied
            if item["path"] == path
            and item["source_revision"] == snapshot["head_sha"]
            and item["source_kind"] in {"head_file", "head_window", "diff"}
        ]
        assert changed_head, f"{path} HEAD evidence was not supplied to its scoped {lens} task"

    for lens in ("correctness", "tests", "security"):
        implementation_task = next(
            task
            for task in plan["tasks"]
            if task["task_kind"] == "SPECIALIST_FINDINGS"
            and task["lens"] == lens
            and units["slopsearx/mcp/security.py"] in task["unit_ids"]
        )
        implementation_evidence = [
            snapshot["evidence"][eid] for eid in implementation_task["evidence_ids"] if eid in snapshot["evidence"]
        ]
        assert {item["path"] for item in implementation_evidence if item["source_kind"] == "profile_context"} >= {
            "AGENTS.md",
            "CONTRIBUTING.md",
            "slopsearx/mcp/security.py",
            "slopsearx/mcp/oauth.py",
        }
        for path in ("tests/test_mcp_security.py", "tests/test_mcp_oauth.py", "docs/MCP_SERVER.md"):
            path_evidence = [item for item in implementation_evidence if item["path"] == path]
            assert {item["source_kind"] for item in path_evidence} == {"diff", "source_window"}
            assert all(item["source_revision"] == snapshot["head_sha"] for item in path_evidence)
            assert all(
                item.get("source_side") == "HEAD" for item in path_evidence if item["source_kind"] == "source_window"
            )
            assert all(item["trust"] == "untrusted_pr_content" for item in path_evidence)


def test_candidate_context_bindings_are_exact_mcp_paths_only():
    candidate = _profile(CANDIDATE_PATH)
    binding = next(
        item
        for item in candidate["context_selection"]["bindings"]
        if "slopsearx/mcp/security.py" in item["unit_patterns"]
    )

    v8 = _profile(V8_PATH)
    v8_binding = next(
        item for item in v8["context_selection"]["bindings"] if "slopsearx/mcp/security.py" in item["unit_patterns"]
    )
    assert binding["unit_patterns"] == v8_binding["unit_patterns"]
    assert binding["context_paths"] == ["slopsearx/mcp/security.py", "slopsearx/mcp/oauth.py"]
    assert not any(path in {"tests/", "docs/", "tests/*.py", "docs/*.md"} for path in binding["head_context_paths"])
    assert binding["head_context_paths"] == [
        "tests/test_mcp_security.py",
        "tests/test_mcp_oauth.py",
        "docs/MCP_SERVER.md",
    ]


def test_missing_or_oversized_head_context_becomes_required_and_unresolvable(tmp_path):
    profile = _profile(CANDIDATE_PATH)
    snapshot = _changed_snapshot(tmp_path, profile)
    target = "tests/test_mcp_oauth.py"
    to_remove = [
        evidence_id
        for evidence_id, item in snapshot["evidence"].items()
        if item.get("path") == target
        and item.get("source_revision") == snapshot["head_sha"]
        and item.get("source_kind") in {"diff", "source_window"}
    ]
    for evidence_id in to_remove:
        snapshot["evidence"].pop(evidence_id)
    plan = plan_review(snapshot, profile)
    security_unit = next(
        unit["unit_id"] for unit in snapshot["inventory"] if unit["path"] == "slopsearx/mcp/security.py"
    )
    code_task = next(
        task
        for task in plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS"
        and task["lens"] == "security"
        and security_unit in task["unit_ids"]
    )
    assert any(value.startswith("missing-head-context-") for value in code_task["required_context_ids"])

    window_only_snapshot = _changed_snapshot(tmp_path / "window-only", _profile(CANDIDATE_PATH))
    for evidence_id, item in list(window_only_snapshot["evidence"].items()):
        if (
            item.get("path") == target
            and item.get("source_revision") == window_only_snapshot["head_sha"]
            and item.get("source_kind") == "source_window"
        ):
            window_only_snapshot["evidence"].pop(evidence_id)
    window_only_plan = plan_review(window_only_snapshot, _profile(CANDIDATE_PATH))
    window_only_task = next(
        task
        for task in window_only_plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS"
        and task["lens"] == "security"
        and next(
            unit["unit_id"] for unit in window_only_snapshot["inventory"] if unit["path"] == "slopsearx/mcp/security.py"
        )
        in task["unit_ids"]
    )
    assert any(value.startswith("missing-head-context-") for value in window_only_task["required_context_ids"])

    capped_profile = _profile(CANDIDATE_PATH)
    capped_snapshot = _changed_snapshot(tmp_path / "capped", capped_profile)
    binding = next(
        item
        for item in capped_profile["context_selection"]["bindings"]
        if "slopsearx/mcp/security.py" in item["unit_patterns"]
    )
    binding["max_context_bytes"] = 1
    capped_plan = plan_review(capped_snapshot, capped_profile)
    capped_security_unit = next(
        unit["unit_id"] for unit in capped_snapshot["inventory"] if unit["path"] == "slopsearx/mcp/security.py"
    )
    capped_task = next(
        task
        for task in capped_plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS"
        and task["lens"] == "security"
        and capped_security_unit in task["unit_ids"]
    )
    assert any(value.startswith("missing-head-context-") for value in capped_task["required_context_ids"])


def test_malformed_head_context_provenance_fails_closed(tmp_path):
    profile = _profile(CANDIDATE_PATH)
    original = _changed_snapshot(tmp_path, profile)
    security_unit = next(
        unit["unit_id"] for unit in original["inventory"] if unit["path"] == "slopsearx/mcp/security.py"
    )
    target = "tests/test_mcp_oauth.py"
    head_window_id = next(
        evidence_id
        for evidence_id, item in original["evidence"].items()
        if item.get("path") == target
        and item.get("source_kind") == "source_window"
        and item.get("source_revision") == original["head_sha"]
        and item.get("source_side") == "HEAD"
    )
    mutations = (
        lambda item: item.update(source_revision="0" * 40),
        lambda item: item.update(source_side="BASE"),
        lambda item: item.update(content_hash="0" * 64),
        lambda item: item.update(content_truncated=True),
    )
    for mutate in mutations:
        snapshot = deepcopy(original)
        mutate(snapshot["evidence"][head_window_id])
        plan = plan_review(snapshot, profile)
        task = next(
            task
            for task in plan["tasks"]
            if task["task_kind"] == "SPECIALIST_FINDINGS"
            and task["lens"] == "security"
            and security_unit in task["unit_ids"]
        )
        assert any(value.startswith("missing-head-context-") for value in task["required_context_ids"])


def test_v2_rejects_broad_head_paths_while_v1_profile_still_validates():
    candidate = _profile(CANDIDATE_PATH)
    binding = next(
        item
        for item in candidate["context_selection"]["bindings"]
        if "slopsearx/mcp/security.py" in item["unit_patterns"]
    )
    binding["head_context_paths"] = ["tests/"]
    try:
        validate_context_selection(candidate)
    except ValueError:
        pass
    else:
        raise AssertionError("directory paths must not enter v2 changed-source context")
    assert validate_context_selection(_profile(V8_PATH))["version"] == "context-selection.v1"
