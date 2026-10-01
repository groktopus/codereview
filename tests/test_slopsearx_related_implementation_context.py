"""Exact HEAD implementation context for MCP documentation/test tasks."""

from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

from pr_review_harness.planner import plan_review, validate_context_selection
from pr_review_harness.snapshot import collect_snapshot

ROOT = Path(__file__).resolve().parents[1]
V10 = ROOT / "profiles" / "slopsearx-v10-bounded-head-context-trial.json"
V11 = ROOT / "profiles" / "slopsearx-v11-related-implementation-context-candidate.json"
IMPLEMENTATION = "slopsearx/mcp/security.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _profile() -> dict:
    return json.loads(V11.read_text(encoding="utf-8"))


def _snapshot(tmp_path: Path) -> dict:
    repo = tmp_path / "target"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "config", "user.email", "fixture@example.invalid")

    profile = _profile()
    paths = set(profile["context_paths"])
    paths.update(profile["context_selection"]["mandatory_policy_paths"])
    for relative in sorted(paths):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == IMPLEMENTATION:
            content = "def make_http_app(server, token):\n    return server.http_app(transport='streamable-http')\n"
        elif relative == "slopsearx/mcp/oauth.py":
            content = "def oauth_settings_from_policy(policy):\n    return None, None\n"
        else:
            content = f"# fixture context for {relative}\n"
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")

    changed = {
        IMPLEMENTATION: (
            "def make_http_app(server, token):\n"
            "    return server.http_app(transport='streamable-http', stateless_http=True, json_response=True)\n"
        ),
        "tests/test_mcp_security.py": "def test_stateless_http_auth():\n    assert make_http_app(server, token)\n",
        "tests/test_mcp_oauth.py": "def test_oauth_http_mode():\n    assert oauth_enabled()\n",
        "docs/MCP_SERVER.md": "# MCP server\nHTTP transport uses stateless JSON responses.\n",
    }
    for relative, content in changed.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "head")
    head = _git(repo, "rev-parse", "HEAD")
    limits = {"max_context_bytes": 600_000, "max_input_bytes_per_task": 80_000}
    return collect_snapshot(str(repo), base, head, profile, limits)


def _correctness_task(snapshot: dict) -> dict:
    plan = plan_review(snapshot, _profile())
    doc_unit = next(unit["unit_id"] for unit in snapshot["inventory"] if unit["path"] == "docs/MCP_SERVER.md")
    return next(
        task
        for task in plan["tasks"]
        if task["task_kind"] == "SPECIALIST_FINDINGS"
        and task["lens"] == "correctness"
        and doc_unit in task["unit_ids"]
    )


def test_v11_adds_only_exact_correctness_binding_and_preserves_v10_obligations():
    before = json.loads(V10.read_text(encoding="utf-8"))
    candidate = _profile()
    assert candidate["version"] == "slopsearx-production-v11-related-implementation-context-candidate"
    assert validate_context_selection(candidate)["version"] == "context-selection.v2"
    for key in ("required_lenses", "docs_lenses", "required_checks", "risk_rules", "effect_policy"):
        assert candidate[key] == before[key]

    added = candidate["context_selection"]["bindings"][-1]
    assert added == {
        "context_paths": ["slopsearx/mcp/security.py", "slopsearx/mcp/oauth.py"],
        "head_context_paths": [IMPLEMENTATION],
        "lenses": ["correctness"],
        "max_context_bytes": 24_000,
        "unit_patterns": ["docs/MCP_SERVER.md", "tests/test_mcp_security.py", "tests/test_mcp_oauth.py"],
    }
    assert candidate["context_selection"]["bindings"][:-1] == before["context_selection"]["bindings"]


def test_changed_doc_task_receives_hash_bound_head_constructor(tmp_path):
    snapshot = _snapshot(tmp_path)
    task = _correctness_task(snapshot)
    supplied = [snapshot["evidence"][eid] for eid in task["evidence_ids"] if eid in snapshot["evidence"]]
    implementation = [item for item in supplied if item.get("path") == IMPLEMENTATION]
    assert any(
        item.get("source_kind") == "profile_context" and item.get("source_revision") == snapshot["base_sha"]
        for item in implementation
    )
    head_windows = [
        item
        for item in implementation
        if item.get("source_kind") == "source_window"
        and item.get("source_side") == "HEAD"
        and item.get("source_revision") == snapshot["head_sha"]
        and item.get("content_truncated") is False
        and item.get("content_hash") == hashlib.sha256(item["content"].encode("utf-8")).hexdigest()
    ]
    assert head_windows, "the docs correctness task must receive the exact changed constructor implementation"
    assert any("stateless_http=True" in item["content"] for item in head_windows)
    assert all(item["trust"] == "untrusted_pr_content" for item in head_windows)


def test_missing_stale_or_truncated_head_implementation_stays_required(tmp_path):
    original = _snapshot(tmp_path)
    target_id = next(
        eid
        for eid, item in original["evidence"].items()
        if item.get("path") == IMPLEMENTATION
        and item.get("source_kind") == "source_window"
        and item.get("source_side") == "HEAD"
    )
    mutations = [
        lambda evidence: evidence.pop(target_id),
        lambda evidence: evidence[target_id].update(source_revision="0" * 40),
        lambda evidence: evidence[target_id].update(source_side="BASE"),
        lambda evidence: evidence[target_id].update(content_hash="0" * 64),
        lambda evidence: evidence[target_id].update(content_truncated=True),
    ]
    for mutate in mutations:
        snapshot = deepcopy(original)
        mutate(snapshot["evidence"])
        task = _correctness_task(snapshot)
        assert any(
            context_id.startswith("missing-head-context-") for context_id in task["required_context_ids"]
        ), "invalid HEAD implementation evidence must remain an explicit required-context gap"
