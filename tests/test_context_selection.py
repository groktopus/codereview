import json
import subprocess
from pathlib import Path

from pr_review_harness.planner import plan_review
from pr_review_harness.snapshot import collect_snapshot

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

    assert profile["version"] == "slopsearx-production-v5-dependency-context"
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


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.strip()


def _dependency_fixture(repo):
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Dependency Fixture")
    files = {
        "AGENTS.md": "Review changes against trusted project rules.\n",
        "CONTRIBUTING.md": "Install the development dependencies and run the relevant tests.\n",
        "requirements-dev.txt": "uvicorn==0.52.4\n",
        "uv.lock": 'version = 1\n\n[[package]]\nname = "uvicorn"\nversion = "0.52.4"\n',
        "pyproject.toml": '[project]\nname = "fixture-app"\ndependencies = ["uvicorn>=0.34"]\n',
        "Dockerfile": 'FROM python:3.12-slim\nRUN pip install -e .\nCMD ["uvicorn", "app:app"]\n',
        "docker-compose.yml": "services:\n  app:\n    build: .\n",
        ".github/workflows/ci.yml": (
            "name: CI\njobs:\n  analysis:\n    steps:\n"
            '      - run: pip install -e ".[dev]"\n'
            "      - run: pip-audit -r requirements-dev.txt\n"
            "      - run: pytest -q\n"
        ),
        "tests/test_mcp_gateway.py": "import uvicorn\n\ndef test_gateway_starts():\n    assert uvicorn.Server\n",
    }
    for relpath, content in files.items():
        path = repo / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    return _git(repo, "rev-parse", "HEAD")


def test_dependency_changes_use_bounded_base_install_ci_and_test_context(tmp_path):
    repo = tmp_path / "dependency-repo"
    base = _dependency_fixture(repo)
    profile = _profile()
    dependency_files = {
        "requirements-dev.txt": "uvicorn==0.53.0\n",
        "uv.lock": 'version = 1\n\n[[package]]\nname = "uvicorn"\nversion = "0.53.0"\n',
        "pyproject.toml": '[project]\nname = "fixture-app"\ndependencies = ["uvicorn>=0.35"]\n',
        "Dockerfile": 'FROM python:3.12-slim\nRUN pip install -e .\nCMD ["uvicorn", "app:app", "--workers", "2"]\n',
    }
    expected_floor = {"uv.lock": "DEEP"}
    expected_by_lens = {
        "correctness": {"pyproject.toml", "Dockerfile", ".github/workflows/ci.yml"},
        "security": {"pyproject.toml", "Dockerfile", ".github/workflows/ci.yml"},
        "tests": {"pyproject.toml", ".github/workflows/ci.yml", "tests/test_mcp_gateway.py"},
    }
    context_bindings = {
        lens: next(
            row
            for row in profile["context_selection"]["bindings"]
            if lens in row["lenses"]
            if set(expected_by_lens[lens]) <= set(row["context_paths"])
        )
        for lens in expected_by_lens
    }
    assert context_bindings["correctness"]["max_context_bytes"] == 16000
    assert context_bindings["security"]["max_context_bytes"] == 16000
    assert context_bindings["tests"]["max_context_bytes"] == 22000
    dependency_risk = next(rule for rule in profile["risk_rules"] if "requirements*.txt" in rule["patterns"])[
        "reason"
    ].lower()

    for index, (changed_path, replacement) in enumerate(dependency_files.items()):
        _git(repo, "checkout", "-q", "-B", f"dependency-{index}", base)
        target = repo / changed_path
        target.write_text(replacement, encoding="utf-8")
        _git(repo, "add", changed_path)
        _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", f"change {changed_path}")
        head = _git(repo, "rev-parse", "HEAD")
        snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 100000})
        plan = plan_review(snapshot, profile)

        unit = next(row for row in snapshot["inventory"] if row["path"] == changed_path)
        risk = plan["risk_by_unit"][unit["unit_id"]]
        assert dependency_risk in risk
        if changed_path == "requirements-dev.txt":
            assert unit["kind"] == "config"
        elif changed_path == "uv.lock":
            assert unit["kind"] == "generated"
        else:
            assert unit["kind"] == "config"
        floor = expected_floor.get(changed_path, "FOCUSED")
        assert plan["risk_floor"] == floor
        assert plan["mode"] == floor
        if changed_path == "uv.lock":
            assert "trusted_generated_path_rule" in risk
        assert {task["lens"] for task in plan["tasks"] if unit["unit_id"] in task["unit_ids"]} >= {
            "security",
            "correctness",
            "tests",
        }

        for lens in ("security", "correctness", "tests"):
            task = next(
                task
                for task in plan["tasks"]
                if task["task_kind"] == "SPECIALIST_FINDINGS"
                and task["lens"] == lens
                and unit["unit_id"] in task["unit_ids"]
            )
            context = [snapshot["evidence"][eid] for eid in task["required_context_ids"]]
            context_paths = {item["path"] for item in context}
            expected_context = expected_by_lens[lens]
            assert expected_context <= context_paths
            assert {"AGENTS.md", "CONTRIBUTING.md"} <= context_paths
            assert not any(path in context_paths for path in ("slopsearx/mcp/oauth.py", "slopsearx/mcp/security.py"))
            assert (
                sum(len(item["content"].encode("utf-8")) for item in context if item["path"] in expected_context)
                <= context_bindings[lens]["max_context_bytes"]
            )
            assert all(
                item["source_kind"] == "profile_context" and item["source_revision"] == base
                for item in context
                if item["path"] in expected_context
            )
            if lens == "tests":
                test_context = next(item for item in context if item["path"] == "tests/test_mcp_gateway.py")
                assert test_context["trust"] == "repository_evidence"
                assert "uvicorn.Server" in test_context["content"]
            else:
                assert "tests/test_mcp_gateway.py" not in context_paths

        assert not any(gap.get("required") for gap in snapshot["gaps"])


def test_dependency_context_budget_omissions_are_explicit_and_policy_is_preserved(tmp_path):
    repo = tmp_path / "bounded-dependency-repo"
    base = _dependency_fixture(repo)
    _git(repo, "checkout", "-q", "-b", "dependency-limit", base)
    (repo / "requirements-dev.txt").write_text("uvicorn==0.53.0\n", encoding="utf-8")
    _git(repo, "add", "requirements-dev.txt")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change dependency")
    head = _git(repo, "rev-parse", "HEAD")
    profile = _profile()
    profile["context_selection"]["max_total_context_bytes"] = 130
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 100000})
    plan = plan_review(snapshot, profile)

    received_policy = {
        snapshot["evidence"][eid]["path"]
        for eid in snapshot["trusted_context_refs"]
        if snapshot["evidence"][eid]["trust"] == "trusted_policy"
    }
    assert received_policy == {"AGENTS.md", "CONTRIBUTING.md"}
    required_context_gaps = [
        gap
        for gap in snapshot["gaps"]
        if gap.get("required") and gap.get("reason") == "context_selection_budget_exhausted"
    ]
    assert required_context_gaps
    assert any(
        gap["path"]
        in {
            "Dockerfile",
            ".github/workflows/ci.yml",
            "tests/test_mcp_gateway.py",
        }
        for gap in required_context_gaps
    )
    assert plan["risk_floor"] == "DEEP"
    assert any(reason == "snapshot_context_gap_raises_depth_floor" for reason in plan["routing_reasons"])
