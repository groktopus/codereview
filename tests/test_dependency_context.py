from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from pr_review_harness.dependency_context import DependencyContextError, project_python_dependencies
from pr_review_harness.engine import _evidence_for
from pr_review_harness.planner import plan_review
from pr_review_harness.snapshot import SnapshotError, collect_snapshot


def _project(manifest: bytes, lock: bytes | None, *, max_bytes: int = 8_000, **overrides):
    return project_python_dependencies(
        binding={"manifest_path": "pyproject.toml", "lock_path": "uv.lock", "packages": ["fastmcp"]},
        side="HEAD",
        revision="a" * 40,
        manifest_oid="b" * 40,
        manifest_bytes=manifest,
        lock_oid="c" * 40 if lock is not None else None,
        lock_bytes=lock,
        max_bytes=max_bytes,
        **overrides,
    )


def test_dependency_projection_extracts_direct_declaration_and_matching_lock_fact():
    result = _project(
        b'[project]\ndependencies = ["FastMCP>=2.0,<4", "other-lib~=1.2"]\n',
        b'[[package]]\nname = "fastmcp"\nversion = "3.1.1"\n',
    )

    assert result["side"] == "HEAD"
    assert result["source_revision"] == "a" * 40
    assert result["manifest_object_id"] == "b" * 40
    assert result["lock_status"] == "LOCK_FILE_PRESENT"
    assert result["packages"] == [
        {
            "package": "fastmcp",
            "declaration_status": "DECLARED",
            "requirements": ["FastMCP>=2.0,<4"],
            "lock_status": "LOCK_ENTRY_PRESENT",
            "locked_versions": ["3.1.1"],
        }
    ]
    assert "installed" in result["statement"]
    assert result["content_hash"] == hashlib.sha256(result["content"].encode()).hexdigest()


def test_dependency_projection_distinguishes_absent_lock_from_missing_lock_entry():
    manifest = b'[project]\ndependencies = ["fastmcp>=2,<4"]\n'
    absent = _project(manifest, None)
    missing_entry = _project(manifest, b'[[package]]\nname = "other-lib"\nversion = "1.0"\n')

    assert absent["lock_status"] == "LOCK_FILE_ABSENT"
    assert absent["packages"][0]["lock_status"] == "LOCK_FILE_ABSENT"
    assert missing_entry["lock_status"] == "LOCK_FILE_PRESENT"
    assert missing_entry["packages"][0]["lock_status"] == "PACKAGE_NOT_IN_LOCK"


def test_dependency_projection_preserves_conditional_declarations_and_multiple_lock_versions():
    result = _project(
        b'[project]\ndependencies = ["fastmcp>=2; python_version < \'3.13\'", "fastmcp>=3; python_version >= \'3.13\'"]\n',
        b'[[package]]\nname = "fastmcp"\nversion = "2.13.0"\n\n'
        b'[[package]]\nname = "fastmcp"\nversion = "3.1.1"\n',
    )
    assert result["packages"][0]["requirements"] == [
        "fastmcp>=2; python_version < '3.13'",
        "fastmcp>=3; python_version >= '3.13'",
    ]
    assert result["packages"][0]["lock_status"] == "LOCK_ENTRIES_MULTIPLE"
    assert result["packages"][0]["locked_versions"] == ["2.13.0", "3.1.1"]


def test_dependency_projection_rejects_malformed_manifest_shape():
    with pytest.raises(DependencyContextError, match="project table is invalid"):
        _project(b'project = "not a table"\n', None)


@pytest.mark.parametrize(
    ("side", "revision", "manifest_oid"),
    [("OTHER", "a" * 40, "b" * 40), ("BASE", "not-a-revision", "b" * 40), ("HEAD", "a" * 40, "b" * 64)],
)
def test_dependency_projection_rejects_inconsistent_source_identity(side, revision, manifest_oid):
    with pytest.raises(DependencyContextError, match="identity is invalid"):
        project_python_dependencies(
            binding={"manifest_path": "pyproject.toml", "lock_path": "uv.lock", "packages": ["fastmcp"]},
            side=side,
            revision=revision,
            manifest_oid=manifest_oid,
            manifest_bytes=b'[project]\ndependencies = ["fastmcp>=2"]\n',
            lock_oid=None,
            lock_bytes=None,
            max_bytes=8_000,
        )


def test_dependency_projection_refuses_output_over_configured_bound():
    manifest = b'[project]\ndependencies = ["fastmcp' + b"<" + b"1" * 2_000 + b'"]\n'
    with pytest.raises(DependencyContextError, match="exceeds its byte limit"):
        _project(manifest, None, max_bytes=100)


def _git(path: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE, env=env
    ).stdout.strip()


@pytest.fixture(params=["main", "master"], ids=["default-branch-main", "default-branch-master"])
def dependency_repo(tmp_path: Path, request) -> tuple[Path, str, str]:
    bare = tmp_path / "target.git"
    work = tmp_path / "work"
    # Simulate either common user/global init.defaultBranch without changing
    # the machine's Git configuration. The fixture always pushes an explicit
    # main branch and clones it explicitly below.
    git_env = {
        key: value
        for key, value in os.environ.items()
        if key != "GIT_CONFIG_COUNT"
        and not key.startswith("GIT_CONFIG_KEY_")
        and not key.startswith("GIT_CONFIG_VALUE_")
    }
    git_env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "init.defaultBranch",
            "GIT_CONFIG_VALUE_0": request.param,
        }
    )
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, stdout=subprocess.DEVNULL, env=git_env)
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL, env=git_env)
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "Fixture")
    (work / "src").mkdir()
    (work / "tests").mkdir()
    (work / "src/server.py").write_text("def serve():\n    return True\n")
    (work / "tests/test_server.py").write_text("def test_serve():\n    assert True\n")
    (work / "pyproject.toml").write_text('[project]\ndependencies = ["fastmcp>=2,<4"]\n')
    (work / "uv.lock").write_text('[[package]]\nname = "fastmcp"\nversion = "2.13.0"\n')
    _git(work, "add", ".")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(work, "rev-parse", "HEAD")
    _git(work, "remote", "add", "origin", str(bare))
    _git(work, "push", "origin", "HEAD:refs/heads/main", env=git_env)
    (work / "src/server.py").write_text("def serve():\n    return False\n")
    (work / "tests/test_server.py").write_text("def test_serve():\n    assert not serve()\n")
    (work / "pyproject.toml").write_text('[project]\ndependencies = ["fastmcp>=3,<4"]\n')
    (work / "uv.lock").write_text('[[package]]\nname = "fastmcp"\nversion = "3.1.1"\n')
    _git(work, "add", ".")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", "HEAD:refs/heads/main", env=git_env)
    return bare, base, head


def _profile(sides: list[str] | None = None) -> dict:
    return {
        "version": "dependency-projection-test-v1",
        "context_paths": [],
        "retrieval_context_patterns": ["pyproject.toml", "uv.lock"],
        "required_lenses": ["correctness", "tests"],
        "dependency_context": {
            "version": "dependency-context.v1",
            "max_total_projection_bytes": 8_000,
            "max_source_bytes": 16_000,
            "bindings": [
                {
                    "unit_patterns": ["src/*.py", "tests/*.py"],
                    "lenses": ["correctness", "tests"],
                    "sides": sides or ["BASE", "HEAD"],
                    "manifest_path": "pyproject.toml",
                    "lock_path": "uv.lock",
                    "packages": ["fastmcp"],
                    "max_bytes": 4_000,
                }
            ],
        },
    }


def test_projection_is_bound_to_base_and_head_objects_and_routed_to_matching_tasks(dependency_repo):
    repo, base, head = dependency_repo
    profile = _profile()
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 80_000})
    projections = [item for item in snapshot["evidence"].values() if item["source_kind"] == "dependency_projection"]
    assert {(item["source_side"], item["source_revision"]) for item in projections} == {
        ("BASE", base),
        ("HEAD", head),
    }
    assert all(item["source_object_id"] == _git(repo, "rev-parse", f"{item['source_revision']}:pyproject.toml") for item in projections)
    assert all(item["trust"] == "repository_evidence" for item in projections)
    assert all("line_start" not in item and "line_end" not in item for item in projections)
    plan = plan_review(snapshot, profile)
    by_lens = {task["lens"]: task for task in plan["tasks"]}
    for lens in ("correctness", "tests"):
        task = by_lens[lens]
        task_projections = [
            snapshot["evidence"][evidence_id]
            for evidence_id in task["required_context_ids"]
            if evidence_id in snapshot["evidence"]
            and snapshot["evidence"][evidence_id]["source_kind"] == "dependency_projection"
        ]
        assert {(item["source_side"], item["source_revision"]) for item in task_projections} == {
            ("BASE", base),
            ("HEAD", head),
        }
        assert all(evidence_id in task["evidence_ids"] for evidence_id in task["required_context_ids"])
        delivered = _evidence_for(task, snapshot, 80_000)
        delivered_projection = [item for item in delivered if item["source_kind"] == "dependency_projection"]
        assert {item["source_side"] for item in delivered_projection} == {"BASE", "HEAD"}
        assert all(item["content_hash"] == hashlib.sha256(item["content"].encode()).hexdigest() for item in delivered_projection)


def test_planner_rejects_projection_from_wrong_revision(dependency_repo):
    repo, base, head = dependency_repo
    profile = _profile(["HEAD"])
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 80_000})
    projection = next(
        item for item in snapshot["evidence"].values() if item["source_kind"] == "dependency_projection"
    )
    projection["source_revision"] = base
    plan = plan_review(snapshot, profile)
    assert any(
        evidence_id.startswith("missing-dependency-context-")
        for task in plan["tasks"]
        for evidence_id in task["required_context_ids"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("content_hash", "a" * 40),
        ("manifest_sha256", "b" * 40),
        ("source_object_size_bytes", -1),
        ("source_object_size_bytes", True),
    ],
)
def test_planner_rejects_malformed_projection_hashes_and_sizes(dependency_repo, field, value):
    repo, base, head = dependency_repo
    profile = _profile(["HEAD"])
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 80_000})
    projection = next(
        item for item in snapshot["evidence"].values() if item["source_kind"] == "dependency_projection"
    )
    projection[field] = value
    plan = plan_review(snapshot, profile)
    assert any(
        evidence_id.startswith("missing-dependency-context-")
        for task in plan["tasks"]
        for evidence_id in task["required_context_ids"]
    )


def test_snapshot_marks_missing_lock_file_as_source_fact_not_context_gap(dependency_repo, tmp_path: Path):
    bare, base, _head = dependency_repo
    work = tmp_path / "without-lock"
    subprocess.run(
        ["git", "clone", "--branch", "main", str(bare), str(work)], check=True, stdout=subprocess.DEVNULL
    )
    _git(work, "config", "user.email", "fixture@example.invalid")
    _git(work, "config", "user.name", "Fixture")
    (work / "uv.lock").unlink()
    (work / "src/server.py").write_text("def serve():\n    return None\n")
    _git(work, "add", "-A")
    _git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "remove lock")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", "HEAD:refs/heads/main")

    profile = _profile(["HEAD"])
    snapshot = collect_snapshot(str(bare), base, head, profile, {"max_context_bytes": 80_000})
    projection = next(
        item for item in snapshot["evidence"].values() if item["source_kind"] == "dependency_projection"
    )
    assert projection["source_revision"] == head
    assert projection["lock_object_id"] is None
    assert '"lock_status":"LOCK_FILE_ABSENT"' in projection["content"]
    assert not any(gap.get("reason") == "dependency_lock_source_unavailable" for gap in snapshot["gaps"])


def test_missing_manifest_becomes_required_context_gap_and_task_sentinel(dependency_repo):
    repo, base, head = dependency_repo
    profile = _profile(["HEAD"])
    profile["retrieval_context_patterns"] = ["uv.lock", "missing.toml"]
    profile["dependency_context"]["bindings"][0]["manifest_path"] = "missing.toml"
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 80_000})
    assert any(
        gap["required"] is True and gap["reason"] == "dependency_manifest_missing"
        for gap in snapshot["gaps"]
    )
    plan = plan_review(snapshot, profile)
    assert any(
        evidence_id.startswith("missing-dependency-context-")
        for task in plan["tasks"]
        for evidence_id in task["required_context_ids"]
    )


def test_invalid_dependency_context_fails_before_git_resolution(monkeypatch):
    monkeypatch.setattr("pr_review_harness.snapshot._sha", lambda *_args: pytest.fail("Git was accessed"))
    profile = _profile()
    profile["dependency_context"]["bindings"][0]["sides"] = [{}]
    with pytest.raises(SnapshotError, match="dependency_context sides are invalid"):
        collect_snapshot("unused", "base", "head", profile, {"max_context_bytes": 80_000})
