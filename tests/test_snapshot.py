import hashlib
import subprocess
from pathlib import Path

import pytest

from pr_review_harness.planner import plan_review
from pr_review_harness.snapshot import (
    SnapshotError,
    _changed_line_ranges,
    _context_head_relation,
    _deleted_line_ranges,
    collect_snapshot,
    recent_commits,
)


def git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str, str]:
    path = tmp_path / "objects.git"
    subprocess.run(["git", "init", "--bare", str(path)], check=True, stdout=subprocess.DEVNULL)
    # Build commits through an isolated temporary worktree with hooks disabled.
    work = tmp_path / "work"
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Fixture")
    (work / "AGENTS.md").write_text("trusted base rules\n")
    (work / "app.py").write_text("def f():\n    return 1\n")
    (work / "docs").mkdir()
    (work / "docs/contract.md").write_text("The adapter returns an integer result.\n")
    (work / "old.txt").write_text("same\n")
    git(work, "add", "AGENTS.md", "app.py", "docs/contract.md", "old.txt")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(work, "rev-parse", "HEAD")
    git(work, "remote", "add", "origin", str(path))
    git(work, "push", "origin", "HEAD:refs/heads/main")
    (work / "app.py").write_text("def f():\n    return 2\n")
    (work / "old.txt").rename(work / "new.txt")
    (work / "link").symlink_to("app.py")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git(work, "rev-parse", "HEAD")
    git(work, "push", "origin", "HEAD:refs/heads/main")
    return path, base, head


def test_snapshot_uses_immutable_objects_and_trusted_base_context(repo):
    path, base, head = repo
    profile = {
        "version": "pilot-v1",
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    snap = collect_snapshot(str(path), base[:12], head, profile, {"max_context_bytes": 100_000})
    assert snap["base_sha"] == base and snap["head_sha"] == head
    assert snap["profile_version"] == "pilot-v1"
    assert snap["trusted_context_refs"]
    trusted = snap["evidence"][snap["trusted_context_refs"][0]]
    assert trusted["content"] == "trusted base rules\n"
    assert trusted["trust"] == "trusted_policy" and trusted["source_revision"] == base
    assert "head_relation" not in trusted and "head_object_id" not in trusted
    by_path = {unit["path"]: unit for unit in snap["inventory"]}
    assert by_path["app.py"]["diff_hash"]
    assert "@@" in by_path["app.py"]["diff"]
    assert "new.txt" in by_path and by_path["new.txt"]["old_path"] == "old.txt"
    assert any(gap["reason"] == "symlink_not_followed" for gap in snap["gaps"])
    assert all(gap.get("required") is True for gap in snap["gaps"] if gap["reason"] == "symlink_not_followed")
    assert snap["snapshot_hash"] and snap["snapshot_id"]


def test_pr_snapshot_excludes_unrelated_changes_on_ahead_base_tip(tmp_path):
    repo = tmp_path / "divergent"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "shared.txt").write_text("common\n")
    (repo / "policy.md").write_text("policy at fork\n")
    (repo / "delete-me.txt").write_text("deleted by PR\n")
    (repo / "old-name.txt").write_text("renamed by PR\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "common base")
    common = git(repo, "rev-parse", "HEAD")

    default_branch = git(repo, "branch", "--show-current")
    git(repo, "checkout", default_branch)
    (repo / "main-only.txt").write_text("unrelated default-branch change\n")
    (repo / "policy.md").write_text("current trusted policy\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "advance default branch")
    current_base = git(repo, "rev-parse", "HEAD")

    git(repo, "checkout", "-b", "pr", common)
    (repo / "pr-change.txt").write_text("intended pull request change\n")
    (repo / "delete-me.txt").unlink()
    (repo / "old-name.txt").rename(repo / "new-name.txt")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "pull request change")
    pr_head = git(repo, "rev-parse", "HEAD")
    merge_base = git(repo, "merge-base", current_base, pr_head)
    assert merge_base == common

    profile = {
        "version": "divergent-pr-v1",
        "context_paths": ["policy.md"],
        "trusted_policy_paths": ["policy.md"],
    }
    limits = {"max_context_bytes": 10_000}
    snapshot = collect_snapshot(str(repo), current_base, pr_head, profile, limits, pr_diff=True)

    # GitHub's PR `base.sha` is the current target-branch tip. The review
    # inventory should reflect the PR-side changes from the merge base, while
    # the current base revision remains available for policy/context/freshness.
    assert snapshot["base_sha"] == current_base
    assert snapshot["change_base_sha"] == common
    by_path = {item["path"]: item for item in snapshot["inventory"]}
    assert set(by_path) == {"pr-change.txt", "delete-me.txt", "new-name.txt"}
    assert by_path["delete-me.txt"]["change_type"] == "delete"
    assert by_path["new-name.txt"]["change_type"] == "rename"
    for path, source_path in (("delete-me.txt", "delete-me.txt"), ("new-name.txt", "old-name.txt")):
        unit = by_path[path]
        anchor = unit["file_level_location"]
        assert anchor["side"] == "BASE" and anchor["path"] == source_path, (path, unit, anchor)
        anchor_evidence = snapshot["evidence"][anchor["evidence_id"]]
        assert anchor_evidence["source_revision"] == common

    policy_ref = snapshot["trusted_context_refs"][0]
    policy_evidence = snapshot["evidence"][policy_ref]
    assert policy_evidence["trust"] == "trusted_policy"
    assert policy_evidence["source_revision"] == current_base
    assert policy_evidence["content"] == "current trusted policy\n"

    exact = collect_snapshot(str(repo), current_base, pr_head, profile, limits)
    exact_paths = {item["path"] for item in exact["inventory"]}
    assert "main-only.txt" in exact_paths
    assert "change_base_sha" not in exact and "comparison_mode" not in exact

    # Match the reusable workflow's bare, shallow, blob-filtered object store;
    # lazy blob hydration must still support immutable snapshot evidence.
    remote = tmp_path / "target.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, stdout=subprocess.DEVNULL)
    git(remote, "config", "uploadpack.allowFilter", "true")
    git(repo, "remote", "add", "target", str(remote))
    git(repo, "push", "target", f"{current_base}:refs/heads/main", f"{pr_head}:refs/pull/1/head")
    store = tmp_path / "object-store.git"
    subprocess.run(["git", "init", "--bare", str(store)], check=True, stdout=subprocess.DEVNULL)
    for key, value in (
        ("remote.origin.url", str(remote)),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("extensions.partialClone", "origin"),
    ):
        git(store, "config", key, value)
    for depth, refspec in (
        (2, "+refs/pull/1/head:refs/pr/head"),
        (2, "+refs/heads/main:refs/pr/base"),
    ):
        subprocess.run(
            ["git", "-C", str(store), "fetch", "--no-tags", "--filter=blob:none", f"--depth={depth}", "origin", refspec],
            check=True,
            capture_output=True,
            timeout=30,
        )
    filtered_snapshot = collect_snapshot(str(store), current_base, pr_head, profile, limits, pr_diff=True)
    assert {item["path"] for item in filtered_snapshot["inventory"]} == set(by_path)
    assert filtered_snapshot["evidence"][filtered_snapshot["trusted_context_refs"][0]]["content"] == "current trusted policy\n"


def test_disabled_context_revision_metadata_preserves_legacy_snapshot_identity(repo):
    path, base, head = repo
    profile = {
        "version": "context-identity-v1",
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    legacy = collect_snapshot(str(path), base, head, profile, {"max_context_bytes": 100_000})
    disabled = collect_snapshot(
        str(path), base, head, {**profile, "context_revision_metadata": False}, {"max_context_bytes": 100_000}
    )
    assert disabled["snapshot_id"] == legacy["snapshot_id"]
    assert disabled["snapshot_hash"] == legacy["snapshot_hash"]
    assert disabled["evidence"] == legacy["evidence"]
    assert all("head_relation" not in item and "head_object_id" not in item for item in disabled["evidence"].values())


@pytest.mark.parametrize("value", [None, "true", 0, 1, [], {}])
def test_context_revision_metadata_rejects_non_boolean_before_git_reads(repo, monkeypatch, value):
    path, base, head = repo
    monkeypatch.setattr("pr_review_harness.snapshot._sha", lambda *_args: pytest.fail("Git resolution started"))
    with pytest.raises(SnapshotError, match="profile context_revision_metadata must be boolean"):
        collect_snapshot(
            str(path), base, head,
            {"version": "context-identity-v1", "context_revision_metadata": value},
            {"max_context_bytes": 100_000},
        )


def test_profile_context_records_bounded_exact_head_blob_relation(repo):
    path, base, head = repo
    profile = {
        "version": "context-identity-v1",
        "context_revision_metadata": True,
        "context_paths": ["AGENTS.md", "app.py", "old.txt", "tests"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    snap = collect_snapshot(str(path), base, head, profile, {"max_context_bytes": 100_000})
    contexts = {
        item["path"]: item
        for item in snap["evidence"].values()
        if item["source_kind"] == "profile_context"
    }
    assert contexts["AGENTS.md"]["head_relation"] == "UNCHANGED"
    assert contexts["AGENTS.md"]["head_object_id"] == contexts["AGENTS.md"]["source_object_id"]
    assert contexts["app.py"]["head_relation"] == "CHANGED"
    assert contexts["app.py"]["head_object_id"] != contexts["app.py"]["source_object_id"]
    assert contexts["old.txt"]["head_relation"] == "MISSING_HEAD"
    assert contexts["old.txt"]["head_object_id"] is None
    assert "tests" not in contexts
    assert contexts["AGENTS.md"]["source_revision"] == base
    assert contexts["AGENTS.md"]["trust"] == "trusted_policy"
    assert contexts["app.py"]["trust"] == "repository_evidence"


@pytest.mark.parametrize(
    ("base_entry", "head_entry", "expected"),
    [
        (("100644", "a" * 40), ("100644", "a" * 40), ("UNCHANGED", "a" * 40)),
        (("100644", "a" * 40), ("100644", "b" * 40), ("CHANGED", "b" * 40)),
        (("100644", "a" * 40), None, ("MISSING_HEAD", None)),
        (("100644", "not-a-git-oid"), ("100644", "b" * 40), ("UNKNOWN", None)),
        (("100644", "a" * 40), ("100644", "invented-oid"), ("UNKNOWN", None)),
        (("100644", "a" * 40), ("120000", "b" * 40), ("UNKNOWN", None)),
    ],
)
def test_context_head_relation_rejects_invalid_or_unsafe_git_identities(base_entry, head_entry, expected):
    assert _context_head_relation(base_entry, head_entry) == expected


def test_snapshot_context_budget_is_separate_with_legacy_fallback(repo):
    path, base, head = repo
    profile = {
        "version": "pilot-v1",
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
    }
    legacy = collect_snapshot(str(path), base, head, profile, {"max_context_bytes": 8_000})
    explicit = collect_snapshot(
        str(path), base, head, profile,
        {"max_context_bytes": 20_000, "max_snapshot_context_bytes": 8_000},
    )
    assert explicit["snapshot_hash"] == legacy["snapshot_hash"]
    assert explicit["evidence"] == legacy["evidence"]

    tiny_capture = collect_snapshot(
        str(path), base, head, profile,
        {"max_context_bytes": 20_000, "max_snapshot_context_bytes": 1},
    )
    assert tiny_capture["snapshot_hash"] != explicit["snapshot_hash"]


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, "100"])
def test_snapshot_context_budget_rejects_invalid_optional_values(repo, value):
    path, base, head = repo
    with pytest.raises(SnapshotError, match="snapshot context byte limit"):
        collect_snapshot(
            str(path), base, head,
            {"version": "pilot-v1", "context_paths": []},
            {"max_context_bytes": 10_000, "max_snapshot_context_bytes": value},
        )


def _selection_profile():
    return {
        "version": "context-selection-test-v3",
        "context_paths": ["AGENTS.md", "docs/contract.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "retrieval_context_patterns": ["AGENTS.md", "docs/contract.md"],
        "required_lenses": ["correctness", "tests"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 4096,
            "window": {
                "before_lines": 1,
                "after_lines": 1,
                "max_bytes": 1024,
                "max_windows_per_unit": 4,
                "max_scan_bytes": 4096,
            },
            "bindings": [
                {
                    "unit_patterns": ["app.py"],
                    "lenses": ["correctness"],
                    "context_paths": ["docs/contract.md"],
                    "max_context_bytes": 2048,
                }
            ],
        },
    }


def test_context_selection_keeps_full_anchor_separate_from_bounded_windows_and_scopes_context(repo):
    path, base, head = repo
    profile = _selection_profile()
    snap = collect_snapshot(str(path), base, head, profile, {"max_context_bytes": 20_000})
    unit = next(row for row in snap["inventory"] if row["path"] == "app.py")
    windows = [
        snap["evidence"][eid]
        for eid in unit["review_context_evidence_ids"]
        if snap["evidence"][eid]["source_kind"] == "source_window"
    ]
    assert windows
    window = next(item for item in windows if item.get("source_side") == "HEAD")
    expected_oid = git(path, "rev-parse", f"{head}:app.py")
    assert window["source_object_id"] == expected_oid
    assert window["source_revision"] == head
    assert window["source_side"] == "HEAD"
    assert window["line_start"] <= 2 <= window["line_end"]
    assert "return 2" in window["content"]
    assert window["content_hash"] == hashlib.sha256(window["content"].encode()).hexdigest()
    assert any(snap["evidence"][eid]["source_kind"] == "head_file" for eid in unit["evidence_ids"])
    assert all(
        snap["evidence"][eid]["source_kind"] in {"diff", "source_window"} for eid in unit["review_context_evidence_ids"]
    )

    plan = plan_review(snap, profile)
    correctness = next(task for task in plan["tasks"] if task["lens"] == "correctness")
    tests = next(task for task in plan["tasks"] if task["lens"] == "tests")
    correctness_evidence = {snap["evidence"][eid]["path"] for eid in correctness["evidence_ids"]}
    tests_evidence = {snap["evidence"][eid]["path"] for eid in tests["evidence_ids"]}
    assert "docs/contract.md" in correctness_evidence
    assert "docs/contract.md" not in tests_evidence
    assert "AGENTS.md" in correctness_evidence and "AGENTS.md" in tests_evidence
    assert all(
        snap["evidence"][eid]["source_kind"] not in {"base_file", "head_file"} for eid in correctness["evidence_ids"]
    )


def test_context_selection_emits_required_gap_instead_of_clipping_hunk_or_missing_lines(repo):
    path, base, head = repo
    profile = _selection_profile()
    profile["context_selection"]["window"]["max_bytes"] = 8
    profile["context_selection"]["window"]["max_scan_bytes"] = 2
    snap = collect_snapshot(str(path), base, head, profile, {"max_context_bytes": 20_000})
    unit = next(row for row in snap["inventory"] if row["path"] == "app.py")
    assert not any(
        snap["evidence"][eid]["source_kind"] == "source_window" for eid in unit["review_context_evidence_ids"]
    )
    reasons = {gap["reason"] for gap in snap["gaps"]}
    assert "window_scan_limit" in reasons or "changed_hunk_exceeds_window_limit" in reasons


def test_context_selection_rejects_non_finite_or_unallowlisted_profile_limits(repo):
    path, base, head = repo
    profile = _selection_profile()
    profile["context_selection"]["window"]["max_scan_bytes"] = True
    with pytest.raises(ValueError, match="max_scan_bytes"):
        plan_review(
            collect_snapshot(str(path), base, head, _selection_profile(), {"max_context_bytes": 20_000}), profile
        )
    profile = _selection_profile()
    profile["context_selection"]["bindings"][0]["context_paths"] = ["secret/private.md"]
    with pytest.raises(ValueError, match="allowlists"):
        plan_review(
            collect_snapshot(str(path), base, head, _selection_profile(), {"max_context_bytes": 20_000}), profile
        )


def test_snapshot_bounds_context_and_marks_gaps(repo):
    path, base, head = repo
    snap = collect_snapshot(
        str(path), base, head, {"version": "pilot-v1", "context_paths": ["AGENTS.md"]}, {"max_context_bytes": 24}
    )
    assert sum(len(row["content"].encode()) for row in snap["evidence"].values()) <= 24
    assert snap["gaps"]
    assert any(gap["reason"] == "context_truncated" for gap in snap["gaps"])


def test_recent_commit_pairs_are_first_parent_and_bounded(repo):
    path, _base, head = repo
    pairs = recent_commits(str(path), 5, head)
    assert len(pairs) == 1
    assert pairs[0]["head"] == head
    assert pairs[0]["base"]
    with pytest.raises(ValueError):
        recent_commits(str(path), 0, head)


def test_recent_pairs_follow_first_parent_through_merge_and_multiline_message(tmp_path):
    work = tmp_path / "merge-work"
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Fixture")
    (work / "base.txt").write_text("base\n")
    git(work, "add", "base.txt")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    default_branch = git(work, "branch", "--show-current")
    git(work, "branch", "side")
    (work / "main.txt").write_text("main\n")
    git(work, "add", "main.txt")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "main title\n\nmain body")
    first_parent = git(work, "rev-parse", "HEAD")
    git(work, "checkout", "side")
    (work / "side.txt").write_text("side\n")
    git(work, "add", "side.txt")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "side title\n\nextra body")
    git(work, "checkout", default_branch)
    git(work, "-c", "core.hooksPath=/dev/null", "merge", "--no-ff", "side", "-m", "merge title\n\nmerge body")
    merge = git(work, "rev-parse", "HEAD")
    pairs = recent_commits(str(work), 4)
    assert pairs[0] == {"base": first_parent, "head": merge, "subject": "merge title"}
    assert pairs[1]["head"] == first_parent and pairs[1]["subject"] == "main title"
    assert all(pair["base"] != "side:" for pair in pairs)


def test_snapshot_classifies_docs_and_security_code_for_routing(tmp_path):
    work = tmp_path / "routing"
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Fixture")
    (work / "notes.md").write_text("before\n")
    (work / "security.py").write_text("before = True\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(work, "rev-parse", "HEAD")
    (work / "notes.md").write_text("after\n")
    (work / "security.py").write_text("after = False\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git(work, "rev-parse", "HEAD")
    profile = {
        "version": "route-v1",
        "context_paths": [],
        "docs_lenses": ["correctness"],
        "required_lenses": ["correctness"],
        "risk_rules": [
            {"patterns": ["security.py"], "min_mode": "FOCUSED", "lenses": ["security"], "reason": "security boundary"}
        ],
    }
    snap = collect_snapshot(str(work), base, head, profile, {"max_context_bytes": 100_000})
    by_path = {unit["path"]: unit for unit in snap["inventory"]}
    assert by_path["notes.md"]["kind"] == "documentation"
    assert by_path["security.py"]["kind"] == "human_code"
    plan = plan_review(snap, profile, "AUTO")
    assert plan["mode"] == "FOCUSED"
    assert "security" in [
        o["lens"] for o in plan["coverage_obligations"] if o["scope_unit_ids"] == [by_path["security.py"]["unit_id"]]
    ]
    assert "security" not in [
        o["lens"] for o in plan["coverage_obligations"] if o["scope_unit_ids"] == [by_path["notes.md"]["unit_id"]]
    ]


def test_diff_treats_pathspec_magic_filename_literally(tmp_path):
    work = tmp_path / "literal"
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Fixture")
    strange = ":(glob)target.txt"
    (work / strange).write_text("old strange\n")
    (work / "other.txt").write_text("old other\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(work, "rev-parse", "HEAD")
    (work / strange).write_text("new strange\n")
    (work / "other.txt").write_text("new other\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git(work, "rev-parse", "HEAD")
    snap = collect_snapshot(
        str(work), base, head, {"version": "v1", "context_paths": []}, {"max_context_bytes": 100_000}
    )
    by_path = {unit["path"]: unit for unit in snap["inventory"]}
    assert "new strange" in by_path[strange]["diff"]
    assert "other.txt" not in by_path[strange]["diff"]


def test_hunk_line_parser_counts_added_lines_starting_with_header_characters():
    assert _changed_line_ranges("@@ -0,0 +1 @@\n++++literal content\n") == [[1, 1]]


def test_deleted_line_ranges_track_base_side_lines():
    diff = "@@ -4,3 +4,2 @@\n context\n-removed\n+added\n last\n"
    assert _deleted_line_ranges(diff) == [[5, 5]]


def test_snapshot_emits_delete_and_rename_location_metadata(tmp_path):
    work = tmp_path / "deleted-and-renamed"
    subprocess.run(["git", "init", str(work)], check=True, stdout=subprocess.DEVNULL)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Fixture")
    (work / "gone.py").write_text("def old():\n    return 7\n")
    (work / "old.py").write_text("same\n")
    (work / "edit.py").write_text("value = 1\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(work, "rev-parse", "HEAD")
    (work / "gone.py").unlink()
    (work / "old.py").rename(work / "new.py")
    (work / "edit.py").write_text("value = 2\n")
    git(work, "add", "-A")
    git(work, "-c", "core.hooksPath=/dev/null", "commit", "-m", "delete and rename")
    head = git(work, "rev-parse", "HEAD")
    snap = collect_snapshot(str(work), base, head, {"version": "v1", "context_paths": []}, {"max_context_bytes": 10000})
    units = {row["path"]: row for row in snap["inventory"]}
    assert units["gone.py"]["change_type"] == "delete"
    assert units["gone.py"]["old_line_ranges"] == [[1, 2]]
    deleted_anchor = units["gone.py"]["file_level_location"]
    assert {key: deleted_anchor[key] for key in ("kind", "path", "side", "reason")} == {
        "kind": "file",
        "path": "gone.py",
        "side": "BASE",
        "reason": "deleted_file_base_blob",
    }
    assert deleted_anchor["evidence_id"] in snap["evidence"]
    assert snap["evidence"][deleted_anchor["evidence_id"]]["source_revision"] == base
    assert deleted_anchor["evidence_hash"] == snap["evidence"][deleted_anchor["evidence_id"]]["content_hash"]
    assert units["new.py"]["change_type"] == "rename"
    assert units["new.py"]["old_path"] == "old.py"
    renamed_anchor = units["new.py"]["file_level_location"]
    assert renamed_anchor["path"] == "new.py" and renamed_anchor["side"] == "HEAD"
    assert renamed_anchor["evidence_hash"] == snap["evidence"][renamed_anchor["evidence_id"]]["content_hash"]
    changed_anchor = units["edit.py"]["file_level_location"]
    assert changed_anchor["path"] == "edit.py" and changed_anchor["side"] == "HEAD"
    assert changed_anchor["evidence_hash"] == snap["evidence"][changed_anchor["evidence_id"]]["content_hash"]
