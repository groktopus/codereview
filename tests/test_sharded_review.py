"""Path-scoped planning and file-batch sharding tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from pr_review_harness.planner import plan_review  # noqa: E402
from scripts import sharded_review  # noqa: E402


def snapshot(units, gaps=None):
    return {
        "snapshot_id": "snap-scope",
        "profile_version": "p1",
        "inventory": units,
        "gaps": gaps or [],
    }


def unit(uid, path, kind="human_code"):
    return {"unit_id": uid, "path": path, "kind": kind, "evidence_ids": [f"diff:{uid}"]}


def base_profile():
    return {
        "version": "p1",
        "required_lenses": ["correctness", "tests", "maintainability"],
        "docs_lenses": ["correctness"],
        "risk_rules": [
            {
                "patterns": ["src/*"],
                "min_mode": "FOCUSED",
                "lenses": ["security"],
                "reason": "source boundary",
            }
        ],
        "required_checks": [{"id": "tests", "patterns": ["src/*", "tests/*"], "reason": "tests"}],
    }


def scoped(plan, unit_ids):
    """Return the same plan shape restricted to the selected unit ids."""
    selected = set(unit_ids)
    obligations = []
    for obligation in plan["coverage_obligations"]:
        units = set(obligation.get("scope_unit_ids", []))
        restricted = units & selected
        if obligation["obligation_kind"] == "REQUIRED_CONTEXT" and not units:
            obligations.append(obligation)
        elif restricted:
            obligations.append(
                {**obligation, "scope_unit_ids": [uid for uid in obligation["scope_unit_ids"] if uid in selected]}
            )
    tasks = []
    for task in plan["tasks"]:
        units = [uid for uid in task.get("unit_ids", []) if uid in selected]
        if units:
            tasks.append({**task, "unit_ids": units, "scope_unit_ids": units})
    reasons = [
        reason
        for reason in plan["routing_reasons"]
        if not any(reason.startswith(f"{uid}:") for uid in plan["risk_by_unit"] if uid not in selected)
    ]
    return {
        "mode": plan["mode"],
        "risk_floor": plan["risk_floor"],
        "risk_by_unit": {uid: risks for uid, risks in plan["risk_by_unit"].items() if uid in selected},
        "coverage_obligations": obligations,
        "tasks": tasks,
        "routing_reasons": reasons,
        "not_applicable": plan["not_applicable"],
    }


def test_scoped_plan_equals_unsharded_plan_restricted_to_paths():
    units = [
        unit("a", "src/a.py"),
        unit("b", "src/b.py"),
        unit("t", "tests/test_a.py"),
        unit("d", "docs/readme.md", "documentation"),
    ]
    full = plan_review(snapshot(units), base_profile())
    scoped_profile = {**base_profile(), "scope_paths": ["src/*"]}
    partial = plan_review(snapshot(units), scoped_profile)
    assert partial["mode"] == full["mode"]
    assert partial["risk_floor"] == full["risk_floor"]
    assert partial["risk_by_unit"] == scoped(full, {"a", "b"})["risk_by_unit"]
    assert partial["routing_reasons"] == scoped(full, {"a", "b"})["routing_reasons"]
    assert partial["not_applicable"] == scoped(full, {"a", "b"})["not_applicable"]

    partial_obligations = {obligation["obligation_id"]: obligation for obligation in partial["coverage_obligations"]}
    for obligation in scoped(full, {"a", "b"})["coverage_obligations"]:
        assert partial_obligations[obligation["obligation_id"]] == obligation
    assert {task["lens"] for task in partial["tasks"]} == {task["lens"] for task in scoped(full, {"a", "b"})["tasks"]}
    assert all(set(task["unit_ids"]) <= {"a", "b"} for task in partial["tasks"])


def test_scope_preserves_risk_rule_security_lens():
    profile = base_profile()
    profile["required_lenses"] = ["correctness"]
    plan = plan_review(snapshot([unit("a", "src/a.py")]), {**profile, "scope_paths": ["src/a.py"]})
    obligations = {obligation["obligation_id"] for obligation in plan["coverage_obligations"]}
    assert "unit:a:lens:security" in obligations
    assert "a:source boundary" in plan["routing_reasons"]


def test_scope_filters_required_gaps_outside_paths():
    profile = {**base_profile(), "scope_paths": ["src/*"]}
    gaps = [
        {"path": "src/a.py", "source_kind": "diff", "reason": "diff_truncated", "required": True},
        {"path": "docs/readme.md", "source_kind": "diff", "reason": "diff_truncated", "required": True},
    ]
    plan = plan_review(snapshot([unit("a", "src/a.py"), unit("d", "docs/readme.md")], gaps), profile)
    required_context = [
        obligation for obligation in plan["coverage_obligations"] if obligation["obligation_kind"] == "REQUIRED_CONTEXT"
    ]
    assert len(required_context) == 1
    assert required_context[0]["scope_unit_ids"] == []
    assert all(obligation["obligation_id"] != "context:1" for obligation in plan["coverage_obligations"])


def test_explicit_check_binding_outside_scope_is_not_applicable():
    profile = {
        "version": "p1",
        "required_lenses": ["correctness"],
        "required_checks": [{"id": "only-test", "unit_ids": ["t"], "reason": "test binding"}],
        "scope_paths": ["src/*"],
    }
    plan = plan_review(snapshot([unit("a", "src/a.py"), unit("t", "tests/test_a.py")]), profile)
    assert plan["not_applicable"] == [
        {
            "obligation_id": "check:only-test",
            "obligation_kind": "PROJECT_CHECK",
            "reason": "configured_unit_binding_outside_scope",
            "profile_rationale": "test binding",
            "state": "NOT_APPLICABLE",
        }
    ]
    assert "check:only-test" not in {item["obligation_id"] for item in plan["coverage_obligations"]}


def test_unmatched_scope_pattern_is_an_explicit_error():
    with pytest.raises(ValueError, match="did not match any changed unit"):
        plan_review(snapshot([unit("a", "src/a.py")]), {"version": "p1", "scope_paths": ["docs/*"]})
    with pytest.raises(ValueError, match="did not match any changed unit"):
        plan_review(
            snapshot([unit("a", "src/a.py")]),
            {"version": "p1", "scope_paths": ["src/*", "docs/*"]},
        )


@pytest.mark.parametrize(
    "value",
    [[], "src/*", [""], [None], ["src/*", "src/*"]],
)
def test_scope_shape_is_validated(value):
    with pytest.raises(ValueError, match="scope_paths"):
        plan_review(snapshot([unit("a", "src/a.py")]), {"version": "p1", "scope_paths": value})


def test_batch_partition_covers_exact_diff_without_overlap():
    paths = [f"src/file_{index}.py" for index in range(21)]
    batches = sharded_review.partition_paths(paths, 6)
    assert [len(batch) for batch in batches] == [6, 6, 6, 3]
    assert [path for batch in batches for path in batch] == paths
    sharded_review.validate_partition(paths, batches)


def test_union_assertion_rejects_missing_and_overlapping_paths():
    with pytest.raises(sharded_review.ShardedReviewError, match="union"):
        sharded_review.validate_partition(["a", "b"], [["a"]])
    with pytest.raises(sharded_review.ShardedReviewError, match="more than one batch"):
        sharded_review.validate_partition(["a", "b"], [["a"], ["a", "b"]])
    with pytest.raises(sharded_review.ShardedReviewError, match="duplicate"):
        sharded_review.validate_partition(["a"], [["a", "a"]])


def test_scoped_profile_keeps_full_profile_and_escapes_exact_paths():
    profile = base_profile()
    scoped_profile = sharded_review.build_scoped_profile(profile, ["src/a*b.py", "src/a[b].py"])
    assert scoped_profile["scope_paths"] == ["src/a[*]b.py", "src/a[[]b].py"]
    assert scoped_profile["required_lenses"] == profile["required_lenses"]
    assert scoped_profile["risk_rules"] == profile["risk_rules"]
    assert "scope_paths" not in profile

    snap = snapshot([unit("a", "src/a*b.py"), unit("b", "src/axb.py"), unit("c", "src/a[b].py")])
    plan = plan_review(snap, scoped_profile)
    assert {obligation["scope_unit_ids"][0] for obligation in plan["coverage_obligations"]} == {"a", "c"}


def test_env_sanitization_strips_event_tokens_actions_and_publication():
    env = {
        "PATH": "/bin",
        "NOUS_API_KEY": "secret-name-not-value",
        "GITHUB_EVENT_PATH": "/tmp/event.json",
        "GITHUB_TOKEN": "token",
        "GH_TOKEN": "token",
        "ACTIONS_RUNTIME_TOKEN": "token",
        "ACTIONS_CACHE_URL": "http://cache",
        "PUBLISH_REVIEW": "1",
    }
    sanitized = sharded_review.sanitized_env(env)
    assert sanitized == {"PATH": "/bin", "NOUS_API_KEY": "secret-name-not-value"}


def test_missing_shard_result_is_incomplete_with_explicit_reason():
    record = sharded_review._shard_record(
        shard_id="shard-000",
        paths=["src/a.py"],
        scope_paths=["src/a.py"],
        profile_path=Path("/tmp/profile.json"),
        profile_sha256="a" * 64,
        base_sha="b" * 40,
        head_sha="c" * 40,
        output_root=Path("/tmp"),
        exit_code=0,
        result_path=None,
        result=None,
        error=None,
    )
    assert record["status"] == "INCOMPLETE"
    assert record["disposition"] == "INCOMPLETE"
    assert "missing_shard_result" in record["reasons"]


def _assemble(records, results):
    return sharded_review.assemble_result(
        repo=Path("/repo"),
        base_sha="b" * 40,
        head_sha="c" * 40,
        diff_files=[path for record in records for path in record["paths"]],
        batches=[record["paths"] for record in records],
        shard_records=records,
        shard_results=results,
        profile_path=Path("/repo/profile.json"),
        profile_sha256="d" * 64,
        profile_version="p1",
        limits_path=None,
        limits_sha256=None,
        provider_sha256=None,
        batch_size=6,
    )


def test_merge_dedupes_findings_and_gaps_and_preserves_blocker_precedence():
    finding = {
        "finding_id": "finding-1",
        "path": "src/a.py",
        "title": "Use after free",
        "observation": "Observed.",
        "status": "UNSUPPORTED",
        "blocking_class": "UNRESOLVED",
    }
    stronger = {**finding, "status": "ACCEPTED", "blocking_class": "BLOCKING"}
    gap = {
        "proposal_id": "gap-1",
        "resolved_unit_id": "a",
        "affected_obligation_ids": ["unit:a:lens:correctness"],
        "proposal": {"target": {"target_path": "src/a.py"}, "rationale": "missing test"},
    }
    records = [
        {
            "shard_id": "shard-000",
            "paths": ["src/a.py"],
            "status": "COMPLETE",
            "disposition": "COMMENT",
            "_findings": [finding],
            "context_gaps": [gap],
            "snapshot_gaps": [],
        },
        {
            "shard_id": "shard-001",
            "paths": ["src/b.py"],
            "status": "COMPLETE",
            "disposition": "REQUEST_CHANGES",
            "_findings": [stronger, {**finding, "finding_id": "finding-2", "title": "Other"}],
            "context_gaps": [{**gap, "affected_obligation_ids": ["unit:b:lens:correctness"]}],
            "snapshot_gaps": [],
        },
    ]
    results = [
        {"provider_identity": {"provider_id": "one"}, "coverage_ledger": [{"required": True, "state": "COMPLETE"}]},
        {"provider_identity": {"provider_id": "one"}, "coverage_ledger": [{"required": True, "state": "COMPLETE"}]},
    ]
    combined = _assemble(records, results)
    assert combined["completeness"] == "COMPLETE"
    assert combined["disposition"] == "REQUEST_CHANGES"
    assert len(combined["findings"]) == 2
    deduped = next(item for item in combined["findings"] if item["finding_id"] == "finding-1")
    assert deduped["status"] == "ACCEPTED"
    assert deduped["shard_ids"] == ["shard-000", "shard-001"]
    assert len(combined["context_gaps"]) == 1
    assert combined["context_gaps"][0]["affected_obligation_ids"] == [
        "unit:a:lens:correctness",
        "unit:b:lens:correctness",
    ]
    assert combined["context_gaps"][0]["shard_ids"] == ["shard-000", "shard-001"]
    assert combined["provider_identities"] == [{"provider_id": "one"}]


def test_incomplete_shard_keeps_known_blocker_and_reports_incomplete():
    records = [
        {
            "shard_id": "shard-000",
            "paths": ["src/a.py"],
            "status": "INCOMPLETE",
            "disposition": "INCOMPLETE",
            "reasons": ["shard_coverage_partial"],
            "_findings": [],
            "context_gaps": [],
            "snapshot_gaps": [],
        },
        {
            "shard_id": "shard-001",
            "paths": ["src/b.py"],
            "status": "COMPLETE",
            "disposition": "REQUEST_CHANGES",
            "_findings": [],
            "context_gaps": [],
            "snapshot_gaps": [],
        },
    ]
    combined = _assemble(records, [None, None])
    assert combined["completeness"] == "INCOMPLETE"
    assert combined["disposition"] == "REQUEST_CHANGES"
    assert combined["incomplete_reasons"] == [
        {"shard_id": "shard-000", "paths": ["src/a.py"], "reasons": ["shard_coverage_partial"]}
    ]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout.strip()


def test_orchestration_partitions_real_diff_and_writes_one_result_per_shard(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    for index in range(8):
        (repo / f"file_{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    for index in range(7):
        (repo / f"file_{index}.py").write_text(f"VALUE = {index + 1}\n", encoding="utf-8")
    _git(repo, "commit", "-am", "head")
    head = _git(repo, "rev-parse", "HEAD")

    profile = {"version": "test-profile", "required_lenses": ["correctness"], "allow_empty_approval": True}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    run_ids = []

    def fake_runner(command, *, repo, result_path, timeout_seconds):
        run_id = command[command.index("--run-id") + 1]
        run_ids.append(run_id)
        result = {
            "disposition": "APPROVE",
            "coverage_state": "COMPLETE",
            "freshness": "CURRENT",
            "policy_valid": True,
            "findings": [],
            "context_gaps": [],
            "snapshot_gaps": [],
            "coverage_ledger": [{"required": True, "state": "COMPLETE", "reason_code": "VALID_RESULT"}],
            "provider_identity": {"provider_id": "fixture"},
        }
        result_path.write_text(json.dumps(result), encoding="utf-8")
        return 0, result, None

    combined = sharded_review.run_sharded_review(
        repo=repo,
        base=base,
        head=head,
        profile=profile,
        profile_path=profile_path,
        output_dir=tmp_path / "out",
        batch_size=3,
        shard_runner=fake_runner,
    )
    assert combined["completeness"] == "COMPLETE"
    assert combined["disposition"] == "APPROVE"
    assert [len(shard["paths"]) for shard in combined["shards"]] == [3, 3, 1]
    assert combined["partition"]["union_matches_diff"] is True
    assert combined["partition"]["overlap_count"] == 0
    assert len(run_ids) == 3
    for shard in combined["shards"]:
        assert shard["profile_sha256"]
        assert shard["result_sha256"]
        generated = json.loads((tmp_path / "out" / shard["shard_id"] / "profile.json").read_text())
        assert generated["scope_paths"] == [sharded_review.escape_glob_path(path) for path in shard["paths"]]


def test_orchestration_marks_missing_shard_incomplete(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Fixture")
    (repo / "a.py").write_text("A = 1\n", encoding="utf-8")
    (repo / "b.py").write_text("B = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("A = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("B = 2\n", encoding="utf-8")
    _git(repo, "commit", "-am", "head")
    head = _git(repo, "rev-parse", "HEAD")
    profile = {"version": "test-profile", "required_lenses": ["correctness"]}
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    calls = {"count": 0}

    def fake_runner(command, *, repo, result_path, timeout_seconds):
        calls["count"] += 1
        if calls["count"] == 2:
            return 0, None, None
        result = {
            "disposition": "COMMENT",
            "coverage_state": "COMPLETE",
            "freshness": "CURRENT",
            "policy_valid": True,
            "findings": [],
            "context_gaps": [],
            "snapshot_gaps": [],
            "coverage_ledger": [],
        }
        result_path.write_text(json.dumps(result), encoding="utf-8")
        return 0, result, None

    combined = sharded_review.run_sharded_review(
        repo=repo,
        base=base,
        head=head,
        profile=profile,
        profile_path=profile_path,
        output_dir=tmp_path / "out",
        batch_size=1,
        shard_runner=fake_runner,
    )
    assert combined["completeness"] == "INCOMPLETE"
    assert combined["disposition"] == "INCOMPLETE"
    assert combined["shards"][1]["status"] == "INCOMPLETE"
    assert "missing_shard_result" in combined["shards"][1]["reasons"]
