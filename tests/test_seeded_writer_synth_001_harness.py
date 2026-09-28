from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.snapshot import collect_snapshot

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"
LIMITS = {
    "deadline_seconds": 10,
    "max_concurrent_scopes": 1,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 50_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 0,
    "max_followup_tasks": 0,
}


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _synthetic_repo(tmp_path: Path) -> tuple[Path, str, str, dict]:
    seed = json.loads((FIXTURE / "seed.json").read_text())
    visible = {relative: (FIXTURE / relative).read_text() for relative in seed["visible_files"]}
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(tmp_path, "init", str(repo))
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "SYNTH-001 fixture")

    # The fixture keeps base/head sources separately, while the synthetic
    # project materializes them at the root import path used by caller.py.
    for relative, content in visible.items():
        if relative in {"base/auth.py", "head/auth.py"}:
            continue
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    reviewed_auth = repo / "auth.py"
    reviewed_auth.write_text(visible["base/auth.py"])
    _git(repo, "add", "-A")
    fixed_commit_time = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "synthetic base", env=fixed_commit_time)
    base = _git(repo, "rev-parse", "HEAD")

    reviewed_auth.write_text(visible["head/auth.py"])
    _git(repo, "add", "-A")
    fixed_commit_time["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:01+00:00"
    fixed_commit_time["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:01+00:00"
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "synthetic change", env=fixed_commit_time)
    head = _git(repo, "rev-parse", "HEAD")

    profile = {
        "version": "seeded-writer-synth-001-v1",
        "required_lenses": ["correctness"],
        "allow_empty_approve": True,
        "context_paths": ["contract.md", "caller.py"],
    }
    assert set(_git(repo, "ls-tree", "-r", "--name-only", head).splitlines()) == {
        "auth.py", "caller.py", "contract.md"
    }
    return repo, base, head, profile


class _LoopbackStyleFakeReviewProvider:
    """In-process provider double; it cannot make an external request."""

    identity = {
        "kind": "offline-synth-001-provider",
        "model": "fixture-reviewer",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self, request_log: Path):
        self.request_log = request_log

    def review(self, task, evidence, _limits):
        with self.request_log.open("a") as stream:
            stream.write(json.dumps({"task": task, "evidence": evidence}, sort_keys=True) + "\n")
        diff = next(item for item in evidence if item.get("source_kind") == "diff")
        assert diff["path"] == "auth.py"
        assert "+    return True" in diff["content"]
        return {
            "finding_candidates": [
                {
                    "unit_id": task["unit_ids"][0],
                    "path": diff["path"],
                    "line": 2,
                    "title": "Authorization no longer checks document ownership",
                    "observation": "The changed predicate returns true for every caller and document.",
                    "consequence": "A caller can read a document owned by a different user.",
                    "rule_or_contract": "The contract requires caller ID to match document owner ID.",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [diff["evidence_id"]],
                }
            ],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit_id,
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": [diff["evidence_id"]],
                    "coverage_basis": "STATIC_REVIEW",
                }
                for unit_id in task["unit_ids"]
            ],
        }

    def adjudicate(self, candidate, evidence, _limits):
        refs = list(candidate["evidence_refs"])
        return {
            "payload": {
                "contract_version": "semantic-adjudication.v3",
                "source_contract_version": "semantic-adjudication.v3",
                "outcome": "SUPPORTED",
                "observation_support": "SUPPORTED",
                "consequence_support": "SUPPORTED",
                "rule_connection_support": "SUPPORTED",
                "introducedness": "INTRODUCED",
                "material_consequence": True,
                "evidence_refs": refs,
                "causal_roles": {
                    role: {
                        "support": "SUPPORTED",
                        "assessment": f"Allowlisted fixture evidence supports the {role} link.",
                        "evidence_refs": refs,
                    }
                    for role in ("behavior", "consumer", "impact")
                },
                "assumptions": [],
                "uncertainties": [],
                "summary": "The changed authorization predicate bypasses the owner check.",
            },
            "provenance": {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
        }


def test_synth_001_runs_snapshot_planner_and_review_without_publication(tmp_path):
    truth = json.loads((FIXTURE / "truth.json").read_text())
    repo, base, head, profile = _synthetic_repo(tmp_path)
    snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)
    second_repo, second_base, second_head, second_profile = _synthetic_repo(tmp_path / "repeat")
    second_snapshot = collect_snapshot(str(second_repo), second_base, second_head, second_profile, LIMITS)
    assert (base, head, snapshot["snapshot_id"]) == (
        second_base,
        second_head,
        second_snapshot["snapshot_id"],
    )
    plan = plan_review(snapshot, profile, "AUTO")
    request_log = tmp_path / "fake-provider-requests.jsonl"
    provider = _LoopbackStyleFakeReviewProvider(request_log)

    result = run_review(
        snapshot,
        plan,
        profile,
        provider,
        None,
        LIMITS,
        str(tmp_path / "results"),
        "synth-001-review",
    )

    diff = next(item for item in snapshot["evidence"].values() if item["source_kind"] == "diff")
    assert diff["path"] == truth["expected_changed_path"]
    assert "+" + truth["expected_changed_line"] in diff["content"].splitlines()
    raw_dispatches = request_log.read_bytes()
    dispatches = [json.loads(line) for line in raw_dispatches.splitlines()]
    assert len(dispatches) == len(plan["tasks"]) == 1
    assert (FIXTURE / "truth.json").read_bytes() not in raw_dispatches
    assert b"expected_changed_line" not in raw_dispatches
    assert "truth.json" not in {item["path"] for item in dispatches[0]["evidence"]}
    assert diff["evidence_id"] in {item["evidence_id"] for item in dispatches[0]["evidence"]}
    assert result["findings"]
    finding = result["findings"][0]
    assert finding["status"] == "ACCEPTED"
    assert finding["path"] == "auth.py"
    assert finding["location"]["line"] == 2
    assert finding["evidence_refs"] == [diff["evidence_id"]]
    assert result["disposition"] == "REQUEST_CHANGES"
    assert result["merge_eligibility"] == "NOT_EVALUATED"
    assert "publication" not in result
    assert "publish" not in result
    assert (tmp_path / "results/synth-001-review.json").is_file()
