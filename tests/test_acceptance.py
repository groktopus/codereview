"""End-to-end acceptance probes for evidence and conservative disposition."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pr_review_harness.engine import _bind_specialist_input, _canonical, run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider
from pr_review_harness.snapshot import collect_snapshot

LIMITS = {
    "deadline_seconds": 2,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 20,
    "max_retries_per_task": 0,
    "max_context_bytes": 50_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 8,
    "max_followup_tasks": 8,
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def make_repo(tmp_path: Path, files: dict[str, str], edits: dict[str, str], contexts=()):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    for path, content in files.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    for path, content in edits.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git(repo, "rev-parse", "HEAD")
    profile = {
        "version": "acceptance-v1",
        "required_lenses": ["correctness"],
        "allow_empty_approval": True,
        "context_paths": list(contexts),
    }
    snap = collect_snapshot(str(repo), base, head, profile, LIMITS)
    return snap, profile


class EmptyProvider:
    identity = {
        "kind": "acceptance-fixture",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self):
        self.tasks = []

    def review(self, task, evidence, limits):
        self.tasks.append((task, evidence))
        return {
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": uid,
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": list(task["evidence_ids"]),
                    "coverage_basis": "STATIC_REVIEW",
                }
                for uid in task["unit_ids"]
            ],
        }


class CandidateProvider(EmptyProvider):
    def __init__(self, line=1, omit_semantic_introducedness=False):
        super().__init__()
        self.line = line
        self.omit_semantic_introducedness = omit_semantic_introducedness

    def review(self, task, evidence, limits):
        self.tasks.append((task, evidence))
        unit = task["unit_ids"][0]
        item = next(e for e in evidence if e["source_kind"] == "diff")
        return {
            "finding_candidates": [
                {
                    "unit_id": unit,
                    "path": item["path"],
                    "line": self.line,
                    "title": "Claimed behavior regression",
                    "observation": "changed result",
                    "consequence": "caller breaks",
                    "rule_or_contract": "return contract",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [item["evidence_id"]],
                }
            ],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": [item["evidence_id"]],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }

    def adjudicate(self, candidate, evidence, limits):
        value = {
            "contract_version": "semantic-adjudication.v3",
            "source_contract_version": "semantic-adjudication.v3",
            "outcome": "SUPPORTED",
            "observation_support": "SUPPORTED",
            "consequence_support": "SUPPORTED",
            "rule_connection_support": "SUPPORTED",
            "material_consequence": True,
            "evidence_refs": [e["evidence_id"] for e in evidence if e["source_kind"] == "diff"],
            "causal_roles": {
                role: {
                    "support": "SUPPORTED",
                    "assessment": f"Fixture evidence supports the {role} link.",
                    "evidence_refs": list(candidate["evidence_refs"]),
                }
                for role in ("behavior", "consumer", "impact")
            },
            "assumptions": [],
            "uncertainties": [],
            "summary": "fixture assessment",
        }
        if not self.omit_semantic_introducedness:
            value["introducedness"] = "INTRODUCED"
        return {
            "payload": value,
            "provenance": {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
        }


class V3DeletedFileProvider(CandidateProvider):
    def __init__(self, citation="diff"):
        super().__init__()
        self.citation = citation

    def review(self, task, evidence, limits):
        unit = task["unit_ids"][0]
        diff = next(item for item in evidence if item["source_kind"] == "diff")
        path = diff["path"]
        if self.citation == "anchor":
            cited = next(item for item in evidence if item["source_kind"] == "base_file" and item["path"] == path)
        elif self.citation == "other_unit_anchor":
            cited = next(item for item in evidence if item["source_kind"] == "base_file" and item["path"] != path)
        else:
            cited = diff
        return {
            "finding_candidates": [
                {
                    "unit_id": unit,
                    "location": {
                        "kind": "file",
                        "path": path,
                        "side": "BASE",
                        "line": None,
                        "reason": "The deleted file has no surviving line anchor.",
                    },
                    "path": path,
                    "line": None,
                    "title": "Deleted contract file",
                    "observation": "A required interface definition was removed.",
                    "consequence": "Callers lose the documented contract.",
                    "rule_or_contract": "The file defines the required interface.",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [cited["evidence_id"]],
                }
            ],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": [diff["evidence_id"]],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }


def run(tmp_path, snapshot, profile, provider, limits=None):
    plan = plan_review(snapshot, profile)
    return run_review(snapshot, plan, profile, provider, None, limits or LIMITS, str(tmp_path), "acceptance-run")


def test_real_snapshot_context_truncation_remains_required_and_blocks_approval(tmp_path):
    repo = tmp_path / "context"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "src").mkdir()
    (repo / "src/a.py").write_text("value = 1\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "src/a.py").write_text("value = 2\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git(repo, "rev-parse", "HEAD")
    profile = {
        "version": "acceptance-v1",
        "required_lenses": ["correctness"],
        "allow_empty_approval": True,
        "context_paths": ["missing-policy.md"],
        "required_context_paths": ["missing-policy.md"],
    }
    snap = collect_snapshot(str(repo), base, head, profile, {**LIMITS, "max_context_bytes": 18})
    assert any(gap.get("required") for gap in snap["gaps"])
    result = run(tmp_path / "out", snap, profile, EmptyProvider())
    assert result["disposition"] == "INCOMPLETE"
    assert result["coverage_state"] != "COMPLETE"


def test_out_of_hunk_finding_location_cannot_be_accepted(tmp_path):
    snap, profile = make_repo(tmp_path, {"src/a.py": "value = 1\n"}, {"src/a.py": "value = 2\n"})
    assert snap["inventory"][0]["changed_lines"] == [[1, 1]]
    result = run(tmp_path / "out", snap, profile, CandidateProvider(line=900))
    finding = result["findings"][0]
    assert finding["status"] != "ACCEPTED"
    assert finding["blocking_class"] != "BLOCKING"


def test_real_deleted_snapshot_accepts_file_location_citing_exact_base_file_anchor(tmp_path):
    repo = tmp_path / "deleted"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "contract.md").write_text("The callable returns a validated response.\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "contract.md").unlink()
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "delete contract")
    head = git(repo, "rev-parse", "HEAD")
    profile = {"version": "v3-file-test", "required_lenses": ["correctness"], "allow_empty_approval": True}
    snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)
    assert snapshot["inventory"][0]["change_type"] == "delete"
    result = run(tmp_path / "out", snapshot, profile, V3DeletedFileProvider("anchor"))
    finding = result["findings"][0]
    assert finding["status"] == "ACCEPTED"
    assert finding["location"] == {
        "kind": "file",
        "path": "contract.md",
        "side": "BASE",
        "line": None,
        "reason": "The deleted file has no surviving line anchor.",
    }
    assert "file-level\\)" in __import__("pr_review_harness.engine", fromlist=["render_report"]).render_report(result)


def test_real_deleted_snapshot_rejects_file_location_citing_only_diff(tmp_path):
    repo = tmp_path / "deleted-diff-only"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "contract.md").write_text("The callable returns a validated response.\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "contract.md").unlink()
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "delete contract")
    head = git(repo, "rev-parse", "HEAD")
    profile = {"version": "v3-file-test", "required_lenses": ["correctness"], "allow_empty_approval": True}
    snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)

    result = run(tmp_path / "out", snapshot, profile, V3DeletedFileProvider("diff"))

    finding = result["findings"][0]
    assert finding["status"] != "ACCEPTED"
    assert finding["blocking_class"] != "BLOCKING"


def test_real_deleted_snapshot_rejects_another_units_file_anchor(tmp_path):
    repo = tmp_path / "deleted-other-anchor"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "a-contract.md").write_text("The first callable returns a response.\n")
    (repo / "b-contract.md").write_text("The second callable returns a response.\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a-contract.md").unlink()
    (repo / "b-contract.md").unlink()
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "delete contracts")
    head = git(repo, "rev-parse", "HEAD")
    profile = {"version": "v3-file-test", "required_lenses": ["correctness"], "allow_empty_approval": True}
    snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)
    assert len(snapshot["inventory"]) == 2

    result = run(tmp_path / "out", snapshot, profile, V3DeletedFileProvider("other_unit_anchor"))

    finding = result["findings"][0]
    assert finding["status"] != "ACCEPTED"
    assert finding["blocking_class"] != "BLOCKING"


def test_real_deleted_snapshot_rejects_stale_file_anchor_hash(tmp_path):
    repo = tmp_path / "deleted-stale-anchor"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "contract.md").write_text("The callable returns a validated response.\n")
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "contract.md").unlink()
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "delete contract")
    head = git(repo, "rev-parse", "HEAD")
    profile = {"version": "v3-file-test", "required_lenses": ["correctness"], "allow_empty_approval": True}
    snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)
    snapshot["inventory"][0]["file_level_location"]["evidence_hash"] = "0" * 64

    result = run(tmp_path / "out", snapshot, profile, V3DeletedFileProvider("anchor"))

    finding = result["findings"][0]
    assert finding["status"] != "ACCEPTED"
    assert finding["blocking_class"] != "BLOCKING"


def test_missing_semantic_introducedness_cannot_fall_back_to_candidate_claim(tmp_path):
    snap, profile = make_repo(tmp_path, {"src/a.py": "value = 1\n"}, {"src/a.py": "value = 2\n"})
    result = run(tmp_path / "out", snap, profile, CandidateProvider(omit_semantic_introducedness=True))
    finding = result["findings"][0]
    assert finding["blocking_class"] != "BLOCKING"
    assert result["disposition"] != "REQUEST_CHANGES"


def test_profile_base_evidence_reaches_specialist_and_is_not_replaced_by_head(tmp_path):
    snap, profile = make_repo(
        tmp_path,
        {"src/a.py": "value = 1\n", "GUIDANCE.md": "base policy\n"},
        {"src/a.py": "value = 2\n", "GUIDANCE.md": "head attacker text\n"},
        contexts=["GUIDANCE.md"],
    )
    provider = EmptyProvider()
    result = run(tmp_path / "out", snap, profile, provider)
    delivered_ids = {
        eid
        for outcome in result["task_results"].values()
        if outcome.get("status") == "SUCCEEDED"
        for eid in outcome.get("input_evidence_ids", [])
    }
    context_ids = set(snap["trusted_context_refs"])
    delivered = [snap["evidence"][eid] for eid in delivered_ids & context_ids]
    assert delivered and all(e["source_revision"] == snap["base_sha"] for e in delivered)
    assert all(
        e["content_hash"]
        == next(
            x["content_hash"]
            for x in snap["evidence"].values()
            if x["path"] == "GUIDANCE.md" and x["source_revision"] == snap["base_sha"]
        )
        for e in delivered
    )
    assert result["coverage_state"] == "COMPLETE"


def test_general_model_provider_is_never_dispatched_for_deterministic_check(tmp_path):
    snap, profile = make_repo(tmp_path, {"src/a.py": "value = 1\n"}, {"src/a.py": "value = 2\n"})
    profile["required_checks"] = [
        {"id": "build", "unit_ids": [snap["inventory"][0]["unit_id"]], "binding": "local:build"}
    ]
    provider = EmptyProvider()
    result = run(tmp_path / "out", snap, profile, provider)
    assert all(
        outcome.get("task_kind") == "SPECIALIST_FINDINGS"
        for outcome in result["task_results"].values()
        if outcome.get("status") == "SUCCEEDED"
    )
    check = next(row for row in result["coverage_ledger"] if row["obligation_kind"] == "PROJECT_CHECK")
    assert check["state"] != "COMPLETE"


def test_trusted_context_is_retained_when_engine_splits_oversized_unit_batch(tmp_path):
    body = "value = 1\n" * 60
    changed = "value = 2\n" * 60
    snap, profile = make_repo(
        tmp_path,
        {"src/a.py": body, "src/b.py": body, "GUIDANCE.md": "base rule\n"},
        {"src/a.py": changed, "src/b.py": changed},
        contexts=["GUIDANCE.md"],
    )
    task = plan_review(snap, profile)["tasks"][0]
    evidence = snap["evidence"]
    per_unit = []
    for uid in task["unit_ids"]:
        unit = next(u for u in snap["inventory"] if u["unit_id"] == uid)
        ids = unit["evidence_ids"] + snap["trusted_context_refs"]
        per_unit.append(
            sum(len(json.dumps(evidence[eid], sort_keys=True, separators=(",", ":")).encode()) for eid in ids)
        )
    all_evidence = sum(
        len(json.dumps(evidence[eid], sort_keys=True, separators=(",", ":")).encode()) for eid in task["evidence_ids"]
    )
    per_task_limit = (max(per_unit) + all_evidence) // 2
    assert max(per_unit) <= per_task_limit < all_evidence
    limits = {**LIMITS, "max_input_bytes_per_task": per_task_limit}
    provider = EmptyProvider()
    result = run(tmp_path / "out", snap, profile, provider, limits)
    successful = [r for r in result["task_results"].values() if r.get("status") == "SUCCEEDED"]
    assert len(successful) >= 2
    assert all(set(snap["trusted_context_refs"]) & set(row["input_evidence_ids"]) for row in successful)


def test_opt_in_context_windows_reduce_real_adapter_wire_size_without_provider_dispatch(tmp_path):
    body = "".join(f"def item_{index}(): return {index}\n" for index in range(100))
    changed = body.replace("def item_50(): return 50", "def item_50(): return 500")
    files = {
        "AGENTS.md": "Review caller compatibility and avoid claiming tests ran.\n",
        "src/module.py": body,
        "docs/contract.md": "item functions return integers.\n",
    }
    baseline_snapshot, baseline_profile = make_repo(
        tmp_path / "baseline",
        files,
        {"src/module.py": changed},
        contexts=["AGENTS.md", "docs/contract.md"],
    )
    selection_profile = {
        **baseline_profile,
        "trusted_policy_paths": ["AGENTS.md"],
        "retrieval_context_patterns": ["AGENTS.md", "docs/contract.md"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 8192,
            "window": {
                "before_lines": 4,
                "after_lines": 4,
                "max_bytes": 4096,
                "max_windows_per_unit": 4,
                "max_scan_bytes": 65_536,
            },
            "bindings": [
                {
                    "unit_patterns": ["src/*.py"],
                    "lenses": ["correctness"],
                    "context_paths": ["docs/contract.md"],
                    "max_context_bytes": 4096,
                }
            ],
        },
    }
    selection_snapshot = collect_snapshot(
        str(tmp_path / "baseline" / "repo"),
        baseline_snapshot["base_sha"],
        baseline_snapshot["head_sha"],
        selection_profile,
        LIMITS,
    )
    baseline_task = next(
        task for task in plan_review(baseline_snapshot, baseline_profile)["tasks"] if task["lens"] == "correctness"
    )
    selection_task = next(
        task for task in plan_review(selection_snapshot, selection_profile)["tasks"] if task["lens"] == "correctness"
    )
    adapter = OpenAIProvider(
        {
            "kind": "openai-compatible",
            "base_url": "https://example.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNREAD_FIXTURE_KEY",
        }
    )
    baseline_evidence = [baseline_snapshot["evidence"][eid] for eid in baseline_task["evidence_ids"]]
    selected_evidence = [selection_snapshot["evidence"][eid] for eid in selection_task["evidence_ids"]]
    baseline_bytes = adapter.review_input_bytes(baseline_task, baseline_evidence, LIMITS)
    selected_bytes = adapter.review_input_bytes(selection_task, selected_evidence, LIMITS)
    assert selected_bytes < baseline_bytes
    assert selected_bytes <= LIMITS["max_input_bytes_per_task"]
    assert all(item["source_kind"] not in {"base_file", "head_file"} for item in selected_evidence)


def test_required_selected_context_over_cap_is_typed_skip_without_dispatch(tmp_path):
    snap, profile = make_repo(
        tmp_path,
        {"AGENTS.md": "review the public contract and caller behavior\n", "src/a.py": "value = 1\n"},
        {"src/a.py": "value = 2\n"},
        contexts=["AGENTS.md"],
    )
    profile["trusted_policy_paths"] = ["AGENTS.md"]
    profile["context_selection"] = {
        "version": "context-selection.v1",
        "mandatory_policy_paths": ["AGENTS.md"],
        "max_total_context_bytes": 2048,
        "window": {
            "before_lines": 0,
            "after_lines": 0,
            "max_bytes": 1024,
            "max_windows_per_unit": 2,
            "max_scan_bytes": 4096,
        },
        "bindings": [],
    }
    snap = collect_snapshot(
        str(tmp_path / "repo"), snap["base_sha"], snap["head_sha"], profile, {**LIMITS, "max_context_bytes": 10_000}
    )
    task = plan_review(snap, profile)["tasks"][0]
    unit = snap["inventory"][0]
    unit_only_ids = [eid for eid in task["evidence_ids"] if eid in unit["review_context_evidence_ids"]]
    required_ids = list(task["required_context_ids"])

    def bound_request(context_ids):
        evidence_ids = list(dict.fromkeys(unit_only_ids + context_ids))
        candidate = {
            **task,
            "unit_ids": [unit["unit_id"]],
            "scope_unit_ids": [unit["unit_id"]],
            "evidence_ids": evidence_ids,
            "base_context_ids": context_ids,
            "required_context_ids": required_ids,
        }
        evidence = [snap["evidence"][eid] for eid in evidence_ids]
        bound = _bind_specialist_input(candidate, snap, profile, evidence)
        return len(_canonical({"task": bound, "evidence": evidence}))

    unit_only_size = bound_request([])
    required_size = bound_request(required_ids)
    assert unit_only_size < required_size
    limits = {**LIMITS, "max_input_bytes_per_task": unit_only_size}
    provider = EmptyProvider()
    result = run_review(
        snap,
        plan_review(snap, profile),
        profile,
        provider,
        None,
        limits,
        str(tmp_path / "out"),
        "required-context-omission",
    )
    assert result["coverage_state"] == "NOT_STARTED"
    assert result["disposition"] == "INCOMPLETE"
    assert result["budget"]["provider_calls_reserved"] == 0
    task_result = next(row for row in result["task_results"].values() if row.get("status") == "SKIPPED")
    assert task_result["error_code"] == "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT"
    assert task_result["required_context_omissions"] == task["required_context_ids"]
    assert task_result["obligation_ids"] == task["obligation_ids"]
    assert task_result["task_id"] == task["task_id"]
    assert all(row["state"] != "COMPLETE" for row in result["coverage_ledger"])
