from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_model_only_shadow_audit as shadow_audit_runner  # noqa: E402

from pr_review_harness.engine import _evidence_for, prepare_plan_tasks, run_review  # noqa: E402
from pr_review_harness.planner import plan_review  # noqa: E402
from pr_review_harness.providers import OpenAIProvider  # noqa: E402
from pr_review_harness.snapshot import collect_snapshot  # noqa: E402

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


def _synthetic_repo(tmp_path: Path, *, seeded_defect: bool = True) -> tuple[Path, str, str, dict]:
    tmp_path.mkdir(parents=True, exist_ok=True)
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

    reviewed_auth.write_text(
        visible["head/auth.py"] if seeded_defect else visible["base/auth.py"] + "# behavior-preserving fixture edit\n"
    )
    _git(repo, "add", "-A")
    fixed_commit_time["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:01+00:00"
    fixed_commit_time["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:01+00:00"
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "synthetic change", env=fixed_commit_time)
    head = _git(repo, "rev-parse", "HEAD")

    profile = {
        "version": "seeded-writer-synth-001-v1",
        "profile_id": "synth-001",
        "required_lenses": ["correctness"],
        "allow_empty_approve": True,
        "context_paths": ["contract.md", "caller.py"],
    }
    assert set(_git(repo, "ls-tree", "-r", "--name-only", head).splitlines()) == {
        "auth.py", "caller.py", "contract.md"
    }
    return repo, base, head, profile


class _SerializedFixtureProvider(OpenAIProvider):
    """Use production serialization and specialist validation with a fixed response."""

    def __init__(self, candidate_enabled: bool):
        super().__init__({
            "kind": "openai_compatible",
            "base_url": "https://offline.invalid/v1",
            "model": "fixture-reviewer",
            "api_key_env": "UNSET_SYNTH_CONTROL_KEY",
            "provider_id": "provider-free-sensitivity-control",
            "semantic_adjudication": False,
        })
        self.candidate_enabled = candidate_enabled

    def _fixture_payload(self, task, evidence):
        diff = next(row for row in evidence if row.get("source_kind") == "diff")
        candidates = []
        if self.candidate_enabled:
            candidates = [{
                "unit_id": task["unit_ids"][0],
                "location": {
                    "kind": "line", "path": diff["path"], "side": "HEAD", "line": 2, "reason": None,
                },
                "title": "Synthetic authorization bypass",
                "observation": "The seeded change makes the authorization predicate unconditional.",
                "consequence": "A caller may access another owner's document.",
                "rule_or_contract": "The supplied contract requires matching caller and owner IDs.",
                "severity": "high", "reasoning_kind": "inferred", "introducedness": "INTRODUCED",
                "evidence_refs": [diff["evidence_id"]],
            }]
        return {
            "contract_version": "specialist-findings.v4",
            "finding_candidates": candidates,
            "context_gap_proposals": [],
            "coverage_notes": [{
                "unit_id": unit_id, "state": "COVERED", "reason_code": "fixture_scope_reviewed",
                "evidence_refs": [diff["evidence_id"]], "coverage_basis": "STATIC_REVIEW",
            } for unit_id in task["unit_ids"]],
            "specific_strengths": [], "future_guidance": [],
        }

    def _call(self, *, system, user, schema, limits, contract_version, capture_exchange=False,
              expected_request_sha256=None, serialized_request_bytes=None, before_dispatch=None,
              on_http_attempt=None):
        assert capture_exchange is True
        expected = self._serialize_request_body(system, user, schema, limits)
        assert serialized_request_bytes == expected
        assert hashlib.sha256(expected).hexdigest() == expected_request_sha256
        payload = self._fixture_payload(user["task"], user["evidence"])
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return json.loads(content), {
            "usage": {}, "provenance": {"provider": "provider-free-sensitivity-control"},
            "_audit_exchange": {
                "structured_response_bytes": content,
                "response_bytes": b'{"fixture":"provider-free"}',
            },
        }


def test_provider_free_seeded_writer_control_roundtrips_serialization_validation_reconciliation_and_packet_selection(
    tmp_path,
):
    """Construction-defined responses test plumbing, not model sensitivity or response parsing."""
    selected = []
    for label, seeded_defect in (("defect", True), ("benign", False)):
        repo, base, head, profile = _synthetic_repo(tmp_path / label, seeded_defect=seeded_defect)
        snapshot = collect_snapshot(str(repo), base, head, profile, LIMITS)
        provider = _SerializedFixtureProvider(candidate_enabled=seeded_defect)
        plan = plan_review(snapshot, profile, "AUTO")
        limits = {
            **LIMITS, "max_provider_calls": 1, "max_retries_per_task": 0,
            "max_followup_tasks": 0, "max_output_tokens": 1_800,
            "max_output_bytes_per_task": 16_000, "max_input_bytes_per_task": 45_000,
        }
        tasks, _skipped = prepare_plan_tasks(snapshot, plan, profile, limits, provider)
        writer_tasks = [task for task in tasks if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"]
        assert len(writer_tasks) == 1
        task = writer_tasks[0]
        evidence = _evidence_for(task, snapshot, limits["max_input_bytes_per_task"])
        request_bytes = provider.serialize_review_request(task, evidence, limits)
        request_pin = {
            task["task_id"]: {
                "task_id": task["task_id"], "input_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "input_bytes": len(request_bytes), "lens": task["lens"],
                "output_bytes_cap": 16_000, "output_tokens_cap": 1_800,
            }
        }
        capture_dir = tmp_path / f"capture-{label}"
        result = run_review(
            snapshot, plan, profile, provider, None, limits, str(tmp_path / f"results-{label}"),
            f"writer-live-synth-{label}", max_claim_assessments=0,
            private_capture_dir=str(capture_dir), private_capture_case_id="SYNTH-001",
            private_capture_request_pins=request_pin,
            private_capture_snapshot_pin={"snapshot_id": snapshot["snapshot_id"],
                                          "snapshot_sha256": snapshot["snapshot_hash"]},
        )
        captured_requests = list((capture_dir / "requests").glob("*.bin"))
        assert len(captured_requests) == 1
        assert captured_requests[0].read_bytes() == request_bytes
        captured_responses = list((capture_dir / "responses").glob("*.bin"))
        assert len(captured_responses) == 1
        expected_payload = provider._fixture_payload(task, evidence)
        expected_response_bytes = json.dumps(
            expected_payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        assert captured_responses[0].read_bytes() == expected_response_bytes
        captured_payload = json.loads(captured_responses[0].read_bytes())
        assert captured_payload == expected_payload
        validated_payload = result["task_results"][task["task_id"]]["payload"]
        assert captured_payload["contract_version"] == validated_payload["source_contract_version"]
        assert len(captured_payload["finding_candidates"]) == len(validated_payload["finding_candidates"])
        if captured_payload["finding_candidates"]:
            raw_candidate = captured_payload["finding_candidates"][0]
            validated_candidate = validated_payload["finding_candidates"][0]
            assert {key: validated_candidate[key] for key in raw_candidate} == raw_candidate
        assert captured_payload["coverage_notes"] == validated_payload["coverage_notes"]
        packet_rows = shadow_audit_runner._packet_candidates(capture_dir)[2]
        packet_path = shadow_audit_runner._select_packet(packet_rows)
        if seeded_defect:
            assert result["findings"]
            assert packet_path is not None
            assert packet_path[2]["writer_candidate"]["title"] == "Synthetic authorization bypass"
        else:
            assert result["findings"] == []
            assert packet_path is None
            assert all(row[2]["writer_candidate"] is None for row in packet_rows)
        selected.append(packet_path)

    assert selected[0] is not None and selected[1] is None


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
