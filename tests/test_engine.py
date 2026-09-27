import hashlib
import json
import os
import time
from pathlib import Path

import pytest

import pr_review_harness.engine as engine_module
from pr_review_harness.engine import render_report, run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider

LIMITS = {
    "deadline_seconds": 2,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 120_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 8,
    "max_followup_tasks": 8,
}


def make_snapshot(units=1):
    inventory, evidence = [], {}
    for index in range(units):
        uid = f"u{index}"
        eid = f"diff:{uid}"
        inventory.append(
            {
                "unit_id": uid,
                "path": f"src/m{index}.py",
                "kind": "human_code",
                "change": "modified",
                "diff": "-old\n+new",
                "changed_lines": [[1, 2]],
                "evidence_ids": [eid],
            }
        )
        evidence[eid] = {
            "evidence_id": eid,
            "snapshot_id": "snap",
            "path": f"src/m{index}.py",
            "line_start": 1,
            "line_end": 2,
            "content": "-old\n+new",
            "content_hash": "a" * 64,
            "source_kind": "diff",
            "trust": "untrusted_pr_content",
        }
    return {
        "snapshot_id": "snap",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "profile_version": "p1",
        "snapshot_hash": "d" * 64,
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": inventory,
        "evidence": evidence,
        "gaps": [],
    }


def profile(lenses=("correctness",)):
    return {"version": "p1", "required_lenses": list(lenses), "allow_empty_approval": True}


def required_context_profile():
    return {
        **profile(),
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 10_000,
            "window": {
                "before_lines": 0,
                "after_lines": 0,
                "max_bytes": 1_000,
                "max_windows_per_unit": 1,
                "max_scan_bytes": 10_000,
            },
            "bindings": [
                {
                    "unit_patterns": ["src/*.py"],
                    "lenses": ["correctness"],
                    "context_paths": [],
                    "max_context_bytes": 1_000,
                }
            ],
        },
    }


class EmptyProvider:
    identity = {
        "kind": "test",
        "model": "empty",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self):
        self.calls = 0

    def review(self, task, evidence, limits):
        self.calls += 1
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": uid,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": list(task["evidence_ids"]),
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for uid in task["unit_ids"]
                ],
            },
            "usage": {"input_tokens": 10},
            "provenance": {"provider": "test"},
        }


class SizingOnlyOpenAIProvider(OpenAIProvider):
    """Use the real request serializer while keeping tests entirely offline."""

    def __init__(self):
        super().__init__(
            {
                "kind": "openai-compatible",
                "base_url": "https://provider.invalid/v1",
                "model": "serializer-test",
                "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
                "max_request_bytes": 100_000,
                "max_response_bytes": 16_000,
                "max_output_tokens": 1_000,
            }
        )

    def review(self, task, evidence, limits):
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": uid,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": list(task["evidence_ids"]),
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for uid in task["unit_ids"]
                ],
                "specific_strengths": [],
                "future_guidance": [],
            },
            "usage": {},
            "provenance": {"provider": "offline-serializer-test"},
        }


class UnitEvidenceProvider(EmptyProvider):
    """Return auditable unit-bound coverage for selected-evidence tests."""

    def review(self, task, evidence, limits):
        self.calls += 1
        evidence_by_id = {item["evidence_id"]: item for item in evidence}
        notes = []
        for unit_id in task["unit_ids"]:
            unit = next(row for row in self.snapshot_inventory if row["unit_id"] == unit_id)
            refs = [evidence_id for evidence_id, item in evidence_by_id.items() if item.get("path") == unit["path"]]
            notes.append(
                {
                    "unit_id": unit_id,
                    "state": "COVERED",
                    "reason_code": "REVIEWED_SELECTED_UNIT_EVIDENCE",
                    "evidence_refs": refs,
                    "coverage_basis": "STATIC_REVIEW",
                }
            )
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": notes,
            },
            "usage": {"input_tokens": 10},
            "provenance": {"provider": "test"},
        }

    def bind_inventory(self, inventory):
        self.snapshot_inventory = inventory


class FindingProvider(EmptyProvider):
    def __init__(
        self, outcome="SUPPORTED", consequence="SUPPORTED", introduced="INTRODUCED", refs_ok=True, material=True
    ):
        super().__init__()
        self.outcome, self.consequence, self.introduced, self.refs_ok = outcome, consequence, introduced, refs_ok
        self.material = material

    def review(self, task, evidence, limits):
        self.calls += 1
        unit = task["unit_ids"][0]
        uid = next(u for u in evidence if u["evidence_id"] == task["evidence_ids"][0])["evidence_id"]
        item = {
            "path": f"src/m{unit[-1]}.py",
            "line": 1,
            "title": "Observed risk",
            "observation": "changed behavior",
            "consequence": "caller receives an invalid result",
            "rule_or_contract": "return contract",
            "severity": "high",
            "reasoning_kind": "inferred",
            "introducedness": self.introduced,
            "evidence_refs": [uid if self.refs_ok else "missing-evidence"],
        }
        return {
            "finding_candidates": [item],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "REVIEWED",
                    "evidence_refs": [uid],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }

    def adjudicate(self, candidate, evidence, limits):
        refs = [e["evidence_id"] for e in evidence]
        return {
            "payload": {
                "contract_version": "semantic-adjudication.v3",
                "source_contract_version": "semantic-adjudication.v3",
                "outcome": self.outcome,
                "observation_support": "SUPPORTED",
                "consequence_support": self.consequence,
                "rule_connection_support": "SUPPORTED",
                "introducedness": self.introduced,
                "evidence_refs": refs[:1],
                "causal_roles": {
                    role: {
                        "support": "SUPPORTED",
                        "assessment": f"Fixture evidence supports the {role} link.",
                        "evidence_refs": refs[:1],
                    }
                    for role in ("behavior", "consumer", "impact")
                },
                "material_consequence": self.material,
                "assumptions": [],
                "uncertainties": [],
                "summary": "Bounded evidence assessment.",
            },
            "provenance": {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
        }


class LegacyFindingProvider(FindingProvider):
    def adjudicate(self, candidate, evidence, limits):
        response = super().adjudicate(candidate, evidence, limits)
        value = response["payload"]
        value.update(
            {
                "contract_version": "semantic-adjudication.v2",
                "source_contract_version": "semantic-adjudication.v2",
                "causal_roles": None,
            }
        )
        response["provenance"] = {"provider_rubric_version": "legacy-unversioned"}
        return response


class InvalidRoleEvidenceProvider(FindingProvider):
    def adjudicate(self, candidate, evidence, limits):
        response = super().adjudicate(candidate, evidence, limits)
        response["payload"]["causal_roles"]["impact"]["evidence_refs"] = ["not-delivered"]
        return response


class SecretShapedEstimateFailureProvider(FindingProvider):
    def estimate_call(self, task_kind, task, evidence, limits):
        if task_kind == "SEMANTIC_ADJUDICATION":
            error = RuntimeError("reservation failed")
            error.code = "sk-example-secret-shaped-value"
            raise error
        return {
            "provider_calls": 1,
            "input_bytes": 0,
            "max_output_bytes": limits["max_output_bytes_per_task"],
            "reservation_kind": "unknown",
            "deadline_seconds": limits["deadline_seconds"],
        }


class LiarProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        return {
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": task["unit_ids"][0],
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": ["not-supplied"],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }


class GapProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        unit, evidence_id = task["unit_ids"][0], task["evidence_ids"][0]
        return {
            "finding_candidates": [],
            "context_gap_proposals": [
                {
                    "evidence_kind": "caller",
                    "target": {"target_unit_id": unit, "target_path": None, "target_symbol": None},
                    "rationale": "Caller contract is missing.",
                    "related_evidence_ids": [evidence_id],
                    "required_lens": task["lens"],
                }
            ],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "REVIEWED",
                    "evidence_refs": [evidence_id],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }


class ContextFollowupProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        unit = task["unit_ids"][0]
        if task.get("context_gap_followup_for"):
            refs = [item["evidence_id"] for item in evidence]
            return {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit,
                        "state": "COVERED",
                        "reason_code": "reviewed_with_context",
                        "evidence_refs": refs,
                        "coverage_basis": "STATIC_REVIEW",
                    }
                ],
            }
        evidence_id = task["evidence_ids"][0]
        return {
            "finding_candidates": [],
            "context_gap_proposals": [
                {
                    "evidence_kind": "caller",
                    "target": {"target_unit_id": None, "target_path": "docs/caller.md", "target_symbol": None},
                    "rationale": "Caller contract is required to finish the review.",
                    "related_evidence_ids": [evidence_id],
                    "required_lens": task["lens"],
                }
            ],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "initial_review",
                    "evidence_refs": [evidence_id],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }


class NoteProvider(EmptyProvider):
    def __init__(self, invalid=False):
        super().__init__()
        self.invalid = invalid

    def review(self, task, evidence, limits):
        unit = task["unit_ids"][0]
        ref = task["evidence_ids"][0]
        note = {
            "unit_id": unit,
            "title": "Stable contract boundary",
            "observation": "The boundary is explicit.",
            "detail": "This makes caller behavior easier to validate.",
            "evidence_refs": [ref],
        }
        if self.invalid:
            note["title"] = ""
        return {
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit,
                    "state": "COVERED",
                    "reason_code": "reviewed",
                    "evidence_refs": [ref],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
            "specific_strengths": [note],
            "future_guidance": [],
        }


class ResolvedContextRetriever:
    def __call__(self, snapshot, profile, proposal, limits):
        path = proposal["target"]["target_path"]
        content = "The caller expects a validated result.\n"
        raw = content.encode()
        content_hash = hashlib.sha256(raw).hexdigest()
        evidence_id = (
            "ev-"
            + hashlib.sha256(
                json.dumps(
                    {
                        "snapshot_id": snapshot["snapshot_id"],
                        "revision": snapshot["base_sha"],
                        "path": path,
                        "hash": content_hash,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()[:24]
        )
        return {
            "status": "RESOLVED",
            "reason": None,
            "evidence": {
                "evidence_id": evidence_id,
                "snapshot_id": snapshot["snapshot_id"],
                "path": path,
                "content": content,
                "source_kind": "repository_file",
                "source_revision": snapshot["base_sha"],
                "source_object_id": "f" * 40,
                "content_hash": content_hash,
                "captured_bytes": len(raw),
                "captured_at": "2026-09-26T00:00:00+00:00",
                "trust": "repository_evidence",
                "evidence_kind": "caller",
                "required_lens": proposal["required_lens"],
                "proposal_id": proposal["_proposal_id"],
                "task_id": proposal["_task_id"],
                "truncated": False,
            },
        }


class SidePathProvider(FindingProvider):
    def review(self, task, evidence, limits):
        payload = super().review(task, evidence, limits)
        payload["finding_candidates"][0]["path"] = "outside.py"
        return payload


class BadOnceProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        if limits.get("attempt_index") == 0:
            return {"payload": {"finding_candidates": []}}
        return super().review(task, evidence, limits)


class SlowProvider(EmptyProvider):
    def __init__(self, started_path=None, completed_path=None, delay_seconds=2):
        super().__init__()
        self.started_path = started_path
        self.completed_path = completed_path
        self.delay_seconds = delay_seconds

    def review(self, task, evidence, limits):
        if self.started_path is not None:
            Path(self.started_path).write_text(str(os.getpid()))
        time.sleep(self.delay_seconds)
        if self.completed_path is not None:
            Path(self.completed_path).write_text("completed")
        return super().review(task, evidence, limits)


class Advisory:
    identity = {"kind": "test-advisory"}

    def assess(self, question, text, limits):
        return {"outcome": "APPROVE", "confidence": 1.0}


class StaticFreshness:
    def __init__(self, result):
        self.result = result

    def __call__(self):
        return self.result


class SimulatedControllerCrash(BaseException):
    pass


def run(
    tmp_path,
    snap=None,
    prof=None,
    provider=None,
    limits=None,
    mode="AUTO",
    fresh=None,
    run_id="r1",
    decision_provider=None,
    context_retriever=None,
):
    snap = snap or make_snapshot()
    prof = prof or profile()
    plan = plan_review(snap, prof, mode)
    return run_review(
        snap,
        plan,
        prof,
        provider,
        decision_provider,
        limits or LIMITS,
        str(tmp_path),
        run_id,
        freshness_check=fresh,
        context_retriever=context_retriever,
    )


def test_provider_free_baseline_is_incomplete_and_has_not_started_semantic_scopes(tmp_path):
    result = run(tmp_path)
    assert result["coverage_state"] == "NOT_STARTED"
    assert result["disposition"] == "INCOMPLETE"
    assert all(scope["state"] == "NOT_STARTED" for scope in result["coverage_ledger"])
    assert result["findings"] == []


def test_unknown_required_lens_fails_before_provider_dispatch_or_result_creation(tmp_path):
    provider = EmptyProvider()

    with pytest.raises(ValueError, match="unsupported lens"):
        run(tmp_path, snap=make_snapshot(), prof=profile(("correctnes",)), provider=provider)

    assert provider.calls == 0
    assert not (tmp_path / "r1.json").exists()


def _add_trusted_policy(snapshot, text):
    evidence_id = "policy:agents"
    snapshot["evidence"][evidence_id] = {
        "evidence_id": evidence_id,
        "snapshot_id": snapshot["snapshot_id"],
        "path": "AGENTS.md",
        "line_start": 1,
        "line_end": 1,
        "content": text,
        "content_hash": hashlib.sha256(text.encode()).hexdigest(),
        "source_kind": "profile_context",
        "trust": "trusted_policy",
    }
    snapshot["trusted_context_refs"] = [evidence_id]
    return evidence_id


def test_required_context_is_included_before_batch_admission_and_units_split(tmp_path):
    snap = make_snapshot(units=2)
    policy_id = _add_trusted_policy(snap, "Mandatory policy applies to every changed unit.\n")
    prof = required_context_profile()
    plan = plan_review(snap, prof)
    assert len(plan["tasks"]) == 1
    assert plan["tasks"][0]["required_context_ids"] == [policy_id]

    provider = SizingOnlyOpenAIProvider()
    base_task = plan["tasks"][0]

    def shaped_task(unit_ids, chunk):
        obligation_ids = [f"unit:{uid}:lens:correctness" for uid in unit_ids]
        return {
            **base_task,
            "task_id": f"{base_task['task_id']}:chunk-{chunk}",
            "unit_ids": unit_ids,
            "scope_unit_ids": unit_ids,
            "evidence_ids": [*(f"diff:{uid}" for uid in unit_ids), policy_id],
            "base_context_ids": [policy_id],
            "required_context_ids": [policy_id],
            "context_omissions": [],
            "required_context_omissions": [],
            "obligation_id": obligation_ids[0],
            "obligation_ids": obligation_ids,
        }

    def estimate(task, cap_for_payload):
        evidence = [snap["evidence"][eid] for eid in task["evidence_ids"]]
        limits = {**LIMITS, "max_input_bytes_per_task": cap_for_payload}
        return provider.review_input_bytes(task, evidence, limits) + 1024

    cap = 100_000
    for _ in range(6):
        cap = max(estimate(shaped_task([uid], index), cap) for index, uid in enumerate(("u0", "u1"), 1)) + 32
    singleton_sizes = [estimate(shaped_task([uid], cap), cap) for uid in ("u0", "u1")]
    assert max(singleton_sizes) <= cap
    assert estimate(shaped_task(["u0", "u1"], 1), cap) > cap
    for uid in ("u0", "u1"):
        wire_bytes = provider.review_input_bytes(
            shaped_task([uid], 1),
            [snap["evidence"][eid] for eid in shaped_task([uid], 1)["evidence_ids"]],
            {**LIMITS, "max_input_bytes_per_task": cap},
        )
        assert wire_bytes + 1024 <= cap

    result = run(
        tmp_path,
        snap,
        prof,
        provider,
        {**LIMITS, "max_input_bytes_per_task": cap},
        run_id="required-context-split",
    )

    dispatched = [row for row in result["task_results"].values() if row.get("status") == "SUCCEEDED"]
    assert len(dispatched) == 2
    for row in dispatched:
        assert policy_id in row["input_evidence_ids"]
        assert len([eid for eid in row["input_evidence_ids"] if eid.startswith("diff:")]) == 1
    for obligation in result["coverage_ledger"]:
        if obligation["obligation_kind"] == "CHANGED_UNIT_LENS":
            assert obligation["state"] == "COMPLETE"
            assert obligation["task_ids"]


def test_unit_skips_when_required_context_cannot_fit_without_dispatch(tmp_path):
    snap = make_snapshot(units=1)
    policy_id = _add_trusted_policy(snap, "Mandatory policy. " + ("rule " * 600))
    prof = required_context_profile()
    plan = plan_review(snap, prof)
    assert plan["tasks"][0]["required_context_ids"] == [policy_id]
    unit_only_size = len(json.dumps(snap["evidence"]["diff:u0"], sort_keys=True, separators=(",", ":")).encode())
    required_size = unit_only_size + len(
        json.dumps(snap["evidence"][policy_id], sort_keys=True, separators=(",", ":")).encode()
    )
    assert unit_only_size < required_size
    cap = unit_only_size + 1

    provider = EmptyProvider()
    result = run(
        tmp_path,
        snap,
        prof,
        provider,
        {**LIMITS, "max_input_bytes_per_task": cap},
        run_id="required-context-overflow",
    )

    assert result["budget"]["provider_calls_reserved"] == 0
    skipped = [row for row in result["task_results"].values() if row.get("status") == "SKIPPED"]
    assert len(skipped) == 1
    assert skipped[0]["error_code"] == "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT"
    assert skipped[0]["required_context_omissions"] == [policy_id]
    assert skipped[0]["obligation_ids"] == ["unit:u0:lens:correctness"]
    assert result["disposition"] == "INCOMPLETE"
    obligation = next(row for row in result["coverage_ledger"] if row["obligation_id"] == "unit:u0:lens:correctness")
    assert obligation["state"] != "COMPLETE"


def test_preflight_skip_keeps_shared_obligation_incomplete_after_sibling_succeeds(tmp_path):
    snap = make_snapshot(units=2)
    # The second unit's evidence is still small enough by itself, but the same
    # mandatory context that fits with u0 makes its request exceed the cap.
    second = snap["evidence"]["diff:u1"]
    second["content"] += "x" * 100
    second["content_hash"] = hashlib.sha256(second["content"].encode()).hexdigest()
    policy_id = _add_trusted_policy(snap, "Shared mandatory policy.\n")
    prof = required_context_profile()
    plan = plan_review(snap, prof)
    task = plan["tasks"][0]
    first_obligation = task["obligation_ids"][0]
    shared_obligation = next(row for row in plan["coverage_obligations"] if row["obligation_id"] == first_obligation)
    shared_obligation["scope_unit_ids"] = ["u0", "u1"]
    plan["coverage_obligations"] = [shared_obligation]
    task["obligation_ids"] = [first_obligation]

    def evidence_size(ids):
        return sum(
            len(json.dumps(snap["evidence"][eid], sort_keys=True, separators=(",", ":")).encode()) for eid in ids
        )

    cap = evidence_size(["diff:u0", policy_id])
    assert evidence_size(["diff:u1"]) < cap < evidence_size(["diff:u1", policy_id])

    result = run_review(
        snap,
        plan,
        prof,
        EmptyProvider(),
        None,
        {**LIMITS, "max_input_bytes_per_task": cap},
        str(tmp_path),
        "shared-obligation-preflight-skip",
    )

    succeeded = [row for row in result["task_results"].values() if row.get("status") == "SUCCEEDED"]
    skipped = [row for row in result["task_results"].values() if row.get("status") == "SKIPPED"]
    assert len(succeeded) == 1
    assert len(skipped) == 1
    assert succeeded[0]["unit_ids"] == ["u0"]
    assert skipped[0]["unit_id"] == "u1"
    assert skipped[0]["error_code"] == "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT"
    assert skipped[0]["obligation_ids"] == [first_obligation]
    coverage = result["coverage_ledger"][0]
    assert coverage["state"] == "PARTIAL"
    assert coverage["reason_code"] == "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT"
    assert set(coverage["task_ids"]) == {task["task_id"], succeeded[0]["task_id"]}
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


@pytest.mark.parametrize("invalid_binding", ["not_in_task", "missing_record", "wrong_evidence_id", "wrong_snapshot"])
def test_missing_or_mismatched_required_context_fails_closed_for_all_obligations(tmp_path, invalid_binding):
    snap = make_snapshot(units=1)
    policy_id = _add_trusted_policy(snap, "Required policy evidence.\n")
    prof = required_context_profile()
    plan = plan_review(snap, prof)
    task = plan["tasks"][0]
    extra_obligation = "unit:u0:lens:security"
    plan["coverage_obligations"].append(
        {
            "obligation_id": extra_obligation,
            "obligation_kind": "CHANGED_UNIT_LENS",
            "required": True,
            "scope_unit_ids": ["u0"],
            "lens": "security",
        }
    )
    task["obligation_ids"].append(extra_obligation)
    if invalid_binding == "not_in_task":
        task["evidence_ids"].remove(policy_id)
    elif invalid_binding == "missing_record":
        del snap["evidence"][policy_id]
    elif invalid_binding == "wrong_evidence_id":
        snap["evidence"][policy_id]["evidence_id"] = "policy:other"
    elif invalid_binding == "wrong_snapshot":
        snap["evidence"][policy_id]["snapshot_id"] = "stale-snapshot"

    provider = EmptyProvider()
    result = run_review(
        snap,
        plan,
        prof,
        provider,
        None,
        LIMITS,
        str(tmp_path),
        f"required-context-invalid-{invalid_binding}",
    )

    assert result["budget"]["provider_calls_reserved"] == 0
    skipped = [row for row in result["task_results"].values() if row.get("status") == "SKIPPED"]
    assert len(skipped) == 1
    assert skipped[0]["error_code"] == "REQUIRED_CONTEXT_MISSING"
    assert skipped[0]["required_context_omissions"] == [policy_id]
    assert skipped[0]["obligation_ids"] == ["unit:u0:lens:correctness", extra_obligation]
    assert result["disposition"] == "INCOMPLETE"
    related_coverage = [
        row
        for row in result["coverage_ledger"]
        if row["obligation_id"] in {"unit:u0:lens:correctness", extra_obligation}
    ]
    assert len(related_coverage) == 2
    assert all(row["state"] != "COMPLETE" for row in related_coverage)


def test_valid_empty_result_is_coverage_complete_and_not_a_missing_task(tmp_path):
    result = run(tmp_path, provider=EmptyProvider())
    assert result["coverage_state"] == "COMPLETE"
    assert result["coverage_ledger"][0]["state"] == "COMPLETE"
    assert result["allow_empty_approve"] is True
    assert result["disposition"] == "APPROVE"
    assert result["findings"] == []
    assert "None recorded." in render_report(result)


def selected_review_fixture():
    snapshot = make_snapshot(units=2)
    policy = {
        "evidence_id": "policy:agents",
        "snapshot_id": snapshot["snapshot_id"],
        "path": "AGENTS.md",
        "line_start": 1,
        "line_end": 1,
        "content": "Review every changed unit using its bound evidence.\n",
        "content_hash": hashlib.sha256(b"Review every changed unit using its bound evidence.\n").hexdigest(),
        "source_kind": "profile_context",
        "trust": "trusted_policy",
    }
    snapshot["evidence"][policy["evidence_id"]] = policy
    snapshot["trusted_context_refs"] = [policy["evidence_id"]]
    for unit in snapshot["inventory"]:
        uid = unit["unit_id"]
        path = unit["path"]
        window_id = f"window:{uid}"
        content = f"Selected context window for {uid}.\n"
        snapshot["evidence"][window_id] = {
            "evidence_id": window_id,
            "snapshot_id": snapshot["snapshot_id"],
            "path": path,
            "line_start": 1,
            "line_end": 1,
            "content": content,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "source_kind": "repository_file_window",
            "source_revision": snapshot["base_sha"],
            "trust": "repository_evidence",
        }
        unit["review_context_evidence_ids"] = [f"diff:{uid}", window_id]
    context_profile = {
        **profile(),
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 10_000,
            "window": {
                "before_lines": 0,
                "after_lines": 0,
                "max_bytes": 1_000,
                "max_windows_per_unit": 1,
                "max_scan_bytes": 10_000,
            },
            "bindings": [
                {
                    "unit_patterns": ["src/*.py"],
                    "lenses": ["correctness"],
                    "context_paths": [],
                    "max_context_bytes": 1_000,
                }
            ],
        },
    }
    return snapshot, context_profile


def test_selected_review_windows_survive_normal_batching_per_unit(tmp_path):
    snapshot, prof = selected_review_fixture()
    plan = plan_review(snapshot, prof)
    provider = UnitEvidenceProvider()
    provider.bind_inventory(snapshot["inventory"])

    result = run_review(snapshot, plan, prof, provider, None, LIMITS, str(tmp_path), "selected-windows")

    assert result["coverage_state"] == "COMPLETE"
    rows = [row for row in result["coverage_ledger"] if row["obligation_kind"] == "CHANGED_UNIT_LENS"]
    assert len(rows) == 2
    for row in rows:
        unit_id = row["scope_unit_ids"][0]
        task_id = row["task_ids"][0]
        output = result["ledger"]["outputs"][task_id]
        assert {"window:u0", "window:u1"}.issubset(output["input_evidence_ids"])
        note = next(note for note in output["payload"]["coverage_notes"] if note["unit_id"] == unit_id)
        assert f"window:{unit_id}" in note["evidence_refs"]
        assert f"window:{'u1' if unit_id == 'u0' else 'u0'}" not in note["evidence_refs"]
        assert f"diff:{unit_id}" in note["evidence_refs"]


def test_legacy_profile_keeps_legacy_unit_evidence_selection(tmp_path):
    snapshot, _ = selected_review_fixture()
    prof = profile()
    plan = plan_review(snapshot, prof)
    provider = UnitEvidenceProvider()
    provider.bind_inventory(snapshot["inventory"])

    result = run_review(snapshot, plan, prof, provider, None, LIMITS, str(tmp_path), "legacy-evidence")

    assert result["coverage_state"] == "COMPLETE"
    rows = [row for row in result["coverage_ledger"] if row["obligation_kind"] == "CHANGED_UNIT_LENS"]
    for row in rows:
        unit_id = row["scope_unit_ids"][0]
        assert f"diff:{unit_id}" in row["evidence_refs"]
        assert f"window:{unit_id}" not in row["evidence_refs"]


@pytest.mark.parametrize(
    "profile_override",
    [
        {"allow_empty_approve": "false"},
        {"allow_empty_approve": 1},
        {"allow_empty_approve": True, "allow_empty_approval": False},
    ],
)
def test_empty_approval_profile_authority_rejects_ambiguous_or_non_boolean_values(tmp_path, profile_override):
    prof = {**profile(), **profile_override}
    with pytest.raises(ValueError, match="allow_empty_approve"):
        plan_review(make_snapshot(), prof)


def test_coverage_note_cannot_claim_units_using_unsupplied_evidence(tmp_path):
    result = run(tmp_path, provider=LiarProvider())
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


def test_valid_required_context_gap_is_preserved_and_prevents_clean_approval(tmp_path):
    result = run(tmp_path, provider=GapProvider())
    assert result["context_gaps"][0]["status"] == "VALID_UNRESOLVED"
    assert result["coverage_state"] == "PARTIAL"
    assert result["coverage_ledger"][0]["reason_code"] == "CONTEXT_GAP_UNRESOLVED"
    assert result["disposition"] == "INCOMPLETE"


def test_retrieval_requires_bounded_followup_that_cites_retrieved_evidence(tmp_path):
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    result = run(
        tmp_path,
        prof=prof,
        provider=ContextFollowupProvider(),
        context_retriever=ResolvedContextRetriever(),
    )
    gap = result["context_gaps"][0]
    assert gap["retrieval_status"] == "RESOLVED"
    assert gap["status"] == "RESOLVED_BY_FOLLOWUP"
    assert gap["retrieved_evidence_ids"]
    assert result["budget"]["context_retrievals_reserved"] == 1
    assert result["budget"]["followup_tasks_reserved"] == 1
    context_coverage = next(c for c in result["coverage_ledger"] if c["obligation_kind"] == "REQUIRED_CONTEXT")
    assert context_coverage["state"] == "COMPLETE"
    assert result["coverage_state"] == "COMPLETE"


def test_v4_notes_are_evidence_linked_and_invalid_optional_notes_do_not_gate(tmp_path):
    valid = run(tmp_path / "valid", provider=NoteProvider())
    note = valid["report_sections"]["specific_strengths"][0]
    assert note["finding_id"].startswith("note-")
    assert note["evidence_refs"] == ["diff:u0"]
    assert valid["coverage_state"] == "COMPLETE"

    invalid = run(tmp_path / "invalid", provider=NoteProvider(invalid=True))
    assert invalid["coverage_state"] == "COMPLETE"
    assert (
        invalid["task_results"][next(iter(invalid["task_results"]))]["quarantined_items"][0]["kind"]
        == "specific_strengths"
    )
    assert invalid["report_sections"]["specific_strengths"] == []


def test_evidence_linked_semantic_blocker_is_preserved_in_report(tmp_path):
    result = run(tmp_path, provider=FindingProvider())
    finding = result["findings"][0]
    assert finding["status"] == "ACCEPTED"
    assert finding["blocking_class"] == "BLOCKING"
    assert result["disposition"] == "REQUEST_CHANGES"
    assert result["report_sections"]["blockers"][0]["finding_id"] == finding["finding_id"]
    assert finding["evidence_refs"] == ["diff:u0"]
    report = render_report(result)
    assert "src/m0.py:1" in report
    assert "caller receives an invalid result" in report
    assert "[diff:u0](./src/m0.py#L1)" in report
    assert report.count("## ") == 4


def test_valid_candidate_records_typed_adjudication_reservation_failure_as_unresolved(tmp_path):
    limits = {**LIMITS, "max_output_bytes": LIMITS["max_output_bytes_per_task"]}
    result = run(tmp_path, provider=FindingProvider(), limits=limits)

    candidate = next(row for row in result["ledger"]["candidate_records"] if row["validation_state"] == "VALID")
    finding = next(row for row in result["findings"] if row["candidate_id"] == candidate["candidate_id"])
    assert finding["semantic_assessment"] == {
        "outcome": "UNCERTAIN",
        "reason": "BudgetExhausted",
        "error_code": "OUTPUT_BYTE_BUDGET_EXHAUSTED",
    }
    assert finding["status"] == "NEEDS_EVIDENCE"
    assert finding["blocking_class"] == "UNRESOLVED"
    assert result["disposition"] == "INCOMPLETE"
    assert not result["ledger"].get("adjudications")


def test_unrecognized_adjudication_error_code_is_not_copied_into_result(tmp_path):
    result = run(tmp_path, provider=SecretShapedEstimateFailureProvider())
    finding = result["findings"][0]

    assert finding["semantic_assessment"]["outcome"] == "UNCERTAIN"
    assert finding["semantic_assessment"]["error_code"] == "RuntimeError"
    assert finding["blocking_class"] == "UNRESOLVED"
    assert "sk-example-secret-shaped-value" not in json.dumps(result)


@pytest.mark.parametrize("max_calls,expected_v3_attempts", [(3, 2), (2, 1)])
def test_legacy_cached_assessment_is_never_upgraded_without_v3_call(tmp_path, max_calls, expected_v3_attempts):
    snap, prof, legacy_provider = make_snapshot(), profile(), LegacyFindingProvider()
    plan = plan_review(snap, prof)
    limits = {**LIMITS, "max_provider_calls": max_calls}
    first = run_review(snap, plan, prof, legacy_provider, None, limits, str(tmp_path), "legacy-cache")
    assert first["findings"][0]["blocking_class"] == "UNRESOLVED"
    assert first["findings"][0]["semantic_assessment"]["contract_version"] == "semantic-adjudication.v2"
    candidate_record = next(row for row in first["ledger"]["candidate_records"] if row["validation_state"] == "VALID")
    candidate = candidate_record["raw"]
    task_result = next(row for row in first["task_results"].values() if row.get("status") == "SUCCEEDED")
    adjudication_evidence = [snap["evidence"][eid] for eid in task_result["input_evidence_ids"]]
    cached = first["ledger"]["adjudications"][candidate_record["candidate_id"]]
    expected_input_hash = engine_module._hash(
        {
            "candidate": candidate,
            "evidence": adjudication_evidence,
            "semantic_contract_version": "semantic-adjudication.v3",
            "semantic_rubric_version": "causal-roles.behavior-consumer-impact.v1",
            "provider_identity_hash": engine_module._hash(engine_module._provider_identity(legacy_provider, None)),
        }
    )
    assert cached["input_hash"] == expected_input_hash
    assert cached["input_hash"] != engine_module._hash({"candidate": candidate, "evidence": adjudication_evidence})
    assert ":adjudicate:semantic-adjudication.v3:causal-roles.behavior-consumer-impact.v1:" in cached["reservation_key"]

    result_path = tmp_path / "legacy-cache.json"
    saved = json.loads(result_path.read_text())
    saved["completed_at"] = None
    saved["ledger"]["reconciled_tasks"] = []
    saved["ledger"].pop("findings", None)
    saved.pop("result_hash")
    saved["result_hash"] = engine_module._hash(saved)
    result_path.write_text(json.dumps(saved))

    resumed = run_review(snap, plan, prof, FindingProvider(), None, limits, str(tmp_path), "legacy-cache", resume=True)

    finding = resumed["findings"][0]
    if max_calls == 3:
        assert finding["blocking_class"] == "BLOCKING"
        assert finding["semantic_assessment"]["contract_version"] == "semantic-adjudication.v3"
    else:
        assert finding["blocking_class"] == "UNRESOLVED"
        assert finding["semantic_assessment"] is None or finding["semantic_assessment"]["outcome"] == "UNCERTAIN"
    reservation_keys = resumed["ledger"]["budget"]["reservations"]
    assert (
        sum(
            ":adjudicate:semantic-adjudication.v3:causal-roles.behavior-consumer-impact.v1:" in key
            for key in reservation_keys
        )
        == expected_v3_attempts
    )


def test_report_rejects_blocker_loss_and_escapes_untrusted_markdown(tmp_path):
    result = run(tmp_path, provider=FindingProvider())
    result["report_sections"]["blockers"] = []
    with pytest.raises(ValueError, match="omits an accepted blocker"):
        render_report(result)

    result = run(tmp_path / "clean", provider=FindingProvider(material=False))
    result["report_sections"]["suggested_improvements"][0]["title"] = "\n## Forged section [link](https://bad)"
    rendered = render_report(result)
    assert "## Forged section" not in rendered
    assert "\\[link\\]\\(https://bad\\)" in rendered


def test_invalid_candidate_evidence_and_missing_semantics_never_create_blocker(tmp_path):
    result = run(tmp_path, provider=FindingProvider(refs_ok=False))
    finding = result["findings"][0]
    assert finding["blocking_class"] == "UNRESOLVED"
    assert finding["status"] == "NEEDS_EVIDENCE"
    assert result["disposition"] == "INCOMPLETE"


def test_causal_role_citation_must_resolve_to_exact_delivered_snapshot_evidence(tmp_path):
    result = run(tmp_path, provider=InvalidRoleEvidenceProvider())
    finding = result["findings"][0]
    assert finding["semantic_assessment"]["outcome"] == "SUPPORTED"
    assert finding["blocking_class"] == "UNRESOLVED"
    assert finding["status"] == "NEEDS_EVIDENCE"


def test_candidate_on_path_outside_task_is_retained_unresolved_without_crash(tmp_path):
    result = run(tmp_path, provider=SidePathProvider())
    assert result["findings"][0]["unit_id"] is None
    assert result["findings"][0]["status"] == "NEEDS_EVIDENCE"
    assert result["findings"][0]["blocking_class"] == "UNRESOLVED"


def test_adjudication_contradiction_does_not_turn_into_a_finding_or_clean_approval(tmp_path):
    result = run(tmp_path, provider=FindingProvider(outcome="CONTRADICTED"))
    assert result["findings"][0]["status"] == "CONTRADICTED"
    assert result["findings"][0]["blocking_class"] == "UNRESOLVED"
    assert result["disposition"] == "INCOMPLETE"
    assert result["report_sections"]["suggested_improvements"] == []


def test_introducedness_unknown_cannot_be_accepted_as_blocker(tmp_path):
    result = run(tmp_path, provider=FindingProvider(introduced="UNKNOWN"))
    assert result["findings"][0]["introducedness"] == "UNKNOWN"
    assert result["findings"][0]["blocking_class"] == "UNRESOLVED"


def test_supported_but_nonmaterial_consequence_is_not_a_blocker(tmp_path):
    result = run(tmp_path, provider=FindingProvider(material=False))
    assert result["findings"][0]["status"] == "ACCEPTED"
    assert result["findings"][0]["blocking_class"] == "NON_BLOCKING"
    assert result["disposition"] == "COMMENT"
    assert len(result["report_sections"]["suggested_improvements"]) == 1


def test_stale_or_unknown_freshness_bars_approval(tmp_path):
    result = run(
        tmp_path, provider=EmptyProvider(), fresh=StaticFreshness({"freshness": "STALE", "observed_head_sha": "e" * 40})
    )
    assert result["freshness"] == "STALE"
    assert result["disposition"] == "INCOMPLETE"
    unknown = run(tmp_path / "unknown", provider=EmptyProvider(), fresh=StaticFreshness({"freshness": "UNKNOWN"}))
    assert unknown["disposition"] == "INCOMPLETE"


def test_required_check_without_adapter_stays_incomplete(tmp_path):
    prof = {
        "version": "p1",
        "required_lenses": ["correctness"],
        "required_checks": [{"id": "portal", "unit_ids": ["u0"], "binding": "external:portal"}],
    }
    result = run(tmp_path, prof=prof, provider=EmptyProvider())
    check = next(scope for scope in result["coverage_ledger"] if scope["obligation_kind"] == "PROJECT_CHECK")
    assert check["state"] == "NOT_STARTED"
    assert check["reason_code"] == "CHECK_ADAPTER_UNAVAILABLE"
    assert result["coverage_state"] == "PARTIAL"


def test_call_budget_includes_each_lens_and_leaves_remaining_scope_unstarted(tmp_path):
    budget = {**LIMITS, "max_provider_calls": 1}
    provider = EmptyProvider()
    result = run(tmp_path, prof=profile(("correctness", "tests")), provider=provider, limits=budget)
    assert result["budget"]["provider_calls_reserved"] == 1
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


def test_retry_calls_are_reserved_before_attempts(tmp_path):
    provider = BadOnceProvider()
    budget = {**LIMITS, "max_retries_per_task": 1}
    result = run(tmp_path, provider=provider, limits=budget)
    assert result["budget"]["provider_calls_reserved"] == 2


def test_timeout_becomes_partial_and_does_not_wait_past_deadline(tmp_path):
    started_path = tmp_path / "provider-started"
    completed_path = tmp_path / "provider-completed"
    provider_delay = 2
    budget = {**LIMITS, "deadline_seconds": 0.8}
    start = time.monotonic()
    result = run(
        tmp_path,
        provider=SlowProvider(str(started_path), str(completed_path), provider_delay),
        limits=budget,
    )
    elapsed = time.monotonic() - start
    assert elapsed < 1.6, "review waited for the provider's full two-second delay"
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
    timed_out = [row for row in result["task_results"].values() if row.get("status") == "TIMED_OUT"]
    assert len(timed_out) == 1
    assert started_path.exists(), "the provider never reached its review call"
    worker_pid = int(started_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pid, 0)
    time.sleep(provider_delay + 0.1)
    assert not completed_path.exists(), "cancelled provider ran to natural completion"


def test_resume_is_idempotent_and_rejects_changed_snapshot_or_tampering(tmp_path):
    provider = EmptyProvider()
    first = run(tmp_path, provider=provider)
    calls = first["budget"]["provider_calls_reserved"]
    snap = make_snapshot()
    plan = plan_review(snap, profile())
    second = run_review(snap, plan, profile(), provider, None, LIMITS, str(tmp_path), "r1", resume=True)
    assert second == first
    assert second["budget"]["provider_calls_reserved"] == calls
    with pytest.raises(ValueError, match="already exists"):
        run_review(snap, plan, profile(), provider, None, LIMITS, str(tmp_path), "r1")
    with pytest.raises(ValueError, match="mismatch"):
        run_review(make_snapshot(2), plan, profile(), provider, None, LIMITS, str(tmp_path), "r1", resume=True)
    path = tmp_path / "r1.json"
    payload = json.loads(path.read_text())
    payload["disposition"] = "REQUEST_CHANGES"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="integrity"):
        run_review(snap, plan, profile(), provider, None, LIMITS, str(tmp_path), "r1", resume=True)


def test_nonterminal_recovery_never_reuses_an_uncertain_reserved_call(tmp_path, monkeypatch):
    snap, prof = make_snapshot(), profile()
    plan = plan_review(snap, prof)
    provider = EmptyProvider()
    limits = {**LIMITS, "max_provider_calls": 1}
    real_invocation = engine_module.IsolatedInvocation

    def crash_after_reserve(*args, **kwargs):
        raise SimulatedControllerCrash()

    monkeypatch.setattr(engine_module, "IsolatedInvocation", crash_after_reserve)
    with pytest.raises(SimulatedControllerCrash):
        run_review(snap, plan, prof, provider, None, limits, str(tmp_path), "crash-run")
    monkeypatch.setattr(engine_module, "IsolatedInvocation", real_invocation)

    recovered = run_review(snap, plan, prof, provider, None, limits, str(tmp_path), "crash-run", resume=True)
    task_result = next(iter(recovered["task_results"].values()))
    assert recovered["budget"]["provider_calls_reserved"] == 1
    assert task_result["status"] == "FAILED"
    assert task_result["error_code"] == "INTERRUPTED_UNKNOWN"
    assert recovered["disposition"] == "INCOMPLETE"


def test_resumed_terminal_run_rechecks_head_without_reinvoking_provider(tmp_path):
    provider = EmptyProvider()
    first = run(tmp_path, provider=provider)
    calls = first["budget"]["provider_calls_reserved"]
    snap = make_snapshot()
    plan = plan_review(snap, profile())
    result = run_review(
        snap,
        plan,
        profile(),
        provider,
        None,
        LIMITS,
        str(tmp_path),
        "r1",
        resume=True,
        freshness_check=StaticFreshness({"freshness": "STALE", "observed_head_sha": "e" * 40}),
    )
    assert result["freshness"] == "STALE"
    assert result["disposition"] == "INCOMPLETE"
    assert result["budget"]["provider_calls_reserved"] == calls
    assert result["result_hash"] != first["result_hash"]


def test_advisory_decision_provider_is_budgeted_and_cannot_change_deterministic_disposition(tmp_path):
    budget = {**LIMITS, "max_provider_calls": 2}
    result = run(tmp_path, provider=None, limits=budget, decision_provider=Advisory())
    assert result["advisory_assessment"]["status"] == "RECEIVED"
    assert result["disposition"] == "INCOMPLETE"
    assert result["budget"]["provider_calls_reserved"] == 1


@pytest.mark.parametrize(
    "limits",
    [
        {**LIMITS, "deadline_seconds": float("inf")},
        {**LIMITS, "deadline_seconds": float("nan")},
        {**LIMITS, "max_provider_calls": True},
        {key: value for key, value in LIMITS.items() if key != "max_context_bytes"},
    ],
)
def test_unbounded_or_invalid_limits_rejected_before_provider_dispatch(tmp_path, limits):
    provider = EmptyProvider()
    with pytest.raises(ValueError):
        run(tmp_path, provider=provider, limits=limits)
    assert not (tmp_path / "r1.json").exists()


def test_unsupported_monetary_cap_rejected_before_provider_dispatch(tmp_path):
    provider = EmptyProvider()
    with pytest.raises(ValueError, match="monetary budget reservation is unsupported"):
        run(tmp_path, provider=provider, limits={**LIMITS, "max_cost_microunits": 1000})
    assert not (tmp_path / "r1.json").exists()
