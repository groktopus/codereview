import copy
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import pr_review_harness.engine as engine_module
from pr_review_harness.engine import EnginePreflightError, prepare_plan_tasks, render_report, run_review
from pr_review_harness.evidence import ContextRetriever
from pr_review_harness.planner import plan_review
from pr_review_harness.private_capture import CONTENT_TRANSFORM
from pr_review_harness.providers import OpenAIProvider, _validate_specialist
from pr_review_harness.snapshot import collect_snapshot


class PinnedCaptureProbeProvider:
    """Offline fake that records captured request bytes, then fails without transport."""

    identity = {"provider_id": "capture-probe", "model_id": "offline-probe-v1"}
    max_request_bytes = 128_000
    max_response_bytes = 32_768
    max_output_tokens = 1_800
    max_output_items = 10
    model = "offline-probe-v1"

    def _serialize_request_body(self, system, user, schema, limits):
        return OpenAIProvider._serialize_request_body(self, system, user, schema, limits)

    def serialize_review_request(self, task, evidence, limits):
        return json.dumps({"task": task, "evidence": evidence}, sort_keys=True, separators=(",", ":")).encode()

    def review_with_capture(self, task, evidence, limits, capture_spec, capture_sink):
        request = self.serialize_review_request(task, evidence, limits)
        if (
            capture_spec.get("strict_request_pin") is not True
            or hashlib.sha256(request).hexdigest() != capture_spec.get("expected_request_sha256")
        ):
            raise ValueError("fake_request_pin_mismatch")
        capture_sink(capture_spec, request, None, "failed", None, None)
        raise RuntimeError("offline_fake_transport_not_configured")


class AdjudicatingCaptureProbeProvider(PinnedCaptureProbeProvider):
    def review_with_capture(self, task, evidence, limits, capture_spec, capture_sink):
        request = self.serialize_review_request(task, evidence, limits)
        if hashlib.sha256(request).hexdigest() != capture_spec.get("expected_request_sha256"):
            raise ValueError("fake_request_pin_mismatch")
        refs = [item["evidence_id"] for item in evidence]
        payload = {
            "contract_version": "specialist-findings.v4",
            "finding_candidates": [{
                "unit_id": task["unit_ids"][0],
                "location": {"kind": "line", "path": evidence[0]["path"], "side": "HEAD", "line": 1, "reason": None},
                "title": "Candidate for offline adjudication probe",
                "observation": "The changed value is used without validation.",
                "consequence": "Malformed values may fail unexpectedly.",
                "rule_or_contract": "Inputs should be validated before use.",
                "severity": "low", "reasoning_kind": "inferred", "evidence_refs": refs,
                "introducedness": "INTRODUCED",
            }],
            "context_gap_proposals": [],
            "coverage_notes": [{
                "unit_id": unit_id, "state": "COVERED", "reason_code": "STATIC_REVIEW",
                "evidence_refs": refs, "coverage_basis": "STATIC_REVIEW",
            } for unit_id in task["unit_ids"]],
            "specific_strengths": [], "future_guidance": [],
        }
        response = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        capture_sink(capture_spec, request, response, "completed", "b" * 64, CONTENT_TRANSFORM)
        return {"payload": payload, "usage": {}, "provenance": {"provider": "offline-capture-probe"}}

    def adjudicate(self, _candidate, _evidence, limits):
        Path(limits["fake_adjudication_marker"]).write_text("called", encoding="utf-8")
        raise RuntimeError("offline_fake_adjudication_not_configured")


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


class BoundWireProvider(SizingOnlyOpenAIProvider):
    """Exercise v2 through the engine and the real OpenAI-compatible serializer."""

    def review(self, task, evidence, limits):
        body = self.serialize_review_request(task, evidence, limits)
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit_id,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": [
                            *next(row["evidence_ids"] for row in task["unit_evidence_bindings"] if row["unit_id"] == unit_id),
                            *(eid for eid in task["evidence_ids"] if eid.startswith("policy:")),
                        ],
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for unit_id in task["unit_ids"]
                ],
                "specific_strengths": [],
                "future_guidance": [],
            },
            "usage": {},
            "provenance": {
                "wire_bytes": len(body),
                "measured_bytes": self.review_input_bytes(task, evidence, limits),
                "task_bindings": task["unit_evidence_bindings"],
            },
        }


class CrossUnitReferenceProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        self.calls += 1
        other = {"u0": "u1", "u1": "u0"}
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit_id,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": [f"diff:{other[unit_id]}"],
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for unit_id in task["unit_ids"]
                ],
            },
            "usage": {},
            "provenance": {},
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


class CoverageNotesProvider(EmptyProvider):
    def __init__(self, state="PARTIAL", reasons=None, refs_override=None, omit=False):
        super().__init__()
        self.state = state
        self.reasons = reasons or {}
        self.refs_override = refs_override
        self.omit = omit

    def review(self, task, evidence, limits):
        self.calls += 1
        notes = []
        if not self.omit:
            for unit_id in task["unit_ids"]:
                notes.append(
                    {
                        "unit_id": unit_id,
                        "state": self.state,
                        "reason_code": self.reasons.get(
                            task["task_id"], self.reasons.get(unit_id, "LIMITED_CHANGED_SCOPE_EVIDENCE")
                        ),
                        "evidence_refs": self.refs_override.get(unit_id, list(task["evidence_ids"]))
                        if isinstance(self.refs_override, dict)
                        else list(task["evidence_ids"]),
                        "coverage_basis": "STATIC_REVIEW",
                    }
                )
        return {
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": notes,
        }


class FailedCoverageProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        raise RuntimeError("provider attempt failed")


class PartialFindingProvider(FindingProvider):
    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        result["coverage_notes"][0]["state"] = "PARTIAL"
        result["coverage_notes"][0]["reason_code"] = "NO_TEST_SOURCE_SUPPLIED"
        return result


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
    def __init__(self, marker=None):
        super().__init__()
        self.marker = marker

    def review(self, task, evidence, limits):
        self.calls += 1
        if self.marker is not None:
            Path(self.marker).write_text("called")
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


class RequiredContextClosureFixtureProvider(ContextFollowupProvider):
    """Exercise the real engine closure reducer with bounded synthetic notes."""

    def __init__(self, followup_state="COVERED", mutation=None):
        super().__init__()
        self.followup_state = followup_state
        self.mutation = mutation

    def review(self, task, evidence, limits):
        if not task.get("context_gap_followup_for"):
            return super().review(task, evidence, limits)

        self.calls += 1
        unit_id = task["unit_ids"][0]
        retrieved_id = next(
            item["evidence_id"] for item in evidence if item.get("path") == "docs/caller.md"
        )
        unit_binding = next(
            row for row in task["unit_evidence_bindings"] if row["unit_id"] == unit_id
        )
        unit_local_id = unit_binding["evidence_ids"][0]
        note = {
            "unit_id": unit_id,
            "state": self.followup_state,
            "reason_code": "synthetic_closure_fixture",
            "evidence_refs": [retrieved_id, unit_local_id],
            "coverage_basis": "STATIC_REVIEW",
        }
        if self.mutation == "wrong_basis":
            note["coverage_basis"] = "DYNAMIC_EXECUTION"
        elif self.mutation == "wrong_scope":
            note["unit_id"] = "unit-outside-scope"
        elif self.mutation == "undispatched_reference":
            note["evidence_refs"].append("ev-not-in-task-input")
        return {
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [note],
        }


class NestedGapContextFollowupProvider(ContextFollowupProvider):
    def review(self, task, evidence, limits):
        if not task.get("context_gap_followup_for"):
            return super().review(task, evidence, limits)
        self.calls += 1
        unit = task["unit_ids"][0]
        evidence_id = task["evidence_ids"][0]
        return {
            "finding_candidates": [],
            "context_gap_proposals": [{
                "evidence_kind": "caller",
                "target": {"target_unit_id": unit, "target_path": None, "target_symbol": None},
                "rationale": "Nested contract gap remains.",
                "related_evidence_ids": [evidence_id],
                "required_lens": task["lens"],
            }],
            "coverage_notes": [],
        }


class AdapterNormalizedContextFollowupProvider(ContextFollowupProvider):
    """Use the production V4 specialist normalizer on the offline fixture."""

    def review(self, task, evidence, limits):
        raw = super().review(task, evidence, limits)
        for proposal in raw["context_gap_proposals"]:
            target = proposal["target"]
            selected = next(key for key, value in target.items() if value)
            kind = {"target_unit_id": "unit", "target_path": "path", "target_symbol": "symbol"}[selected]
            proposal["target"] = {"kind": kind, "value": target[selected]}
            proposal["related_candidate_ids"] = []
        raw.update(
            {
                "contract_version": "specialist-findings.v4",
                "specific_strengths": [],
                "future_guidance": [],
            }
        )
        return _validate_specialist(
            raw,
            valid_evidence_ids={item["evidence_id"] for item in evidence},
            valid_unit_ids=set(task["unit_ids"]),
        )


class MalformedUnusedTargetProvider(ContextFollowupProvider):
    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        if result.get("context_gap_proposals"):
            result["context_gap_proposals"][0]["target"]["target_symbol"] = ""
        return result


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


class ExistingEvidenceContextRetriever:
    def __init__(self, evidence):
        self.evidence = evidence

    def __call__(self, snapshot, profile, proposal, limits):
        return {"status": "RESOLVED", "reason": None, "evidence": self.evidence}


class OversizedContextRetriever:
    def __call__(self, snapshot, prof, proposal, limits):
        return {"status": "UNRESOLVED", "reason": "safe", "evidence": None, "untrusted": "secret-marker" * 2000}


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


def test_private_capture_pins_preflight_real_plan_and_reject_missing_extra_or_changed_requests(tmp_path):
    class PinProvider:
        identity = {"provider_id": "pin-test", "model_id": "pin-test-v1"}
        model = "pin-test-v1"
        max_request_bytes = 128_000
        max_response_bytes = 32_768
        max_output_tokens = 1_800
        max_output_items = 10

        def __init__(self):
            self.mutate = False
            self.calls = 0

        def serialize_review_request(self, task, evidence, limits):
            body = json.dumps({"task": task, "evidence": evidence}, sort_keys=True, separators=(",", ":")).encode()
            return body + (b" " if self.mutate else b"")

        def _serialize_request_body(self, system, user, schema, limits):
            return OpenAIProvider._serialize_request_body(self, system, user, schema, limits)

        def review_with_capture(self, *_args):
            self.calls += 1
            pytest.fail("pinned preflight rejection must happen before dispatch")

    provider = PinProvider()
    snapshot = make_snapshot()
    prof = profile()
    limits = {**LIMITS, "max_provider_calls": 1, "max_followup_tasks": 0,
              "max_input_bytes_per_task": 128_000, "max_output_bytes_per_task": 32_768,
              "max_output_tokens": 1_800}
    plan = plan_review(snapshot, prof, "AUTO")
    prepared, _skipped = prepare_plan_tasks(snapshot, plan, prof, limits, provider)
    from pr_review_harness.engine import _evidence_for

    writer_tasks = [task for task in prepared if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"]
    assert len(writer_tasks) == 1
    pins = {}
    for task in writer_tasks:
        evidence = _evidence_for(task, snapshot, limits["max_input_bytes_per_task"])
        request = provider.serialize_review_request(task, evidence, limits)
        pins[task["task_id"]] = {
            "task_id": task["task_id"], "input_sha256": hashlib.sha256(request).hexdigest(),
            "input_bytes": len(request), "lens": task["lens"], "output_bytes_cap": 32_768,
            "output_tokens_cap": 1_800,
        }

    def reject(pin_map, *, mutate=False):
        provider.mutate = mutate
        capture_dir = tmp_path / f"capture-{len(list(tmp_path.iterdir()))}"
        with pytest.raises(EnginePreflightError, match="review request is invalid"):
            run_review(
                snapshot, plan, prof, provider, None, limits, str(tmp_path / "results"), "pinned-run",
                private_capture_dir=str(capture_dir), private_capture_case_id="PR-464",
                private_capture_request_pins=pin_map,
                private_capture_snapshot_pin={"snapshot_id": "snap", "snapshot_sha256": "d" * 64},
            )
        assert not capture_dir.exists()
        assert provider.calls == 0

    reject({})
    reject({**pins, "unknown-task": {**next(iter(pins.values())), "task_id": "unknown-task"}})
    reject(pins, mutate=True)

    assert provider.calls == 0
    assert not (tmp_path / "r1.json").exists()


def test_private_capture_accepts_exact_six_pins_under_ten_call_ceiling(tmp_path):
    provider = PinnedCaptureProbeProvider()
    snapshot = make_snapshot()
    prof = profile(("correctness", "tests", "design", "security", "performance", "maintainability"))
    frozen_plan = json.loads(
        (Path(__file__).resolve().parents[1] / "experiments/model-only-shadow-live-pr464-plan-v3.json").read_text()
    )
    prof["repository"] = frozen_plan["case"]["repository"]
    snapshot["profile_hash"] = hashlib.sha256(json.dumps(
        prof, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    snapshot["snapshot_hash"] = hashlib.sha256(json.dumps(
        {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    limits = {
        **LIMITS,
        "max_provider_calls": 10,
        "max_retries_per_task": 0,
        "max_followup_tasks": 0,
        "max_context_bytes": 1_000_000,
        "max_output_bytes": 200_000,
        "max_input_bytes_per_task": 128_000,
        "max_output_bytes_per_task": 32_768,
        "max_output_tokens": 1_800,
    }
    plan = plan_review(snapshot, prof, "AUTO")
    prepared, _skipped = prepare_plan_tasks(snapshot, plan, prof, limits, provider)
    writer_tasks = [task for task in prepared if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"]
    assert len(writer_tasks) == 6
    from pr_review_harness.engine import _evidence_for

    pins = {}
    for task in writer_tasks:
        evidence = _evidence_for(task, snapshot, limits["max_input_bytes_per_task"])
        request = provider.serialize_review_request(task, evidence, limits)
        pins[task["task_id"]] = {
            "task_id": task["task_id"],
            "input_sha256": hashlib.sha256(request).hexdigest(),
            "input_bytes": len(request),
            "lens": task["lens"],
            "output_bytes_cap": 32_768,
            "output_tokens_cap": 1_800,
        }

    rejected_profile = {**prof, "profile_id": "../bad"}
    rejected_snapshot = copy.deepcopy(snapshot)
    rejected_snapshot["profile_hash"] = hashlib.sha256(json.dumps(
        rejected_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    rejected_snapshot["snapshot_hash"] = hashlib.sha256(json.dumps(
        {key: value for key, value in rejected_snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    rejected_plan = plan_review(rejected_snapshot, rejected_profile, "AUTO")
    rejected_prepared, _skipped = prepare_plan_tasks(rejected_snapshot, rejected_plan, rejected_profile, limits, provider)
    rejected_tasks = [task for task in rejected_prepared if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"]
    rejected_pins = {}
    for task in rejected_tasks:
        evidence = _evidence_for(task, rejected_snapshot, limits["max_input_bytes_per_task"])
        request = provider.serialize_review_request(task, evidence, limits)
        rejected_pins[task["task_id"]] = {
            "task_id": task["task_id"], "input_sha256": hashlib.sha256(request).hexdigest(),
            "input_bytes": len(request), "lens": task["lens"],
            "output_bytes_cap": 32_768, "output_tokens_cap": 1_800,
        }
    rejected_capture = tmp_path / "capture-missing-profile-id"
    with pytest.raises(EnginePreflightError, match="review request is invalid"):
        run_review(
            rejected_snapshot, rejected_plan, rejected_profile, provider, None, limits,
            str(tmp_path / "results"), "missing-profile-id",
            private_capture_dir=str(rejected_capture), private_capture_case_id="PR-464",
            private_capture_request_pins=rejected_pins,
            private_capture_snapshot_pin={"snapshot_id": "snap", "snapshot_sha256": rejected_snapshot["snapshot_hash"]},
        )
    assert not rejected_capture.exists()

    capture_dir = tmp_path / "capture-six-of-ten"
    result = run_review(
        snapshot, plan, prof, provider, None, limits, str(tmp_path / "results"), "six-of-ten",
        private_capture_dir=str(capture_dir), private_capture_case_id="PR-457",
        private_capture_request_pins=pins,
        private_capture_snapshot_pin={"snapshot_id": "snap", "snapshot_sha256": snapshot["snapshot_hash"]},
    )
    captured_requests = list((capture_dir / "requests").glob("*.bin"))
    assert len(captured_requests) == 6
    source_tasks = json.loads((capture_dir / "source_tasks.json").read_text())
    assert source_tasks["profile_id"] == "slopsearx"
    assert {hashlib.sha256(path.read_bytes()).hexdigest() for path in captured_requests} == {
        pin["input_sha256"] for pin in pins.values()
    }
    assert result["budget"]["provider_calls_limit"] == 10
    assert result["budget"]["provider_calls_reserved"] == 6

    below_cap_limits = {**limits, "max_provider_calls": 5}
    below_cap_dir = tmp_path / "capture-below-cap"
    with pytest.raises(EnginePreflightError, match="review request is invalid"):
        run_review(
            snapshot, plan, prof, provider, None, below_cap_limits, str(tmp_path / "results"), "below-cap",
            private_capture_dir=str(below_cap_dir), private_capture_case_id="PR-457",
            private_capture_request_pins=pins,
            private_capture_snapshot_pin={"snapshot_id": "snap", "snapshot_sha256": snapshot["snapshot_hash"]},
        )
    assert not below_cap_dir.exists()


def test_private_capture_profile_identity_resolution():
    from pr_review_harness.engine import _private_capture_profile_id

    assert _private_capture_profile_id({"profile_id": "variant-a", "repository": "magnus919/SlopSearX"}) == "variant-a"
    assert _private_capture_profile_id({"id": "variant-b", "repository": "magnus919/SlopSearX"}) == "variant-b"
    assert _private_capture_profile_id({"name": "variant-c", "repository": "magnus919/SlopSearX"}) == "variant-c"
    assert _private_capture_profile_id({"repository": {"owner": "magnus919", "name": "SlopSearX"}}) == "slopsearx"
    assert _private_capture_profile_id({"repository": "magnus919/SlopSearX"}) == "slopsearx"
    with pytest.raises(ValueError, match="profile identity is invalid"):
        _private_capture_profile_id({"profile_id": "../bad", "repository": "magnus919/SlopSearX"})
    assert _private_capture_profile_id({}) == "unknown"
    with pytest.raises(ValueError, match="repository identity is invalid"):
        _private_capture_profile_id({"repository": "unknown"})
    with pytest.raises(ValueError, match="repository identity is invalid"):
        _private_capture_profile_id({"repository": None})
    with pytest.raises(ValueError, match="profile identity is invalid"):
        _private_capture_profile_id({"profile_id": None, "repository": "owner/repo"})
    # The slug is a local alias; repository and snapshot hashes carry provenance.
    assert _private_capture_profile_id({"repository": "owner-a/SlopSearX"}) == "slopsearx"
    assert _private_capture_profile_id({"repository": "owner-b/SlopSearX"}) == "slopsearx"


def test_private_capture_skips_semantic_adjudication_for_valid_candidate(tmp_path):
    provider = AdjudicatingCaptureProbeProvider()
    snapshot = make_snapshot()
    prof = json.loads((Path(__file__).resolve().parents[1] / "experiments/synth-001-writer-profile-v1.json").read_text())
    snapshot["profile_hash"] = hashlib.sha256(json.dumps(
        prof, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    snapshot["snapshot_hash"] = hashlib.sha256(json.dumps(
        {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    marker = tmp_path / "adjudication-called"
    limits = {
        **LIMITS,
        "max_provider_calls": 10,
        "max_retries_per_task": 0,
        "max_followup_tasks": 0,
        "max_input_bytes_per_task": 128_000,
        "max_output_bytes_per_task": 32_768,
        "max_output_tokens": 1_800,
        "fake_adjudication_marker": str(marker),
    }
    plan = plan_review(snapshot, prof, "AUTO")
    prepared, _skipped = prepare_plan_tasks(snapshot, plan, prof, limits, provider)
    writer_task = next(task for task in prepared if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS")
    from pr_review_harness.engine import _evidence_for

    evidence = _evidence_for(writer_task, snapshot, limits["max_input_bytes_per_task"])
    request = provider.serialize_review_request(writer_task, evidence, limits)
    pins = {writer_task["task_id"]: {
        "task_id": writer_task["task_id"], "input_sha256": hashlib.sha256(request).hexdigest(),
        "input_bytes": len(request), "lens": writer_task["lens"],
        "output_bytes_cap": 32_768, "output_tokens_cap": 1_800,
    }}

    capture_dir = tmp_path / "capture-no-adjudication"
    result = run_review(
        snapshot, plan, prof, provider, None, limits, str(tmp_path / "results"), "capture-no-adjudication",
        private_capture_dir=str(capture_dir), private_capture_case_id="PR-457",
        private_capture_request_pins=pins,
        private_capture_snapshot_pin={"snapshot_id": "snap", "snapshot_sha256": snapshot["snapshot_hash"]},
    )
    assert len(result["findings"]) == 1
    assert result["ledger"]["candidate_records"][0]["validation_state"] == "VALID"
    assert result["findings"][0]["semantic_assessment"] is None
    assert result["budget"]["provider_calls_reserved"] == 1
    assert not marker.exists()
    assert len(list((capture_dir / "requests").glob("*.bin"))) == 1
    source_tasks = json.loads((capture_dir / "source_tasks.json").read_text())
    assert source_tasks["profile_id"] == "unknown"


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
        task = {
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
        evidence = [snap["evidence"][eid] for eid in task["evidence_ids"]]
        return engine_module._bind_specialist_input(task, snap, prof, evidence)

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


def test_engine_v2_binds_each_unit_and_allows_shared_policy_refs(tmp_path):
    snap = make_snapshot(units=2)
    policy_id = _add_trusted_policy(snap, "Shared policy is available to both units.\n")
    prof = profile()
    plan = plan_review(snap, prof)
    plan["tasks"][0]["evidence_ids"].append(policy_id)
    plan["tasks"][0]["base_context_ids"] = [policy_id]
    provider = BoundWireProvider()

    result = run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), "bound-v2")
    row = next(value for value in result["task_results"].values() if value.get("status") == "SUCCEEDED")
    bindings = row["unit_evidence_bindings"]
    assert row["request_input_contract"] == "specialist-input.v2"
    assert bindings == [
        {"unit_id": "u0", "binding_status": "VERIFIED", "evidence_ids": ["diff:u0"]},
        {"unit_id": "u1", "binding_status": "VERIFIED", "evidence_ids": ["diff:u1"]},
    ]
    assert row["provenance"]["task_bindings"] == bindings
    assert row["provenance"]["wire_bytes"] == row["provenance"]["measured_bytes"]
    assert result["coverage_state"] == "COMPLETE"


def test_collector_to_engine_serializes_owned_windows_and_required_context(tmp_path):
    bare, work = tmp_path / "objects.git", tmp_path / "work"

    def git(path, *args):
        return subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        ).stdout.strip()

    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True, timeout=10)
    subprocess.run(["git", "init", str(work)], check=True, capture_output=True, timeout=10)
    git(work, "config", "user.email", "fixture@example.invalid")
    git(work, "config", "user.name", "Unit Binding Fixture")
    (work / "src").mkdir()
    (work / "docs").mkdir()
    (work / "AGENTS.md").write_text("Preserve evidence ownership in the review.\n")
    (work / "docs/contract.md").write_text("Both functions return an integer.\n")
    (work / "src/a.py").write_text("def alpha():\n    return 1\n")
    (work / "src/b.py").write_text("def beta():\n    return 1\n")
    git(work, "add", "AGENTS.md", "docs/contract.md", "src/a.py", "src/b.py")
    subprocess.run(
        ["git", "-C", str(work), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "commit", "-m", "base"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    base = git(work, "rev-parse", "HEAD")
    (work / "src/a.py").write_text("def alpha():\n    return 2\n")
    (work / "src/b.py").write_text("def beta():\n    return 2\n")
    git(work, "add", "src/a.py", "src/b.py")
    subprocess.run(
        ["git", "-C", str(work), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "commit", "-m", "change"],
        check=True,
        capture_output=True,
        timeout=10,
    )
    head = git(work, "rev-parse", "HEAD")
    git(work, "remote", "add", "origin", str(bare))
    subprocess.run(["git", "-C", str(work), "push", "origin", "HEAD:refs/heads/main"], check=True, capture_output=True, timeout=10)
    prof = {
        **profile(),
        "context_paths": ["AGENTS.md", "docs/contract.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "retrieval_context_patterns": ["AGENTS.md", "docs/contract.md"],
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
                    "context_paths": ["docs/contract.md"],
                    "max_context_bytes": 1_000,
                }
            ],
        },
    }
    snap = collect_snapshot(
        str(bare), base, head, prof, {"max_context_bytes": 100_000, "max_snapshot_context_bytes": 100_000}
    )
    plan = plan_review(snap, prof)
    provider = BoundWireProvider()
    result = run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path / "runs"), "collector-bindings")

    inventory = {row["unit_id"]: set(row["evidence_ids"]) for row in snap["inventory"]}
    windows = {item["evidence_id"] for item in snap["evidence"].values() if item.get("source_kind") == "source_window"}
    whole_files = {
        item["evidence_id"]
        for item in snap["evidence"].values()
        if item.get("source_kind") in {"base_file", "head_file"}
    }
    assert len(inventory) == 2 and windows
    for row in result["task_results"].values():
        assert row["status"] == "SUCCEEDED"
        sent = set(row["input_evidence_ids"])
        assert snap["trusted_context_refs"][0] in sent
        assert row["provenance"]["wire_bytes"] == row["provenance"]["measured_bytes"]
        assert not (sent & whole_files)
        for binding in row["unit_evidence_bindings"]:
            expected = inventory[binding["unit_id"]] & sent
            assert set(binding["evidence_ids"]) == expected
            assert set(binding["evidence_ids"]).issubset(sent)
        assert set(row["input_evidence_ids"]) & windows
    code_coverage = [row for row in result["coverage_ledger"] if row["obligation_kind"] == "CHANGED_UNIT_LENS"]
    expected_code_obligations = sum(row["obligation_kind"] == "CHANGED_UNIT_LENS" for row in plan["coverage_obligations"])
    assert len(code_coverage) == expected_code_obligations
    assert all(row["state"] == "COMPLETE" for row in code_coverage)


def test_engine_rejects_forged_cross_unit_binding_before_dispatch(tmp_path):
    snap = make_snapshot(units=2)
    prof = profile()
    plan = plan_review(snap, prof)
    task = plan["tasks"][0]
    task["unit_evidence_bindings"] = [
        {"unit_id": unit_id, "binding_status": "VERIFIED", "evidence_ids": [f"diff:{other_id}"]}
        for unit_id, other_id in (("u0", "u1"), ("u1", "u0"))
    ]
    provider = EmptyProvider()
    with pytest.raises(ValueError, match="engine_owned"):
        run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), "forged-binding")
    assert provider.calls == 0
    assert not (tmp_path / "forged-binding.json").exists()


def test_missing_task_kind_uses_specialist_v2_and_explicit_unknown_kind_fails(tmp_path):
    snap, prof = make_snapshot(), profile()
    plan = plan_review(snap, prof)
    plan["tasks"][0].pop("task_kind")
    result = run_review(snap, plan, prof, EmptyProvider(), None, LIMITS, str(tmp_path), "default-kind")
    assert next(iter(result["task_results"].values()))["request_input_contract"] == "specialist-input.v2"

    bad_plan = plan_review(snap, prof)
    bad_plan["tasks"][0]["task_kind"] = None
    provider = EmptyProvider()
    with pytest.raises(ValueError, match="invalid planned task kind"):
        run_review(snap, bad_plan, prof, provider, None, LIMITS, str(tmp_path), "unknown-kind")
    assert provider.calls == 0


def test_cross_unit_only_coverage_refs_remain_invalid_after_dispatch(tmp_path):
    snap, prof = make_snapshot(units=2), profile()
    plan = plan_review(snap, prof)
    result = run_review(snap, plan, prof, CrossUnitReferenceProvider(), None, LIMITS, str(tmp_path), "cross-ref")
    assert next(iter(result["task_results"].values()))["status"] == "SUCCEEDED"
    assert result["coverage_state"] == "PARTIAL"
    assert result["coverage_ledger"][0]["reason_code"] == "COVERAGE_NOTE_EVIDENCE_INVALID"


def test_resume_rejects_changed_persisted_unit_binding_map(tmp_path):
    provider = EmptyProvider()
    snap, prof = make_snapshot(units=2), profile()
    plan = plan_review(snap, prof)
    run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), "binding-resume")
    path = tmp_path / "binding-resume.json"
    payload = json.loads(path.read_text())
    payload["ledger"]["planned_task_inputs"] = {}
    payload["result_hash"] = engine_module._hash({key: value for key, value in payload.items() if key != "result_hash"})
    path.write_text(json.dumps(payload))

    calls = provider.calls
    with pytest.raises(ValueError, match="planned input binding"):
        run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), "binding-resume", resume=True)
    assert provider.calls == calls

    second_id = "binding-output-resume"
    run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), second_id)
    output_path = tmp_path / f"{second_id}.json"
    saved = json.loads(output_path.read_text())
    task_result = next(iter(saved["ledger"]["outputs"].values()))
    task_result["unit_evidence_bindings"][0]["evidence_ids"] = []
    saved["result_hash"] = engine_module._hash({key: value for key, value in saved.items() if key != "result_hash"})
    output_path.write_text(json.dumps(saved))
    with pytest.raises(ValueError, match="task input binding"):
        run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), second_id, resume=True)


def test_oversized_initial_request_is_measured_then_split_below_unchanged_dispatch_caps():
    snap = make_snapshot(units=2)
    for unit in snap["inventory"]:
        evidence = snap["evidence"][unit["evidence_ids"][0]]
        content = f"source for {unit['unit_id']}\n" + ("x" * 65_000)
        evidence["content"] = content
        evidence["content_hash"] = hashlib.sha256(content.encode()).hexdigest()
    prof = profile()
    plan = plan_review(snap, prof)
    provider = SizingOnlyOpenAIProvider()
    provider.max_request_bytes = 128_000
    limits = {
        **LIMITS,
        "max_context_bytes": 8_000_000,
        "max_snapshot_context_bytes": 300_000,
        "max_input_bytes_per_task": 128_000,
    }
    initial = plan["tasks"][0]
    initial_evidence = [snap["evidence"][eid] for eid in initial["evidence_ids"]]
    initial_bytes = provider.review_input_bytes(initial, initial_evidence, limits)
    assert initial_bytes > provider.max_request_bytes

    prepared, skipped = prepare_plan_tasks(snap, plan, prof, limits, provider)
    assert skipped == {}
    assert len(prepared) == 2
    final_sizes = [
        provider.review_input_bytes(
            task,
            [snap["evidence"][eid] for eid in task["evidence_ids"]],
            limits,
        )
        for task in prepared
    ]
    assert all(size <= provider.max_request_bytes for size in final_sizes)
    assert all(size <= limits["max_input_bytes_per_task"] for size in final_sizes)


def test_lower_adapter_ceiling_drives_splitting_below_runtime_ceiling():
    snap = make_snapshot(units=2)
    for unit in snap["inventory"]:
        evidence = snap["evidence"][unit["evidence_ids"][0]]
        content = f"source for {unit['unit_id']}\n" + ("x" * 50_000)
        evidence["content"] = content
        evidence["content_hash"] = hashlib.sha256(content.encode()).hexdigest()
    prof = profile()
    plan = plan_review(snap, prof)
    provider = SizingOnlyOpenAIProvider()
    provider.max_request_bytes = 90_000
    limits = {**LIMITS, "max_context_bytes": 8_000_000, "max_input_bytes_per_task": 128_000}

    original = plan["tasks"][0]
    original_evidence = [snap["evidence"][eid] for eid in original["evidence_ids"]]
    assert provider.review_input_bytes(original, original_evidence, limits) > provider.max_request_bytes
    prepared, skipped = prepare_plan_tasks(snap, plan, prof, limits, provider)

    assert skipped == {}
    assert len(prepared) == 2
    final_sizes = [
        provider.review_input_bytes(task, [snap["evidence"][eid] for eid in task["evidence_ids"]], limits)
        for task in prepared
    ]
    assert all(size <= provider.max_request_bytes for size in final_sizes)
    assert all(size <= limits["max_input_bytes_per_task"] for size in final_sizes)


def test_adapter_cap_rejects_unsplittable_task_before_reservation_or_secret_lookup(
    tmp_path, monkeypatch
):
    snap = make_snapshot(units=1)
    evidence = snap["evidence"]["diff:u0"]
    evidence["content"] = "x" * 5_000
    evidence["content_hash"] = hashlib.sha256(evidence["content"].encode()).hexdigest()
    prof = profile()
    provider = OpenAIProvider({
        "kind": "openai_compatible",
        "base_url": "https://provider.invalid/v1",
        "model": "adapter-cap-test",
        "api_key_env": "ADAPTER_CAP_MUST_NOT_BE_READ",
        "max_request_bytes": 1_000,
    })

    class GuardedEnv(dict):
        def get(self, key, default=None):
            if key == "ADAPTER_CAP_MUST_NOT_BE_READ":
                raise AssertionError("rejected task looked up a provider credential")
            return super().get(key, default)

    monkeypatch.setenv("ADAPTER_CAP_MUST_NOT_BE_READ", "synthetic-secret")
    monkeypatch.setattr(os, "environ", GuardedEnv(os.environ))

    class NoTransport:
        def open(self, *_args, **_kwargs):
            raise AssertionError("rejected task opened provider transport")

    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", NoTransport())
    result = run(
        tmp_path,
        snap,
        prof,
        provider,
        {**LIMITS, "max_input_bytes_per_task": 128_000},
        run_id="adapter-cap-rejected",
    )

    assert result["budget"]["provider_calls_reserved"] == 0
    skipped = [row for row in result["task_results"].values() if row.get("status") == "SKIPPED"]
    assert len(skipped) == 1
    assert skipped[0]["error_code"] == "UNIT_EVIDENCE_EXCEEDS_INPUT_LIMIT"
    assert result["disposition"] == "INCOMPLETE"


@pytest.mark.parametrize("adapter_cap", [True, 0, -1, 1.5])
def test_invalid_declared_adapter_input_cap_fails_preflight(adapter_cap):
    provider = EmptyProvider()
    provider.max_request_bytes = adapter_cap
    with pytest.raises(ValueError, match="invalid provider input byte capability"):
        engine_module.effective_task_input_ceiling(
            {**LIMITS, "max_input_bytes_per_task": 128_000}, provider
        )


def test_provider_without_declared_request_cap_keeps_runtime_input_ceiling():
    assert engine_module.effective_task_input_ceiling(
        {**LIMITS, "max_input_bytes_per_task": 128_000}, EmptyProvider()
    ) == 128_000


def test_unit_skips_when_required_context_cannot_fit_without_dispatch(tmp_path):
    snap = make_snapshot(units=1)
    policy_id = _add_trusted_policy(snap, "Mandatory policy. " + ("rule " * 600))
    prof = required_context_profile()
    plan = plan_review(snap, prof)
    assert plan["tasks"][0]["required_context_ids"] == [policy_id]
    planned = plan["tasks"][0]

    def request_size(evidence_ids, required_ids):
        candidate = {
            **planned,
            "unit_ids": ["u0"],
            "scope_unit_ids": ["u0"],
            "evidence_ids": evidence_ids,
            "base_context_ids": required_ids,
            "required_context_ids": required_ids,
        }
        evidence = [snap["evidence"][eid] for eid in evidence_ids]
        bound = engine_module._bind_specialist_input(candidate, snap, prof, evidence)
        return len(engine_module._canonical({"task": bound, "evidence": evidence}))

    unit_only_size = request_size(["diff:u0"], [])
    required_size = request_size(["diff:u0", policy_id], [policy_id])
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

    provider = SizingOnlyOpenAIProvider()

    def sized_unit(unit_id):
        candidate = {
            **task,
            "unit_ids": [unit_id],
            "scope_unit_ids": [unit_id],
            "evidence_ids": [f"diff:{unit_id}", policy_id],
            "base_context_ids": [policy_id],
            "required_context_ids": [policy_id],
            "context_omissions": [],
            "required_context_omissions": [],
        }
        evidence = [snap["evidence"][eid] for eid in candidate["evidence_ids"]]
        candidate = engine_module._bind_specialist_input(candidate, snap, prof, evidence)
        return provider.review_input_bytes(candidate, evidence, LIMITS) + 1024

    cap = sized_unit("u0") + 32  # reserve room for the deterministic split task suffix
    assert sized_unit("u1") > cap

    result = run_review(
        snap,
        plan,
        prof,
        provider,
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


def test_accepted_partial_coverage_has_truthful_deterministic_reason_and_keeps_incomplete(tmp_path):
    result = run(tmp_path, provider=CoverageNotesProvider())
    row = result["coverage_ledger"][0]
    assert row["state"] == "PARTIAL"
    assert row["reason_code"] == "PARTIAL_REVIEW_COVERAGE"
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


def test_missing_coverage_note_is_distinct_from_an_accepted_partial_note(tmp_path):
    result = run(tmp_path, provider=CoverageNotesProvider(omit=True))
    row = result["coverage_ledger"][0]
    assert row["state"] == "PARTIAL"
    assert row["reason_code"] == "COVERAGE_NOTE_MISSING"
    assert result["disposition"] == "INCOMPLETE"


def test_failed_provider_call_reason_is_preserved_over_coverage_fallback(tmp_path):
    result = run(tmp_path, provider=FailedCoverageProvider())
    row = result["coverage_ledger"][0]
    task_result = next(iter(result["task_results"].values()))
    assert task_result["status"] == "FAILED"
    assert row["state"] == "PARTIAL"
    assert row["reason_code"] == task_result["error_code"]
    assert row["reason_code"] != "MISSING_RESULT"


def test_cross_unit_coverage_evidence_is_not_reported_as_valid_partial(tmp_path):
    snapshot = make_snapshot(units=2)
    plan = plan_review(snapshot, profile())
    # Force one dispatched task to cite only the other unit's evidence.
    provider = CoverageNotesProvider(
        state="COVERED",
        refs_override={"u0": ["diff:u1"], "u1": ["diff:u0"]},
    )
    result = run_review(snapshot, plan, profile(), provider, None, LIMITS, str(tmp_path), "cross-unit-coverage")
    rows = [row for row in result["coverage_ledger"] if row["obligation_kind"] == "CHANGED_UNIT_LENS"]
    assert len(rows) == 2
    assert all(row["state"] == "PARTIAL" for row in rows)
    assert all(row["reason_code"] == "COVERAGE_NOTE_EVIDENCE_INVALID" for row in rows)
    assert "Specialist reported partial coverage" not in render_report(result)


def test_partial_reason_is_stable_across_task_order_and_blocker_is_preserved(tmp_path):
    snapshot = make_snapshot()
    prof = profile()
    plan = plan_review(snapshot, prof)
    original = plan["tasks"][0]
    first, second = copy.deepcopy(original), copy.deepcopy(original)
    first["task_id"], second["task_id"] = "partial-a", "partial-b"
    plan["tasks"] = [first, second]
    reasons = {"partial-a": "LIMITED_CHANGED_SCOPE_EVIDENCE", "partial-b": "NO_TEST_SOURCE_SUPPLIED"}
    forward = run_review(
        snapshot,
        plan,
        prof,
        CoverageNotesProvider(reasons=reasons),
        None,
        LIMITS,
        str(tmp_path / "forward"),
        "partial-order-a",
    )
    plan["tasks"] = [second, first]
    reverse = run_review(
        snapshot,
        plan,
        prof,
        CoverageNotesProvider(reasons=reasons),
        None,
        LIMITS,
        str(tmp_path / "reverse"),
        "partial-order-b",
    )
    assert forward["coverage_ledger"][0]["reason_code"] == "PARTIAL_REVIEW_COVERAGE"
    assert reverse["coverage_ledger"][0]["reason_code"] == "PARTIAL_REVIEW_COVERAGE"
    assert render_report(forward).count("Specialist reported partial coverage:") == 1
    assert render_report(reverse).count("Specialist reported partial coverage:") == 1

    blocked = run(tmp_path / "blocker", provider=PartialFindingProvider())
    assert blocked["disposition"] == "REQUEST_CHANGES"
    assert blocked["coverage_state"] == "PARTIAL"
    assert any(item["blocking_class"] == "BLOCKING" and item["status"] == "ACCEPTED" for item in blocked["findings"])
    blocked_report = render_report(blocked)
    assert "Coverage: PARTIAL" in blocked_report
    assert "## Blockers" in blocked_report
    assert "## Coverage" not in blocked_report
    assert blocked_report.count("## ") == 4
    assert blocked["report_sections"]["blockers"][0]["title"] in blocked_report


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
        binding = next(row for row in output["unit_evidence_bindings"] if row["unit_id"] == unit_id)
        assert binding["evidence_ids"] == [f"diff:{unit_id}"]
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
    assert result["coverage_ledger"][0]["reason_code"] == "COVERAGE_NOTE_EVIDENCE_INVALID"


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
    assert context_coverage["reason_code"] == "VALID_RESULT"
    assert result["disposition"] == "APPROVE"
    assert result["budget"]["provider_calls_reserved"] == 2
    followup_id = next(task["task_id"] for task in result["ledger"]["dynamic_tasks"])
    metadata = result["ledger"]["planned_task_inputs"][followup_id]["context_followup"]
    assert metadata == result["task_results"][followup_id]["context_followup"]
    assert metadata["contract_version"] == "context-followup.v1"
    assert metadata["target"] == {"kind": "path", "value": "docs/caller.md"}
    assert metadata["rationale"] == "Caller contract is required to finish the review."
    assert metadata["related_evidence_ids"] == ["diff:u0"]
    assert metadata["related_candidate_ids"] == []  # Supported legacy V1 gap normalization.
    assert "context_followup" not in result["ledger"]["planned_task_inputs"][metadata["parent_task_id"]]
    assert context_coverage["closure_diagnostics"]["state"] == "OBSERVED"
    assert context_coverage["closure_diagnostics"]["coverage_note_result"] == "COVERED"
    assert context_coverage["closure_diagnostics"]["coverage_note_failure_counts"]["MATCH"] >= 1


@pytest.mark.parametrize(
    ("followup_state", "mutation", "expected_note_code", "expected_coverage"),
    [
        ("COVERED", None, "MATCH", "COMPLETE"),
        ("PARTIAL", None, "STATE_NOT_COVERED", "PARTIAL"),
        ("NOT_COVERED", None, "STATE_NOT_COVERED", "PARTIAL"),
        ("COVERED", "wrong_basis", "BASIS_NOT_STATIC_REVIEW", "PARTIAL"),
        ("COVERED", "wrong_scope", "UNIT_OUT_OF_SCOPE", "PARTIAL"),
        ("COVERED", "undispatched_reference", "REFERENCE_NOT_IN_TASK_INPUT", "PARTIAL"),
    ],
)
def test_required_context_closure_fixtures_preserve_engine_decision(
    tmp_path, followup_state, mutation, expected_note_code, expected_coverage
):
    provider = RequiredContextClosureFixtureProvider(followup_state, mutation)
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    result = run(
        tmp_path,
        prof=prof,
        provider=provider,
        context_retriever=ResolvedContextRetriever(),
    )

    followup_id = next(task["task_id"] for task in result["ledger"]["dynamic_tasks"])
    followup_result = result["task_results"][followup_id]
    assert followup_result["status"] == "SUCCEEDED"
    assert followup_result["input_evidence_ids"]
    assert result["context_gaps"][0]["status"] == (
        "RESOLVED_BY_FOLLOWUP" if expected_coverage == "COMPLETE" else "VALID_UNRESOLVED"
    )
    context_coverage = next(
        row for row in result["coverage_ledger"] if row["obligation_kind"] == "REQUIRED_CONTEXT"
    )
    assert context_coverage["state"] == expected_coverage
    assert context_coverage["reason_code"] == (
        "VALID_RESULT" if expected_coverage == "COMPLETE" else "REQUIRED_CONTEXT_NOT_COVERED"
    )
    diagnostics = context_coverage["closure_diagnostics"]
    assert diagnostics["state"] == "OBSERVED"
    assert diagnostics["coverage_note_result"] == (
        "COVERED" if expected_coverage == "COMPLETE" else "NO_COVERING_NOTE"
    )
    assert diagnostics["coverage_note_failure_counts"][expected_note_code] == 1
    assert result["coverage_state"] == expected_coverage
    assert result["disposition"] == ("APPROVE" if expected_coverage == "COMPLETE" else "INCOMPLETE")


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda note: None, "MATCH"),
        (lambda note: note.update(state="PARTIAL"), "STATE_NOT_COVERED"),
        (lambda note: note.update(coverage_basis="DYNAMIC_EXECUTION"), "BASIS_NOT_STATIC_REVIEW"),
        (lambda note: note.update(unit_id="unit-outside"), "UNIT_OUT_OF_SCOPE"),
        (lambda note: note.update(evidence_refs=["ev-other"]), "NO_RETRIEVED_EVIDENCE_REFERENCE"),
        (lambda note: note.update(evidence_refs=["ev-required", "ev-not-dispatched"]), "REFERENCE_NOT_IN_TASK_INPUT"),
    ],
)
def test_required_context_note_diagnostics_share_the_acceptance_predicate(mutation, expected_code):
    note = {
        "unit_id": "unit-1",
        "state": "COVERED",
        "coverage_basis": "STATIC_REVIEW",
        "evidence_refs": ["ev-required"],
    }
    mutation(note)
    covered, observation = engine_module._coverage_note_observation(
        [note],
        notes_present=True,
        scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"],
        task_input_evidence_ids=["ev-required"],
    )
    assert covered is (expected_code == "MATCH")
    assert observation["state"] == "OBSERVED"
    assert observation["failure_counts"][expected_code] == 1


def test_required_context_note_diagnostics_keep_empty_missing_and_malformed_distinct():
    empty, empty_observation = engine_module._coverage_note_observation(
        [], notes_present=True, scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"], task_input_evidence_ids=["ev-required"],
    )
    absent, absent_observation = engine_module._coverage_note_observation(
        [], notes_present=False, scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"], task_input_evidence_ids=["ev-required"],
    )
    malformed, malformed_observation = engine_module._coverage_note_observation(
        ["private-note-canary"], notes_present=True, scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"], task_input_evidence_ids=["ev-required"],
    )
    assert not empty and empty_observation["result"] == "NO_NOTES"
    assert not absent and absent_observation["result"] == "UNKNOWN"
    assert not malformed and malformed_observation["failure_counts"]["NOTE_NOT_OBJECT"] == 1
    assert "private-note-canary" not in json.dumps(malformed_observation)

    multiple = {
        "unit_id": "unit-outside",
        "state": "PARTIAL",
        "coverage_basis": "DYNAMIC_EXECUTION",
        "evidence_refs": ["ev-other"],
    }
    covered, multiple_observation = engine_module._coverage_note_observation(
        [multiple, {
            "unit_id": "unit-1", "state": "COVERED", "coverage_basis": "STATIC_REVIEW",
            "evidence_refs": ["ev-required"],
        }],
        notes_present=True, scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"], task_input_evidence_ids=["ev-required"],
    )
    assert covered and multiple_observation["result"] == "COVERED"
    assert multiple_observation["failure_counts"]["STATE_NOT_COVERED"] == 1
    assert multiple_observation["failure_counts"]["MATCH"] == 1

    valid_first = {
        "unit_id": "unit-1", "state": "COVERED", "coverage_basis": "STATIC_REVIEW",
        "evidence_refs": ["ev-required"],
    }
    malformed_later = {**valid_first, "evidence_refs": [{"unhashable": "private"}]}
    matched, short_circuited = engine_module._coverage_note_observation(
        [valid_first, malformed_later], notes_present=True, scope_unit_ids=["unit-1"],
        required_evidence_ids=["ev-required"], task_input_evidence_ids=["ev-required"],
    )
    assert matched and short_circuited["notes_unexamined_after_match_count"] == 1


def test_required_context_note_first_failure_order_matches_each_existing_call_site():
    note = {
        "unit_id": "unit-outside", "state": "PARTIAL", "coverage_basis": "DYNAMIC_EXECUTION",
        "evidence_refs": ["ev-other"],
    }
    common = {
        "notes_present": True,
        "scope_unit_ids": ["unit-1"],
        "required_evidence_ids": ["ev-required"],
        "task_input_evidence_ids": ["ev-required"],
    }
    final_match, final_observation = engine_module._coverage_note_observation(
        [note], predicate_order="final_coverage", **common
    )
    followup_match, followup_observation = engine_module._coverage_note_observation(
        [note], predicate_order="followup_resolution", **common
    )
    assert not final_match and not followup_match
    assert final_observation["failure_counts"]["STATE_NOT_COVERED"] == 1
    assert followup_observation["failure_counts"]["UNIT_OUT_OF_SCOPE"] == 1


def test_required_context_shared_helper_matches_both_legacy_any_predicates():
    scope = {"unit-1"}
    required = {"ev-required"}
    dispatched = {"ev-required", "ev-extra"}
    note_rows = [
        [],
        ["not-an-object"],
        [{"unit_id": "unit-1", "state": "PARTIAL", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-required"]}],
        [{"unit_id": "unit-outside", "state": "PARTIAL", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-required"]}],
        [{"unit_id": "unit-1", "state": "COVERED", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-extra"]}],
        [{"unit_id": "unit-1", "state": "COVERED", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-required", "ev-missing"]}],
        [
            {"unit_id": "unit-outside", "state": "PARTIAL", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-required"]},
            {"unit_id": "unit-1", "state": "COVERED", "coverage_basis": "STATIC_REVIEW", "evidence_refs": ["ev-required"]},
        ],
    ]
    for notes in note_rows:
        legacy_followup = any(
            isinstance(note, dict)
            and note.get("unit_id") in scope
            and note.get("state") == "COVERED"
            and note.get("coverage_basis") == "STATIC_REVIEW"
            and set(note.get("evidence_refs", [])) & required
            and set(note.get("evidence_refs", [])).issubset(dispatched)
            for note in notes
        )
        legacy_final = any(
            isinstance(note, dict)
            and note.get("state") == "COVERED"
            and note.get("coverage_basis") == "STATIC_REVIEW"
            and note.get("unit_id") in scope
            and set(note.get("evidence_refs", [])) & required
            and set(note.get("evidence_refs", [])).issubset(dispatched)
            for note in notes
        )
        actual_followup, _ = engine_module._coverage_note_observation(
            notes, notes_present=True, scope_unit_ids=scope,
            required_evidence_ids=required, task_input_evidence_ids=dispatched,
            predicate_order="followup_resolution",
        )
        actual_final, _ = engine_module._coverage_note_observation(
            notes, notes_present=True, scope_unit_ids=scope,
            required_evidence_ids=required, task_input_evidence_ids=dispatched,
            predicate_order="final_coverage",
        )
        assert actual_followup is legacy_followup
        assert actual_final is legacy_final


def test_required_output_quarantine_diagnostic_preserves_current_required_kind_rule():
    rows = [{
        "quarantined_items": [
            {"kind": "future_guidance", "index": 0},
            {"kind": "coverage_notes", "index": 1, "item_hash": "secret-hash"},
        ]
    }]
    required, observation = engine_module._required_output_quarantine_observation(rows)
    legacy_required = any(
        item.get("kind") not in {"specific_strengths", "future_guidance"}
        for result_row in rows for item in result_row.get("quarantined_items", [])
    )
    assert required is legacy_required
    assert required is True
    assert observation["count"] == 1
    assert observation["by_kind"]["coverage_notes"] == 1
    assert "secret-hash" not in json.dumps(observation)
    _, unknown_kind = engine_module._required_output_quarantine_observation([{
        "quarantined_items": [{"kind": "future_guidance"}, {"kind": "new_unrecognized_kind"}],
    }])
    assert unknown_kind["count"] == 1
    assert unknown_kind["by_kind"]["other_required_kind"] == 1
    _, missing = engine_module._required_output_quarantine_observation([{}])
    assert missing["state"] == "UNKNOWN"
    assert missing["count"] == "UNKNOWN"
    with pytest.raises(AttributeError):
        engine_module._required_output_quarantine_observation([{"quarantined_items": ["malformed"]}])
    early = {"quarantined_items": [
        {"kind": "coverage_notes"},
        "malformed-but-short-circuited-by-the-existing-any-predicate",
    ]}
    early_required, early_observation = engine_module._required_output_quarantine_observation([early])
    assert early_required is True
    assert early_observation["state"] == "UNKNOWN"
    assert early_observation["count"] == "UNKNOWN"
    multiple_required, multiple_observation = engine_module._required_output_quarantine_observation([{
        "quarantined_items": [{"kind": "coverage_notes"}, {"kind": "context_gap_proposals"}],
    }])
    assert multiple_required is True
    assert multiple_observation["count"] == "UNKNOWN"


def test_nested_followup_gap_is_counted_without_changing_no_recursion_closure(tmp_path):
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    provider = NestedGapContextFollowupProvider()
    result = run(
        tmp_path,
        prof=prof,
        provider=provider,
        context_retriever=ResolvedContextRetriever(),
    )
    followup_coverage = [
        row for row in result["coverage_ledger"]
        if row.get("obligation_kind") == "REQUIRED_CONTEXT" and row.get("context_gap_id")
    ]
    assert followup_coverage
    assert all(row["state"] == "PARTIAL" for row in followup_coverage)
    assert all(row["reason_code"] == "CONTEXT_GAP_UNRESOLVED" for row in followup_coverage)
    assert result["disposition"] == "INCOMPLETE"
    assert any(row["closure_diagnostics"]["unresolved_followup_gap_count"] >= 1 for row in followup_coverage)
    assert result["budget"]["followup_tasks_reserved"] <= LIMITS["max_followup_tasks"]
    assert result["budget"]["provider_calls_reserved"] == 2


def test_adapter_normalized_v4_gap_can_authorize_bound_context_followup(tmp_path):
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    result = run(
        tmp_path,
        prof=prof,
        provider=AdapterNormalizedContextFollowupProvider(),
        context_retriever=ResolvedContextRetriever(),
    )
    assert result["context_gaps"][0]["retrieval_status"] == "RESOLVED"
    assert result["context_gaps"][0]["status"] == "RESOLVED_BY_FOLLOWUP"
    parent = result["task_results"][result["ledger"]["context_gaps"][0]["task_id"]]
    assert parent["source_contract_version"] == "specialist-findings.v4"
    followup_id = result["ledger"]["dynamic_tasks"][0]["task_id"]
    metadata = result["task_results"][followup_id]["context_followup"]
    assert metadata["related_candidate_ids"] == []
    assert metadata["target"] == {"kind": "path", "value": "docs/caller.md"}
    assert result["budget"]["followup_tasks_reserved"] == 1


def test_malformed_unused_target_value_is_not_repaired_before_reservation(tmp_path):
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    result = run(
        tmp_path,
        prof=prof,
        provider=MalformedUnusedTargetProvider(),
        context_retriever=ResolvedContextRetriever(),
    )
    assert result["context_gaps"][0]["retrieval_status"] == "RESOLVED"
    assert result["context_gaps"][0]["followup_error"] == "invalid_context_followup_target"
    assert result["budget"]["followup_tasks_reserved"] == 0
    assert result["ledger"].get("dynamic_tasks", []) == []


def test_followup_metadata_is_authenticated_before_followup_reservation(tmp_path, monkeypatch):
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}

    def reject_metadata(**_kwargs):
        raise ValueError("invalid_context_followup_test_binding")

    monkeypatch.setattr(engine_module, "_context_followup_metadata", reject_metadata)
    result = run(
        tmp_path,
        prof=prof,
        provider=ContextFollowupProvider(),
        context_retriever=ResolvedContextRetriever(),
    )
    assert result["context_gaps"][0]["retrieval_status"] == "RESOLVED"
    assert result["context_gaps"][0]["followup_error"] == "invalid_context_followup_test_binding"
    assert result["budget"]["context_retrievals_reserved"] == 1
    assert result["budget"]["followup_tasks_reserved"] == 0
    assert result["ledger"].get("dynamic_tasks", []) == []
    assert not any(":followup:" in key for key in result["ledger"]["budget"]["reservations"])


def test_tampered_followup_metadata_fails_resume_against_controller_owned_gap(tmp_path):
    snap = make_snapshot()
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    plan = plan_review(snap, prof)
    provider = ContextFollowupProvider()
    retriever = ResolvedContextRetriever()
    run_id = "tampered-followup"
    result = run_review(snap, plan, prof, provider, None, LIMITS, str(tmp_path), run_id, context_retriever=retriever)
    saved_path = tmp_path / f"{run_id}.json"
    saved = json.loads(saved_path.read_text())
    task_id = saved["ledger"]["dynamic_tasks"][0]["task_id"]
    task = saved["ledger"]["dynamic_tasks"][0]
    task["context_followup"]["rationale"] = "Forged request to expand scope."
    provenance = engine_module._task_input_provenance(task)
    saved["ledger"]["planned_task_inputs"][task_id] = provenance
    saved["ledger"]["outputs"][task_id]["context_followup"] = task["context_followup"]
    saved["task_results"] = saved["ledger"]["outputs"]
    saved["result_hash"] = engine_module._hash({key: value for key, value in saved.items() if key != "result_hash"})
    forged = engine_module._canonical(saved) + b"\n"
    saved_path.write_bytes(forged)

    with pytest.raises(ValueError, match="invalid_context_followup_metadata_binding"):
        run_review(
            snap,
            plan,
            prof,
            ContextFollowupProvider(),
            None,
            LIMITS,
            str(tmp_path),
            run_id,
            context_retriever=retriever,
            resume=True,
        )
    assert saved_path.read_bytes() == forged
    assert result["budget"]["followup_tasks_reserved"] == 1


def test_legacy_cached_dynamic_followup_without_binding_is_rejected_before_replay(tmp_path):
    snap = make_snapshot()
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    plan = plan_review(snap, prof)
    run_id = "legacy-followup-cache"
    path = tmp_path / f"{run_id}.json"
    run_review(snap, plan, prof, ContextFollowupProvider(), None, LIMITS, str(tmp_path), run_id,
               context_retriever=ResolvedContextRetriever())
    saved = json.loads(path.read_text())
    task = saved["ledger"]["dynamic_tasks"][0]
    task_id = task["task_id"]
    del task["context_followup"]
    del saved["ledger"]["planned_task_inputs"][task_id]["context_followup"]
    del saved["ledger"]["outputs"][task_id]["context_followup"]
    saved["task_results"] = saved["ledger"]["outputs"]
    saved["result_hash"] = engine_module._hash({key: value for key, value in saved.items() if key != "result_hash"})
    legacy_bytes = engine_module._canonical(saved) + b"\n"
    path.write_bytes(legacy_bytes)
    marker = tmp_path / "provider-called"

    with pytest.raises(ValueError, match="invalid_context_followup_contract"):
        run_review(
            snap,
            plan,
            prof,
            ContextFollowupProvider(marker=marker),
            None,
            LIMITS,
            str(tmp_path),
            run_id,
            context_retriever=ResolvedContextRetriever(),
            resume=True,
        )
    assert path.read_bytes() == legacy_bytes
    assert not marker.exists()


def test_cached_followup_rejects_unknown_parent_contract_version(tmp_path):
    snap = make_snapshot()
    prof = {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    plan = plan_review(snap, prof)
    run_id = "unknown-parent-contract"
    path = tmp_path / f"{run_id}.json"
    run_review(snap, plan, prof, ContextFollowupProvider(), None, LIMITS, str(tmp_path), run_id,
               context_retriever=ResolvedContextRetriever())
    saved = json.loads(path.read_text())
    parent_id = saved["ledger"]["dynamic_tasks"][0]["context_followup"]["parent_task_id"]
    saved["ledger"]["outputs"][parent_id]["source_contract_version"] = {"unrecognized": "version"}
    saved["task_results"] = saved["ledger"]["outputs"]
    saved["result_hash"] = engine_module._hash({key: value for key, value in saved.items() if key != "result_hash"})
    forged = engine_module._canonical(saved) + b"\n"
    path.write_bytes(forged)

    with pytest.raises(ValueError, match="invalid_context_followup_parent_contract"):
        run_review(
            snap,
            plan,
            prof,
            ContextFollowupProvider(),
            None,
            LIMITS,
            str(tmp_path),
            run_id,
            context_retriever=ResolvedContextRetriever(),
            resume=True,
        )
    assert path.read_bytes() == forged


def test_followup_deduplicates_repeated_identical_context_and_binds_v2(tmp_path):
    snap, prof = make_snapshot(), {**profile(), "retrieval_context_patterns": ["docs/caller.md"]}
    path, content = "docs/caller.md", "The caller expects a validated result.\n"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    evidence_id = "ev-" + hashlib.sha256(
        json.dumps(
            {"snapshot_id": snap["snapshot_id"], "revision": snap["base_sha"], "path": path, "hash": content_hash},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:24]
    retrieved = {
        "evidence_id": evidence_id,
        "snapshot_id": snap["snapshot_id"],
        "path": path,
        "content": content,
        "source_kind": "repository_file",
        "source_revision": snap["base_sha"],
        "content_hash": content_hash,
        "trust": "repository_evidence",
    }
    snap["evidence"][evidence_id] = retrieved
    plan = plan_review(snap, prof)
    plan["tasks"][0]["evidence_ids"].append(evidence_id)
    plan["tasks"][0]["base_context_ids"] = [evidence_id]
    original_snapshot, original_plan = copy.deepcopy(snap), copy.deepcopy(plan)
    output_dir = str(tmp_path)
    result = run_review(
        snap,
        plan,
        prof,
        ContextFollowupProvider(),
        None,
        LIMITS,
        output_dir,
        "repeat-context",
        context_retriever=ExistingEvidenceContextRetriever(retrieved),
    )
    assert snap == original_snapshot
    assert plan == original_plan
    followup = next(row for row in result["task_results"].values() if row.get("task_id", "").endswith(":followup:0"))
    assert followup["status"] == "SUCCEEDED"
    assert followup["request_input_contract"] == "specialist-input.v2"
    assert len(followup["input_evidence_ids"]) == len(set(followup["input_evidence_ids"]))
    assert evidence_id in followup["input_evidence_ids"]
    reservations = result["budget"]["provider_calls_reserved"]
    provider_marker = tmp_path / "resume-provider-called"
    resume_provider = ContextFollowupProvider(marker=str(provider_marker))
    resumed = run_review(
        snap,
        plan,
        prof,
        resume_provider,
        None,
        LIMITS,
        output_dir,
        "repeat-context",
        resume=True,
        context_retriever=ExistingEvidenceContextRetriever(retrieved),
    )
    assert resumed["budget"]["provider_calls_reserved"] == reservations
    assert not provider_marker.exists()


def test_repeated_evidence_id_requires_same_source_binding_but_ignores_proposal_annotations():
    evidence = {
        "evidence_id": "ev-1",
        "snapshot_id": "snap",
        "path": "src/a.py",
        "source_revision": "a" * 40,
        "source_kind": "source_window",
        "source_side": "HEAD",
        "source_object_id": "b" * 40,
        "line_start": 4,
        "line_end": 8,
        "content_hash": "c" * 64,
        "trust": "repository_evidence",
        "content": "selected lines\n",
    }
    annotated = {**evidence, "proposal_id": "proposal-2", "task_id": "task-2", "required_lens": "tests"}
    assert engine_module._merge_evidence_rows([evidence, annotated]) == [evidence]
    with pytest.raises(ValueError, match="evidence_identity_conflict"):
        engine_module._merge_evidence_rows([evidence, {**annotated, "source_side": "BASE"}])
    with pytest.raises(ValueError, match="evidence_identity_conflict"):
        engine_module._merge_evidence_rows([evidence, {**annotated, "line_start": 3}])


def test_real_context_retriever_fits_ipc_cap_and_partial_context_never_dispatches_followup(tmp_path):
    repo = tmp_path / "evidence-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Fixture"], check=True)
    (repo / "src").mkdir()
    (repo / "src" / "m0.py").write_text("trusted context line\n" * 5000, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "src/m0.py"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", "commit", "-m", "fixture"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()
    snapshot = make_snapshot()
    snapshot["base_sha"] = snapshot["head_sha"] = revision
    provider = GapProvider()
    result = run(
        tmp_path / "run",
        snap=snapshot,
        prof={**profile(), "retrieval_context_patterns": ["src/*.py"]},
        provider=provider,
        context_retriever=ContextRetriever(str(repo)),
    )

    gap = result["context_gaps"][0]
    assert gap["retrieval_status"] == "PARTIAL", gap.get("retrieval_reason")
    retrieved = result["ledger"]["retrieved_context"][gap["proposal_id"]]
    item = retrieved["evidence"][0]
    content_bytes = item["content"].encode("utf-8")
    assert gap["retrieval_status"] == "PARTIAL"
    assert gap["retrieval_reason"] == "ipc_envelope_truncated"
    assert gap["retrieved_bytes"] == len(content_bytes)
    assert gap["retrieval_envelope_bytes"] <= LIMITS["max_output_bytes_per_task"]
    assert gap["retrieved_bytes"] <= LIMITS["max_output_bytes_per_task"]
    assert hashlib.sha256(content_bytes).hexdigest() == item["content_hash"]
    settlement = result["ledger"]["budget"]["settlements"][f"{gap['proposal_id']}:context-retrieval"]
    assert settlement["actual_output_bytes"] == len(content_bytes)
    assert settlement["actual_output_bytes"] < gap["retrieval_envelope_bytes"]
    assert result["budget"]["context_retrievals_reserved"] == 1
    assert result["budget"]["followup_tasks_reserved"] == 0
    assert len(result["task_results"]) == 1
    assert result["disposition"] == "INCOMPLETE"


def test_oversized_untrusted_retriever_is_rejected_by_ipc_without_metadata_leak(tmp_path):
    result = run(
        tmp_path,
        prof={**profile(), "retrieval_context_patterns": ["docs/*.md"]},
        provider=GapProvider(),
        context_retriever=OversizedContextRetriever(),
    )
    gap = result["context_gaps"][0]
    assert gap["retrieval_status"] == "UNRESOLVED"
    assert gap["retrieval_reason"] == "OUTPUT_BYTE_LIMIT_EXCEEDED"
    assert gap.get("retrieval_envelope_bytes") is None
    assert "secret-marker" not in json.dumps(result)
    assert result["budget"]["context_retrievals_reserved"] == 1
    assert result["budget"]["followup_tasks_reserved"] == 0


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


def test_invalid_run_id_and_resume_state_are_typed_preflight_without_calls_or_mutation(tmp_path):
    provider = EmptyProvider()
    first = run(tmp_path, provider=provider)
    path = tmp_path / "r1.json"
    original = path.read_bytes()
    marker = tmp_path / "preflight-provider-called"
    attempt_provider = ContextFollowupProvider(marker=marker)

    with pytest.raises(EnginePreflightError) as collision:
        run_review(make_snapshot(), plan_review(make_snapshot(), profile()), profile(), attempt_provider, None,
                   LIMITS, str(tmp_path), "r1")
    assert collision.value.reason == "run_id_already_exists"
    assert path.read_bytes() == original
    assert not marker.exists()

    other_snapshot = make_snapshot(2)
    with pytest.raises(EnginePreflightError) as mismatch:
        run_review(other_snapshot, plan_review(other_snapshot, profile()), profile(), attempt_provider, None,
                   LIMITS, str(tmp_path), "r1", resume=True)
    assert mismatch.value.reason == "resume_state_invalid"
    assert path.read_bytes() == original
    assert not marker.exists()

    tampered = json.loads(original)
    tampered["disposition"] = "REQUEST_CHANGES"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    tampered_bytes = path.read_bytes()
    snap = make_snapshot()
    with pytest.raises(EnginePreflightError) as integrity:
        run_review(snap, plan_review(snap, profile()), profile(), attempt_provider, None,
                   LIMITS, str(tmp_path), "r1", resume=True)
    assert integrity.value.reason == "resume_state_invalid"
    assert path.read_bytes() == tampered_bytes
    assert not marker.exists()
    assert first["budget"]["provider_calls_reserved"] == json.loads(original)["budget"]["provider_calls_reserved"]


def test_invalid_engine_limits_are_typed_preflight_without_output(tmp_path):
    provider = EmptyProvider()
    snap = make_snapshot()
    plan = plan_review(snap, profile())
    limits = {**LIMITS, "max_provider_calls": True}
    with pytest.raises(EnginePreflightError) as rejected:
        run_review(snap, plan, profile(), provider, None, limits, str(tmp_path), "invalid-limits")
    assert rejected.value.reason == "invalid_review_request"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("run_id", [True, 1, [], {}])
def test_non_string_run_ids_are_typed_preflight_without_output(tmp_path, run_id):
    snap = make_snapshot()
    plan = plan_review(snap, profile())
    with pytest.raises(EnginePreflightError) as rejected:
        run_review(snap, plan, profile(), EmptyProvider(), None, LIMITS, str(tmp_path), run_id)
    assert rejected.value.reason == "invalid_review_request"
    assert not list(tmp_path.iterdir())


def test_completed_resume_persistence_failure_remains_runtime(tmp_path, monkeypatch):
    provider = EmptyProvider()
    run(tmp_path, provider=provider)
    path = tmp_path / "r1.json"
    original = path.read_bytes()
    snap = make_snapshot()
    plan = plan_review(snap, profile())

    def fail_write(*_args, **_kwargs):
        raise OSError("private persistence detail")

    monkeypatch.setattr(engine_module, "_atomic_write", fail_write)
    with pytest.raises(OSError, match="private persistence detail"):
        run_review(
            snap, plan, profile(), provider, None, LIMITS, str(tmp_path), "r1",
            resume=True,
            freshness_check=StaticFreshness({"freshness": "STALE", "observed_head_sha": "e" * 40}),
        )
    assert path.read_bytes() == original


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


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "100"])
def test_invalid_optional_snapshot_budget_rejected_before_provider_dispatch(tmp_path, value):
    provider = EmptyProvider()
    with pytest.raises(ValueError, match="max_snapshot_context_bytes"):
        run(
            tmp_path,
            provider=provider,
            limits={**LIMITS, "max_context_bytes": 8_000_000, "max_snapshot_context_bytes": value},
        )
    assert provider.calls == 0
    assert not (tmp_path / "r1.json").exists()


def test_unsupported_monetary_cap_rejected_before_provider_dispatch(tmp_path):
    provider = EmptyProvider()
    with pytest.raises(ValueError, match="monetary budget reservation is unsupported"):
        run(tmp_path, provider=provider, limits={**LIMITS, "max_cost_microunits": 1000})
    assert not (tmp_path / "r1.json").exists()
