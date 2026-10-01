from __future__ import annotations

import copy
import hashlib
import json

import pytest

from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider, ProviderError, _validate_specialist

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


def _provider(max_request_bytes=100_000):
    return OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.example.invalid/v1",
            "model": "offline-schema-test",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
            "max_request_bytes": max_request_bytes,
        }
    )


def _task_and_evidence():
    task = {
        "task_id": "task-one",
        "unit_ids": ["u1"],
        "evidence_ids": ["ev-local", "ev-shared"],
        "request_input_contract": "specialist-input.v2",
        "unit_evidence_bindings": [
            {"unit_id": "u1", "binding_status": "VERIFIED", "evidence_ids": ["ev-local"]}
        ],
    }
    evidence = [
        {"evidence_id": "ev-local", "path": "src/a.py", "content": "local evidence"},
        {"evidence_id": "ev-shared", "path": "AGENTS.md", "content": "shared task evidence"},
    ]
    return task, evidence


def _payload(*, coverage_refs, strengths=None):
    return {
        "contract_version": "specialist-findings.v4",
        "finding_candidates": [],
        "context_gap_proposals": [],
        "coverage_notes": [
            {
                "unit_id": "u1",
                "state": "COVERED",
                "reason_code": "REVIEWED",
                "evidence_refs": coverage_refs,
                "coverage_basis": "STATIC_REVIEW",
            }
        ],
        "specific_strengths": strengths or [],
        "future_guidance": [],
    }


def test_schema_enumerates_exact_current_request_ids_and_keeps_optional_arrays_empty():
    provider = _provider()
    task, evidence = _task_and_evidence()
    _system, _user, response_schema = provider._review_parts(task, evidence)
    schema = response_schema["schema"]
    properties = schema["properties"]

    expected = ["ev-local", "ev-shared"]
    assert properties["finding_candidates"]["items"]["properties"]["evidence_refs"]["items"]["enum"] == expected
    assert properties["context_gap_proposals"]["items"]["properties"]["related_evidence_ids"]["items"]["enum"] == expected
    assert properties["coverage_notes"]["items"]["properties"]["evidence_refs"]["items"]["enum"] == expected
    for name in ("specific_strengths", "future_guidance"):
        assert properties[name]["items"]["properties"]["evidence_refs"]["items"]["enum"] == expected
        assert properties[name].get("minItems", 0) == 0

    # All task IDs can be cited, but only the explicitly bound local ID can
    # establish COVERED for this unit; that remains an engine-side decision.
    assert task["unit_evidence_bindings"][0]["evidence_ids"] == ["ev-local"]
    assert _validate_specialist(
        _payload(coverage_refs=["ev-local", "ev-shared"]),
        valid_evidence_ids=set(task["evidence_ids"]),
        valid_unit_ids={"u1"},
    )["coverage_notes"][0]["evidence_refs"] == ["ev-local", "ev-shared"]


def test_mutated_and_cross_task_ids_still_fail_closed_in_adapter():
    payload = _payload(coverage_refs=["ev-local"])
    payload["specific_strengths"] = [
        {
            "unit_id": "u1",
            "title": "Positive behavior",
            "observation": "Concrete behavior in evidence.",
            "why_it_matters": "It avoids a failure.",
            "evidence_refs": ["ev-other-task"],
        }
    ]
    accepted = _validate_specialist(
        payload,
        valid_evidence_ids={"ev-local", "ev-shared"},
        valid_unit_ids={"u1"},
    )
    assert accepted["specific_strengths"] == []
    assert accepted["quarantined_items"][-1]["reason_code"] == "report_note_references_unknown_evidence"
    assert "ev-other-task" not in json.dumps(accepted["quarantined_items"])

    mutated = copy.deepcopy(payload)
    mutated["coverage_notes"][0]["evidence_refs"] = ["ev-locaL"]
    rejected = _validate_specialist(
        mutated,
        valid_evidence_ids={"ev-local", "ev-shared"},
        valid_unit_ids={"u1"},
    )
    assert rejected["coverage_notes"] == []
    assert rejected["quarantined_items"][0]["reason_code"] == "coverage_references_unknown_evidence"


def test_empty_task_evidence_has_no_nonempty_citation_value():
    task = {
        "task_id": "no-evidence",
        "unit_ids": ["u1"],
        "evidence_ids": [],
        "request_input_contract": "specialist-input.v2",
        "unit_evidence_bindings": [
            {"unit_id": "u1", "binding_status": "UNKNOWN", "evidence_ids": []}
        ],
    }
    _system, _user, response_schema = _provider()._review_parts(task, [])
    item_schema = response_schema["schema"]["properties"]["coverage_notes"]["items"]["properties"]["evidence_refs"]["items"]
    assert item_schema == {"type": "string", "minLength": 1, "maxLength": 0}
    assert response_schema["schema"]["properties"]["coverage_notes"]["items"]["properties"]["evidence_refs"]["type"] == "array"
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(item_schema)
    assert not validator.is_valid("")
    assert not validator.is_valid("made-up-id")


def test_enumeration_bytes_are_measured_and_both_request_caps_still_apply():
    task, evidence = _task_and_evidence()
    baseline = _provider()
    measured = baseline.review_input_bytes(task, evidence, LIMITS)
    assert measured == len(baseline.serialize_review_request(task, evidence, LIMITS))

    exact_transport_cap = _provider(max_request_bytes=measured)
    assert len(exact_transport_cap.serialize_review_request(task, evidence, LIMITS)) == measured
    too_small_transport_cap = _provider(max_request_bytes=measured - 1)
    system, user, schema = too_small_transport_cap._review_parts(task, evidence)
    with pytest.raises(ProviderError, match="request_exceeds_limit"):
        too_small_transport_cap._request_bytes(system, user, schema, LIMITS)

    task_cap_too_small = {**LIMITS, "max_input_bytes_per_task": measured - 1}
    with pytest.raises(ProviderError, match="request_exceeds_limit"):
        exact_transport_cap.review(task, evidence, task_cap_too_small)


class _UnitBoundaryProvider:
    identity = {"provider_id": "offline-evidence-boundary", "model_id": "fixture"}

    def __init__(self, *, cite_local: bool, invalid_optional_note: bool = False):
        self.cite_local = cite_local
        self.invalid_optional_note = invalid_optional_note

    def review(self, task, evidence, limits):
        coverage_notes = []
        strengths = []
        for unit_id in task["unit_ids"]:
            refs = [f"diff:{unit_id}"] if self.cite_local else ["policy:shared"]
            coverage_notes.append(
                {
                    "unit_id": unit_id,
                    "state": "COVERED",
                    "reason_code": "REVIEWED",
                    "evidence_refs": refs,
                    "coverage_basis": "STATIC_REVIEW",
                }
            )
        if self.invalid_optional_note:
            unit_id = task["unit_ids"][0]
            strengths = [
                {
                    "unit_id": unit_id,
                    "title": "Unverified optional note",
                    "observation": "This note cites another task's evidence.",
                    "why_it_matters": "It must not alter coverage disposition.",
                    "evidence_refs": ["ev-from-another-task"],
                }
            ]
        return {
            "payload": {
                "contract_version": "specialist-findings.v4",
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": coverage_notes,
                "specific_strengths": strengths,
                "future_guidance": [],
            }
        }


def _selected_snapshot_and_profile():
    inventory = []
    evidence = {}
    for unit_id in ("u0", "u1"):
        index = int(unit_id[1:])
        evidence_id = f"diff:{unit_id}"
        path = f"src/m{index}.py"
        inventory.append(
            {
                "unit_id": unit_id,
                "path": path,
                "kind": "human_code",
                "change": "modified",
                "diff": "-old\n+new",
                "changed_lines": [[1, 2]],
                "evidence_ids": [evidence_id],
                "review_context_evidence_ids": [evidence_id],
            }
        )
        evidence[evidence_id] = {
            "evidence_id": evidence_id,
            "snapshot_id": "snap",
            "path": path,
            "line_start": 1,
            "line_end": 2,
            "content": "-old\n+new",
            "content_hash": "a" * 64,
            "source_kind": "diff",
            "trust": "untrusted_pr_content",
        }
    policy_text = "Review every changed unit using its bound evidence.\n"
    evidence["policy:shared"] = {
        "evidence_id": "policy:shared",
        "snapshot_id": "snap",
        "path": "AGENTS.md",
        "line_start": 1,
        "line_end": 1,
        "content": policy_text,
        "content_hash": hashlib.sha256(policy_text.encode()).hexdigest(),
        "source_kind": "profile_context",
        "trust": "trusted_policy",
    }
    snapshot = {
        "snapshot_id": "snap",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "profile_version": "p1",
        "snapshot_hash": "d" * 64,
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": inventory,
        "evidence": evidence,
        "trusted_context_refs": ["policy:shared"],
        "gaps": [],
    }
    profile = {
        "version": "p1",
        "required_lenses": ["correctness"],
        "allow_empty_approve": True,
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
    return snapshot, profile


def test_taskwide_enum_does_not_make_shared_evidence_unit_local(tmp_path):
    snapshot, profile = _selected_snapshot_and_profile()
    plan = plan_review(snapshot, profile)
    result = run_review(
        snapshot,
        plan,
        profile,
        _UnitBoundaryProvider(cite_local=False),
        None,
        LIMITS,
        str(tmp_path),
        "taskwide-not-local",
    )
    rows = [row for row in result["coverage_ledger"] if row["obligation_kind"] == "CHANGED_UNIT_LENS"]
    assert len(rows) == 2
    assert all(row["state"] == "PARTIAL" for row in rows)
    assert all(row["reason_code"] == "COVERAGE_NOTE_EVIDENCE_INVALID" for row in rows)


def test_invalid_optional_note_does_not_change_valid_local_coverage(tmp_path):
    snapshot, profile = _selected_snapshot_and_profile()
    plan = plan_review(snapshot, profile)
    result = run_review(
        snapshot,
        plan,
        profile,
        _UnitBoundaryProvider(cite_local=True, invalid_optional_note=True),
        None,
        LIMITS,
        str(tmp_path),
        "invalid-optional-note",
    )
    assert result["coverage_state"] == "COMPLETE"
    assert result["disposition"] == "APPROVE"
    for output in result["ledger"]["outputs"].values():
        assert output["payload"]["specific_strengths"] == []
        assert any(
            row["kind"] == "specific_strengths"
            and row["reason_code"] in {"report_note_references_unknown_evidence", "invalid_report_note"}
            for row in output["quarantined_items"]
        )
