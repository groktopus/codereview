from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from pr_review_harness import selected_model_trial as trial  # noqa: E402


def _hash(value) -> str:
    return hashlib.sha256(trial.canonical_json(value)).hexdigest()


def _request() -> dict:
    return {
        "task_id": "review-001",
        "lens": "correctness",
        "unit_ids": ["unit-001"],
        "input_bytes": 1234,
        "input_sha256": "a" * 64,
        "admitted": True,
    }


def _plan(source_revision: str = "b" * 40) -> dict:
    rows = []
    for index, case_id in enumerate(trial.PREPARED_CASE_IDS):
        rows.append(
            {
                "case_id": case_id,
                "role": "synthetic",
                "base_sha": f"{index + 1:040x}",
                "head_sha": f"{index + 4:040x}",
                "snapshot_id": f"snapshot-{case_id}",
                "snapshot_hash": "e" * 64,
                "profile_sha256": "f" * 64,
                "limits_sha256": "1" * 64,
                "provider_identity_sha256": "2" * 64,
                "primary_request_count": 1,
                "primary_requests": [_request()],
            }
        )
    return {
        "schema": trial.PREPARED_PLAN_SCHEMA,
        "state": "PREPARED_PROVIDER_FREE",
        "source_revision": source_revision,
        "fixture_sources": {"injection_suite_sha256": "3" * 64},
        "implementation_identity": {"git_head": source_revision},
        "shared_review_policy": {"sha256": "4" * 64},
        "frozen_inputs": {"profile_sha256": "f" * 64, "limits_sha256": "1" * 64},
        "bounds": {"effect_policy": "READ_ONLY", "publication": "DISABLED", "target_execution": "DISABLED"},
        "cases": rows,
    }


def _runtime_snapshot(row: dict) -> tuple[dict, list[dict], str]:
    evidence = {
        "evidence-001": {
            "content_hash": "a" * 64,
            "path": "src/auth.py",
            "source_revision": row["head_sha"],
            "source_kind": "head_file",
            "trust": "repository_evidence",
            "content": "synthetic fixture evidence",
        }
    }
    base = {"snapshot_id": row["snapshot_id"], "snapshot_hash": "9" * 64,
            "base_sha": row["base_sha"], "head_sha": row["head_sha"],
            "profile_version": "test-profile", "evidence": evidence}
    index, index_hash = trial._cli_evidence_index_projection(base)
    return base, index, index_hash


def test_current_coverage_projection_preserves_unit_lens_and_partial_reason_without_raw_refs():
    result = {
        "coverage_ledger": [
            {
                "coverage_id": "coverage-001",
                "obligation_id": "AC-011",
                "obligation_kind": "REQUIRED_TEST_CONTEXT",
                "scope_unit_ids": ["unit-001"],
                "lens": "correctness",
                "required": True,
                "state": "PARTIAL",
                "reason_code": "RELEVANT_TEST_CONTEXT_INSUFFICIENT",
                "task_ids": ["task-001"],
                "context_gap_ids": ["gap-001"],
                "evidence_refs": ["private-evidence-ref-1"],
            }
        ]
    }

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is True
    assert projected["state"] == "PRESERVED"
    assert projected["required_row_count"] == 1
    row = projected["rows"][0]
    assert (row["lens"], row["scope_unit_ids"], row["state"], row["reason_code"]) == (
        "correctness",
        ["unit-001"],
        "PARTIAL",
        "RELEVANT_TEST_CONTEXT_INSUFFICIENT",
    )
    assert row["evidence_ref_count"] == 1
    assert row["explanatory_notes"] == []
    assert "private-evidence-ref-1" not in json.dumps(projected)


def _coverage_note_result(note=None):
    row = {
        "coverage_id": "coverage-001",
        "obligation_id": "unit:unit-001:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "scope_unit_ids": ["unit-001"],
        "lens": "correctness",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "PARTIAL_REVIEW_COVERAGE",
        "task_ids": ["task-001"],
        "context_gap_ids": [],
        "evidence_refs": [],
    }
    task = {
        "status": "SUCCEEDED",
        "unit_ids": ["unit-001"],
        "input_evidence_ids": ["evidence-001"],
        "payload": {"coverage_notes": [] if note is None else [note]},
    }
    return {"coverage_ledger": [row], "task_results": {"task-001": task}}


def test_current_coverage_projection_retains_bounded_task_explanation_and_reference_hash():
    reason = "No test assertions exercise timeout handling."
    projected, valid = trial._current_coverage_diagnostics(
        _coverage_note_result(
            {
                "unit_id": "unit-001",
                "state": "PARTIAL",
                "coverage_basis": "STATIC_REVIEW",
                "reason_code": reason,
                "evidence_refs": ["evidence-001"],
            }
        )
    )
    assert valid is True
    note = projected["rows"][0]["explanatory_notes"][0]
    assert note["task_id"] == "task-001"
    assert note["unit_id"] == "unit-001"
    assert note["state"] == "PARTIAL"
    assert note["coverage_basis"] == "STATIC_REVIEW"
    assert note["reason_code"] == reason
    assert note["reason_sha256"] == _hash(reason)
    assert note["evidence_ref_count"] == 1
    assert note["evidence_refs_sha256"] == _hash(["evidence-001"])
    assert "evidence-001" not in json.dumps(projected)


@pytest.mark.parametrize(
    "note",
    [
        None,
        {
            "unit_id": "unit-other",
            "state": "PARTIAL",
            "coverage_basis": "STATIC_REVIEW",
            "reason_code": "MISSING_TESTS",
            "evidence_refs": ["evidence-001"],
        },
        {
            "unit_id": "unit-001",
            "state": "PARTIAL",
            "coverage_basis": "STATIC_REVIEW",
            "reason_code": "MISSING_TESTS",
            "evidence_refs": ["other-task-evidence"],
        },
    ],
)
def test_current_coverage_projection_rejects_missing_or_unbound_task_explanation(note):
    projected, valid = trial._current_coverage_diagnostics(_coverage_note_result(note))
    assert valid is False
    assert projected["state"] == "INVALID"
    assert projected["rows"] == []


def test_malformed_coverage_row_is_explicitly_invalid_instead_of_silently_dropped():
    projected, valid = trial._current_coverage_diagnostics(
        {"coverage_ledger": [{"obligation_id": "AC-011", "state": "PARTIAL"}]}
    )
    assert valid is False
    assert projected["state"] == "INVALID"
    assert projected["row_count_observed"] == 1
    assert projected["rows"] == []


def _native_claim_coverage_fixture(*, complete: bool):
    from pr_review_harness.claim_reconciliation import classify_reconciliation

    candidate_id = "candidate-001"
    task_id = "task-001"
    candidate_refs = ["candidate-evidence-001"]
    primary = {
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "material_consequence": True,
        "evidence_refs": ["primary-evidence-001"],
    }
    assessments = None
    claim = {
        "candidate_id": candidate_id,
        "status": "NOT_RUN",
        "request_hash": None,
        "assessments": None,
        "primary_assessment_hash": None,
    }
    if complete:
        answer_choices = {
            "observation_support": "SUPPORTED",
            "consequence_support": "SUPPORTED",
            "rule_connection_support": "SUPPORTED",
            "introducedness": "INTRODUCED",
            "materiality": "MATERIAL",
            "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
        }
        assessments = {
            dimension: {
                "status": "ANSWERED",
                "choice": choice,
                "evidence_refs": sorted(candidate_refs + primary["evidence_refs"]),
            }
            for dimension, choice in answer_choices.items()
        }
        claim = {
            "candidate_id": candidate_id,
            "status": "COMPLETE",
            "response_valid": True,
            "request_hash": "a" * 64,
            "assessments": assessments,
            "primary_assessment_hash": _hash(primary),
        }
    candidate = {
        "candidate_id": candidate_id,
        "validation_state": "VALID",
        "task_id": task_id,
        "raw": {"unit_id": "unit-001", "evidence_refs": candidate_refs},
    }
    relation = classify_reconciliation(
        primary,
        claim,
        candidate_valid=True,
        introducedness_available=complete,
    )
    obligation_id = f"claim-reconciliation:{candidate_id}"
    coverage = {
        "coverage_id": "coverage-001",
        "obligation_id": obligation_id,
        "obligation_kind": "CLAIM_RECONCILIATION",
        "required": True,
        "candidate_id": candidate_id,
        "scope_unit_ids": ["unit-001"],
        "state": "COMPLETE" if relation["state"] == "AGREES" else "PARTIAL",
        "reconciliation_state": relation["state"],
        "reason_code": relation["reason_code"],
        "task_ids": [task_id],
        "evidence_refs": sorted(candidate_refs + primary["evidence_refs"]),
        "primary_assessment_hash": relation["primary_assessment_hash"],
        "claim_assessment_hash": relation["claim_assessment_hash"],
        "request_hash": relation["request_hash"],
        "context_gap_ids": [],
    }
    result = {
        "coverage_ledger": [coverage],
        "task_results": {},
        "ledger": {
            "candidate_records": [candidate],
            "identity": {"claim_reconciliation": {"version": "claim-reconciliation.v1"}},
        },
        "claim_assessments": [claim],
        "findings": [
            {
                "candidate_ids": [candidate_id],
                "assessment_records": [
                    {"candidate_id": candidate_id, "semantic_assessment": primary}
                ],
            }
        ],
    }
    return result


@pytest.mark.parametrize("complete", [False, True])
def test_current_coverage_projection_preserves_engine_native_claim_reconciliation_rows(complete):
    result = _native_claim_coverage_fixture(complete=complete)

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is True
    row = projected["rows"][0]
    assert row["obligation_kind"] == "CLAIM_RECONCILIATION"
    assert row["candidate_id"] == "candidate-001"
    assert row["reconciliation_state"] == ("AGREES" if complete else "PARTIAL")
    assert row["state"] == ("COMPLETE" if complete else "PARTIAL")
    assert row["evidence_ref_count"] == 2
    assert row["evidence_refs_sha256"] == _hash(
        ["candidate-evidence-001", "primary-evidence-001"]
    )
    assert "candidate-evidence-001" not in json.dumps(projected)
    assert "lens" not in row


def test_current_coverage_projection_rejects_malformed_completed_request_hash():
    result = _native_claim_coverage_fixture(complete=True)
    result["claim_assessments"][0]["request_hash"] = "not-a-sha256"
    result["coverage_ledger"][0]["request_hash"] = "not-a-sha256"

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"
    assert projected["rows"] == []


@pytest.mark.parametrize(
    "remove_key",
    ["coverage_ledger", "candidate_records", "claim_assessments"],
)
def test_current_native_policy_rejects_missing_candidate_claim_or_coverage_rows(remove_key):
    result = _native_claim_coverage_fixture(complete=False)
    if remove_key == "coverage_ledger":
        result["coverage_ledger"] = []
    elif remove_key == "candidate_records":
        result["ledger"].pop("candidate_records")
    else:
        result.pop("claim_assessments")

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"


def test_current_native_policy_rejects_duplicate_reconciliation_row():
    result = _native_claim_coverage_fixture(complete=False)
    result["coverage_ledger"].append(dict(result["coverage_ledger"][0]))

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"


def test_native_coverage_row_requires_exact_inventory_even_without_policy_marker():
    result = _native_claim_coverage_fixture(complete=False)
    result["ledger"]["identity"].pop("claim_reconciliation")
    result["ledger"]["candidate_records"].append(
        {
            "candidate_id": "candidate-unprojected",
            "validation_state": "INVALID",
            "task_id": "task-001",
            "raw_hash": "b" * 64,
        }
    )
    result["claim_assessments"].append(
        {"candidate_id": "candidate-unprojected", "status": "NOT_RUN", "request_hash": None}
    )

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"


def test_current_coverage_projection_rejects_malformed_present_inventories_even_without_rows():
    result = {
        "coverage_ledger": [],
        "ledger": {"candidate_records": [None]},
        "claim_assessments": [None],
        "findings": [None],
    }

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"


def test_current_coverage_projection_allows_legacy_claim_rows_without_native_policy():
    result = _coverage_note_result(
        {
            "unit_id": "unit-001",
            "state": "PARTIAL",
            "coverage_basis": "STATIC_REVIEW",
            "reason_code": "Legacy row is independently preserved.",
            "evidence_refs": ["evidence-001"],
        }
    )
    result["claim_assessments"] = [{"candidate_id": "legacy-candidate", "status": "NOT_RUN"}]

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is True
    assert projected["state"] == "PRESERVED"


@pytest.mark.parametrize(
    ("mutate",),
    [
        (lambda result: result["coverage_ledger"][0].update({"lens": "correctness"}),),
        (lambda result: result["coverage_ledger"][0].update({"reconciliation_state": "AGREES"}),),
        (lambda result: result["coverage_ledger"][0].update({"candidate_id": "candidate-other"}),),
        (lambda result: result["coverage_ledger"][0].update({"task_ids": []}),),
        (lambda result: result["coverage_ledger"][0].update({"coverage_id": None}),),
        (lambda result: result["findings"].append(None),),
        (lambda result: result["findings"][0].update({"assessment_records": None}),),
    ],
)
def test_current_coverage_projection_rejects_unbound_or_malformed_native_claim_rows(mutate):
    result = _native_claim_coverage_fixture(complete=False)
    mutate(result)

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"
    assert projected["rows"] == []


def test_current_coverage_projection_still_rejects_generic_row_without_lens():
    result = _coverage_note_result()
    result["coverage_ledger"][0].pop("lens")

    projected, valid = trial._current_coverage_diagnostics(result)

    assert valid is False
    assert projected["state"] == "INVALID"


def test_quarantine_diagnostics_keep_reason_and_content_hash_only():
    secretish_note = "raw candidate note must not leave the result"
    result = {
        "ledger": {
            "outputs": {
                "task-001": {
                    "quarantined_items": [
                        {
                            "kind": "coverage_note",
                            "reason_code": "invalid_report_note",
                            "item_hash": "5" * 64,
                            "raw": secretish_note,
                        }
                    ]
                }
            }
        },
        "task_results": {"task-001": {"status": "SUCCEEDED"}},
    }

    projected, valid = trial._current_quarantine_diagnostics(result)

    assert valid is True
    assert projected["state"] == "OBSERVED"
    assert projected["quarantined_item_count"] == 1
    assert projected["items"] == [
        {
            "task_id": "task-001",
            "kind": "coverage_note",
            "reason_code": "invalid_report_note",
            "item_hash": "5" * 64,
        }
    ]
    assert secretish_note not in json.dumps(projected)


def test_missing_output_for_succeeded_task_is_invalid_and_failed_task_is_explicitly_unobserved():
    malformed, valid = trial._current_quarantine_diagnostics(
        {"ledger": {"outputs": {}}, "task_results": {"task-001": {"status": "SUCCEEDED"}}}
    )
    assert valid is False
    assert malformed["state"] == "INVALID"

    partial, valid = trial._current_quarantine_diagnostics(
        {"ledger": {"outputs": {}}, "task_results": {"task-001": {"status": "FAILED"}}}
    )
    assert valid is True
    assert partial["state"] == "PARTIAL"
    assert partial["unobserved_tasks"] == [{"task_id": "task-001", "status": "FAILED"}]


def test_budget_diagnostics_separate_local_check_reservations_and_do_not_claim_actual_provider_calls():
    result = {
        "budget": {
            "provider_calls_reserved": 2,
            "provider_calls_limit": 9,
            "local_check_reservations": 1,
            "local_check_input_bytes_reserved": 88,
            "local_check_output_bytes_reserved": 77,
            "output_bytes_reserved": 1_000,
            "output_bytes_limit": 294_912,
            "context_bytes_reserved": 2_000,
            "context_bytes_limit": 300_000,
            "context_retrievals_reserved": 1,
            "context_retrievals_limit": 8,
            "cost": "UNKNOWN",
        }
    }

    projected = trial._current_budget_accounting(result)

    assert projected["provider_calls_reserved"] == 2
    assert projected["local_check_reservations"] == 1
    assert projected["local_check_input_bytes_reserved"] == 88
    assert projected["local_check_output_bytes_reserved"] == 77
    assert "provider_calls_actual" not in projected
    assert projected["billing"] == "UNKNOWN"


def _local_exchange(request_hash="a" * 64):
    return {
        "contract_version": "local-http-exchange.v1",
        "state": "HTTP_RESPONSE_RECEIVED",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": True,
        "request_sha256": request_hash,
        "request_bytes": 100,
        "endpoint_sha256": "b" * 64,
        "http_status": 200,
        "response_sha256": "c" * 64,
        "response_bytes": 50,
        "response_complete": True,
    }


def test_current_report_note_diagnostics_count_and_hash_without_retaining_note_text():
    secret_text = "private provider note"
    projected, valid = trial._current_report_note_diagnostics(
        {"report_sections": {"specific_strengths": [secret_text], "future_guidance": []}}
    )

    assert valid is True
    assert projected["specific_strengths_count"] == 1
    assert projected["specific_strengths_sha256"] == _hash([secret_text])
    assert projected["future_guidance_count"] == 0
    assert projected["future_guidance_sha256"] == _hash([])
    assert secret_text not in json.dumps(projected)


@pytest.mark.parametrize("value, expected", [("COMMENT", "COMMENT"), ("APPROVE", "APPROVE"), ("BOGUS", "UNKNOWN")])
def test_selected_result_disposition_preserves_only_known_engine_values(value, expected):
    assert trial._safe_review_disposition(value) == expected


def test_current_case_summary_preserves_engine_comment_disposition():
    from types import SimpleNamespace

    result = {
        "request_hash": "a" * 64,
        "snapshot_id": "snapshot-clean",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "project_profile_version": "profile-current",
        "disposition": "COMMENT",
        "findings": [],
        "claim_assessments": [],
        "ledger": {
            "request_hash": "a" * 64,
            "identity": {"snapshot_id": "snapshot-clean", "profile_version": "profile-current"},
            "candidate_records": [],
        },
    }
    result["result_hash"] = _hash(result)
    case = SimpleNamespace(
        case_id="r1-code-clean-control",
        variant={"kind": "control", "vector": "clean"},
        snapshot={"snapshot_id": "snapshot-clean", "snapshot_hash": "d" * 64},
        base_sha="b" * 40,
        head_sha="c" * 40,
        anchor=None,
    )

    projected = trial._case_result_summary(
        result,
        case,
        {},
        raw_output_secret_match=False,
        canary_match=False,
        expected_profile_id="profile-current",
        expected_profile_hash="e" * 64,
    )

    assert projected["result_integrity_valid"] is True
    assert projected["result_identity_match"] is True
    assert projected["disposition"] == "COMMENT"


def test_current_case_summary_exposes_only_bounded_note_and_provider_diagnostics():
    from types import SimpleNamespace

    secret_note = "do not include this report text in the projection"
    result = {
        "request_hash": "a" * 64,
        "snapshot_id": "snapshot-clean",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "project_profile_version": "profile-current",
        "disposition": "COMMENT",
        "coverage_state": "COMPLETE",
        "findings": [],
        "claim_assessments": [],
        "coverage_ledger": [],
        "task_results": {},
        "report_sections": {"specific_strengths": [secret_note], "future_guidance": []},
        "budget": {"provider_calls_reserved": 0, "local_check_reservations": 0, "cost_billing_known": False},
        "ledger": {
            "request_hash": "a" * 64,
            "identity": {"snapshot_id": "snapshot-clean", "profile_version": "profile-current"},
            "candidate_records": [],
            "outputs": {},
            "budget": {"reservations": {}, "settlements": {}},
        },
    }
    result["result_hash"] = _hash(result)
    case = SimpleNamespace(
        case_id="r1-code-clean-control",
        variant={"kind": "control", "vector": "clean"},
        snapshot={"snapshot_id": "snapshot-clean", "snapshot_hash": "d" * 64},
        base_sha="b" * 40,
        head_sha="c" * 40,
        anchor=None,
    )

    projected = trial._case_result_summary(
        result,
        case,
        {},
        raw_output_secret_match=False,
        canary_match=False,
        expected_profile_id="profile-current",
        expected_profile_hash="e" * 64,
        current_diagnostics=True,
    )

    assert projected["diagnostic_projection_valid"] is True
    assert projected["report_note_diagnostics"]["specific_strengths_count"] == 1
    assert projected["report_note_diagnostics"]["future_guidance_count"] == 0
    assert projected["provider_telemetry"]["provider_call_reservations"] == 0
    assert projected["provider_telemetry"]["local_check_reservations"] == 0
    assert secret_note not in json.dumps(projected)


def test_current_provider_telemetry_separates_reservations_local_checks_usage_and_http_attempts():
    task_key = "task-001:review:0"
    claim_key = "claim-assessment:claim-assessor.2:candidate-001:attempt:0"
    advisory_key = "system-one:advisory:0"
    result = {
        "budget": {
            "provider_calls_reserved": 3,
            "local_check_reservations": 1,
            "cost_billing_known": False,
            "cost_billed_microunits": 0,
        },
        "ledger": {
            "budget": {
                "reservations": {
                    task_key: {"key": task_key, "kind": "provider", "provider_calls": 1},
                    "task-002:check:0": {"key": "task-002:check:0", "kind": "deterministic_check", "provider_calls": 0},
                    claim_key: {"key": claim_key, "kind": "claim_assessment", "provider_calls": 1},
                    advisory_key: {"key": advisory_key, "kind": "provider", "provider_calls": 1},
                },
                "settlements": {
                    task_key: {
                        "status": "SUCCEEDED",
                        "usage": {
                            "known": True,
                            "prompt_tokens": 10,
                            "completion_tokens": 3,
                            "total_tokens": 13,
                            "estimated_cost_microunits": 99,
                        },
                    },
                    claim_key: {"status": "COMPLETE", "usage": {"known": True, "input_tokens": 5, "output_tokens": 2}},
                    advisory_key: {
                        "status": "SUCCEEDED",
                        "usage": {"known": False, "prompt_tokens": 900, "tokens": 900, "cost": None},
                    },
                },
            }
        },
        "task_results": {
            "task-001": {"attempts": 1, "provenance": {"local_http_exchange": _local_exchange()}},
        },
        "claim_assessments": [{"reservation_key": claim_key, "usage": {"known": True}}],
        "advisory_assessment": {"status": "RECEIVED", "provenance": {"local_http_exchange": _local_exchange("d" * 64)}},
    }

    projected, valid = trial._current_provider_telemetry(result, bound=True)

    assert valid is True
    assert projected["state"] == "PARTIAL"
    assert projected["provider_call_reservations"] == 3
    assert projected["provider_call_settlements"] == 3
    assert projected["provider_usage_known_records"] == 2
    assert projected["provider_usage_unknown_records"] == 1
    assert projected["provider_usage_fields"]["prompt_tokens"] == {"reported_record_count": 1, "reported_sum": 10}
    assert projected["provider_usage_fields"]["input_tokens"] == {"reported_record_count": 1, "reported_sum": 5}
    assert projected["provider_usage_fields"]["tokens"] == {"reported_record_count": 0, "reported_sum": None}
    assert "estimated_cost_microunits" not in projected["provider_usage_fields"]
    assert projected["local_http_attempt_receipts"] == 2
    assert projected["local_http_attempts_observed"] == 2
    assert projected["provider_reservations_without_local_http_receipt"] == 1
    assert projected["local_check_reservations"] == 1
    assert projected["remote_delivery_observation"] == "UNKNOWN"
    assert projected["billing"] == "UNKNOWN"
    assert projected["billed_cost_microunits"] is None

    result["budget"].update({"cost_billing_known": True, "cost_billed_microunits": 42})
    known_billing, valid = trial._current_provider_telemetry(result, bound=True)
    assert valid is True
    assert known_billing["billing"] == "KNOWN"
    assert known_billing["billed_cost_microunits"] == 42


def test_current_provider_telemetry_fails_closed_on_malformed_receipt_or_unbound_result():
    key = "task-001:review:0"
    result = {
        "budget": {"provider_calls_reserved": 1, "local_check_reservations": 0},
        "ledger": {
            "budget": {
                "reservations": {key: {"key": key, "provider_calls": 1}},
                "settlements": {key: {"usage": {"known": False}}},
            }
        },
        "task_results": {"task-001": {"attempts": 1, "provenance": {"local_http_exchange": {"raw": "bad"}}}},
        "claim_assessments": [],
    }
    malformed, valid = trial._current_provider_telemetry(result, bound=True)
    assert valid is False
    assert malformed == {"state": "INVALID"}

    unbound, valid = trial._current_provider_telemetry(result, bound=False)
    assert valid is True
    assert unbound == {"state": "UNKNOWN_UNBOUND_RESULT"}


def test_provider_free_current_preparation_binds_exact_requests_and_strips_inherited_credentials(tmp_path, monkeypatch):
    source_revision = "b" * 40
    plan = _plan(source_revision)
    plan_path = tmp_path / "selected-pair-clean-control-trial-v1.json"
    plan_path.write_text("synthetic plan placeholder", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    output = tmp_path / "receipt"
    output.mkdir()
    cli = tmp_path / "pr-review"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o755)
    profile = tmp_path / "profile.json"
    limits = tmp_path / "limits.json"
    profile.write_text("{}", encoding="utf-8")
    limits.write_text("{}", encoding="utf-8")
    frozen = {
        "repositories": {case_id: tmp_path for case_id in trial.PREPARED_CASE_IDS},
        "provider_config": tmp_path / "provider-reference.json",
        "decision_config": tmp_path / "decision-reference.json",
        "profile": {"version": "test-profile"},
        "limits": trial._limits(),
    }
    monkeypatch.setattr(trial, "_prepared_plan", lambda *_args, **_kwargs: (plan, profile, limits, frozen))
    monkeypatch.setattr(
        trial,
        "_expected_cli_snapshot_projection",
        lambda **kwargs: _runtime_snapshot(next(
            row for row in plan["cases"]
            if row["base_sha"] == kwargs["base_sha"] and row["head_sha"] == kwargs["head_sha"]
        )),
    )
    monkeypatch.setattr(
        trial,
        "_runtime_provenance",
        lambda *_args: {
            "cli_path": str(cli),
            "cli_executable_sha256": "6" * 64,
            "runtime_version": "1.0",
            "python_version": "3.13",
            "runtime_tree_sha256": "7" * 64,
            "source_fingerprint": {"file_hashes": {"src/pr_review_harness/dependency_context.py": "8" * 64}},
        },
    )
    monkeypatch.setattr(
        trial,
        "_command",
        lambda _cli, case, *_args, **_kwargs: [str(cli), "--run-id", case.case_id, "review"],
    )
    calls = []

    def invoke(command, *, cwd, env, timeout_seconds):
        case_id = command[command.index("--run-id") + 1]
        calls.append({"case_id": case_id, "env": env, "timeout": timeout_seconds})
        row = next(item for item in plan["cases"] if item["case_id"] == case_id)
        fresh_snapshot, evidence_index, evidence_index_hash = _runtime_snapshot(row)
        return {
            "run_status": "CLI_COMPLETED",
            "cli_result": {
                "status": "PREPARED_ONLY",
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "snapshot": {
                    "snapshot_id": fresh_snapshot["snapshot_id"],
                    "snapshot_hash": fresh_snapshot["snapshot_hash"],
                    "evidence_index": evidence_index,
                    "evidence_index_sha256": evidence_index_hash,
                    "profile_version": "test-profile",
                    "base_sha": row["base_sha"],
                    "head_sha": row["head_sha"],
                    "profile_file_sha256": row["profile_sha256"],
                    "limits_sha256": row["limits_sha256"],
                    "provider_identity_sha256": row["provider_identity_sha256"],
                },
                "primary_requests": row["primary_requests"],
            },
        }

    result = trial.prepare_current_source_trial(
        prepared_plan=plan_path,
        cli_executable=cli,
        expected_source_revision=source_revision,
        output=output,
        repo_support_root=root,
        environ={"PATH": "/usr/bin", "LLM_API_KEY": "must-not-pass", "JEV_API_KEY": "must-not-pass"},
        invoke=invoke,
    )

    assert result["status"] == "PREPARED_NOT_RUN"
    assert result["case_count"] == 3
    assert len(calls) == 3
    assert all(not any(key.endswith("API_KEY") for key in call["env"]) for call in calls)
    receipt = json.loads((output / "manifest.json").read_bytes())
    assert receipt["runtime"]["installed_source_match"] is True
    assert receipt["cases"][0]["plan_snapshot_hash"] == "e" * 64
    assert receipt["cases"][0]["runtime_snapshot_hash"] == "9" * 64
    assert receipt["cases"][0]["snapshot_hash_relation"] == "DIFFERENT_PER_PREPARATION_CAPTURE"
    assert receipt["provider_calls"] == 0
    assert receipt["target_code_execution"] == "NOT_RUN"


def test_provider_free_current_preparation_rejects_exact_request_descriptor_drift(tmp_path, monkeypatch):
    source_revision = "b" * 40
    plan = _plan(source_revision)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("plan", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    output = tmp_path / "receipt"
    output.mkdir()
    cli = tmp_path / "pr-review"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o755)
    profile = tmp_path / "profile.json"
    limits = tmp_path / "limits.json"
    profile.write_text("{}", encoding="utf-8")
    limits.write_text("{}", encoding="utf-8")
    frozen = {
        "repositories": {case_id: tmp_path for case_id in trial.PREPARED_CASE_IDS},
        "provider_config": tmp_path / "provider-reference.json",
        "decision_config": tmp_path / "decision-reference.json",
        "profile": {"version": "test-profile"},
        "limits": trial._limits(),
    }
    monkeypatch.setattr(trial, "_prepared_plan", lambda *_args, **_kwargs: (plan, profile, limits, frozen))
    monkeypatch.setattr(
        trial,
        "_expected_cli_snapshot_projection",
        lambda **kwargs: _runtime_snapshot(next(
            row for row in plan["cases"]
            if row["base_sha"] == kwargs["base_sha"] and row["head_sha"] == kwargs["head_sha"]
        )),
    )
    monkeypatch.setattr(
        trial,
        "_runtime_provenance",
        lambda *_args: {"cli_path": str(cli), "source_fingerprint": {"file_hashes": {"src/pr_review_harness/x.py": "8" * 64}}},
    )
    monkeypatch.setattr(
        trial,
        "_command",
        lambda _cli, case, *_args, **_kwargs: [str(cli), "--run-id", case.case_id, "review"],
    )

    def invoke(command, *, cwd, env, timeout_seconds):
        row = next(item for item in plan["cases"] if item["case_id"] == command[command.index("--run-id") + 1])
        changed = [{**row["primary_requests"][0], "input_sha256": "9" * 64}]
        fresh_snapshot, evidence_index, evidence_index_hash = _runtime_snapshot(row)
        return {
            "run_status": "CLI_COMPLETED",
            "cli_result": {
                "status": "PREPARED_ONLY",
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "snapshot": {
                    "snapshot_id": fresh_snapshot["snapshot_id"],
                    "snapshot_hash": fresh_snapshot["snapshot_hash"],
                    "evidence_index": evidence_index,
                    "evidence_index_sha256": evidence_index_hash,
                    "base_sha": row["base_sha"],
                    "head_sha": row["head_sha"],
                    "profile_file_sha256": row["profile_sha256"],
                    "limits_sha256": row["limits_sha256"],
                    "provider_identity_sha256": row["provider_identity_sha256"],
                },
                "primary_requests": changed,
            },
        }

    with pytest.raises(trial.SelectedTrialError, match="installed_cli_prepare_parity_mismatch"):
        trial.prepare_current_source_trial(
            prepared_plan=plan_path,
            cli_executable=cli,
            expected_source_revision=source_revision,
            output=output,
            repo_support_root=root,
            environ={"PATH": "/usr/bin"},
            invoke=invoke,
        )
    assert not (output / "manifest.json").exists()


def test_current_run_receipt_rechecks_exact_plan_and_request_bindings(tmp_path, monkeypatch):
    source_revision = "b" * 40
    plan = _plan(source_revision)
    preparation = tmp_path / "preparation"
    plan_dir = preparation / "prepared"
    plan_dir.mkdir(parents=True)
    plan_path = plan_dir / "selected-pair-clean-control-trial-v1.json"
    plan_path.write_text("plan", encoding="utf-8")
    plan_hash = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    manifest_cases = []
    for row in plan["cases"]:
        manifest_cases.append(
            {
                key: row[key]
                for key in (
                    "case_id", "role", "base_sha", "head_sha", "snapshot_id",
                    "profile_sha256", "limits_sha256", "provider_identity_sha256",
                )
            }
            | {
                "plan_snapshot_hash": row["snapshot_hash"],
                "runtime_snapshot_hash": "9" * 64,
                "snapshot_hash_relation": "DIFFERENT_PER_PREPARATION_CAPTURE",
                "evidence_index_sha256": "a" * 64,
                "evidence_index_count": 1,
                "primary_request_count": 1,
                "primary_requests": trial._compact_primary_requests(row["primary_requests"]),
                "provider_calls": 0,
                "target_code_execution": "NOT_RUN",
            }
        )
    manifest = {
        "contract_version": trial.CURRENT_PREPARATION_ID,
        "state": "CURRENT_SOURCE_PREPARED_NOT_RUN",
        "source_revision": source_revision,
        "prepared_plan_sha256": plan_hash,
        "fixture_sources": plan["fixture_sources"],
        "profile_sha256": plan["frozen_inputs"]["profile_sha256"],
        "limits_sha256": plan["frozen_inputs"]["limits_sha256"],
        "provider_calls": 0,
        "target_code_execution": "NOT_RUN",
        "github_publication": "NOT_PERFORMED",
        "cases": manifest_cases,
    }
    manifest_raw = trial.canonical_json(manifest) + b"\n"
    (preparation / "manifest.json").write_bytes(manifest_raw)
    summary = {
        "contract_version": trial.CURRENT_PREPARATION_ID,
        "status": "PREPARED_NOT_RUN",
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "source_revision": source_revision,
        "prepared_plan_sha256": plan_hash,
        "case_count": 3,
    }
    (preparation / "summary.json").write_bytes(trial.canonical_json(summary) + b"\n")
    frozen = {"repositories": {case_id: tmp_path for case_id in trial.PREPARED_CASE_IDS}}
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(trial, "_prepared_plan", lambda *_args, **_kwargs: (plan, tmp_path / "profile", tmp_path / "limits", frozen))
    seen = {}

    def fake_run(**kwargs):
        seen.update(kwargs)
        return {"status": "PROCESS_COMPLETED"}

    monkeypatch.setattr(trial, "run_provider_trial", fake_run)
    result = trial.run_current_provider_trial(
        output=tmp_path / "result",
        cli_executable=tmp_path / "pr-review",
        preparation_dir=preparation,
        provider_config=tmp_path / "provider.json",
        decision_config=tmp_path / "decision.json",
        expected_source_revision=source_revision,
        repo_support_root=root,
        environ={},
    )
    assert result["status"] == "PROCESS_COMPLETED"
    assert seen["current_source_contract"] is True
    assert seen["prepared_plan"] == plan_path

    manifest_cases[0]["primary_requests"][0]["input_sha256"] = "9" * 64
    bad_manifest = {**manifest, "cases": manifest_cases}
    bad_raw = trial.canonical_json(bad_manifest) + b"\n"
    (preparation / "manifest.json").write_bytes(bad_raw)
    bad_summary = {**summary, "manifest_sha256": hashlib.sha256(bad_raw).hexdigest()}
    (preparation / "summary.json").write_bytes(trial.canonical_json(bad_summary) + b"\n")
    with pytest.raises(trial.SelectedTrialError, match="current_preparation_case_mismatch"):
        trial.run_current_provider_trial(
            output=tmp_path / "bad-result",
            cli_executable=tmp_path / "pr-review",
            preparation_dir=preparation,
            provider_config=tmp_path / "provider.json",
            decision_config=tmp_path / "decision.json",
            expected_source_revision=source_revision,
            repo_support_root=root,
            environ={},
        )


def test_current_workflow_is_opt_in_source_main_only_and_keeps_legacy_workflow_unchanged():
    legacy = ROOT / ".github/workflows/prepared-selected-model-provider-trial.yml"
    legacy_before = __import__("subprocess").run(
        ["git", "show", "HEAD:.github/workflows/prepared-selected-model-provider-trial.yml"],
        check=True,
        capture_output=True,
    ).stdout
    assert legacy.read_bytes() == legacy_before

    workflow = (ROOT / ".github/workflows/selected-current-source-paired-trial.yml").read_text(encoding="utf-8")
    assert "default: false" in workflow
    assert "if: inputs.run_live_trial == true" in workflow
    assert "github.repository == 'groktopus/codereview'" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "contents: read" in workflow
    for denied in ("contents: write", "pull-requests: write", "checks: write", "actions: write", "github.token"):
        assert denied not in workflow
    prepare_step = workflow.index("Prepare and validate the exact current-source requests")
    provider_step = workflow.index("Run the selected current-source trial with private temporary configs")
    assert prepare_step < provider_step
    provider = workflow[provider_step : workflow.index("- name: Remove only the private provider configs", provider_step)]
    assert provider.count("secrets.") == 6
    assert "--run-provider-trial" in provider
    assert "--observe-effects" in provider
    upload = workflow[workflow.index("Upload only versioned sanitized trial receipts") :]
    assert "summary.json" in upload and "manifest.json" in upload
    assert "provider-config" not in upload
    assert "prepared/selected-pair-clean-control-trial-v1.json" not in upload
