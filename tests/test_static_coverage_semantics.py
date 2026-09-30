"""Offline engine boundaries for static test review versus execution evidence."""

from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider

LIMITS = {
    "deadline_seconds": 2,
    "max_concurrent_scopes": 1,
    "max_provider_calls": 4,
    "max_retries_per_task": 0,
    "max_context_bytes": 20_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 4_000,
    "max_output_bytes": 8_000,
    "max_context_retrievals": 0,
    "max_followup_tasks": 0,
}


class OfflineStructuredProvider(OpenAIProvider):
    """Exercise real request measurement and structured validation with offline output."""

    def __init__(self, state: str, reason: str):
        super().__init__(
            {
                "kind": "openai-compatible",
                "base_url": "https://offline.example.invalid/v1",
                "model": "contract-fixture",
                "api_key_env": "UNUSED_STATIC_COVERAGE_TEST_KEY",
                "max_request_bytes": 45_000,
                "max_response_bytes": 4_000,
                "max_output_tokens": 500,
            }
        )
        self.state = state
        self.reason = reason

    def _call(self, *, system, user, schema, limits, contract_version, **kwargs):
        task = user["task"]
        local_ids = next(
            binding["evidence_ids"]
            for binding in task["unit_evidence_bindings"]
            if binding["unit_id"] == task["unit_ids"][0]
        )
        payload = {
            "contract_version": "specialist-findings.v4",
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": unit_id,
                    "state": self.state,
                    "reason_code": self.reason,
                    "evidence_refs": list(local_ids),
                    "coverage_basis": "STATIC_REVIEW",
                }
                for unit_id in task["unit_ids"]
            ],
            "specific_strengths": [],
            "future_guidance": [],
        }
        return payload, {"usage": {}, "provenance": {"transport": "offline_test_double"}}


def _review_inputs():
    base_sha = "b" * 40
    head_sha = "c" * 40
    snapshot_id = "snap-static-test-review"
    snapshot = {
        "snapshot_id": snapshot_id,
        "snapshot_hash": "d" * 64,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "repository": "example/repository",
        "pull_request_number": 7,
        "profile_version": "static-tests-v1",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "unit-requirements",
                "path": "requirements-dev.txt",
                "kind": "config",
                "change": "modified",
                "evidence_ids": ["diff:requirements", "test-source:contract"],
            }
        ],
        "evidence": {
            "diff:requirements": {
                "evidence_id": "diff:requirements",
                "snapshot_id": snapshot_id,
                "path": "requirements-dev.txt",
                "source_revision": head_sha,
                "content": "-example==1.0\n+example==1.1",
                "content_hash": "1" * 64,
                "source_kind": "diff",
                "trust": "untrusted_pr_content",
            },
            "test-source:contract": {
                "evidence_id": "test-source:contract",
                "snapshot_id": snapshot_id,
                "path": "tests/test_dependency_contract.py",
                "source_revision": base_sha,
                "content": "def test_dependency_contract():\n    assert configured_version() == expected_version()\n",
                "content_hash": "2" * 64,
                "source_kind": "profile_context",
                "trust": "repository_evidence",
            },
        },
        "gaps": [],
    }
    profile = {
        "version": "static-tests-v1",
        "required_lenses": ["tests"],
        "allow_empty_approval": True,
        "review_criteria": {
            "tests": "Assess test-source adequacy for the changed behavior; do not claim execution.",
        },
    }
    return snapshot, profile


def _run(tmp_path, *, state: str, reason: str):
    snapshot, profile = _review_inputs()
    plan = plan_review(snapshot, profile, "AUTO")
    provider = OfflineStructuredProvider(state, reason)
    result = run_review(
        snapshot,
        plan,
        profile,
        provider,
        None,
        LIMITS,
        str(tmp_path),
        f"static-tests-{state.lower()}",
    )
    return result, provider


def test_engine_accepts_complete_static_test_assessment_without_execution_receipt(tmp_path):
    result, provider = _run(tmp_path, state="COVERED", reason="STATIC_TEST_SOURCE_ASSESSMENT_COMPLETE")

    assert result["coverage_state"] == "COMPLETE"
    assert result["coverage_ledger"][0]["state"] == "COMPLETE"
    task_result = next(iter(result["task_results"].values()))
    note = task_result["payload"]["coverage_notes"][0]
    assert note["coverage_basis"] == "STATIC_REVIEW"
    assert set(note["evidence_refs"]) == {"diff:requirements", "test-source:contract"}
    assert task_result["status"] == "SUCCEEDED"
    assert set(task_result["input_evidence_ids"]) == set(note["evidence_refs"])
    assert "external_check_results" not in _review_inputs()[0]
    assert "test execution" not in note["reason_code"].lower()


def test_engine_preserves_partial_static_test_assessment_as_incomplete(tmp_path):
    result, _ = _run(tmp_path, state="PARTIAL", reason="STATIC_TEST_CONTEXT_INSUFFICIENT")

    assert result["coverage_ledger"][0]["state"] == "PARTIAL"
    assert result["coverage_ledger"][0]["reason_code"] == "PARTIAL_REVIEW_COVERAGE"
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
