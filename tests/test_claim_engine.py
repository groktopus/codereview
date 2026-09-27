"""Offline tests for the optional per-candidate claim-assessment shadow stage."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import pr_review_harness.engine as engine_module
from pr_review_harness.budget import BudgetExhausted
from pr_review_harness.claim_assessment import ClaimAssessmentAdapter
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review

BASE = "b" * 40
HEAD = "c" * 40
LIMITS = {
    "deadline_seconds": 30,
    "max_concurrent_scopes": 1,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 120_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 0,
    "max_followup_tasks": 0,
}


def _snapshot() -> dict:
    content = "-old\n+new"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    evidence = {
        "diff:u0": {
            "evidence_id": "diff:u0",
            "snapshot_id": "snap",
            "path": "src/auth.py",
            "line_start": 1,
            "line_end": 1,
            "source_revision": HEAD,
            "content": content,
            "content_hash": content_hash,
            "source_kind": "diff",
            "trust": "untrusted_pr_content",
        }
    }
    return {
        "snapshot_id": "snap",
        "snapshot_hash": "d" * 64,
        "base_sha": BASE,
        "head_sha": HEAD,
        "profile_version": "profile-v1",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "u0",
                "path": "src/auth.py",
                "kind": "human_code",
                "change": "modified",
                "diff": content,
                "changed_lines": [[1, 1]],
                "evidence_ids": ["diff:u0"],
            }
        ],
        "evidence": evidence,
        "gaps": [],
    }


def _profile() -> dict:
    return {"version": "profile-v1", "required_lenses": ["correctness"], "allow_empty_approval": True}


class PrimaryProvider:
    identity = {
        "kind": "offline-test",
        "model": "primary-fixture",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self, outcome: str = "NOT_SUPPORTED"):
        self.outcome = outcome

    def review(self, task: dict, evidence: list[dict], limits: dict) -> dict:
        evidence_id = task["evidence_ids"][0]
        return {
            "finding_candidates": [
                {
                    "path": "src/auth.py",
                    "line": 1,
                    "title": "Fixture candidate — café",
                    "observation": "The changed predicate admits the request.",
                    "consequence": "A caller can reach a protected operation.",
                    "rule_or_contract": "Protected operations require authorization.",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [evidence_id],
                }
            ],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": "u0",
                    "state": "COVERED",
                    "reason_code": "REVIEWED",
                    "evidence_refs": [evidence_id],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }

    def adjudicate(self, candidate: dict, evidence: list[dict], limits: dict) -> dict:
        refs = [item["evidence_id"] for item in evidence]
        return {
            "contract_version": "semantic-adjudication.v3",
            "source_contract_version": "semantic-adjudication.v3",
            "outcome": self.outcome,
            "observation_support": "NOT_ESTABLISHED",
            "consequence_support": "NOT_ESTABLISHED",
            "rule_connection_support": "NOT_ESTABLISHED",
            "introducedness": "UNKNOWN",
            "assumptions": [],
            "uncertainties": [],
            "summary": "The fixture evidence does not establish the candidate claim.",
            "evidence_refs": refs,
            "causal_roles": {
                name: {
                    "support": "NOT_ESTABLISHED",
                    "assessment": "The bounded fixture evidence does not establish this link.",
                    "evidence_refs": [],
                }
                for name in ("behavior", "consumer", "impact")
            },
            "material_consequence": False,
        }


@dataclass(frozen=True)
class Prepared:
    contract_version: str
    request_bytes: bytes
    request_hash: str
    candidate_hash: str
    evidence_hash: str
    question_hash: str
    primary_assessment_hash: str
    question_ids: tuple[tuple[str, str], ...]
    evidence_refs: tuple[str, ...]
    introducedness_available: bool


def _claim_hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class FakeClaimAssessor:
    """Importable spawn target; its result is test data, not semantic truth."""

    identity = {"contract_version": "claim-assessment.2", "provider": "offline-fake"}

    def __init__(
        self,
        sleep_seconds: float = 0,
        status: str = "COMPLETE",
        padding_bytes: int = 0,
        empty_assessments: bool = False,
        empty_question_metadata: bool = False,
        corrupt_provenance: bool = False,
        budget_error: str | None = None,
    ):
        self.sleep_seconds = sleep_seconds
        self.status = status
        self.padding_bytes = padding_bytes
        self.empty_assessments = empty_assessments
        self.empty_question_metadata = empty_question_metadata
        self.corrupt_provenance = corrupt_provenance
        self.budget_error = budget_error
        self.prepare_calls = 0

    def prepare(
        self,
        candidate: dict,
        evidence: list[dict],
        identity: dict,
        limits: dict,
        *,
        primary_assessment: dict,
    ) -> Prepared:
        self.prepare_calls += 1
        cited = [
            {
                "evidence_id": item["evidence_id"],
                "source_kind": item["source_kind"],
                "content_hash": item["content_hash"],
                "trust": item["trust"],
                "path": item.get("path"),
                "side": "HEAD" if item.get("source_revision") == identity["head_sha"] else None,
                "source_revision": item.get("source_revision"),
                "line": item.get("line"),
                "content": item["content"],
            }
            for item in evidence
        ]
        state = {
            "assessment_contract_version": "claim-assessment.2",
            "assessment_identity": identity,
            "candidate": candidate,
            "primary_assessment": primary_assessment,
            "cited_evidence": cited,
        }
        dimensions = (
            "observation_support",
            "consequence_support",
            "rule_connection_support",
            "materiality",
            "missing_context",
            "introducedness",
        )
        question_ids = tuple((name, f"question-{name}") for name in dimensions)
        questions = {
            f"question-{name}": {"criteria": {"NOT_ESTABLISHED": "test"}}
            for name in dimensions
            if name != "introducedness"
        }
        request = json.dumps(
            {"model": "offline-fake", "state": state, "questions": questions},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return Prepared(
            contract_version="claim-assessment.2",
            request_bytes=request,
            request_hash=hashlib.sha256(request).hexdigest(),
            candidate_hash=_claim_hash(candidate),
            evidence_hash=_claim_hash(cited),
            question_hash=_claim_hash(questions),
            primary_assessment_hash=_claim_hash(primary_assessment),
            question_ids=() if self.empty_question_metadata else question_ids,
            evidence_refs=tuple(item["evidence_id"] for item in cited),
            introducedness_available=False,
        )

    def estimate_prepared(self, prepared: Prepared, limits: dict) -> dict:
        if self.budget_error is not None:
            raise BudgetExhausted(self.budget_error)
        return {
            "provider_calls": 1,
            "input_bytes": len(prepared.request_bytes),
            "max_output_bytes": limits["max_output_bytes_per_task"],
            "provider_response_bytes": 2_000,
            "deadline_seconds": limits["deadline_seconds"],
            "reservation_kind": "unknown",
        }

    def assess_prepared(self, prepared: Prepared, limits: dict) -> dict:
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        request = json.loads(prepared.request_bytes)
        assessments = {}
        for dimension, question_id in prepared.question_ids:
            not_shown = dimension == "introducedness" and not prepared.introducedness_available
            assessments[dimension] = {
                "question_id": question_id,
                "status": "NOT_SHOWN" if not_shown else "ANSWERED",
                "native_primitive": "Choice",
                "choice": None if not_shown else "NOT_ESTABLISHED",
                "probabilities": None,
                "confidence": None,
                "evidence_refs": list(prepared.evidence_refs),
                "interpretation": "advisory_uncalibrated",
            }
        provenance = {
            "contract_version": prepared.contract_version,
            "request_hash": prepared.request_hash,
            "candidate_hash": prepared.candidate_hash,
            "evidence_hash": prepared.evidence_hash,
            "question_hash": prepared.question_hash,
            "primary_assessment_hash": prepared.primary_assessment_hash,
            **request["state"]["assessment_identity"],
            "provider_model_id": "offline-fake",
            "raw_response_cap_received": limits["max_output_bytes_per_task"],
        }
        if self.corrupt_provenance:
            provenance["request_hash"] = "f" * 64
        return {
            "contract_version": "claim-assessment.2",
            "status": self.status,
            "decision": "ADVISORY_ONLY",
            "assessments": {} if self.empty_assessments else assessments,
            "provenance": provenance,
            "usage": {},
            "padding": "x" * self.padding_bytes,
        }


class Freshness:
    def __init__(self, value: str):
        self.value = value

    def __call__(self) -> dict:
        return {
            "freshness": self.value,
            "expected_head_sha": HEAD,
            "observed_head_sha": HEAD if self.value == "CURRENT" else "e" * 40,
        }


class ClaimChoiceHandler(BaseHTTPRequestHandler):
    """Loopback-only System One fixture that answers the prepared Choice IDs."""

    seen: list[bytes] = []
    token = "claim-engine-loopback-test-token"

    def do_POST(self):
        request_bytes = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append(request_bytes)
        request = json.loads(request_bytes)
        answers = {}
        for question_id, question in request["questions"].items():
            choices = list(question["criteria"])
            probabilities = {choice: 0.0 for choice in choices}
            probabilities[choices[0]] = 1.0
            answers[question_id] = {
                "type": "choice",
                "choice": choices[0],
                "probabilities": probabilities,
                "confidence": 1.0,
            }
        response = json.dumps(
            {
                "model": "jev-1.13.0",
                "request_id": "loopback-claim-engine-test",
                "answers": answers,
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


def _run(tmp_path, *, assessor=None, cap=0, limits=None, freshness=None, run_id="r1"):
    snapshot = _snapshot()
    profile = _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    return run_review(
        snapshot,
        plan,
        profile,
        PrimaryProvider(),
        None,
        limits or LIMITS,
        str(tmp_path),
        run_id,
        freshness_check=freshness,
        claim_assessor=assessor,
        max_claim_assessments=cap,
    )


def test_disabled_shadow_preserves_legacy_identity_and_result_shape(tmp_path):
    legacy = _run(tmp_path / "legacy")
    explicit_zero = _run(tmp_path / "zero", assessor=FakeClaimAssessor(), cap=0)

    assert legacy["request_hash"] == explicit_zero["request_hash"]
    assert legacy["disposition"] == explicit_zero["disposition"]
    assert legacy["findings"] == explicit_zero["findings"]
    assert "claim_assessments" not in legacy["ledger"]
    assert "claim_assessments" not in legacy
    assert "claim_assessment" not in legacy["ledger"]["identity"]


def test_positive_cap_requires_assessor_before_any_run_artifact(tmp_path):
    with pytest.raises(ValueError, match="requires a claim assessor"):
        _run(tmp_path, cap=1)
    assert not (tmp_path / "r1.json").exists()


def test_shadow_runs_after_primary_and_records_exact_reservation_without_changing_disposition(tmp_path):
    legacy = _run(tmp_path / "legacy")
    shadow = _run(tmp_path / "shadow", assessor=FakeClaimAssessor(), cap=1)

    assert shadow["disposition"] == legacy["disposition"]
    assert shadow["findings"] == legacy["findings"]
    row = shadow["claim_assessments"][0]
    reservations = shadow["ledger"]["budget"]["reservations"]
    keys = list(reservations)
    shadow_key = row["reservation_key"]
    assert row["status"] == "COMPLETE"
    assert keys.index(shadow_key) > max(i for i, key in enumerate(keys) if ":adjudicate:" in key)
    assert reservations[shadow_key]["kind"] == "claim_assessment"
    assert reservations[shadow_key]["input_bytes"] == row["input_bytes_reserved"]
    assert reservations[shadow_key]["max_output_bytes"] == row["ipc_output_bytes_reserved"]
    assert row["request_hash"] == row["provenance"]["request_hash"]
    assert row["provenance"]["raw_response_cap_received"] == 2_000
    assert row["assessments"]["observation_support"]["choice"] == "NOT_ESTABLISHED"
    assert shadow["coverage_state"] == legacy["coverage_state"]


def test_real_claim_adapter_and_loopback_transport_bind_candidate_primary_and_result(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    ClaimChoiceHandler.seen = []
    thread.start()
    monkeypatch.setenv("CLAIM_ENGINE_TEST_KEY", ClaimChoiceHandler.token)
    try:
        transport = ClaimTransport(
            {
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1/systemone",
                "api_key_env": "CLAIM_ENGINE_TEST_KEY",
                "model": "jev-latest",
                "timeout_seconds": 2,
                "max_request_bytes": 64_000,
                "max_response_bytes": 64_000,
            }
        )
        assessor = ClaimAssessmentAdapter(transport, "jev-latest")
        result = _run(tmp_path, assessor=assessor, cap=1)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert len(ClaimChoiceHandler.seen) == 1
    payload = json.loads(ClaimChoiceHandler.seen[0])
    state = payload["state"]
    assert state["assessment_contract_version"] == "claim-assessment.2"
    assert state["candidate"]["evidence_refs"] == ["diff:u0"]
    assert state["primary_assessment"]["outcome"] == "NOT_SUPPORTED"
    assert [item["evidence_id"] for item in state["cited_evidence"]] == ["diff:u0"]
    row = result["claim_assessments"][0]
    assert row["status"] == "COMPLETE"
    assert row["response_valid"] is True
    assert row["provenance_valid"] is True
    assert row["provenance"]["primary_assessment_hash"] == row["primary_assessment_hash"]
    assert row["candidate_hash"] == row["provenance"]["candidate_hash"]
    assert row["assessments"]["introducedness"]["status"] == "NOT_SHOWN"


def test_complete_claim_result_requires_bound_provenance_and_all_answers(tmp_path):
    empty = _run(tmp_path / "empty", assessor=FakeClaimAssessor(empty_assessments=True), cap=1)
    corrupt = _run(tmp_path / "corrupt", assessor=FakeClaimAssessor(corrupt_provenance=True), cap=1)

    assert empty["claim_assessments"][0]["status"] == "FAILED"
    assert empty["claim_assessments"][0]["reason_code"] == "RESPONSE_SCHEMA_INVALID"
    assert corrupt["claim_assessments"][0]["status"] == "FAILED"
    assert corrupt["claim_assessments"][0]["reason_code"] == "RESPONSE_PROVENANCE_MISMATCH"
    assert empty["findings"] == corrupt["findings"]
    assert empty["disposition"] == corrupt["disposition"]


def test_empty_prepared_question_metadata_fails_before_reservation(tmp_path):
    result = _run(
        tmp_path,
        assessor=FakeClaimAssessor(empty_question_metadata=True),
        cap=1,
    )

    row = result["claim_assessments"][0]
    assert row["status"] == "FAILED"
    assert row["error_type"] == "ValueError"
    assert row["reservation_key"] is None
    assert not any(
        item.get("kind") == "claim_assessment" for item in result["ledger"]["budget"]["reservations"].values()
    )


@pytest.mark.parametrize("primary_outcome", ["SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"])
def test_shadow_assesses_each_valid_primary_outcome_without_rewriting_it(tmp_path, primary_outcome):
    snapshot = _snapshot()
    profile = _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    result = run_review(
        snapshot,
        plan,
        profile,
        PrimaryProvider(primary_outcome),
        None,
        LIMITS,
        str(tmp_path),
        "r1",
        claim_assessor=FakeClaimAssessor(),
        max_claim_assessments=1,
    )
    assert result["claim_assessments"][0]["status"] == "COMPLETE"
    assert result["findings"][0]["semantic_assessment"]["outcome"] == primary_outcome


def test_claim_cap_and_shared_provider_budget_fail_closed(tmp_path):
    capped = _run(tmp_path / "capped", assessor=FakeClaimAssessor(), cap=1)
    assert capped["claim_assessments"][0]["status"] == "COMPLETE"

    no_call_capacity = _run(
        tmp_path / "no-capacity",
        assessor=FakeClaimAssessor(),
        cap=1,
        limits={**LIMITS, "max_provider_calls": 2},
    )
    row = no_call_capacity["claim_assessments"][0]
    assert row["status"] == "NOT_RUN"
    assert row["reason_code"] == "PROVIDER_CALL_BUDGET_EXHAUSTED"
    assert len(no_call_capacity["ledger"]["budget"]["reservations"]) == 2


def test_unknown_budget_exception_text_is_not_persisted(tmp_path):
    marker = "private-budget-marker-do-not-persist"
    result = _run(tmp_path, assessor=FakeClaimAssessor(budget_error=marker), cap=1)
    row = result["claim_assessments"][0]
    saved = (tmp_path / "r1.json").read_text(encoding="utf-8")

    assert row["status"] == "NOT_RUN"
    assert row["reason_code"] == "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE"
    assert marker not in saved


def test_shadow_failure_preserves_primary_and_oversized_ipc_fails_closed(tmp_path):
    baseline = _run(tmp_path / "baseline")
    failed = _run(tmp_path / "failed", assessor=FakeClaimAssessor(status="FAILED"), cap=1)
    oversized = _run(
        tmp_path / "oversized",
        assessor=FakeClaimAssessor(padding_bytes=20_000),
        cap=1,
    )

    assert failed["claim_assessments"][0]["status"] == "FAILED"
    assert oversized["claim_assessments"][0]["status"] == "FAILED"
    assert oversized["claim_assessments"][0]["actual_output_bytes_observed"] > LIMITS["max_output_bytes_per_task"]
    assert oversized["claim_assessments"][0]["observed_output_limit_violation"] == {
        "actual_bytes": oversized["claim_assessments"][0]["actual_output_bytes_observed"],
        "reserved_bytes": LIMITS["max_output_bytes_per_task"],
    }
    for result in (failed,):
        assert result["disposition"] == baseline["disposition"]
        assert result["findings"] == baseline["findings"]
        assert result["budget"]["budget_breaches"] == baseline["budget"]["budget_breaches"]
    assert oversized["findings"] == baseline["findings"]
    assert oversized["disposition"] == "INCOMPLETE"
    assert oversized["budget"]["budget_breaches"] == [
        {
            "key": oversized["claim_assessments"][0]["reservation_key"],
            "reason": "OUTPUT_RESERVATION_OVERRUN",
            "actual": oversized["claim_assessments"][0]["actual_output_bytes_observed"],
            "reserved": LIMITS["max_output_bytes_per_task"],
        }
    ]


def test_enabled_claim_configuration_is_bound_to_resume_identity(tmp_path):
    first = _run(tmp_path, assessor=FakeClaimAssessor(), cap=1)
    assert first["claim_assessments"][0]["status"] == "COMPLETE"
    snapshot = _snapshot()
    profile = _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    with pytest.raises(ValueError, match="resume request mismatch"):
        run_review(
            snapshot,
            plan,
            profile,
            PrimaryProvider(),
            None,
            LIMITS,
            str(tmp_path),
            "r1",
            resume=True,
            claim_assessor=FakeClaimAssessor(),
            max_claim_assessments=2,
        )


def test_unsettled_shadow_reservation_is_not_redispatched_on_resume(tmp_path, monkeypatch):
    class SimulatedControllerCrash(BaseException):
        pass

    original_reserve = engine_module.BudgetLedger.reserve

    def crash_after_claim_reservation(self, key, estimate, *, kind="provider"):
        reservation = original_reserve(self, key, estimate, kind=kind)
        if kind == "claim_assessment":
            raise SimulatedControllerCrash()
        return reservation

    assessor = FakeClaimAssessor()
    monkeypatch.setattr(engine_module.BudgetLedger, "reserve", crash_after_claim_reservation)
    with pytest.raises(SimulatedControllerCrash):
        _run(tmp_path, assessor=assessor, cap=1)

    monkeypatch.setattr(engine_module.BudgetLedger, "reserve", original_reserve)
    snapshot = _snapshot()
    profile = _profile()
    result = run_review(
        snapshot,
        plan_review(snapshot, profile, "AUTO"),
        profile,
        PrimaryProvider(),
        None,
        LIMITS,
        str(tmp_path),
        "r1",
        resume=True,
        claim_assessor=assessor,
        max_claim_assessments=1,
    )

    row = result["claim_assessments"][0]
    assert row["status"] == "INTERRUPTED_UNKNOWN"
    assert row["reason_code"] == "PRIOR_SHADOW_ATTEMPT_UNSETTLED"
    assert assessor.prepare_calls == 1
    assert result["ledger"]["budget"]["settlements"][row["reservation_key"]]["status"] == "INTERRUPTED_UNKNOWN"


def test_final_callable_freshness_runs_after_timed_out_shadow_and_stale_still_gates(tmp_path):
    # With 18 seconds total, primary isolated calls leave less than eight
    # seconds for the shadow after its 16 second freshness reserve. The shadow
    # deliberately runs past its child deadline; the final freshness callback
    # must still be invoked and remains authoritative.
    timeout = _run(
        tmp_path / "timeout",
        assessor=FakeClaimAssessor(sleep_seconds=10),
        cap=1,
        limits={**LIMITS, "deadline_seconds": 18},
        freshness=Freshness("CURRENT"),
    )
    assert timeout["claim_assessments"][0]["status"] == "INTERRUPTED_UNKNOWN"
    assert timeout["freshness"] == "CURRENT"

    stale = _run(
        tmp_path / "stale",
        assessor=FakeClaimAssessor(),
        cap=1,
        limits={**LIMITS, "deadline_seconds": 24},
        freshness=Freshness("STALE"),
    )
    assert stale["claim_assessments"][0]["status"] == "COMPLETE"
    assert stale["freshness"] == "STALE"
    assert stale["disposition"] == "INCOMPLETE"
