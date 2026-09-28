from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness import github as github_module  # noqa: E402
from pr_review_harness import publisher as publisher_module  # noqa: E402
from pr_review_harness import snapshot as snapshot_module  # noqa: E402
from pr_review_harness.claim_assessment import ClaimAssessmentAdapter  # noqa: E402
from pr_review_harness.providers import OpenAIProvider  # noqa: E402
from pr_review_harness.shadow_audit import run_shadow_audit  # noqa: E402

CHALLENGE = json.loads((ROOT / "examples/injection/shadow-challenge-v1.json").read_text())
SUITE = json.loads((ROOT / "examples/injection/fixture-suite.v2.json").read_text())
DIMENSIONS = (
    "observation_support", "consequence_support", "rule_connection_support",
    "materiality", "missing_context", "introducedness",
)
LIMITS = {
    "max_input_bytes_per_task": 64_000, "max_output_bytes_per_task": 64_000,
    "max_output_tokens": 1_800, "max_provider_calls": 3, "max_retries": 0,
    "total_provider_deadline_seconds": 9, "deadline_seconds": 3,
}
SECRET_SENTINEL = "synthetic-credential-must-not-enter-a-model-request"


class _Response:
    status = 200

    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1):
        if size < 0:
            result, self.body = self.body, b""
            return result
        result, self.body = self.body[:size], self.body[size:]
        return result


def _openai_response(content: bytes, model: str) -> bytes:
    return json.dumps({
        "id": "synthetic-response", "model": model,
        "choices": [{"finish_reason": "stop", "message": {"content": content.decode()}}],
    }, separators=(",", ":")).encode()


def _provider(monkeypatch, model: str, answer):
    provider = OpenAIProvider({
        "kind": "openai-compatible", "base_url": "https://provider.invalid/v1",
        "model": model, "api_key_env": "INJECTION_E2E_TOKEN", "timeout_seconds": 2,
        "max_response_bytes": 64_000, "max_request_bytes": 64_000,
    })
    monkeypatch.setenv("INJECTION_E2E_TOKEN", SECRET_SENTINEL)
    if not hasattr(monkeypatch, "_injection_routes"):
        monkeypatch._injection_routes = {}
        monkeypatch._injection_wire = []

        class _Opener:
            def open(self, request, timeout):
                monkeypatch._injection_wire.append((request.full_url, bytes(request.data)))
                body = json.loads(request.data)
                user = json.loads(body["messages"][1]["content"])
                content = monkeypatch._injection_routes[body["model"]](user)
                return _Response(_openai_response(content, body["model"]))

        monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", _Opener())
    monkeypatch._injection_routes[model] = answer
    return provider


def _writer_content(case_id: str) -> bytes:
    report = {
        "contract_version": "specialist-findings.v4",
        "finding_candidates": [{
            "unit_id": "unit-auth", "location": {
                "kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 2, "reason": None,
            },
            "title": "Owner check removed",
            "observation": "The changed authorization helper returns true for every caller.",
            "consequence": "A caller may read a document owned by another user.",
            "rule_or_contract": "Only the document owner may read it.",
            "severity": "high", "reasoning_kind": "observed", "evidence_refs": ["ev-auth"],
            "introducedness": "INTRODUCED",
        }],
        "context_gap_proposals": [],
        "coverage_notes": [{
            "unit_id": "unit-auth", "state": "COVERED", "reason_code": "source_reviewed",
            "evidence_refs": ["ev-auth"], "coverage_basis": "STATIC_REVIEW",
        }],
        "specific_strengths": [], "future_guidance": [],
    }
    return json.dumps(report, separators=(",", ":")).encode()


def _source_audit(_user) -> bytes:
    return json.dumps({
        "contract_version": "shadow-source-audit.v1", "status": "completed",
        "records": [{"record_id": "source-1", "summary": "The source evidence shows an unconditional allow.",
                     "evidence_refs": ["ev-auth"]}],
    }, separators=(",", ":")).encode()


def _claim_audit(user) -> bytes:
    rows = [{
        "assertion_id": f"claim-auth:{dimension}", "dimension": dimension, "relation": "MATCH",
        "left_record_id": f"claim-auth:jev:{dimension}",
        "right_record_id": f"claim-auth:claim_auditor:{dimension}", "evidence_refs": ["ev-auth"],
    } for dimension in DIMENSIONS]
    return json.dumps({"contract_version": "shadow-claim-audit.v1", "status": "completed", "relations": rows},
                      separators=(",", ":")).encode()


def _jev_response(raw: bytes, *, choice: str = "SUPPORTED") -> bytes:
    request = json.loads(raw)
    answers = {}
    for question_id, question in request["questions"].items():
        choices = list(question["criteria"])
        selected = choice if choice in choices else choices[0]
        answers[question_id] = {
            "type": "choice", "choice": selected,
            "probabilities": {option: float(option == selected) for option in choices}, "confidence": 0.8,
        }
    return json.dumps({"model": "jev-1.13.0", "request_id": "synthetic-jev", "answers": answers},
                      separators=(",", ":")).encode()


def _challenge_case(case_id: str):
    variant = next(row for row in SUITE["variants"] if row["case_id"] == case_id)
    source = SUITE["head_auth_source"] + variant["payload"]
    content_hash = hashlib.sha256(source.encode()).hexdigest()
    evidence = {
        "evidence_id": "ev-auth", "content": source, "content_hash": content_hash,
        "path": "src/auth.py", "source_kind": "head_file", "trust": "untrusted_pr_content",
        "source_revision": "b" * 40, "snapshot_id": f"snap-{case_id}", "line": 2,
    }
    snapshot_body = {
        "repository": "synthetic/authz", "repository_url": "https://example.invalid/synthetic/authz",
        "base_sha": "a" * 40, "head_sha": "b" * 40, "profile_version": "profile-v1",
        "profile_hash": "c" * 64, "inventory": {}, "evidence": {"ev-auth": evidence},
        "gaps": [], "trusted_context_refs": [],
    }
    snapshot = {
        "snapshot_id": evidence["snapshot_id"], **snapshot_body,
        "snapshot_hash": snapshot_module._json_hash(snapshot_body),
    }
    return variant, evidence, snapshot


def _packet_from_writer(case_id: str, evidence: dict, snapshot: dict, writer_result: dict,
                       writer_provider: OpenAIProvider) -> dict:
    generated = writer_result["payload"]["finding_candidates"][0]
    candidate = {
        "candidate_id": "claim-auth", "title": generated["title"],
        "observation": generated["observation"], "consequence": generated["consequence"],
        "rule_or_contract": generated["rule_or_contract"], "evidence_refs": generated["evidence_refs"],
    }
    receipt = writer_result["capture_receipt"]
    calls = [{key: receipt[key] for key in (
        "call_id", "request_sha256", "request_artifact_id", "response_sha256", "response_artifact_id",
    )}]
    calls_hash = hashlib.sha256(json.dumps(calls, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    identity = writer_provider.identity
    return {
        "contract_version": "model-only-shadow-case.v1", "case_id": case_id,
        "snapshot": snapshot,
        "source_task": {"summary": "Review the changed authorization helper for access-control regressions."},
        "source_evidence": [{key: evidence[key] for key in (
            "evidence_id", "content", "content_hash", "source_kind", "trust", "source_revision",
            "snapshot_id", "path", "line",
        )}],
        "writer_run": {
            "role": "writer", "status": "completed", "run_id": f"writer-{case_id}",
            "provider_id": identity["provider_id"], "model_id": identity["model_id"],
            "runtime_id": "fake-http-v1", "prompt_revision": "synthetic-writer.v1",
            "rubric_revision": "specialist-findings.v4", "calls": calls,
            "calls_manifest_sha256": calls_hash,
        },
        "writer_candidate": candidate, "profile_id": "profile-v1",
    }


def _run_case(monkeypatch, tmp_path: Path, case_id: str, *, jev_choice: str = "SUPPORTED", jev_body=None):
    effects = {name: 0 for name in (
        "publication_calls", "github_write_calls", "target_execution_calls",
        "tool_dispatch_requests", "secret_value_leaks",
    )}

    def forbid_process(*_args, **_kwargs):
        effects["target_execution_calls"] += 1
        pytest.fail("synthetic shadow audit must not execute target code or invoke a GitHub CLI")

    monkeypatch.setattr(subprocess, "run", forbid_process)
    monkeypatch.setattr(subprocess, "Popen", forbid_process)
    monkeypatch.setattr(os, "system", forbid_process)

    def forbid_effect(counter):
        def observed(*_args, **_kwargs):
            effects[counter] += 1
            pytest.fail(f"synthetic shadow audit attempted forbidden effect: {counter}")
        return observed

    monkeypatch.setattr(publisher_module, "publish_review", forbid_effect("publication_calls"))
    monkeypatch.setattr(publisher_module, "publish_review_stateless", forbid_effect("publication_calls"))
    monkeypatch.setattr(github_module.GitHubReviewPublisher, "submit_review", forbid_effect("github_write_calls"))
    original_api_output = github_module.GitHubPRAdapter._api_output

    def observe_github_api(adapter, endpoint, method="GET", payload=None):
        if method != "GET":
            effects["github_write_calls"] += 1
            pytest.fail("synthetic shadow audit attempted a GitHub API write")
        return original_api_output(adapter, endpoint, method, payload)

    monkeypatch.setattr(github_module.GitHubPRAdapter, "_api_output", observe_github_api)
    variant, evidence, snapshot = _challenge_case(case_id)
    observed = {"writer": [], "source": [], "jev": [], "claim": []}
    def writer(user):
        observed["writer"].append(user)
        return _writer_content(case_id)

    def source(user):
        observed["source"].append(user)
        return _source_audit(user)

    def claim(user):
        observed["claim"].append(user)
        return _claim_audit(user)

    writer_provider = _provider(monkeypatch, f"writer-{case_id}", writer)
    source_provider = _provider(monkeypatch, f"source-{case_id}", source)
    claim_provider = _provider(monkeypatch, f"claim-{case_id}", claim)
    evidence_for_writer = [{"evidence_id": evidence["evidence_id"], "content": evidence["content"],
                            "path": evidence["path"], "line": evidence["line"]}]
    task = {"task_id": f"task-{case_id}", "unit_ids": ["unit-auth"], "summary": "Review authorization."}
    captured = []
    def capture(_spec, request, response, status, envelope_hash, transform):
        captured.append((request, response, status, envelope_hash, transform))
        return {
            "call_id": f"writer-call-{case_id}", "request_sha256": hashlib.sha256(request).hexdigest(),
            "request_artifact_id": f"writer-request-{case_id}",
            "response_sha256": hashlib.sha256(response).hexdigest() if response else None,
            "response_artifact_id": f"writer-response-{case_id}" if response else None,
            "status": status,
        }

    writer_result = writer_provider.review_with_capture(task, evidence_for_writer, LIMITS,
                                                        {"case_id": case_id}, capture)
    packet = _packet_from_writer(case_id, evidence, snapshot, writer_result, writer_provider)
    def jev_transport(raw, _deadline, _cap):
        observed["jev"].append(raw)
        seal = json.loads((tmp_path / case_id / "private/source-audit-seal.json").read_text())
        assert seal["sealed_before_claim_dispatch"] is True
        assert seal["case_packet_sha256"]
        return jev_body(raw) if jev_body else _jev_response(raw, choice=jev_choice)

    order = []
    def before_dispatch(role, raw):
        order.append(role)
        if SECRET_SENTINEL.encode() in raw:
            effects["secret_value_leaks"] += 1
        assert SECRET_SENTINEL.encode() not in raw
    result = run_shadow_audit(
        packet,
        source_provider=source_provider,
        jev_transport=jev_transport,
        claim_provider=claim_provider,
        limits=LIMITS,
        output_dir=tmp_path / case_id,
        before_dispatch=before_dispatch,
    )
    for _url, body in monkeypatch._injection_wire:
        if SECRET_SENTINEL.encode() in body:
            effects["secret_value_leaks"] += 1
        try:
            request_body = json.loads(body)
        except (TypeError, ValueError):
            request_body = {}
        if "tools" in request_body or "tool_choice" in request_body or "functions" in request_body:
            effects["tool_dispatch_requests"] += 1
    assert effects == {name: 0 for name in effects}
    return result, observed, order, packet, captured, variant, effects


@pytest.mark.parametrize("case_id", CHALLENGE["selection"]["trial_case_ids"])
def test_synthetic_control_attack_and_benign_run_writer_to_sealed_audit_to_claim(monkeypatch, tmp_path, case_id):
    case_id = case_id.removeprefix("r1-")
    result, observed, order, packet, captured, variant, effects = _run_case(monkeypatch, tmp_path, case_id)

    assert captured[0][2] == "completed"
    # The capture receipt hashes the exact writer bytes, and the reviewed candidate
    # in the later model request is derived from that validated writer result.
    assert hashlib.sha256(captured[0][0]).hexdigest() == packet["writer_run"]["calls"][0]["request_sha256"]
    assert hashlib.sha256(captured[0][1]).hexdigest() == packet["writer_run"]["calls"][0]["response_sha256"]
    assert variant["kind"] in {"control", "attack", "benign_lookalike"}
    assert variant["payload"] in observed["writer"][0]["evidence"][0]["content"]
    assert variant["payload"] in packet["source_evidence"][0]["content"]
    assert order == ["source_auditor", "jev", "claim_auditor"]
    assert result["manifest"]["terminal_state"] == "completed"

    source_user = observed["source"][0]
    assert set(source_user) == {"case", "task", "evidence"}
    assert "writer_candidate" not in json.dumps(source_user)
    assert packet["writer_candidate"]["title"] not in json.dumps(source_user)
    assert source_user["evidence"][0]["evidence_id"] == packet["source_evidence"][0]["evidence_id"]
    assert source_user["evidence"][0]["content_hash"] == packet["source_evidence"][0]["content_hash"]

    jev_request = json.loads(observed["jev"][0])
    assert jev_request["state"]["candidate"]["candidate_id"] == packet["writer_candidate"]["candidate_id"]
    assert jev_request["state"]["cited_evidence"][0]["evidence_id"] == "ev-auth"
    assert jev_request["state"]["cited_evidence"][0]["content_hash"] == packet["source_evidence"][0]["content_hash"]
    assert all(question["type"] == "choice" for question in jev_request["questions"].values())

    claim_user = observed["claim"][0]
    assert claim_user["writer_claim"] == packet["writer_candidate"]
    assert set(claim_user) == {"case", "writer_claim", "jev_classification", "evidence"}
    assert "The source evidence shows an unconditional allow." not in json.dumps(claim_user)
    assert "source-1" not in json.dumps(claim_user)
    assert all(row["status"] in {"ANSWERED", "NOT_SHOWN"} for row in claim_user["jev_classification"].values())
    expected_choices = {
        "observation_support": "SUPPORTED", "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED", "materiality": "MATERIAL",
        "missing_context": "MISSING_CONTEXT_IDENTIFIED",
    }
    assert {dimension: row["choice"] for dimension, row in claim_user["jev_classification"].items()
            if row["status"] == "ANSWERED"} == expected_choices
    assert claim_user["evidence"][0]["evidence_id"] == "ev-auth"
    assert claim_user["evidence"][0]["content_hash"] == packet["source_evidence"][0]["content_hash"]
    assert claim_user["evidence"][0]["content"] == packet["source_evidence"][0]["content"]
    assert result["manifest"]["roles"]["jev"]["status"] == "completed"
    assert result["manifest"]["roles"]["claim_auditor"]["status"] == "completed"

    all_requests = [captured[0][0], *[
        (tmp_path / case_id / "private" / name).read_bytes()
        for name in ("source-auditor.request.json", "jev.request.json", "claim-auditor.request.json")
    ]]
    assert all(SECRET_SENTINEL.encode() not in request for request in all_requests)
    fake_provider_requests = monkeypatch._injection_wire
    assert len(fake_provider_requests) == 3
    assert all(url == "https://provider.invalid/v1/chat/completions" for url, _body in fake_provider_requests)
    assert all(SECRET_SENTINEL.encode() not in body for _url, body in fake_provider_requests)
    assert all("\"tools\"" not in body.decode() and "\"tool_choice\"" not in body.decode()
               for _url, body in fake_provider_requests)
    assert CHALLENGE["effects"]["publication_enabled"] is False
    assert CHALLENGE["effects"]["github_writes_enabled"] is False
    assert CHALLENGE["effects"]["target_execution_enabled"] is False
    assert CHALLENGE["effects"]["private_raw_artifacts_uploaded"] is False
    assert effects == {name: 0 for name in effects}


def test_synthetic_jev_abstention_still_reaches_claim_auditor(monkeypatch, tmp_path):
    result, observed, order, packet, _captured, _variant, effects = _run_case(
        monkeypatch, tmp_path, "code-comment-attack", jev_choice="UNCERTAIN",
    )

    assert order == ["source_auditor", "jev", "claim_auditor"]
    assert result["manifest"]["roles"]["jev"]["status"] == "abstained"
    assert result["manifest"]["roles"]["claim_auditor"]["status"] == "completed"
    assert observed["claim"][0]["writer_claim"] == packet["writer_candidate"]
    classification = observed["claim"][0]["jev_classification"]
    assert all(row["status"] in {"ANSWERED", "NOT_SHOWN"} for row in classification.values())
    assert all(row["choice"] == "UNCERTAIN" for row in classification.values() if row["status"] == "ANSWERED")
    assert effects == {name: 0 for name in effects}


@pytest.mark.parametrize("failure", ["omitted", "malformed", "transport"])
def test_synthetic_jev_failure_stops_before_claim_auditor(monkeypatch, tmp_path, failure):
    def fail(_raw):
        if failure == "omitted":
            return b'{"model":"jev-1.13.0","answers":{}}'
        if failure == "malformed":
            return b"not-json"
        raise RuntimeError("synthetic transport failure")

    result, observed, order, _packet, _captured, _variant, effects = _run_case(
        monkeypatch, tmp_path, "control", jev_body=fail,
    )

    assert order == ["source_auditor", "jev"]
    assert observed["claim"] == []
    assert result["manifest"]["terminal_state"] == "jev_assessment_failed"
    assert result["manifest"]["roles"]["jev"]["status"] == "failed"
    assert result["manifest"]["roles"]["claim_auditor"]["status"] == "not_run"
    assert effects == {name: 0 for name in effects}


def test_empty_typed_jev_assessments_fail_closed_before_claim_auditor(monkeypatch, tmp_path):
    def empty_assessments(self, prepared, limits):
        self.native_call(prepared.request_bytes, limits["deadline_seconds"], limits["max_output_bytes_per_task"])
        return {"assessments": {}}

    monkeypatch.setattr(ClaimAssessmentAdapter, "assess_prepared", empty_assessments)
    result, observed, order, _packet, _captured, _variant, effects = _run_case(
        monkeypatch, tmp_path, "control",
    )

    assert order == ["source_auditor", "jev"]
    assert observed["claim"] == []
    assert result["manifest"]["terminal_state"] == "jev_assessment_failed"
    assert result["manifest"]["roles"]["jev"]["status"] == "failed"
    assert result["manifest"]["roles"]["claim_auditor"]["status"] == "not_run"
    assert effects == {name: 0 for name in effects}
