from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from pr_review_harness.claim_assessment import _DIMENSIONS as JEV_CHOICES
from pr_review_harness.claim_assessment import CONTRACT_VERSION as JEV_VERSION
from pr_review_harness.claim_assessment import _question_id
from pr_review_harness.cross_model_package import build_cross_model_package, validate_model_teacher_packet_identity
from pr_review_harness.cross_model_v2 import calls_manifest_sha256
from pr_review_harness.evaluation import EvaluationError
from pr_review_harness.private_capture import CONTENT_TRANSFORM, PrivateShadowCapture, write_provider_exchange

ROOT = Path(__file__).resolve().parents[1]
DIMENSIONS = (
    "observation_support", "consequence_support", "rule_connection_support",
    "materiality", "missing_context", "introducedness",
)


def _json_bytes(value, *, ascii_only=False):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only, allow_nan=False).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _role(role, response_id, request_id, request, response, status="completed"):
    calls = [{
        "call_id": f"{role}-call-1", "request_sha256": _sha(request), "request_artifact_id": request_id,
        "response_sha256": _sha(response), "response_artifact_id": response_id,
    }]
    return {
        "role": role, "status": status, "run_id": f"{role}-run-1", "provider_id": f"provider-{role}",
        "model_id": f"model-{role}-1", "runtime_id": f"runtime-{role}-1", "prompt_revision": f"prompt-{role}-v1",
        "rubric_revision": f"rubric-{role}-v1", "calls": calls,
        "calls_manifest_sha256": calls_manifest_sha256(calls),
    }


def _fixture(tmp_path, *, duplicate_candidate=False):
    corpus = deepcopy(json.loads((ROOT / "examples/evaluation/corpus.json").read_text()))
    identity = corpus["cases"][0]["identity"]
    profile = {"profile_id": identity["profile"]["profile_id"], "version": identity["profile"]["version"],
               "required_lenses": ["correctness"]}
    identity["profile"]["sha256"] = _sha(_json_bytes(profile, ascii_only=True))
    case_id = identity["case_id"]
    writer_run_id = "writer-run-1"
    task_id = "task-7"
    evidence = {
        "evidence_id": "ev-1", "content": "Über untrusted excerpt includes writer_candidate and jev_classification words.",
        "content_hash": _sha("Über untrusted excerpt includes writer_candidate and jev_classification words.".encode()),
        "source_kind": "head_file", "trust": "repository_evidence", "source_revision": identity["head_sha"],
        "snapshot_id": identity["snapshot_id"], "path": "src/example.py", "line": 7,
    }
    snapshot_body = {
        "repository": "magnus919/SlopSearX", "repository_url": "https://github.com/magnus919/SlopSearX",
        "base_sha": identity["base_sha"], "head_sha": identity["head_sha"],
        "profile_version": profile["version"], "profile_hash": identity["profile"]["sha256"],
        "inventory": [], "evidence": {"ev-1": evidence},
        "gaps": [], "trusted_context_refs": [],
    }
    snapshot = {"snapshot_id": identity["snapshot_id"], **snapshot_body,
                "snapshot_hash": _sha(_json_bytes(snapshot_body, ascii_only=True))}
    source_task = {"task_id": task_id, "summary": "Review the supplied handler."}
    raw_candidate = {
        "path": "src/example.py", "line": 7, "title": "Missing validation — Über", "observation": "The handler forwards an unchecked value.",
        "consequence": "A malformed value may fail unexpectedly.", "rule_or_contract": "Inputs must be validated.",
        "severity": "medium", "reasoning_kind": "inferred", "evidence_refs": ["ev-1"],
    }
    writer_candidate = {
        "candidate_id": _sha(_json_bytes({"task_id": task_id, "index": 0, "raw": raw_candidate}, ascii_only=True))[:24],
        **{key: raw_candidate[key] for key in ("title", "observation", "consequence", "rule_or_contract", "evidence_refs")},
    }
    capture_root = tmp_path / "capture"
    task_payload = {"task": source_task, "evidence": [evidence]}
    writer_request = _json_bytes({"model": "writer-model", "messages": [
        {"role": "system", "content": "review"}, {"role": "user", "content": _json_bytes(task_payload).decode()},
    ]})
    writer_findings = [raw_candidate, deepcopy(raw_candidate)] if duplicate_candidate else [raw_candidate]
    writer_response = _json_bytes({"contract_version": "specialist-findings.v4", "finding_candidates": writer_findings,
                                   "context_gap_proposals": [], "coverage_notes": []})
    writer_provider = type("WriterProvider", (), {"identity": {
        "provider_id": "writer-provider", "model_id": "writer-model", "adapter_version": "writer-adapter-v1",
    }})()
    capture = PrivateShadowCapture(
        capture_root, case_id=writer_run_id, corpus_case_id=case_id, snapshot=snapshot,
        source_task=writer_run_id, provider=writer_provider, request_byte_limit=128_000, response_byte_limit=32_768,
    )
    capture.export_source_tasks([{"task": source_task, "evidence": [evidence]}],
                                profile_id=identity["profile"]["profile_id"])
    capture_spec = capture.begin_call(run_id=writer_run_id, task_id=task_id, attempt=1)
    capture_spec.update(root=str(capture_root), provider=capture.provider_identity)
    receipt = write_provider_exchange(capture_spec, writer_request, writer_response, "completed", "b" * 64, CONTENT_TRANSFORM)
    capture.reconcile(capture_spec)
    result = {
        "snapshot_id": snapshot["snapshot_id"], "run_id": writer_run_id,
        "findings": [{"assessment_records": [{"candidate_id": writer_candidate["candidate_id"], "task_id": task_id}]}],
        "task_results": {task_id: {"status": "SUCCEEDED", "payload": {"finding_candidates": writer_findings}}},
    }
    packet_path = capture.export_case_packets(result, profile=profile)[0]
    packet = json.loads(packet_path.read_text())
    assert packet["case_id"] == case_id
    assert packet["writer_run"]["run_id"] == writer_run_id
    assert receipt["status"] == "completed"

    shadow_root = tmp_path / "shadow"
    private = shadow_root / "private"
    private.mkdir(parents=True)
    (private / "case-packet.json").write_bytes(_json_bytes(packet, ascii_only=True))
    (private / "snapshot.json").write_bytes(_json_bytes(snapshot, ascii_only=True))
    source_user = {"case": {"case_id": case_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
                            "base_sha": snapshot["base_sha"], "head_sha": snapshot["head_sha"], "profile_id": packet["profile_id"],
                            "profile_hash": snapshot["profile_hash"]}, "task": source_task, "evidence": [evidence]}
    source_request = _json_bytes({"model": "source-model", "messages": [
        {"role": "system", "content": "source-only"}, {"role": "user", "content": _json_bytes(source_user).decode()},
    ]})
    source_response = _json_bytes({"contract_version": "shadow-source-audit.v1", "status": "completed",
                                   "records": [{"record_id": "source-note-1", "summary": "A grounded observation.", "evidence_refs": ["ev-1"]}]})
    jev_state = {"candidate": writer_candidate, "cited_evidence": [evidence], "assessment_identity": {
        "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"], "profile_id": packet["profile_id"],
        "profile_hash": snapshot["profile_hash"], "base_sha": snapshot["base_sha"], "head_sha": snapshot["head_sha"]
    }}
    questions = {}
    answers = {}
    jev_classification = {}
    for dimension in DIMENSIONS:
        qid = _question_id(writer_candidate["candidate_id"], dimension, JEV_VERSION)
        questions[qid] = {"criteria": JEV_CHOICES[dimension]}
        selected = next(iter(JEV_CHOICES[dimension]))
        answers[qid] = {"type": "choice", "choice": selected,
                        "probabilities": {option: float(option == selected) for option in JEV_CHOICES[dimension]},
                        "confidence": 0.8}
        record_id = f"{writer_candidate['candidate_id']}:jev:{dimension}"
        jev_classification[dimension] = {"record_id": record_id, "status": "ANSWERED", "choice": selected,
                                        "evidence_refs": ["ev-1"]}
    jev_request = _json_bytes({"model": "jev-model", "state": jev_state, "questions": questions})
    jev_response = _json_bytes({"model": "jev-1.13.0", "request_id": "jev-request-1", "answers": answers})
    claim_user = {"case": {"case_id": case_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"]},
                  "writer_claim": writer_candidate, "jev_classification": jev_classification, "evidence": [evidence]}
    claim_request = _json_bytes({"model": "claim-model", "messages": [
        {"role": "system", "content": "claim audit"}, {"role": "user", "content": _json_bytes(claim_user).decode()},
    ]})
    claim_relations = [{"assertion_id": f"{writer_candidate['candidate_id']}:{dimension}", "dimension": dimension,
                        "relation": "UNKNOWN", "left_record_id": f"{writer_candidate['candidate_id']}:jev:{dimension}",
                        "right_record_id": f"{writer_candidate['candidate_id']}:claim_auditor:{dimension}",
                        "evidence_refs": ["ev-1"]} for dimension in DIMENSIONS]
    claim_response = _json_bytes({"contract_version": "shadow-claim-audit.v1", "status": "completed", "relations": claim_relations})
    role_data = {
        "source_auditor": ("source-auditor-request", "source-auditor-response", source_request, source_response),
        "jev": ("jev-request", "jev-response", jev_request, jev_response),
        "claim_auditor": ("claim-auditor-request", "claim-auditor-response", claim_request, claim_response),
    }
    roles = {"writer": packet["writer_run"]}
    for role, (request_id, response_id, request_raw, response_raw) in role_data.items():
        (private / f"{role.replace('_', '-')}.request.json").write_bytes(request_raw)
        (private / f"{role.replace('_', '-')}.response.json").write_bytes(response_raw)
        roles[role] = _role(role, response_id, request_id, request_raw, response_raw)
    (private / "source-audit-seal.json").write_bytes(_json_bytes({
        "contract_version": "source-audit-seal.v1", "case_id": case_id,
        "case_packet_sha256": _sha(_json_bytes(packet, ascii_only=True)), "snapshot_id": snapshot["snapshot_id"],
        "snapshot_hash": snapshot["snapshot_hash"], "source_auditor_run_id": roles["source_auditor"]["run_id"],
        "source_auditor_status": "completed", "source_response_sha256": _sha(source_response),
        "sealed_before_claim_dispatch": True,
    }, ascii_only=True))
    shadow_manifest = {
        "contract_version": "model-only-shadow-audit.v1", "case_id": case_id,
        "case_packet_sha256": _sha(_json_bytes(packet, ascii_only=True)), "snapshot_id": snapshot["snapshot_id"],
        "snapshot_hash": snapshot["snapshot_hash"], "snapshot_artifact_sha256": _sha(_json_bytes(snapshot, ascii_only=True)),
        "base_sha": snapshot["base_sha"], "head_sha": snapshot["head_sha"], "terminal_state": "completed",
        "roles": roles, "terminal_details": {}, "transport_response_sha256": {},
    }
    (shadow_root / "shadow-audit-manifest.json").write_bytes(_json_bytes(shadow_manifest, ascii_only=True))
    out = tmp_path / "packaged"
    return corpus, packet_path, capture_root, shadow_root, out, packet, shadow_manifest


def test_package_verifies_four_role_bytes_and_reports_only_advisory_presence(tmp_path):
    corpus, packet_path, capture_root, shadow_root, out, packet, shadow = _fixture(tmp_path)
    result = build_cross_model_package(corpus_value=corpus, case_packet_path=packet_path,
                                      capture_root=capture_root, shadow_root=shadow_root, output_dir=out)
    report = result["report"]
    assert report["artifact_verification"]["status_counts"]["VERIFIED"] == 8
    assert report["assertion_verification"]["verified_structured_relation_count"] == 6
    assert report["relation_counts"]["writer_jev"]["denominator"] == 0
    assert report["role_record_counts"]["source_auditor"]["record_denominator"] == 1
    assert report["claims"] == {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None}
    assert "semantic truth" in report["relation_semantics"]
    assert packet["source_evidence"][0]["content"].startswith("Über untrusted excerpt")
    assert (out / "comparison-v2.json").stat().st_mode & 0o777 == 0o600
    assert (out / "comparison-report.json").stat().st_mode & 0o777 == 0o600
    assert not any(value in (out / "comparison-report.json").read_text() for value in ("Missing validation", "Über untrusted excerpt"))


def test_model_teacher_corpus_accepts_only_the_pinned_pr464_packet_identity():
    corpus_root = ROOT / "examples/evaluation/model-only-shadow-pr464-v1"
    corpus = json.loads((corpus_root / "corpus.json").read_text())
    manifest = json.loads((corpus_root / "manifest.json").read_text())
    plan_raw = (ROOT / manifest["plan_path"]).read_bytes()
    plan = json.loads(plan_raw)
    plan_sha256 = _sha(plan_raw)
    case = corpus["cases"][0]["identity"]
    packet = {
        "contract_version": "model-only-shadow-case.v1",
        "case_id": manifest["case_id"],
        "snapshot": {
            "snapshot_id": case["snapshot_id"],
            "snapshot_hash": manifest["snapshot_sha256"],
            "base_sha": case["base_sha"],
            "head_sha": case["head_sha"],
            "profile_version": case["profile"]["version"],
            "profile_hash": case["profile"]["sha256"],
        },
    }
    validate_model_teacher_packet_identity(corpus, packet, manifest, plan, plan_sha256)
    assert manifest["reviewer_kind"] == "model_teacher"
    assert manifest["gold_labels"] == {"status": "UNAVAILABLE", "packets_present": 0}
    assert manifest["accuracy_claims"] == "NOT_ESTIMABLE_FROM_THIS_CORPUS"

    discovery_corpus = json.loads((ROOT / "examples/evaluation/corpus.json").read_text())
    with pytest.raises(EvaluationError, match="evaluation_identity_manifest_invalid"):
        validate_model_teacher_packet_identity(discovery_corpus, packet, manifest, plan, plan_sha256)

    packet["snapshot"]["snapshot_id"] = "snap-c54e437de81bc6a7e9ae5d6a"
    with pytest.raises(EvaluationError, match="case_snapshot_corpus_mismatch"):
        validate_model_teacher_packet_identity(corpus, packet, manifest, plan, plan_sha256)


def test_model_teacher_corpus_rejects_a_profile_mismatch():
    corpus_root = ROOT / "examples/evaluation/model-only-shadow-pr464-v1"
    corpus = json.loads((corpus_root / "corpus.json").read_text())
    manifest = json.loads((corpus_root / "manifest.json").read_text())
    plan_raw = (ROOT / manifest["plan_path"]).read_bytes()
    plan = json.loads(plan_raw)
    plan_sha256 = _sha(plan_raw)
    packet = {
        "case_id": manifest["case_id"],
        "snapshot": {
            "snapshot_id": manifest["snapshot_id"], "snapshot_hash": manifest["snapshot_sha256"],
            "base_sha": manifest["base_sha"], "head_sha": manifest["head_sha"],
            "profile_version": "slopsearx-production-v2", "profile_hash": "1" * 64,
        },
    }
    with pytest.raises(EvaluationError, match="case_snapshot_corpus_mismatch"):
        validate_model_teacher_packet_identity(corpus, packet, manifest, plan, plan_sha256)


@pytest.mark.parametrize("non_object", [[], "not-an-object", 7])
def test_package_cli_sanitizes_non_object_corpus_values(monkeypatch, capsys, non_object):
    import scripts.package_cross_model_v2 as cli

    monkeypatch.setattr(cli, "_json", lambda *_args: (non_object, b"invalid-shape"))
    status = cli.main([
        "--corpus", "unused.json",
        "--capture-root", "unused-capture",
        "--case-packet", "unused-packet.json",
        "--shadow-root", "unused-shadow",
        "--output-dir", "unused-output",
        "--json",
    ])
    assert status == 2
    assert json.loads(capsys.readouterr().out) == {"ok": False, "error_code": "package_json_shape_invalid"}


def test_duplicate_matching_writer_candidate_fails_even_when_hashes_are_bound(tmp_path):
    corpus, packet_path, capture_root, shadow_root, out, _, _ = _fixture(tmp_path, duplicate_candidate=True)
    with pytest.raises(EvaluationError, match="writer_candidate_response_missing_or_ambiguous"):
        build_cross_model_package(corpus_value=corpus, case_packet_path=packet_path,
                                  capture_root=capture_root, shadow_root=shadow_root, output_dir=out)


def test_writer_request_for_another_task_fails_even_with_updated_receipt_hash(tmp_path):
    corpus, packet_path, capture_root, shadow_root, out, packet, shadow = _fixture(tmp_path)
    request = _json_bytes({"model": "writer-model", "messages": [
        {"role": "system", "content": "review"},
        {"role": "user", "content": _json_bytes({"task": {"task_id": "other-task"}, "evidence": packet["source_evidence"]}).decode()},
    ]})
    call_id = packet["writer_run"]["calls"][0]["call_id"]
    (capture_root / "requests" / f"{call_id}.bin").write_bytes(request)
    packet["writer_run"]["calls"][0]["request_sha256"] = _sha(request)
    packet["writer_run"]["calls_manifest_sha256"] = calls_manifest_sha256(packet["writer_run"]["calls"])
    packet_path.write_bytes(_json_bytes(packet))
    shadow_packet_raw = _json_bytes(packet, ascii_only=True)
    (shadow_root / "private/case-packet.json").write_bytes(shadow_packet_raw)
    shadow["case_packet_sha256"] = _sha(shadow_packet_raw)
    (shadow_root / "private/source-audit-seal.json").write_bytes(_json_bytes({
        "contract_version": "source-audit-seal.v1", "case_id": packet["case_id"],
        "case_packet_sha256": _sha(shadow_packet_raw), "snapshot_id": packet["snapshot"]["snapshot_id"],
        "snapshot_hash": packet["snapshot"]["snapshot_hash"], "source_auditor_run_id": shadow["roles"]["source_auditor"]["run_id"],
        "source_auditor_status": "completed", "source_response_sha256": shadow["roles"]["source_auditor"]["calls"][0]["response_sha256"],
        "sealed_before_claim_dispatch": True,
    }, ascii_only=True))
    (shadow_root / "shadow-audit-manifest.json").write_bytes(_json_bytes(shadow, ascii_only=True))
    capture = json.loads((capture_root / "manifest.json").read_text())
    capture["calls"][0]["request_sha256"] = _sha(request)
    (capture_root / "manifest.json").write_bytes(_json_bytes(capture))
    with pytest.raises(EvaluationError, match="writer_request_task_binding_mismatch"):
        build_cross_model_package(corpus_value=corpus, case_packet_path=packet_path,
                                  capture_root=capture_root, shadow_root=shadow_root, output_dir=out)


def test_claim_audit_cannot_bind_to_a_mutated_jev_classification(tmp_path):
    corpus, packet_path, capture_root, shadow_root, out, _, shadow = _fixture(tmp_path)
    claim_call = shadow["roles"]["claim_auditor"]["calls"][0]
    claim_request_path = shadow_root / "private/claim-auditor.request.json"
    payload = json.loads(claim_request_path.read_text())
    user = json.loads(payload["messages"][1]["content"])
    user["jev_classification"]["observation_support"]["choice"] = "CONTRADICTED"
    payload["messages"][1]["content"] = _json_bytes(user).decode()
    request = _json_bytes(payload)
    claim_request_path.write_bytes(request)
    claim_call["request_sha256"] = _sha(request)
    shadow["roles"]["claim_auditor"]["calls_manifest_sha256"] = calls_manifest_sha256([claim_call])
    (shadow_root / "shadow-audit-manifest.json").write_bytes(_json_bytes(shadow, ascii_only=True))
    with pytest.raises(EvaluationError, match="jev_classification_response_mismatch"):
        build_cross_model_package(corpus_value=corpus, case_packet_path=packet_path,
                                  capture_root=capture_root, shadow_root=shadow_root, output_dir=out)


def test_private_capture_emits_the_packet_and_run_id_join_expected_by_packager(tmp_path):
    from pr_review_harness.private_capture import (
        CONTENT_TRANSFORM,
        MAX_REQUEST_BYTES,
        PrivateShadowCapture,
        write_provider_exchange,
    )

    corpus = json.loads((ROOT / "examples/evaluation/corpus.json").read_text())
    identity = corpus["cases"][0]["identity"]
    profile = json.loads((ROOT / "profiles/slopsearx.json").read_text())
    evidence = {
        "evidence_id": "ev-1", "content": "Exact private capture source.", "content_hash": _sha(b"Exact private capture source."),
        "source_kind": "head_file", "trust": "repository_evidence", "source_revision": identity["head_sha"],
        "snapshot_id": identity["snapshot_id"], "path": "src/example.py", "line": 7,
    }
    snapshot_body = {
        "repository": "magnus919/SlopSearX", "repository_url": "https://github.com/magnus919/SlopSearX",
        "base_sha": identity["base_sha"], "head_sha": identity["head_sha"],
        "profile_version": profile["version"], "profile_hash": _sha(_json_bytes(profile, ascii_only=True)),
        "inventory": [], "evidence": {"ev-1": evidence},
        "gaps": [], "trusted_context_refs": [],
    }
    snapshot = {"snapshot_id": identity["snapshot_id"], **snapshot_body}
    snapshot["snapshot_hash"] = _sha(_json_bytes(snapshot_body, ascii_only=True))
    capture = PrivateShadowCapture(
        tmp_path / "actual-capture", case_id="writer-run-real", snapshot=snapshot, source_task="writer-run-real",
        provider=type("Provider", (), {"identity": {"provider_id": "fixture", "model_id": "fixture-model", "adapter_version": "test"}})(),
        request_byte_limit=MAX_REQUEST_BYTES, response_byte_limit=2_000_000,
    )
    task = {"task_id": "task-real", "task_kind": "SPECIALIST_FINDINGS", "summary": "Inspect the supplied change."}
    capture.export_source_tasks([{"task": task, "evidence": [evidence]}], profile_id=identity["profile"]["profile_id"])
    request = _json_bytes({"model": "fixture-model", "messages": [
        {"role": "system", "content": "review"},
        {"role": "user", "content": _json_bytes({"task": task, "evidence": [evidence]}).decode()},
    ]})
    raw = {"path": "src/example.py", "line": 7, "title": "Observed issue", "observation": "Unchecked value.",
           "consequence": "Malformed input may fail.", "rule_or_contract": "Validate input.", "severity": "medium",
           "reasoning_kind": "inferred", "evidence_refs": ["ev-1"]}
    task_spec = capture.begin_call(run_id="writer-run-real", task_id="task-real", attempt=0)
    task_spec.update(root=str(capture.root), provider=capture.provider_identity, attempt=0)
    response = _json_bytes({"contract_version": "specialist-findings.v4", "finding_candidates": [raw],
                            "context_gap_proposals": [], "coverage_notes": []})
    receipt = write_provider_exchange(task_spec, request, response, "completed", _sha(b"envelope"), CONTENT_TRANSFORM)
    capture.reconcile(task_spec)
    # The producer computes its own ID from the exact candidate object and task-local index.
    from pr_review_harness.private_capture import _canonical
    candidate_id = _sha(_canonical({"task_id": "task-real", "index": 0, "raw": raw}))[:24]
    result = {
        "snapshot_id": identity["snapshot_id"], "run_id": "writer-run-real",
        "findings": [{"assessment_records": [{"candidate_id": candidate_id, "task_id": "task-real"}]}],
        "task_results": {"task-real": {"status": "SUCCEEDED", "payload": {"finding_candidates": [raw]}}},
    }
    packet_path = capture.export_case_packets(result, profile=profile)[0]
    packet = json.loads(packet_path.read_text())
    manifest = json.loads((capture.root / "manifest.json").read_text())
    assert packet["case_id"] != manifest["case_id"]
    assert packet["writer_run"]["run_id"] == manifest["case_id"] == "writer-run-real"
    assert receipt["call_id"] == manifest["calls"][0]["call_id"]
    assert packet["source_task"] == task
    assert packet["writer_candidate"]["candidate_id"] == candidate_id
