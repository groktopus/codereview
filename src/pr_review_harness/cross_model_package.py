"""Deterministically join private writer and shadow-audit captures to v2."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .claim_assessment import _DIMENSIONS as JEV_DIMENSION_CRITERIA
from .claim_assessment import CONTRACT_VERSION as JEV_CONTRACT_VERSION
from .claim_assessment import _question_id
from .cross_model_v2 import CONTRACT_VERSION, calls_manifest_sha256, compare_cross_model_v2
from .evaluation import MAX_INPUT_BYTES, EvaluationError, validate_corpus

PACKAGE_REVISION = "cross-model-package.v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_DIMENSIONS = (
    "observation_support", "consequence_support", "rule_connection_support",
    "materiality", "missing_context", "introducedness",
)
_WRITER_FIELDS = ("title", "observation", "consequence", "rule_or_contract", "evidence_refs")
_SHADOW_FILES = {
    "source_auditor": ("source-auditor-request", "source-auditor-response"),
    "jev": ("jev-request", "jev-response"),
    "claim_auditor": ("claim-auditor-request", "claim-auditor-response"),
}
_SHADOW_PATHS = {
    "source-auditor-request": "source-auditor.request.json",
    "source-auditor-response": "source-auditor.response.json",
    "jev-request": "jev.request.json",
    "jev-response": "jev.response.json",
    "claim-auditor-request": "claim-auditor.request.json",
    "claim-auditor-response": "claim-auditor.response.json",
}


def _fail(code: str) -> None:
    raise EvaluationError(code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _shadow_canonical(value: Any) -> bytes:
    """Match the shadow runner's ASCII-escaped canonical snapshot/packet bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    """Read one bounded regular file, refusing symlinks and path traversal."""
    if ".." in path.parts:
        _fail("package_path_traversal")
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            _fail("package_symlink_rejected")
    try:
        before = absolute.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            _fail("package_file_type_or_size_invalid")
        fd = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            after = os.fstat(fd)
            if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                _fail("package_file_changed")
            data = bytearray()
            while len(data) <= limit:
                block = os.read(fd, min(64 * 1024, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(fd)
    except OSError:
        _fail("package_file_unavailable")
    if len(data) > limit:
        _fail("package_file_too_large")
    return bytes(data)


def _json(path: Path, limit: int = MAX_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = _read(path, limit)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        _fail("package_json_invalid")
    if not isinstance(value, dict):
        _fail("package_json_shape_invalid")
    return value, raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonfinite")


def _expect_hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        _fail(code)
    return value


def _expect_id(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail(code)
    return value


def _provider_content(raw: bytes) -> dict[str, Any]:
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant)
        messages = envelope["messages"]
        user_messages = [item for item in messages if item.get("role") == "user"]
        if len(user_messages) != 1 or not isinstance(user_messages[0].get("content"), str):
            _fail("provider_request_binding_invalid")
        user = json.loads(user_messages[0]["content"], object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        _fail("provider_request_binding_invalid")
    if not isinstance(user, dict):
        _fail("provider_request_binding_invalid")
    return user


def _role_call(run: dict[str, Any], role: str, private_dir: Path, artifact_map: dict[str, Path]) -> dict[str, Any]:
    if run.get("role") != role or run.get("status") not in {"completed", "abstained"}:
        _fail("shadow_role_not_complete")
    calls = run.get("calls")
    if not isinstance(calls, list) or len(calls) != 1:
        _fail("shadow_call_missing_or_ambiguous")
    call = calls[0]
    if set(call) != {"call_id", "request_sha256", "request_artifact_id", "response_sha256", "response_artifact_id"}:
        _fail("shadow_call_binding_invalid")
    call_id = _expect_id(call["call_id"], "shadow_call_binding_invalid")
    request_id = _expect_id(call["request_artifact_id"], "shadow_call_binding_invalid")
    response_id = _expect_id(call["response_artifact_id"], "shadow_call_binding_invalid")
    request_hash = _expect_hash(call["request_sha256"], "shadow_call_binding_invalid")
    response_hash = _expect_hash(call["response_sha256"], "shadow_call_binding_invalid")
    expected_request, expected_response = _SHADOW_FILES[role]
    if (request_id, response_id) != (expected_request, expected_response):
        _fail("shadow_artifact_identity_mismatch")
    request_path = private_dir / _SHADOW_PATHS[request_id]
    response_path = private_dir / _SHADOW_PATHS[response_id]
    request_raw = _read(request_path)
    response_raw = _read(response_path)
    if _sha(request_raw) != request_hash or _sha(response_raw) != response_hash:
        _fail("shadow_artifact_hash_mismatch")
    artifact_map[request_id] = request_path
    artifact_map[response_id] = response_path
    return {"call": call, "request": request_raw, "response": response_raw, "call_id": call_id}


_MODEL_TEACHER_CORPUS_ID = "model-only-shadow-pr464-v1"
_MODEL_TEACHER_MANIFEST_FIELDS = {
    "schema", "corpus_id", "dataset_version", "case_id", "repository", "base_sha", "head_sha",
    "snapshot_id", "snapshot_sha256", "profile_version", "profile_sha256", "evidence_index_sha256",
    "historical_checks_sha256", "check_evidence_sha256", "plan_path", "plan_sha256", "corpus_path",
    "corpus_sha256", "reviewer_kind", "evaluation_status", "gold_labels", "accuracy_claims", "interpretation",
}


def validate_model_teacher_packet_identity(
    corpus_value: dict[str, Any], packet: dict[str, Any], manifest_value: dict[str, Any],
    plan_value: dict[str, Any], plan_sha256: str,
) -> None:
    """Require the PR-464 packet to match its frozen, explicitly non-gold manifest."""
    corpus = validate_corpus(corpus_value)
    manifest = manifest_value
    if not isinstance(manifest, dict) or set(manifest) != _MODEL_TEACHER_MANIFEST_FIELDS:
        _fail("evaluation_identity_manifest_invalid")
    if (
        manifest.get("schema") != "model-only-shadow-evaluation-identity.v1"
        or manifest.get("reviewer_kind") != "model_teacher"
        or manifest.get("evaluation_status") != "FROZEN_INPUTS_NO_MODEL_OUTPUTS"
        or manifest.get("gold_labels") != {"status": "UNAVAILABLE", "packets_present": 0}
        or manifest.get("accuracy_claims") != "NOT_ESTIMABLE_FROM_THIS_CORPUS"
        or corpus.get("corpus_id") != _MODEL_TEACHER_CORPUS_ID
        or manifest.get("corpus_id") != corpus.get("corpus_id")
        or manifest.get("dataset_version") != corpus.get("dataset_version")
        or manifest.get("plan_path") != "experiments/model-only-shadow-live-pr464-plan-v1.json"
    ):
        _fail("evaluation_identity_manifest_invalid")
    if manifest.get("corpus_sha256") != _sha(_canonical(corpus)):
        _fail("evaluation_identity_manifest_mismatch")
    if plan_sha256 != manifest.get("plan_sha256"):
        _fail("evaluation_identity_manifest_mismatch")
    plan_case = plan_value.get("case") if isinstance(plan_value, dict) else None
    if not isinstance(plan_case, dict) or any(
        manifest.get(manifest_key) != plan_case.get(plan_key)
        for manifest_key, plan_key in (
            ("case_id", "case_id"), ("repository", "repository"), ("base_sha", "base_sha"),
            ("head_sha", "head_sha"), ("snapshot_id", "snapshot_id"),
            ("snapshot_sha256", "snapshot_sha256"), ("profile_version", "profile_version"),
            ("profile_sha256", "profile_file_sha256"), ("evidence_index_sha256", "evidence_index_sha256"),
            ("historical_checks_sha256", "historical_checks_sha256"),
            ("check_evidence_sha256", "check_evidence_sha256"),
        )
    ):
        _fail("evaluation_identity_manifest_mismatch")
    cases = [case for case in corpus["cases"] if case["identity"]["case_id"] == manifest.get("case_id")]
    if len(cases) != 1:
        _fail("evaluation_identity_manifest_mismatch")
    identity = cases[0]["identity"]
    expected_repository = identity["repository"]
    if (
        manifest.get("repository") != f"{expected_repository['owner']}/{expected_repository['name']}"
        or manifest.get("base_sha") != identity["base_sha"]
        or manifest.get("head_sha") != identity["head_sha"]
        or manifest.get("snapshot_id") != identity["snapshot_id"]
        or manifest.get("profile_version") != identity["profile"]["version"]
        or manifest.get("profile_sha256") != identity["profile"]["sha256"]
        or identity["source_manifest"].get("manifest_id") != "model-only-shadow-live-pr464-plan-v1"
        or identity["source_manifest"].get("sha256") != manifest.get("plan_sha256")
    ):
        _fail("evaluation_identity_manifest_mismatch")
    snapshot = packet.get("snapshot")
    if not isinstance(snapshot, dict) or (
        packet.get("case_id") != manifest["case_id"]
        or snapshot.get("snapshot_id") != manifest["snapshot_id"]
        or snapshot.get("snapshot_hash") != manifest["snapshot_sha256"]
        or snapshot.get("base_sha") != manifest["base_sha"]
        or snapshot.get("head_sha") != manifest["head_sha"]
        or snapshot.get("profile_version") != manifest["profile_version"]
        or snapshot.get("profile_hash") != manifest["profile_sha256"]
    ):
        _fail("case_snapshot_corpus_mismatch")


def build_cross_model_package(
    *, corpus_value: dict[str, Any], case_packet_path: Path, capture_root: Path,
    shadow_root: Path, output_dir: Path, identity_manifest_value: dict[str, Any] | None = None,
    identity_plan_value: dict[str, Any] | None = None, identity_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify exact writer/audit captures, emit v2 comparison and sanitized report."""
    corpus = validate_corpus(corpus_value)
    packet, packet_raw = _json(case_packet_path, 4_000_000)
    capture, _ = _json(capture_root / "manifest.json", 4_000_000)
    shadow, _ = _json(shadow_root / "shadow-audit-manifest.json", 4_000_000)
    if case_packet_path.absolute().parent != (capture_root / "case-packets").absolute():
        _fail("case_packet_outside_capture")
    matching_packet_paths = []
    for candidate_path in sorted((capture_root / "case-packets").glob("*.json")):
        candidate_packet, _ = _json(candidate_path, 4_000_000)
        if candidate_packet == packet:
            matching_packet_paths.append(candidate_path.absolute())
    if matching_packet_paths != [case_packet_path.absolute()]:
        _fail("case_packet_missing_or_ambiguous")
    if packet.get("contract_version") != "model-only-shadow-case.v1":
        _fail("case_packet_contract_invalid")
    if corpus.get("corpus_id") == _MODEL_TEACHER_CORPUS_ID:
        if identity_manifest_value is None or identity_plan_value is None or identity_plan_sha256 is None:
            _fail("evaluation_identity_manifest_required")
        validate_model_teacher_packet_identity(
            corpus, packet, identity_manifest_value, identity_plan_value, identity_plan_sha256,
        )
    case_id = _expect_id(packet.get("case_id"), "case_packet_identity_invalid")
    matching = [item for item in corpus["cases"] if item["identity"]["case_id"] == case_id]
    if len(matching) != 1:
        _fail("corpus_case_missing_or_ambiguous")
    identity = matching[0]["identity"]
    snapshot = packet.get("snapshot")
    if not isinstance(snapshot, dict):
        _fail("case_snapshot_missing")
    if (
        snapshot.get("snapshot_id") != identity["snapshot_id"]
        or snapshot.get("base_sha") != identity["base_sha"]
        or snapshot.get("head_sha") != identity["head_sha"]
        or snapshot.get("profile_version") != identity["profile"]["version"]
        or snapshot.get("profile_hash") != identity["profile"]["sha256"]
    ):
        _fail("case_snapshot_corpus_mismatch")
    if (
        set(capture) != {"contract_version", "case_id", "snapshot_id", "snapshot_hash", "source_task", "provider", "calls", "private_artifacts"}
        or capture.get("contract_version") != "model-only-shadow-case.v1"
        or capture.get("case_id") != packet.get("writer_run", {}).get("run_id")
        or capture.get("snapshot_id") != snapshot["snapshot_id"]
        or capture.get("snapshot_hash") != snapshot.get("snapshot_hash")
        or capture.get("source_task") != packet.get("writer_run", {}).get("run_id")
        or capture.get("private_artifacts") is not True
    ):
        _fail("writer_capture_identity_mismatch")
    if (
        shadow.get("contract_version") != "model-only-shadow-audit.v1"
        or shadow.get("case_id") != case_id
        or shadow.get("snapshot_id") != snapshot["snapshot_id"]
        or shadow.get("snapshot_hash") != snapshot.get("snapshot_hash")
        or shadow.get("terminal_state") not in {"completed", "claim_audit_abstained"}
    ):
        _fail("shadow_manifest_identity_mismatch")

    private_dir = shadow_root / "private"
    packet_copy, packet_copy_raw = _json(private_dir / "case-packet.json", 4_000_000)
    snapshot_copy, snapshot_copy_raw = _json(private_dir / "snapshot.json", 1_000_000)
    if packet_copy != packet or packet_copy_raw != _shadow_canonical(packet) or snapshot_copy != snapshot:
        _fail("shadow_packet_join_mismatch")
    if _sha(packet_copy_raw) != shadow.get("case_packet_sha256") or _sha(snapshot_copy_raw) != shadow.get("snapshot_artifact_sha256"):
        _fail("shadow_snapshot_hash_mismatch")
    snapshot_payload = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}}
    if _sha(_shadow_canonical(snapshot_payload)) != snapshot.get("snapshot_hash"):
        _fail("snapshot_digest_invalid")

    writer = packet.get("writer_run")
    candidate = packet.get("writer_candidate")
    if not isinstance(writer, dict) or not isinstance(candidate, dict):
        _fail("writer_candidate_missing")
    capture_calls = capture.get("calls")
    packet_calls = writer.get("calls")
    if not isinstance(capture_calls, list) or not isinstance(packet_calls, list) or not packet_calls:
        _fail("writer_call_missing")
    by_capture_call: dict[str, dict[str, Any]] = {}
    for receipt in capture_calls:
        if not isinstance(receipt, dict) or set(receipt) != {
            "call_id", "case_id", "run_id", "snapshot_id", "snapshot_hash", "task_id", "attempt", "provider", "status",
            "request_artifact_id", "request_sha256", "response_artifact_id", "response_sha256", "response_envelope_sha256", "content_transform",
        }:
            _fail("writer_capture_call_invalid")
        call_id = _expect_id(receipt.get("call_id"), "writer_capture_call_invalid")
        if call_id in by_capture_call:
            _fail("writer_call_ambiguous")
        by_capture_call[call_id] = receipt
    writer_artifacts: dict[str, Path] = {}
    writer_calls = []
    source_task = packet.get("source_task")
    source_evidence = packet.get("source_evidence")
    task_id = source_task.get("task_id") if isinstance(source_task, dict) else None
    if not isinstance(task_id, str) or not _ID.fullmatch(task_id) or not isinstance(source_evidence, list):
        _fail("writer_task_identity_invalid")
    candidate_occurrences = 0
    candidate_content_occurrences = 0
    for call in packet_calls:
        call_id = _expect_id(call.get("call_id"), "writer_call_invalid")
        receipt = by_capture_call.get(call_id)
        if receipt is None:
            _fail("writer_capture_receipt_missing")
        if (
            receipt.get("case_id") != writer.get("run_id")
            or receipt.get("run_id") != writer.get("run_id")
            or receipt.get("task_id") != task_id
            or receipt.get("snapshot_id") != snapshot.get("snapshot_id")
            or receipt.get("snapshot_hash") != snapshot.get("snapshot_hash")
            or receipt.get("status") not in {"completed", "incomplete", "abstained"}
            or receipt.get("request_sha256") != call.get("request_sha256")
            or receipt.get("response_sha256") != call.get("response_sha256")
            or receipt.get("request_artifact_id") != call.get("request_artifact_id")
            or receipt.get("response_artifact_id") != call.get("response_artifact_id")
        ):
            _fail("writer_capture_receipt_mismatch")
        request_path = capture_root / "requests" / f"{call_id}.bin"
        response_path = capture_root / "responses" / f"{call_id}.bin"
        request_raw = _read(request_path, 16 * 1024 * 1024)
        if _sha(request_raw) != call["request_sha256"]:
            _fail("writer_request_hash_mismatch")
        request_user = _provider_content(request_raw)
        if set(request_user) != {"task", "evidence"} or request_user["task"] != source_task or request_user["evidence"] != source_evidence:
            _fail("writer_request_task_binding_mismatch")
        writer_artifacts[call["request_artifact_id"]] = request_path
        if call.get("response_sha256") is None:
            if call.get("response_artifact_id") is not None:
                _fail("writer_call_response_binding_invalid")
            _fail("writer_response_missing")
        response_raw = _read(response_path, 4 * 1024 * 1024)
        if _sha(response_raw) != call["response_sha256"]:
            _fail("writer_response_hash_mismatch")
        try:
            writer_payload = json.loads(response_raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            _fail("writer_response_invalid")
        candidates = writer_payload.get("finding_candidates") if isinstance(writer_payload, dict) else None
        if not isinstance(candidates, list):
            _fail("writer_response_contract_invalid")
        for index, item in enumerate(candidates):
            if not isinstance(item, dict):
                continue
            if all(item.get(field) == candidate.get(field) for field in _WRITER_FIELDS):
                candidate_content_occurrences += 1
            candidate_id = _sha(_canonical({"task_id": task_id, "index": index, "raw": item}))[:24]
            if candidate_id == candidate.get("candidate_id") and all(item.get(field) == candidate.get(field) for field in _WRITER_FIELDS):
                candidate_occurrences += 1
        writer_artifacts[call["response_artifact_id"]] = response_path
        writer_calls.append(dict(call))
    if candidate_occurrences != 1 or candidate_content_occurrences != 1:
        _fail("writer_candidate_response_missing_or_ambiguous")

    source_role = shadow.get("roles", {}).get("source_auditor")
    jev_role = shadow.get("roles", {}).get("jev")
    claim_role = shadow.get("roles", {}).get("claim_auditor")
    if not all(isinstance(role, dict) for role in (source_role, jev_role, claim_role)):
        _fail("shadow_role_missing")
    artifacts = dict(writer_artifacts)
    source = _role_call(source_role, "source_auditor", private_dir, artifacts)
    _role_call(jev_role, "jev", private_dir, artifacts)
    claim = _role_call(claim_role, "claim_auditor", private_dir, artifacts)
    seal, _ = _json(private_dir / "source-audit-seal.json", 16_384)
    if (
        seal.get("case_id") != case_id
        or seal.get("snapshot_hash") != snapshot.get("snapshot_hash")
        or seal.get("source_auditor_run_id") != source_role.get("run_id")
        or seal.get("source_auditor_status") != source_role.get("status")
        or seal.get("source_response_sha256") != source["call"]["response_sha256"]
        or seal.get("sealed_before_claim_dispatch") is not True
    ):
        _fail("source_audit_seal_mismatch")

    source_user = _provider_content(source["request"])
    expected_source_case = {
        "case_id": case_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"],
        "base_sha": snapshot["base_sha"], "head_sha": snapshot["head_sha"], "profile_id": packet["profile_id"],
        "profile_hash": snapshot["profile_hash"],
    }
    if (
        set(source_user) != {"case", "task", "evidence"}
        or source_user["case"] != expected_source_case
        or source_user["task"] != packet["source_task"]
        or source_user["evidence"] != packet["source_evidence"]
    ):
        _fail("source_auditor_blinding_contract_failed")
    source_output, _ = _json(private_dir / _SHADOW_PATHS["source-auditor-response"], 4 * 1024 * 1024)
    if source_output.get("contract_version") != "shadow-source-audit.v1" or source_output.get("status") != source_role["status"]:
        _fail("source_response_contract_invalid")
    source_records = source_output.get("records")
    if not isinstance(source_records, list) or (source_role["status"] == "abstained") != (len(source_records) == 0):
        _fail("source_records_invalid")

    jev_output, _ = _json(private_dir / _SHADOW_PATHS["jev-response"], 4 * 1024 * 1024)
    jev_request = _json(private_dir / _SHADOW_PATHS["jev-request"], 4 * 1024 * 1024)[0]
    if (
        set(jev_output) - {"model", "request_id", "answers", "usage"}
        or not isinstance(jev_output.get("answers"), dict)
        or not isinstance(jev_request.get("questions"), dict)
        or not isinstance(jev_request.get("state"), dict)
        or jev_request["state"].get("candidate", {}).get("candidate_id") != candidate["candidate_id"]
        or jev_request["state"].get("assessment_identity", {}).get("snapshot_hash") != snapshot["snapshot_hash"]
    ):
        _fail("jev_response_contract_invalid")
    claim_user = _provider_content(claim["request"])
    if set(claim_user) != {"case", "writer_claim", "jev_classification", "evidence"}:
        _fail("claim_auditor_request_contract_invalid")
    expected_claim_case = {"case_id": case_id, "snapshot_id": snapshot["snapshot_id"], "snapshot_hash": snapshot["snapshot_hash"]}
    expected_claim_evidence = [item for item in packet["source_evidence"] if item["evidence_id"] in candidate["evidence_refs"]]
    if (
        claim_user["writer_claim"] != candidate
        or claim_user["case"] != expected_claim_case
        or claim_user["evidence"] != expected_claim_evidence
    ):
        _fail("claim_auditor_input_binding_mismatch")
    jev_classifications = claim_user["jev_classification"]
    if not isinstance(jev_classifications, dict) or set(jev_classifications) != set(_DIMENSIONS):
        _fail("jev_classification_binding_invalid")
    jev_records = []
    claim_records = []
    answers = jev_output["answers"]
    questions = jev_request["questions"]
    cited_refs = jev_request["state"].get("candidate", {}).get("evidence_refs")
    if not isinstance(cited_refs, list) or cited_refs != candidate["evidence_refs"]:
        _fail("jev_evidence_binding_invalid")
    expected_answer_statuses = []
    choices = []
    for dimension in _DIMENSIONS:
        item = jev_classifications[dimension]
        expected_id = f"{candidate['candidate_id']}:jev:{dimension}"
        if not isinstance(item, dict) or item.get("record_id") != expected_id:
            _fail("jev_record_binding_invalid")
        question_id = _question_id(candidate["candidate_id"], dimension, JEV_CONTRACT_VERSION)
        if question_id in questions:
            question = questions[question_id]
            answer = answers.get(question_id)
            allowed = set(JEV_DIMENSION_CRITERIA[dimension])
            if (
                not isinstance(question, dict)
                or question.get("criteria") != JEV_DIMENSION_CRITERIA[dimension]
                or not isinstance(answer, dict)
                or set(answer) != {"type", "choice", "probabilities", "confidence"}
                or answer.get("type") != "choice"
                or answer.get("choice") not in allowed
                or not isinstance(answer.get("probabilities"), dict)
                or set(answer["probabilities"]) != allowed
                or not isinstance(answer.get("confidence"), (int, float))
                or isinstance(answer.get("confidence"), bool)
                or not 0 <= answer["confidence"] <= 1
            ):
                _fail("jev_answer_binding_invalid")
            probs = answer["probabilities"]
            if (
                any(isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1 for value in probs.values())
                or abs(sum(probs.values()) - 1) > 0.02
                or probs[answer["choice"]] < max(probs.values()) - 1e-6
            ):
                _fail("jev_answer_binding_invalid")
            expected_row = {"record_id": expected_id, "status": "ANSWERED", "choice": answer["choice"], "evidence_refs": cited_refs}
            expected_answer_statuses.append("ANSWERED")
            choices.append(answer["choice"])
        else:
            if dimension != "introducedness":
                _fail("jev_question_missing")
            expected_row = {"record_id": expected_id, "status": "NOT_SHOWN", "choice": None, "evidence_refs": cited_refs}
            expected_answer_statuses.append("NOT_SHOWN")
        if item != expected_row:
            _fail("jev_classification_response_mismatch")
        jev_records.append({"role": "jev", "record_id": expected_id})
        claim_records.append({"role": "claim_auditor", "record_id": f"{candidate['candidate_id']}:claim_auditor:{dimension}"})
    if set(answers) - set(questions):
        _fail("jev_unbound_answer")
    expected_jev_status = "abstained" if not choices or all(choice in {"UNCERTAIN", "UNKNOWN"} for choice in choices) else "completed"
    if jev_role["status"] != expected_jev_status:
        _fail("jev_role_status_mismatch")

    claim_output, _ = _json(private_dir / _SHADOW_PATHS["claim-auditor-response"], 4 * 1024 * 1024)
    if claim_output.get("contract_version") != "shadow-claim-audit.v1" or claim_output.get("status") != claim_role["status"]:
        _fail("claim_response_contract_invalid")
    raw_relations = claim_output.get("relations")
    if not isinstance(raw_relations, list) or (claim_role["status"] == "abstained") != (len(raw_relations) == 0):
        _fail("claim_relations_invalid")
    assertions = []
    for index, relation in enumerate(raw_relations):
        if not isinstance(relation, dict) or relation.get("dimension") not in _DIMENSIONS:
            _fail("claim_relation_invalid")
        assertions.append({
            "assertion_id": _expect_id(relation.get("assertion_id"), "claim_relation_invalid"),
            "pair": "jev_claim_auditor",
            "relation": relation.get("relation"),
            "reporter_role": "claim_auditor",
            "reporter_run_id": claim_role["run_id"],
            "reporter_call_id": claim["call_id"],
            "response_artifact_id": claim["call"]["response_artifact_id"],
            "json_pointer": f"/relations/{index}",
            "left_record_id": relation.get("left_record_id"),
            "right_record_id": relation.get("right_record_id"),
        })
    records = ([{"role": "writer", "record_id": candidate["candidate_id"]}]
               + jev_records + claim_records
               + [{"role": "source_auditor", "record_id": _expect_id(row.get("record_id"), "source_record_invalid")} for row in source_records])

    writer_identity = capture.get("provider", {})
    if not isinstance(writer_identity, dict):
        _fail("writer_provider_identity_missing")
    runs = []
    runs.append({
        "role": "writer", "status": writer["status"], "run_id": writer["run_id"],
        "provider_id": writer_identity.get("provider_id"), "model_id": writer_identity.get("model_id"),
        "runtime_id": writer_identity.get("adapter_version"), "prompt_revision": writer["prompt_revision"],
        "rubric_revision": writer["rubric_revision"], "calls": writer_calls,
        "calls_manifest_sha256": calls_manifest_sha256(writer_calls),
    })
    runs.extend(shadow["roles"][role] for role in ("jev", "source_auditor", "claim_auditor"))
    if shadow["roles"].get("writer") != writer:
        _fail("shadow_writer_copy_mismatch")
    comparison = {
        "contract_version": CONTRACT_VERSION,
        "comparison_id": "pkg-" + _sha(_canonical([
            case_id, _sha(packet_raw), _sha(_read(shadow_root / "shadow-audit-manifest.json", 4_000_000)),
        ]))[:24],
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "procedure": {"revision": PACKAGE_REVISION, "frozen_sha256": _sha(Path(__file__).read_bytes())},
        "cases": [{"case_id": case_id, "identity": identity, "runs": runs, "records": records, "assertions": assertions}],
    }
    one_case_corpus = dict(corpus)
    one_case_corpus["cases"] = [matching[0]]
    report = compare_cross_model_v2(comparison, one_case_corpus, artifacts=artifacts)
    if report["artifact_verification"]["status_counts"].get("VERIFIED", 0) != len(artifacts):
        _fail("package_artifact_verification_incomplete")
    if report["assertion_verification"]["verified_structured_relation_count"] != len(assertions):
        _fail("package_relation_verification_incomplete")
    if output_dir.exists() or output_dir.is_symlink():
        _fail("package_output_directory_exists")
    try:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(output_dir, 0o700)
        for name, value in (("comparison-v2.json", comparison), ("comparison-report.json", report)):
            path = output_dir / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(_canonical(value) + b"\n")
                target.flush()
                os.fsync(target.fileno())
    except OSError:
        _fail("package_output_write_failed")
    return {"comparison": comparison, "report": report}
