"""Offline bridge from a sealed no-candidate shadow audit to source-record Jev.

This helper is not wired into the hosted runner or workflow. The separate
``run_sealed_source_record_jev.py`` operator CLI uses it only for frozen PR464.
It checks the internal consistency of a supplied ``run_shadow_audit`` result's
packet, snapshot, source request, response, and source-audit-seal bindings
before replaying the source response into the separate typed Jev path. These
checks are not authenticated origin: a caller able to forge the whole result
and its artifacts can construct a self-consistent substitute.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Mapping

from model_only_shadow_evaluation_identity import validate_identity
from shadow_case_policy import validate_plan_binding
from source_record_decision import run_source_record_decision

from pr_review_harness.shadow_audit import (
    _canonical,
    _not_run,
    _parse_output,
    _sha,
    _validate_packet,
    _validate_source_output,
)

MAX_ARTIFACT_BYTES = 4_000_000
ROOT = Path(__file__).resolve().parents[1]
# The operator bridge is bound to the active frozen identity. Historical v1/v2
# artifacts remain available for their own evaluation workflows, but are not a
# fallback identity for this bridge.
PR464_CORPUS = ROOT / "examples/evaluation/model-only-shadow-pr464-v3/corpus.json"
PR464_IDENTITY = ROOT / "examples/evaluation/model-only-shadow-pr464-v3/manifest.json"
PR464_PLAN = ROOT / "experiments/model-only-shadow-live-pr464-plan-v3.json"


class SealedSourceIntegrationError(ValueError):
    """A sanitized failure to verify or replay a sealed source-only audit."""


def _artifact(paths: Mapping[str, Any], artifact_id: str, cap: int = MAX_ARTIFACT_BYTES) -> bytes:
    path = paths.get(artifact_id)
    if not isinstance(path, (str, os.PathLike)):
        raise SealedSourceIntegrationError("sealed_source_artifact_missing")
    candidate = Path(path)
    try:
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > cap:
            raise SealedSourceIntegrationError("sealed_source_artifact_invalid")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise SealedSourceIntegrationError("sealed_source_artifact_permissions_invalid")
        raw = candidate.read_bytes()
    except OSError:
        raise SealedSourceIntegrationError("sealed_source_artifact_unreadable") from None
    if len(raw) != info.st_size:
        raise SealedSourceIntegrationError("sealed_source_artifact_changed")
    return raw


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SealedSourceIntegrationError("sealed_source_json_invalid") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise ValueError("non_finite_constant")


def _source_user(packet: dict[str, Any]) -> dict[str, Any]:
    snapshot = packet["snapshot"]
    return {
        "case": {
            "case_id": packet["case_id"],
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_hash": snapshot["snapshot_hash"],
            "base_sha": snapshot["base_sha"],
            "head_sha": snapshot["head_sha"],
            "profile_id": packet["profile_id"],
            "profile_hash": snapshot["profile_hash"],
        },
        "task": packet["source_task"],
        "evidence": packet["source_evidence"],
    }


def _validate_frozen_pr464(packet: dict[str, Any]) -> str:
    """Bind the no-candidate packet to the checked-in PR464 identity and plan."""
    try:
        plan_raw = PR464_PLAN.read_bytes()
        plan = _decode(plan_raw)
        case_id, policy = validate_plan_binding(plan, plan_raw)
        corpus = _decode(PR464_CORPUS.read_bytes())
        identity = _decode(PR464_IDENTITY.read_bytes())
        profile_raw = (ROOT / policy["profile_path"]).read_bytes()
        profile = _decode(profile_raw)
        raw_profile_sha = hashlib.sha256(profile_raw).hexdigest()
        if raw_profile_sha != policy["profile_sha256"] or not isinstance(profile, dict):
            raise ValueError("profile_file_hash_mismatch")
        canonical_profile_sha = hashlib.sha256(_canonical(profile)).hexdigest()
        snapshot = packet.get("snapshot")
        if not isinstance(snapshot, dict) or snapshot.get("profile_hash") != canonical_profile_sha:
            raise ValueError("snapshot_profile_hash_mismatch")
        # The corpus manifest pins the exact profile file bytes, while runtime
        # snapshots pin the canonical JSON form. Validate both independently,
        # adapting only a clone for the generic file-hash identity validator.
        identity_packet = dict(packet)
        identity_snapshot = dict(snapshot)
        identity_snapshot["profile_hash"] = raw_profile_sha
        identity_packet["snapshot"] = identity_snapshot
        validate_identity(corpus, identity, plan, plan_raw, identity_packet)
        case_identity = corpus["cases"][0]["identity"]
        if packet.get("profile_id") != case_identity["profile"]["profile_id"]:
            raise ValueError("profile_id_mismatch")
    except Exception:
        raise SealedSourceIntegrationError("frozen_pr464_identity_invalid") from None
    if case_id != "PR-464" or packet.get("case_id") != "PR-464":
        raise SealedSourceIntegrationError("frozen_pr464_identity_invalid")
    return hashlib.sha256(plan_raw).hexdigest()


def run_sealed_no_candidate_decision(
    shadow_result: Mapping[str, Any],
    *,
    expected_jev_model_id: str,
    jev_transport: Callable[[bytes, float, int], bytes],
    deadline_seconds: float = 90.0,
    clock: Callable[[], float] | None = None,
    require_frozen_pr464: bool = False,
) -> dict[str, Any]:
    """Classify at most one sealed source record and retain incomplete overall status."""
    if not isinstance(shadow_result, Mapping) or set(shadow_result) != {"manifest", "artifact_paths"}:
        raise SealedSourceIntegrationError("shadow_result_invalid")
    manifest, paths = shadow_result["manifest"], shadow_result["artifact_paths"]
    if not isinstance(manifest, dict) or not isinstance(paths, Mapping):
        raise SealedSourceIntegrationError("shadow_result_invalid")
    if manifest.get("terminal_state") != "missing_writer_candidate":
        raise SealedSourceIntegrationError("no_candidate_terminal_required")
    roles = manifest.get("roles")
    if not isinstance(roles, dict) or any(roles.get(role) != _not_run(role) for role in ("jev", "claim_auditor")):
        raise SealedSourceIntegrationError("candidate_audit_roles_not_run")
    manifest_raw = _artifact(paths, "shadow-audit-manifest", 64_000)
    if manifest_raw != _canonical(manifest):
        raise SealedSourceIntegrationError("shadow_manifest_binding_invalid")

    packet_raw = _artifact(paths, "case-packet")
    packet = _decode(packet_raw)
    try:
        packet = _validate_packet(packet)
    except Exception:
        raise SealedSourceIntegrationError("case_packet_invalid") from None
    if _sha(packet_raw) != manifest.get("case_packet_sha256") or packet["writer_candidate"] is not None:
        raise SealedSourceIntegrationError("no_candidate_packet_binding_invalid")
    plan_sha256 = _validate_frozen_pr464(packet) if require_frozen_pr464 else None
    snapshot_raw = _artifact(paths, "case-snapshot")
    if snapshot_raw != _canonical(packet["snapshot"]):
        raise SealedSourceIntegrationError("snapshot_artifact_binding_invalid")
    snapshot = packet["snapshot"]
    if (
        _sha(snapshot_raw) != manifest.get("snapshot_artifact_sha256")
        or snapshot["snapshot_id"] != manifest.get("snapshot_id")
        or snapshot["snapshot_hash"] != manifest.get("snapshot_hash")
        or snapshot["base_sha"] != manifest.get("base_sha")
        or snapshot["head_sha"] != manifest.get("head_sha")
    ):
        raise SealedSourceIntegrationError("snapshot_manifest_binding_invalid")

    source_role = roles.get("source_auditor") if isinstance(roles, dict) else None
    calls = source_role.get("calls") if isinstance(source_role, dict) else None
    if (not isinstance(source_role, dict) or source_role.get("status") not in {"completed", "abstained"}
            or not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict)):
        raise SealedSourceIntegrationError("source_audit_not_sealed")
    call = calls[0]
    if require_frozen_pr464 and call.get("dispatch_state") != "http_attempted":
        raise SealedSourceIntegrationError("source_provider_call_not_observed")
    response_raw = _artifact(paths, "source-auditor-response", 64_000)
    request_raw = _artifact(paths, "source-auditor-request", 64_000)
    if (call.get("response_artifact_id") != "source-auditor-response"
            or call.get("request_artifact_id") != "source-auditor-request"
            or call.get("response_sha256") != _sha(response_raw)
            or call.get("request_sha256") != _sha(request_raw)):
        raise SealedSourceIntegrationError("source_call_binding_invalid")
    seal = _decode(_artifact(paths, "source-audit-seal", 64_000))
    expected_seal = {
        "contract_version": "source-audit-seal.v1",
        "case_id": packet["case_id"],
        "case_packet_sha256": _sha(packet_raw),
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_hash": snapshot["snapshot_hash"],
        "source_auditor_run_id": source_role.get("run_id"),
        "source_auditor_status": source_role["status"],
        "source_response_sha256": _sha(response_raw),
        "sealed_before_claim_dispatch": True,
    }
    if seal != expected_seal:
        raise SealedSourceIntegrationError("source_audit_seal_binding_invalid")

    request = _decode(request_raw)
    try:
        messages = request["messages"]
        user_messages = [message for message in messages if isinstance(message, dict) and message.get("role") == "user"]
        user_payload = _decode(user_messages[0]["content"].encode("utf-8")) if len(user_messages) == 1 else None
    except (KeyError, TypeError, AttributeError):
        user_payload = None
    if user_payload != _source_user(packet):
        raise SealedSourceIntegrationError("source_request_packet_binding_invalid")

    source_payload = _parse_output(response_raw)
    try:
        _validate_source_output(source_payload, {row["evidence_id"] for row in packet["source_evidence"]})
    except Exception:
        raise SealedSourceIntegrationError("source_response_contract_invalid") from None

    def replay_sealed_source(raw_request: bytes, _timeout: float, _cap: int) -> bytes:
        source_input = _decode(raw_request)
        if (source_input.get("subject_id") != packet["case_id"]
                or source_input.get("task") != packet["source_task"]
                or source_input.get("evidence") != packet["source_evidence"]):
            raise SealedSourceIntegrationError("source_replay_packet_binding_invalid")
        return response_raw

    decision_kwargs = {
        "subject_id": packet["case_id"],
        "expected_model_id": expected_jev_model_id,
        "source_task": packet["source_task"],
        "source_evidence": packet["source_evidence"],
        "source_transport": replay_sealed_source,
        "jev_transport": jev_transport,
        "deadline_seconds": deadline_seconds,
    }
    if clock is not None:
        decision_kwargs["clock"] = clock
    advisory = run_source_record_decision(**decision_kwargs)
    result = {
        "contract_version": "sealed-no-candidate-source-record.v1",
        "subject_kind": "frozen_case",
        "subject_id_sha256": hashlib.sha256(packet["case_id"].encode()).hexdigest(),
        "shadow_terminal_state": "missing_writer_candidate",
        "terminal_state": "incomplete",
        "terminal_reason": "no_writer_candidate",
        "disposition": "not_set",
        "writer_comparison": "not_applicable",
        "shadow_manifest_sha256": _sha(manifest_raw),
        "source_auditor_request_sha256": call.get("request_sha256"),
        "source_response_sha256": _sha(response_raw),
        "advisory_source_record_decision": advisory,
    }
    if plan_sha256 is not None:
        result["plan_sha256"] = plan_sha256
    return result
