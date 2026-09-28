#!/usr/bin/env python3
"""Bind a SYNTH-001 four-role package to its same-job local preflight bundle.

This command is offline. It reads already captured artifacts and delegates
byte-level role verification to the existing cross-model package builder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from materialize_seeded_writer_synth_001 import MaterializeError  # noqa: E402
from verify_synth_001_preflight import VerifyError, _document, _read, verify  # noqa: E402

from pr_review_harness.cross_model_package import build_cross_model_package  # noqa: E402
from pr_review_harness.evaluation import EvaluationError  # noqa: E402

IDENTITY_PATH = ROOT / "experiments/synth-001-package-identity-v1.json"
IDENTITY_SHA256 = "c08c8eea5100abce4728d638f7da06ca34ba4fff30ae958e67b90e56a1dbf34f"
FIXTURE_DIR = ROOT / "examples/evaluation/seeded-writer-synth-001"
PROFILE_PATH = ROOT / "experiments/synth-001-writer-profile-v1.json"
LIMITS_PATH = ROOT / "experiments/synth-001-writer-limits-v1.json"
PROVIDER_PATH = ROOT / "experiments/synth-001-writer-provider-v1.json"
JOB_DIR = re.compile(r"^synth-001-preflight-([0-9a-f]{24})$")


class PackageError(ValueError):
    """The private capture is not bound to the pinned SYNTH-001 preflight."""


def _fail(code: str) -> None:
    raise PackageError(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _safe_child(root: Path, path: Path, *, must_exist: bool) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        candidate = path if path.is_absolute() else Path.cwd() / path
        candidate = candidate.absolute()
        relative = candidate.relative_to(resolved_root)
        if ".." in relative.parts:
            _fail("package_path_outside_preflight")
        current = resolved_root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                _fail("package_path_symlink")
        resolved = candidate.resolve(strict=must_exist)
    except ValueError:
        _fail("package_path_outside_preflight")
    except OSError:
        _fail("package_path_unavailable")
    if resolved == resolved_root or resolved_root not in resolved.parents:
        _fail("package_path_outside_preflight")
    if must_exist and not resolved.exists():
        _fail("package_path_unavailable")
    return resolved


def _hash_file(path: Path, limit: int = 256_000) -> str:
    return _sha(_read(path, limit))


def _identity() -> dict[str, Any]:
    raw = _read(IDENTITY_PATH, 64_000)
    if _sha(raw) != IDENTITY_SHA256:
        _fail("package_identity_contract_mismatch")
    value, _ = _document(IDENTITY_PATH)
    if value.get("schema") != "synth-001-cross-model-package-identity.v1":
        _fail("package_identity_contract_invalid")
    return value


def _preflight_bundle(preflight_dir: Path, contract: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    if preflight_dir.is_symlink() or not preflight_dir.is_dir():
        _fail("preflight_directory_invalid")
    preflight_dir = preflight_dir.resolve(strict=True)
    match = JOB_DIR.fullmatch(preflight_dir.name)
    if not match:
        _fail("preflight_job_identity_invalid")
    nonce = match.group(1)
    repo = preflight_dir / "repo"
    materialization_path = preflight_dir / "materialization.json"
    prepared_path = preflight_dir / "prepared.json"
    verification_path = preflight_dir / "verification.json"
    bundle_path = preflight_dir / "live-preflight-bundle.json"
    materialization, materialization_raw = _document(materialization_path)
    prepared, prepared_raw = _document(prepared_path)
    verification, verification_raw = _document(verification_path)
    bundle, _ = _document(bundle_path)
    expected_bundle_fields = {
        "schema", "job_nonce", "workflow_run_id", "workflow_run_attempt", "repository_path_sha256",
        "materialization_sha256", "prepared_sha256", "verification_sha256", "request_sha256",
        "request_bytes", "lens", "output_bytes_cap", "output_tokens_cap", "max_provider_calls",
        "planned_provider_calls", "dispatched_provider_calls", "retries", "context_retrievals",
        "followups", "decision_provider", "claim_assessments", "publication_enabled", "target_code_execution",
    }
    if set(bundle) != expected_bundle_fields:
        _fail("preflight_bundle_shape_invalid")
    expected_preflight = contract["preflight"]
    expected_bundle = {
        "schema": "synth-001-live-preflight-bundle.v1",
        "job_nonce": nonce,
        "repository_path_sha256": _sha(os.fsencode(str(repo.resolve(strict=True)))),
        "materialization_sha256": _sha(materialization_raw),
        "prepared_sha256": _sha(prepared_raw),
        "verification_sha256": _sha(verification_raw),
        **expected_preflight,
        "decision_provider": None,
    }
    if any(bundle.get(key) != value for key, value in expected_bundle.items()):
        _fail("preflight_bundle_mismatch")
    if (not isinstance(bundle.get("workflow_run_id"), str) or not 1 <= len(bundle["workflow_run_id"]) <= 128
            or not isinstance(bundle.get("workflow_run_attempt"), str) or not 1 <= len(bundle["workflow_run_attempt"]) <= 32):
        _fail("preflight_job_identity_invalid")
    if repo.is_symlink():
        _fail("repository_identity_mismatch")
    expected_verification = verify(
        materialization_path, prepared_path, repo, FIXTURE_DIR,
        PROFILE_PATH, LIMITS_PATH, PROVIDER_PATH, ROOT,
    )
    if verification != expected_verification:
        _fail("preflight_verification_mismatch")
    expected_materialization = {
        "schema": "seeded-writer-materialization.v1",
        "fixture_id": contract["fixture"]["fixture_id"],
        "seed": str(contract["fixture"]["seed"]),
        "payload_sha256": contract["fixture"]["payload_sha256"],
        "base_sha": contract["fixture"]["materialized"]["base_sha"],
        "head_sha": contract["fixture"]["materialized"]["head_sha"],
        "changed_path": contract["fixture"]["materialized"]["changed_path"],
    }
    if materialization != expected_materialization:
        _fail("materialization_identity_mismatch")
    return materialization, prepared, verification, repo


def _check_configuration(contract: dict[str, Any], verification: dict[str, Any]) -> None:
    expected = contract["configuration"]
    files = {
        "profile_sha256": PROFILE_PATH,
        "limits_sha256": LIMITS_PATH,
        "provider_config_sha256": PROVIDER_PATH,
    }
    for key, path in files.items():
        if _hash_file(path, 32_000) != expected[key]:
            _fail("package_configuration_mismatch")
    provider, _ = _document(PROVIDER_PATH, 32_000)
    if (provider.get("provider_id") != expected["provider_id"]
            or provider.get("model") != expected["model"]):
        _fail("package_provider_identity_mismatch")
    for key in ("runtime", "module_count", "module_tree_sha256"):
        if verification.get(key) != expected[key]:
            _fail("package_runtime_identity_mismatch")


def _check_capture_and_packet(
    capture_root: Path, packet_path: Path, verification: dict[str, Any],
    prepared: dict[str, Any], contract: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from pr_review_harness.cross_model_package import _json

    capture, _ = _json(capture_root / "manifest.json", 4_000_000)
    packet, _ = _json(packet_path, 4_000_000)
    expected = contract["package_identity"]["case"]["identity"]
    if packet.get("contract_version") != "model-only-shadow-case.v1" or packet.get("case_id") != expected["case_id"]:
        _fail("writer_packet_case_mismatch")
    snapshot = packet.get("snapshot")
    if not isinstance(snapshot, dict) or any(
        snapshot.get(key) != verification.get(source_key)
        for key, source_key in (("snapshot_id", "snapshot_id"), ("snapshot_hash", "snapshot_hash"),
                                ("base_sha", "base_sha"), ("head_sha", "head_sha"))
    ):
        _fail("writer_packet_snapshot_mismatch")
    if snapshot.get("profile_version") != expected["profile"]["version"] or snapshot.get("profile_hash") != expected["profile"]["sha256"]:
        _fail("writer_packet_profile_mismatch")
    writer = packet.get("writer_run")
    packet_calls = writer.get("calls") if isinstance(writer, dict) else None
    capture_calls = capture.get("calls")
    if (not isinstance(packet_calls, list) or len(packet_calls) != 1
            or not isinstance(capture_calls, list) or len(capture_calls) != 1
            or not isinstance(writer, dict) or writer.get("status") != "completed"
            or packet.get("profile_id") != expected["profile"]["profile_id"]):
        _fail("writer_call_cardinality_mismatch")
    call = packet_calls[0]
    receipt = capture_calls[0]
    if (not isinstance(call, dict) or not isinstance(receipt, dict)
            or not isinstance(call.get("call_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", call["call_id"])
            or call.get("call_id") != receipt.get("call_id")
            or receipt.get("status") != "completed"):
        _fail("writer_call_identity_mismatch")
    if (capture.get("snapshot_id") != verification.get("snapshot_id")
            or capture.get("snapshot_hash") != verification.get("snapshot_hash")):
        _fail("writer_capture_snapshot_mismatch")
    config = contract["configuration"]
    if capture.get("provider") != {
        "provider_id": config["provider_id"], "model_id": config["model"],
        "adapter_version": config["adapter_version"],
    }:
        _fail("writer_capture_provider_mismatch")
    request_path = capture_root / "requests" / f"{call['call_id']}.bin"
    request_raw = _read(request_path, 16 * 1024 * 1024)
    preflight = contract["preflight"]
    if (_sha(request_raw) != preflight["request_sha256"] or len(request_raw) != preflight["request_bytes"]
            or call.get("request_sha256") != preflight["request_sha256"]
            or receipt.get("request_sha256") != preflight["request_sha256"]):
        _fail("writer_request_preflight_mismatch")
    primary = prepared.get("primary_requests")
    if not isinstance(primary, list) or len(primary) != 1:
        _fail("prepared_request_invalid")
    descriptor = primary[0]
    descriptor_sha = _sha(_canonical(descriptor))
    if descriptor_sha != preflight["request_descriptor_sha256"]:
        _fail("prepared_request_descriptor_mismatch")
    if (descriptor.get("input_sha256") != preflight["request_sha256"]
            or descriptor.get("input_bytes") != preflight["request_bytes"]
            or descriptor.get("lens") != preflight["lens"]
            or descriptor.get("output_bytes_cap") != preflight["output_bytes_cap"]
            or descriptor.get("output_tokens_cap") != preflight["output_tokens_cap"]):
        _fail("prepared_request_mismatch")
    expected_rows = descriptor.get("evidence_bindings")
    if not isinstance(expected_rows, list) or not expected_rows:
        _fail("prepared_evidence_bindings_invalid")
    expected_bindings = {}
    for row in expected_rows:
        if not isinstance(row, dict) or not isinstance(row.get("evidence_id"), str) or row["evidence_id"] in expected_bindings:
            _fail("prepared_evidence_bindings_invalid")
        expected_bindings[row["evidence_id"]] = (
            row.get("path"), row.get("content_hash"), row.get("source_kind"),
            row.get("source_revision"), row.get("content_bytes"),
        )
    source_evidence = packet.get("source_evidence")
    if not isinstance(source_evidence, list) or not source_evidence:
        _fail("writer_source_evidence_invalid")
    observed_bindings = {}
    for row in source_evidence:
        if (not isinstance(row, dict) or not isinstance(row.get("evidence_id"), str)
                or row["evidence_id"] in observed_bindings
                or row.get("path") not in {"auth.py", "caller.py", "contract.md"}):
            _fail("writer_truth_or_unlisted_evidence_rejected")
        if row["path"].lower().endswith("truth.json"):
            _fail("writer_truth_or_unlisted_evidence_rejected")
        content = row.get("content")
        if not isinstance(content, str):
            _fail("writer_source_evidence_invalid")
        content_sha256 = _sha(content.encode("utf-8"))
        if content_sha256 != row.get("content_hash"):
            _fail("writer_source_evidence_hash_mismatch")
        observed_bindings[row.get("evidence_id")] = (
            row.get("path"), content_sha256, row.get("source_kind"), row.get("source_revision"),
            len(content.encode("utf-8")),
        )
    if observed_bindings != expected_bindings:
        _fail("writer_source_evidence_preflight_mismatch")
    return capture, packet


def package_synth_001(
    preflight_dir: Path, capture_root: Path, case_packet_path: Path,
    shadow_root: Path, output_dir: Path,
) -> dict[str, Any]:
    contract = _identity()
    if preflight_dir.is_symlink():
        _fail("preflight_directory_invalid")
    preflight_dir = preflight_dir.resolve(strict=True)
    capture_root = _safe_child(preflight_dir, capture_root, must_exist=True)
    case_packet_path = _safe_child(preflight_dir, case_packet_path, must_exist=True)
    shadow_root = _safe_child(preflight_dir, shadow_root, must_exist=True)
    output_dir = _safe_child(preflight_dir, output_dir, must_exist=False)
    materialization, prepared, verification, repo = _preflight_bundle(preflight_dir, contract)
    _check_configuration(contract, verification)
    if case_packet_path.parent != (capture_root / "case-packets").resolve(strict=True):
        _fail("writer_packet_outside_capture")
    _check_capture_and_packet(capture_root, case_packet_path, verification, prepared, contract)
    if output_dir.exists() or output_dir.is_symlink():
        _fail("package_output_directory_exists")
    identity = contract["package_identity"]
    corpus = {
        "contract_version": identity["corpus_version"],
        "corpus_id": identity["corpus_id"],
        "dataset_version": identity["dataset_version"],
        "sampling_frame": identity["sampling_frame"],
        "expected_arms": identity["expected_arms"],
        "cases": [identity["case"]],
    }
    return build_cross_model_package(
        corpus_value=corpus, case_packet_path=case_packet_path,
        capture_root=capture_root, shadow_root=shadow_root, output_dir=output_dir,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-dir", type=Path, required=True)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--case-packet", type=Path, required=True)
    parser.add_argument("--shadow-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        result = package_synth_001(args.preflight_dir, args.capture_root, args.case_packet,
                                   args.shadow_root, args.output_dir)
    except (PackageError, VerifyError, MaterializeError, EvaluationError, OSError, TypeError, ValueError) as exc:
        code = str(exc) if isinstance(exc, (PackageError, VerifyError, MaterializeError, EvaluationError)) else "package_input_invalid"
        print(json.dumps({"ok": False, "error_code": code}, sort_keys=True, separators=(",", ":")))
        return 2
    report = result["report"]
    print(json.dumps({
        "ok": True,
        "comparison_id": report["comparison_id"],
        "case_count": len(report["cases"]),
        "verified_artifact_count": report["artifact_verification"]["status_counts"]["VERIFIED"],
        "verified_structured_relation_count": report["assertion_verification"]["verified_structured_relation_count"],
        "claims": report["claims"],
        "comparison_path": str(args.output_dir / "comparison-v2.json"),
        "report_path": str(args.output_dir / "comparison-report.json"),
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
