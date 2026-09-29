#!/usr/bin/env python3
"""Read-only consistency preview for a fetched PR review recovery artifact.

This command never authorizes resume, calls a provider, or writes a checkpoint.
The engine's normal resume preflight remains authoritative.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pr_analysis_artifact_manifest as manifest

from pr_review_harness.recovery_inputs import RecoveryInputError, read_packet
from pr_review_harness.recovery_inputs import canonical as packet_canonical


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _checkpoint(root: Path, identity: dict[str, Any]) -> tuple[dict[str, Any], int]:
    path = root / "review" / f"{identity['run_id']}.json"
    value = manifest._parse_json(manifest._read_regular(path, manifest.MAX_FILE_BYTES), "recovery_checkpoint_invalid")
    if _digest(json.dumps({k: v for k, v in value.items() if k != "result_hash"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()) != value.get("result_hash"):
        raise manifest.ManifestError("recovery_checkpoint_integrity_mismatch")
    ledger = value.get("ledger")
    if (
        not isinstance(ledger, dict)
        or ledger.get("request_hash") != value.get("request_hash")
        or value.get("request_hash") != identity["request_hash"]
        or value.get("run_id") != identity["run_id"]
        or value.get("base_sha") != identity["base_sha"]
        or value.get("head_sha") != identity["head_sha"]
        or value.get("snapshot_id") != identity["snapshot_id"]
    ):
        raise manifest.ManifestError("recovery_checkpoint_binding_mismatch")
    events = ledger.get("events")
    if not isinstance(events, list):
        raise manifest.ManifestError("recovery_checkpoint_integrity_mismatch")
    for event in events:
        if not isinstance(event, dict) or _digest(json.dumps({k: v for k, v in event.items() if k != "event_hash"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()) != event.get("event_hash"):
            raise manifest.ManifestError("recovery_checkpoint_integrity_mismatch")
    budget = ledger.get("budget")
    reservations = budget.get("reservations") if isinstance(budget, dict) else None
    settlements = budget.get("settlements") if isinstance(budget, dict) else None
    if not isinstance(reservations, dict) or not isinstance(settlements, dict) or set(settlements) - set(reservations):
        raise manifest.ManifestError("recovery_reservation_ledger_invalid")
    for reservation_key, reservation in reservations.items():
        if (
            not isinstance(reservation_key, str)
            or not reservation_key
            or not isinstance(reservation, dict)
            or "provider_calls" not in reservation
            or isinstance(reservation.get("provider_calls"), bool)
            or not isinstance(reservation.get("provider_calls"), int)
            or reservation.get("provider_calls") < 0
        ):
            raise manifest.ManifestError("recovery_reservation_ledger_invalid")
    if any(not isinstance(settlement, dict) for settlement in settlements.values()):
        raise manifest.ManifestError("recovery_reservation_ledger_invalid")
    unsettled_provider_calls = sum(
        1
        for key, reservation in reservations.items()
        if reservation["provider_calls"] > 0 and key not in settlements
    )
    return value, unsettled_provider_calls


def preview(
    artifact_root: Path,
    *,
    expected_identity: dict[str, Any],
    source_repository: Path,
    profile: Path,
    provider_config: Path,
    decision_config: Path,
    current_recovery_inputs: Path,
) -> dict[str, Any]:
    identity = manifest._identity(expected_identity)
    manifest.verify_manifest(artifact_root, identity)
    try:
        current_source_sha = subprocess.run(
            ["git", "-C", str(source_repository), "rev-parse", "--verify", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(source_repository), "status", "--porcelain"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        raise manifest.ManifestError("recovery_current_source_unavailable") from None
    if dirty or current_source_sha != identity["harness_sha"]:
        raise manifest.ManifestError("recovery_current_source_mismatch")
    for path, key in ((profile, "profile_sha256"), (provider_config, "provider_config_sha256"), (decision_config, "decision_config_sha256")):
        raw = manifest._read_regular(path, manifest.MAX_FILE_BYTES)
        if _digest(raw) != identity[key]:
            raise manifest.ManifestError("recovery_current_config_mismatch")
    artifact_packet, artifact_raw = read_packet(
        artifact_root / "recovery-inputs.json",
        repository=identity["target_repository"],
        run_id=identity["run_id"],
        base_sha=identity["base_sha"],
        head_sha=identity["head_sha"],
    )
    current_packet, current_raw = read_packet(
        current_recovery_inputs,
        repository=identity["target_repository"],
        run_id=identity["run_id"],
        base_sha=identity["base_sha"],
        head_sha=identity["head_sha"],
    )
    if artifact_raw != packet_canonical(artifact_packet) or current_raw != artifact_raw or current_packet != artifact_packet:
        raise manifest.ManifestError("recovery_current_inputs_mismatch")
    checkpoint, unsettled_provider_calls = _checkpoint(artifact_root, identity)
    ambiguous = unsettled_provider_calls > 0
    return {
        "status": "AMBIGUOUS_INFLIGHT_REQUIRES_ENGINE_RECONCILIATION" if ambiguous else "CONSISTENCY_PREVIEW_PASSED",
        "resume_authorized": False,
        "resume_attempt_assessment": "ambiguous_provider_call_requires_engine_reconciliation" if ambiguous else "pins_and_checkpoint_consistent_only",
        "engine_reconciliation_expected": ambiguous,
        "engine_preflight_required": True,
        "current_pr_head_revalidated": False,
        "remaining_checks": ["engine_resume_preflight", "current_pr_head_freshness"],
        "provider_calls": 0,
        "checkpoint_writes": 0,
        "checkpoint_sha256": _digest(manifest._read_regular(artifact_root / "review" / f"{identity['run_id']}.json", manifest.MAX_FILE_BYTES)),
        "request_hash": checkpoint["request_hash"],
        "recovery_packet_sha256": _digest(artifact_raw),
        "reservations": len(checkpoint["ledger"]["budget"]["reservations"]),
        "unsettled_provider_call_reservations": unsettled_provider_calls,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--identity-json", type=Path, required=True, help="trusted identity from the recovery controller")
    parser.add_argument("--source-repository", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--decision-config", type=Path, required=True)
    parser.add_argument("--recovery-inputs", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        identity = manifest._parse_json(manifest._read_regular(args.identity_json, 64 * 1024), "recovery_identity_invalid")
        result = preview(
            args.artifact_root,
            expected_identity=identity,
            source_repository=args.source_repository,
            profile=args.profile,
            provider_config=args.provider_config,
            decision_config=args.decision_config,
            current_recovery_inputs=args.recovery_inputs,
        )
    except (manifest.ManifestError, RecoveryInputError, OSError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, (manifest.ManifestError, RecoveryInputError)) else "recovery_preview_failed"
        print(json.dumps({"error": code, "consistency_preview_passed": False, "resume_authorized": False}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
