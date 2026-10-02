#!/usr/bin/env python3
"""Continue one sealed, frozen PR464 no-candidate audit with one bounded Jev call."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from sealed_source_record_integration import (  # noqa: E402
    SealedSourceIntegrationError,
    run_sealed_no_candidate_decision,
)
from source_record_decision import MAX_PAYLOAD_BYTES, SourceRecordTransport, SourceRecordTransportError  # noqa: E402

MAX_CONFIG_BYTES = 16_000
MAX_JEV_SECONDS = 90
ADVISORY_SUMMARY_NAME = "source-record-jev-advisory-summary.json"
ADVISORY_SUMMARY_SCHEMA = "private-sealed-source-record-advisory.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ADVISORY_CHOICES = {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}
ARTIFACTS = {
    "shadow-audit-manifest": "shadow-audit-manifest.json",
    "case-packet": "private/case-packet.json",
    "case-snapshot": "private/snapshot.json",
    "source-auditor-request": "private/source-auditor.request.json",
    "source-auditor-response": "private/source-auditor.response.json",
    "source-audit-seal": "private/source-audit-seal.json",
}


def _read_regular(path: Path, cap: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size > cap:
            raise SealedSourceIntegrationError("operator_input_invalid")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > cap):
                raise SealedSourceIntegrationError("operator_input_invalid")
            chunks = bytearray()
            while len(chunks) <= cap:
                chunk = os.read(fd, min(64 * 1024, cap + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            raw = bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise SealedSourceIntegrationError("operator_input_unavailable") from None
    if len(raw) != before.st_size or len(raw) > cap:
        raise SealedSourceIntegrationError("operator_input_invalid")
    return raw


def _json_object(raw: bytes, code: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SealedSourceIntegrationError(code) from None
    if not isinstance(value, dict):
        raise SealedSourceIntegrationError(code)
    return value


def _private_artifact_dir(path: Path) -> Path:
    try:
        info = path.lstat()
    except OSError:
        raise SealedSourceIntegrationError("sealed_source_directory_unavailable") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise SealedSourceIntegrationError("sealed_source_directory_invalid")
    try:
        private_info = (path / "private").lstat()
    except OSError:
        raise SealedSourceIntegrationError("sealed_source_directory_unavailable") from None
    if (not stat.S_ISDIR(private_info.st_mode) or stat.S_ISLNK(private_info.st_mode)
            or stat.S_IMODE(private_info.st_mode) != 0o700):
        raise SealedSourceIntegrationError("sealed_source_directory_invalid")
    return path


def _sanitized_receipt(
    result: Mapping[str, Any], *, jev_external_calls: int, jev_transport_invocations: int,
    jev_dispatch_state: str,
) -> dict[str, Any]:
    advisory = result.get("advisory_source_record_decision")
    if not isinstance(advisory, dict):
        raise SealedSourceIntegrationError("advisory_result_invalid")
    if (result.get("terminal_state") != "incomplete"
            or result.get("terminal_reason") != "no_writer_candidate"
            or result.get("disposition") != "not_set"
            or result.get("writer_comparison") != "not_applicable"):
        raise SealedSourceIntegrationError("no_candidate_result_contract_invalid")
    if jev_external_calls not in (0, 1) or advisory.get("retries") != 0:
        raise SealedSourceIntegrationError("provider_call_budget_invalid")
    if (jev_transport_invocations not in (0, 1)
            or jev_external_calls > jev_transport_invocations
            or (jev_external_calls == 1) != (jev_dispatch_state == "http_attempted")
            or advisory.get("transport_invocations") != 1 + jev_transport_invocations):
        raise SealedSourceIntegrationError("provider_call_accounting_invalid")
    return {
        "contract_version": "pr464-sealed-source-record-jev-receipt.v1",
        "case_id": "PR-464",
        "subject_id_sha256": result.get("subject_id_sha256"),
        "snapshot_id": "snap-e20deb18f2ac6cb39c6ebafd",
        "snapshot_sha256": "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868",
        "plan_sha256": result.get("plan_sha256"),
        "shadow_manifest_sha256": result.get("shadow_manifest_sha256"),
        "source_auditor_request_sha256": result.get("source_auditor_request_sha256"),
        "source_response_sha256": result.get("source_response_sha256"),
        "source_status": advisory.get("source_status"),
        "source_dispatch_state": "http_attempted",
        "source_record_count": advisory.get("source_record_count"),
        "source_record_replay_request_sha256": advisory.get("request_sha256", {}).get("source"),
        "selected_record_id_sha256": advisory.get("selected_record_id_sha256"),
        "jev_status": advisory.get("jev_status"),
        "jev_dispatch_state": jev_dispatch_state,
        "jev_request_sha256": advisory.get("request_sha256", {}).get("jev"),
        "jev_response_sha256": advisory.get("response_sha256", {}).get("jev"),
        "external_provider_calls": {"source_auditor": 1, "jev": jev_external_calls, "total": 1 + jev_external_calls},
        "jev_transport_invocations": jev_transport_invocations,
        "external_provider_call_limit": 3,
        "retries": 0,
        "transport_invocations_including_local_source_replay": advisory.get("transport_invocations"),
        "terminal_state": "incomplete",
        "terminal_reason": "no_writer_candidate",
        "disposition": "not_set",
        "writer_comparison": "not_applicable",
        "publication_enabled": False,
        "target_code_execution": False,
        "retry_limit": 0,
        "per_call_timeout_seconds": MAX_JEV_SECONDS,
        "request_and_response_byte_limit": MAX_PAYLOAD_BYTES,
    }


def _private_advisory_summary(receipt: Mapping[str, Any], advisory_choice: Any) -> dict[str, Any]:
    """Project only bounded, hash-bound advisory state into a private summary."""
    if (receipt.get("case_id") != "PR-464"
            or receipt.get("snapshot_id") != "snap-e20deb18f2ac6cb39c6ebafd"
            or receipt.get("snapshot_sha256") != "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868"):
        raise SealedSourceIntegrationError("advisory_summary_binding_invalid")
    plan_hash = receipt.get("plan_sha256")
    record_hash = receipt.get("selected_record_id_sha256")
    if not isinstance(plan_hash, str) or not _SHA256.fullmatch(plan_hash):
        raise SealedSourceIntegrationError("advisory_summary_binding_invalid")
    source_status, record_count = receipt.get("source_status"), receipt.get("source_record_count")
    source_request_hash = receipt.get("source_record_replay_request_sha256")
    source_response_hash = receipt.get("source_response_sha256")
    jev_request_hash, jev_response_hash = receipt.get("jev_request_sha256"), receipt.get("jev_response_sha256")
    if (not isinstance(source_request_hash, str) or not _SHA256.fullmatch(source_request_hash)
            or (source_response_hash is not None and
                (not isinstance(source_response_hash, str) or not _SHA256.fullmatch(source_response_hash)))
            or (jev_request_hash is not None and
                (not isinstance(jev_request_hash, str) or not _SHA256.fullmatch(jev_request_hash)))
            or (jev_response_hash is not None and
                (not isinstance(jev_response_hash, str) or not _SHA256.fullmatch(jev_response_hash)))):
        raise SealedSourceIntegrationError("advisory_summary_binding_invalid")
    if (not isinstance(source_status, str) or source_status not in {"completed", "abstained", "failed"}
            or isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 0):
        raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    if source_status == "completed":
        if (record_count < 1 or (record_hash is not None
                and (not isinstance(record_hash, str) or not _SHA256.fullmatch(record_hash)))):
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    elif source_status == "abstained":
        if record_count != 0 or record_hash is not None:
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    elif record_count != 0 or record_hash is not None:
        raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    if source_status in {"completed", "abstained"} and source_response_hash is None:
        raise SealedSourceIntegrationError("advisory_summary_binding_invalid")

    jev_status, choice = receipt.get("jev_status"), advisory_choice
    if not isinstance(jev_status, str):
        raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    if jev_status == "completed":
        if (record_hash is None or not isinstance(choice, str) or choice not in _ADVISORY_CHOICES
                or jev_request_hash is None or jev_response_hash is None):
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    elif jev_status in {"abstained", "not_run", "failed"}:
        if choice is not None:
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
        if (record_hash is None and (jev_status != "not_run" or jev_response_hash is not None)):
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
        if (record_hash is None and source_status != "completed" and jev_request_hash is not None):
            raise SealedSourceIntegrationError("advisory_summary_binding_invalid")
        if (record_hash is not None and jev_request_hash is None):
            raise SealedSourceIntegrationError("advisory_summary_binding_invalid")
        if jev_status == "abstained" and (record_hash is None or jev_response_hash is None):
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
        if jev_status == "failed" and record_hash is None:
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
        if jev_status == "not_run" and jev_response_hash is not None:
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
    else:
        raise SealedSourceIntegrationError("advisory_summary_state_invalid")

    return {
        "schema_version": ADVISORY_SUMMARY_SCHEMA,
        "case_id": "PR-464",
        "snapshot_id": receipt["snapshot_id"],
        "snapshot_sha256": receipt["snapshot_sha256"],
        "plan_sha256": plan_hash,
        "source_record_replay_request_sha256": source_request_hash,
        "source_response_sha256": source_response_hash,
        "jev_request_sha256": jev_request_hash,
        "jev_response_sha256": jev_response_hash,
        "selected_record_id_sha256": record_hash,
        "source_record_count": record_count,
        "source_status": source_status,
        "jev_status": jev_status,
        "choice": choice if jev_status == "completed" else None,
    }


def _write_private_json(path: Path, value: Mapping[str, Any], error_code: str) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
    except FileExistsError:
        raise SealedSourceIntegrationError("receipt_output_exists") from None
    except OSError:
        raise SealedSourceIntegrationError(error_code) from None


def run_private_artifact_decision(
    artifact_dir: Path,
    jev_config: Mapping[str, Any],
    output_dir: Path,
    *,
    jev_transport: Callable[[bytes, float, int], bytes] | None = None,
    decision_runner: Callable[..., dict[str, Any]] = run_sealed_no_candidate_decision,
    write_advisory_summary: bool = False,
) -> dict[str, Any]:
    """Verify private source artifacts, make at most one Jev call, and write a hash-only receipt."""
    artifact_dir = _private_artifact_dir(artifact_dir)
    if (not isinstance(jev_config, Mapping)
            or set(jev_config) != {"kind", "endpoint", "model", "api_key_env"}
            or jev_config.get("kind") != "typesafe"):
        raise SealedSourceIntegrationError("jev_config_invalid")
    paths = {artifact_id: artifact_dir / relative for artifact_id, relative in ARTIFACTS.items()}
    manifest = _json_object(_read_regular(paths["shadow-audit-manifest"], 64_000), "shadow_manifest_invalid")
    shadow_result = {"manifest": manifest, "artifact_paths": paths}

    calls: list[None] = []
    external_calls: list[None] = []
    dispatch_state = ["not_run"]
    if jev_transport is None:
        config = {
            "endpoint": jev_config["endpoint"],
            "model": jev_config["model"],
            "api_key_env": jev_config["api_key_env"],
            "timeout_seconds": MAX_JEV_SECONDS,
            "max_request_bytes": MAX_PAYLOAD_BYTES,
            "max_response_bytes": MAX_PAYLOAD_BYTES,
        }
        transport = SourceRecordTransport(config)

        def bounded_transport(raw: bytes, timeout: float, response_cap: int) -> bytes:
            if calls:
                raise SealedSourceIntegrationError("jev_call_limit_exceeded")
            calls.append(None)
            try:
                return transport(raw, min(timeout, MAX_JEV_SECONDS), min(response_cap, MAX_PAYLOAD_BYTES))
            finally:
                dispatch_state[0] = transport.last_dispatch_state
                if transport.last_dispatch_state == "http_attempted":
                    external_calls.append(None)
    else:
        def bounded_transport(raw: bytes, timeout: float, response_cap: int) -> bytes:
            if calls:
                raise SealedSourceIntegrationError("jev_call_limit_exceeded")
            calls.append(None)
            dispatch_state[0] = "http_attempted"
            external_calls.append(None)
            return jev_transport(raw, min(timeout, MAX_JEV_SECONDS), min(response_cap, MAX_PAYLOAD_BYTES))

    result = decision_runner(
        shadow_result,
        expected_jev_model_id=jev_config["model"],
        jev_transport=bounded_transport,
        deadline_seconds=MAX_JEV_SECONDS,
        require_frozen_pr464=True,
    )
    receipt = _sanitized_receipt(
        result, jev_external_calls=len(external_calls), jev_transport_invocations=len(calls),
        jev_dispatch_state=dispatch_state[0],
    )
    advisory_summary = None
    if write_advisory_summary:
        advisory = result.get("advisory_source_record_decision")
        if not isinstance(advisory, Mapping):
            raise SealedSourceIntegrationError("advisory_summary_state_invalid")
        advisory_summary = _private_advisory_summary(receipt, advisory.get("advisory_choice"))
    try:
        output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(output_dir, 0o700)
        _write_private_json(output_dir / "source-record-jev-receipt.json", receipt, "receipt_output_failed")
        if advisory_summary is not None:
            _write_private_json(output_dir / ADVISORY_SUMMARY_NAME, advisory_summary, "advisory_summary_output_failed")
    except FileExistsError:
        raise SealedSourceIntegrationError("receipt_output_exists") from None
    except OSError:
        raise SealedSourceIntegrationError("receipt_output_failed") from None
    return receipt


def _read_jev_config(path: Path) -> dict[str, Any]:
    return _json_object(_read_regular(path, MAX_CONFIG_BYTES), "jev_config_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True, help="private 0700 source-only audit artifact directory")
    parser.add_argument("--jev-config", type=Path, required=True, help="trusted TypeSafe decision.json; no literal credentials")
    parser.add_argument("--output-dir", type=Path, required=True, help="new private directory for sanitized receipt")
    parser.add_argument("--live", action="store_true", help="authorize at most one bounded Jev provider call")
    parser.add_argument("--write-private-advisory-summary", action="store_true",
                        help="also write a bounded private advisory summary; it is not uploaded by the workflow")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("provider dispatch requires --live after reviewing the frozen PR464 artifacts")
    try:
        receipt = run_private_artifact_decision(
            args.artifacts, _read_jev_config(args.jev_config), args.output_dir,
            write_advisory_summary=args.write_private_advisory_summary,
        )
    except (OSError, ValueError, SourceRecordTransportError) as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or not code.replace("_", "").isalnum():
            code = str(exc) if str(exc).isidentifier() else "sealed_source_decision_failed"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
