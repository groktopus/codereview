#!/usr/bin/env python3
"""Run a bounded, advisory-only TypeSafe claim screen over frozen findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.claim_assessment import ClaimAssessmentAdapter  # noqa: E402
from pr_review_harness.claim_transport import ClaimTransport  # noqa: E402
from pr_review_harness.snapshot import SnapshotError, collect_snapshot  # noqa: E402

MAX_CANDIDATES = 3
MAX_INPUT_BYTES = 64_000
MAX_OUTPUT_BYTES = 8_000
PER_CANDIDATE_DEADLINE_SECONDS = 8.0
MAX_WORKER_STDOUT_BYTES = 128_000
MAX_ARTIFACT_BYTES = 4_000_000
MAX_CONFIG_BYTES = 16_000
_SAFE_ERROR_CODES = {
    "candidate_evidence_invalid",
    "candidate_evidence_reference_missing",
    "candidate_fields_missing",
    "candidate_missing",
    "candidate_text_too_large",
    "cited_evidence_hash_mismatch",
    "cited_evidence_metadata_mismatch",
    "cited_evidence_not_reconstructed",
    "credential_reference_missing",
    "credential_reference_required",
    "evidence_content_hash_mismatch",
    "evidence_snapshot_mismatch",
    "hard_deadline_exceeded",
    "invalid_claim_candidate",
    "invalid_claim_evidence",
    "invalid_claim_transport_config",
    "invalid_deadline",
    "invalid_native_envelope",
    "invalid_native_request",
    "invalid_transport_config",
    "malformed_native_response",
    "native_call_deadline_exceeded",
    "native_call_failed",
    "native_response_exceeds_limit",
    "prepared_request_hash_mismatch",
    "request_exceeds_limit",
    "sealed_result_hash_mismatch",
    "snapshot_identity_mismatch",
    "snapshot_reconstruction_failed",
    "unsupported_native_endpoint",
    "unsupported_native_operation",
    "worker_assessment_failed",
    "worker_failed",
    "worker_input_exceeds_limit",
    "worker_input_invalid",
    "worker_output_exceeds_limit",
    "worker_output_invalid",
    "worker_start_failed",
}

# These IDs and result digests identify the preserved e22a085 development run.
# The run contains development examples, not held-out cases or truth labels.
SCREEN_CASES = (
    {
        "case_id": "r1-control",
        "candidate_id": "039dc8001dbf4cd9dd258fa1",
        "kind": "control_auth_candidate",
        "result_sha256": "a473be167d72b2c6db0745e4355b24ce91a84c173a60f9e05d0516a66c0a7b15",
    },
    {
        "case_id": "r1-code-comment-attack",
        "candidate_id": "0fa466c4d5bbf651d5e8c30f",
        "kind": "attack_auth_candidate",
        "result_sha256": "ef9b6b673b495c374496f5cfb3355b0454c01203e8168b7226ee3405342e2f5a",
    },
    {
        "case_id": "r1-code-comment-attack",
        "candidate_id": "d16dc959e0bb1dfbbec96592",
        "kind": "accepted_attack_comment_candidate",
        "result_sha256": "ef9b6b673b495c374496f5cfb3355b0454c01203e8168b7226ee3405342e2f5a",
    },
)


class ScreenError(ValueError):
    """A local sealed-artifact, limit, or worker-boundary failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ScreenCase:
    case_id: str
    candidate_id: str
    kind: str
    result_sha256: str
    snapshot_id: str
    snapshot_hash: str
    profile_id: str
    profile_hash: str
    profile_source_sha256: str
    base_sha: str
    head_sha: str
    candidate: dict[str, Any]
    evidence: tuple[dict[str, Any], ...]

    def assessment_identity(self) -> dict[str, str]:
        return {
            "snapshot_id": self.snapshot_id,
            "snapshot_hash": self.snapshot_hash,
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> tuple[dict[str, Any], bytes]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        raise ScreenError("artifact_unavailable") from None
    if len(raw) > max_bytes:
        raise ScreenError("artifact_exceeds_limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ScreenError("artifact_invalid_json") from None
    if not isinstance(value, dict):
        raise ScreenError("artifact_invalid_shape")
    return value, raw


def load_screen_cases(artifact_dir: Path) -> tuple[ScreenCase, ...]:
    """Reconstruct cited evidence through the normal bounded Git collector."""
    root = artifact_dir.resolve(strict=True)
    work = root / ".injection-fixture-work"
    profile, profile_raw = _read_json(work / "trusted-profile.json", max_bytes=MAX_CONFIG_BYTES)
    limits, _limits_raw = _read_json(work / "limits.json", max_bytes=MAX_CONFIG_BYTES)
    if not isinstance(profile.get("version"), str):
        raise ScreenError("trusted_profile_invalid")
    profile_source_hash = _sha256(profile_raw)

    loaded: list[ScreenCase] = []
    for spec in SCREEN_CASES:
        case_id = spec["case_id"]
        result_path = root / "runs" / case_id / f"{case_id}.json"
        result, result_raw = _read_json(result_path)
        result_hash = _sha256(result_raw)
        if result_hash != spec["result_sha256"]:
            raise ScreenError("sealed_result_hash_mismatch")
        if result.get("snapshot_id") is None or not isinstance(result.get("evidence_index"), dict):
            raise ScreenError("sealed_result_identity_missing")
        repo = work / "fixtures" / case_id
        try:
            snapshot = collect_snapshot(str(repo), result.get("base_sha"), result.get("head_sha"), profile, limits)
        except (SnapshotError, TypeError):
            raise ScreenError("snapshot_reconstruction_failed") from None
        if snapshot["snapshot_id"] != result["snapshot_id"]:
            raise ScreenError("snapshot_identity_mismatch")
        candidate = next(
            (
                item
                for item in result.get("findings", [])
                if isinstance(item, dict) and item.get("candidate_id") == spec["candidate_id"]
            ),
            None,
        )
        if not isinstance(candidate, dict):
            raise ScreenError("candidate_missing")
        refs = candidate.get("evidence_refs")
        index = result["evidence_index"]
        collected = snapshot.get("evidence", {})
        if not isinstance(refs, list) or not refs or len(set(refs)) != len(refs):
            raise ScreenError("candidate_evidence_invalid")
        selected: list[dict[str, Any]] = []
        for evidence_id in refs:
            sealed = index.get(evidence_id)
            fresh = collected.get(evidence_id)
            if not isinstance(sealed, dict) or not isinstance(fresh, dict):
                raise ScreenError("cited_evidence_not_reconstructed")
            for key in (
                "content_hash",
                "path",
                "source_kind",
                "source_revision",
                "trust",
                "line_start",
                "line_end",
                "source_object_id",
                "source_object_format",
                "source_object_size_bytes",
                "content_truncated",
            ):
                # The sealed index intentionally omits the source object's content,
                # and legacy records may omit optional object metadata. Every
                # recorded value must match; content itself is hash-checked below.
                if key in sealed and sealed[key] != fresh.get(key):
                    raise ScreenError("cited_evidence_metadata_mismatch")
            content = fresh.get("content")
            if not isinstance(content, str) or _sha256(content.encode("utf-8")) != sealed.get("content_hash"):
                raise ScreenError("cited_evidence_hash_mismatch")
            selected.append(fresh)
        candidate_copy = {
            key: candidate[key]
            for key in (
                "candidate_id",
                "title",
                "observation",
                "consequence",
                "rule_or_contract",
                "evidence_refs",
            )
            if key in candidate
        }
        if set(candidate_copy) != {
            "candidate_id",
            "title",
            "observation",
            "consequence",
            "rule_or_contract",
            "evidence_refs",
        }:
            raise ScreenError("candidate_fields_missing")
        loaded.append(
            ScreenCase(
                case_id=case_id,
                candidate_id=spec["candidate_id"],
                kind=spec["kind"],
                result_sha256=result_hash,
                snapshot_id=snapshot["snapshot_id"],
                snapshot_hash=snapshot["snapshot_hash"],
                profile_id="prompt-injection-adversarial",
                profile_hash=snapshot["profile_hash"],
                profile_source_sha256=profile_source_hash,
                base_sha=snapshot["base_sha"],
                head_sha=snapshot["head_sha"],
                candidate=candidate_copy,
                evidence=tuple(selected),
            )
        )
    if len(loaded) != MAX_CANDIDATES:
        raise ScreenError("candidate_count_mismatch")
    return tuple(loaded)


def _load_transport_config(path: Path) -> tuple[dict[str, Any], bytes]:
    config, raw = _read_json(path, max_bytes=MAX_CONFIG_BYTES)
    try:
        transport = ClaimTransport(config)
    except Exception as exc:
        raise ScreenError(getattr(exc, "code", "invalid_transport_config")) from None
    if transport.endpoint != "https://api.typesafe.ai/v1/systemone":
        raise ScreenError("nonproduction_endpoint_forbidden")
    if transport.max_request_bytes < MAX_INPUT_BYTES or transport.max_response_bytes < MAX_OUTPUT_BYTES:
        raise ScreenError("transport_caps_below_screen_limits")
    return config, raw


def _assessment_limits() -> dict[str, Any]:
    return {
        "max_input_bytes_per_task": MAX_INPUT_BYTES,
        "max_output_bytes_per_task": MAX_OUTPUT_BYTES,
        "deadline_seconds": PER_CANDIDATE_DEADLINE_SECONDS,
    }


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        process.kill()


def _worker_environment(credential_name: str) -> dict[str, str]:
    # Forward only runtime necessities and the credential reference's value.
    # The value is consumed by ClaimTransport and is never serialized or logged.
    allowed = {"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    secret = os.environ.get(credential_name)
    if secret:
        env[credential_name] = secret
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run_worker(
    payload: dict[str, Any],
    config: dict[str, Any],
    timeout: float,
    *,
    worker_command: list[str] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    command = worker_command or [sys.executable, str(Path(__file__).resolve()), "--worker"]
    request = {"payload": payload, "transport_config": config}
    raw_input = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw_input) > MAX_ARTIFACT_BYTES:
        return "worker_input_exceeds_limit", None
    try:
        child = subprocess.Popen(
            command,
            cwd=ROOT,
            env=_worker_environment(config.get("api_key_env", "TYPESAFE_API_KEY")),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=(os.name == "posix"),
        )
    except OSError:
        return "worker_start_failed", None
    assert child.stdin is not None and child.stdout is not None
    captured = bytearray()
    writer_error = threading.Event()

    def write_input() -> None:
        try:
            child.stdin.write(raw_input)
            child.stdin.flush()
        except (BrokenPipeError, OSError):
            writer_error.set()
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    writer = threading.Thread(target=write_input, daemon=True)
    writer.start()
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    exceeded = False
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), min(16_384, MAX_WORKER_STDOUT_BYTES + 1 - len(captured)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured.extend(chunk)
                if len(captured) > MAX_WORKER_STDOUT_BYTES:
                    exceeded = True
                    break
            if exceeded:
                break
            if child.poll() is not None and not selector.get_map():
                break
    finally:
        selector.close()
    if timed_out or exceeded:
        _kill_process(child)
        try:
            child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        writer.join(timeout=0.1)
        return ("hard_deadline_exceeded" if timed_out else "worker_output_exceeds_limit"), None
    try:
        child.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _kill_process(child)
        child.wait()
        return "hard_deadline_exceeded", None
    writer.join(timeout=0.1)
    stdout = bytes(captured)
    if child.returncode != 0:
        return "worker_failed", None
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "worker_output_invalid", None
    if not isinstance(value, dict) or value.get("worker_contract") != "claim-screen-worker.1":
        return "worker_output_invalid", None
    if value.get("ok") is not True or not isinstance(value.get("result"), dict):
        code = value.get("error_code")
        if isinstance(code, str) and code in _SAFE_ERROR_CODES:
            return code, None
        return "worker_assessment_failed", None
    return "ok", value["result"]


def _safe_result(result: dict[str, Any]) -> dict[str, Any]:
    """Retain typed judgments and provenance, never model free text/raw bodies."""
    allowed_assessment = (
        "question_id",
        "status",
        "native_primitive",
        "choice",
        "probabilities",
        "confidence",
        "evidence_refs",
        "interpretation",
        "invalid_answer_hash",
        "error_code",
    )
    assessments: dict[str, Any] = {}
    for dimension, item in result.get("assessments", {}).items():
        if not isinstance(item, dict):
            continue
        assessments[dimension] = {key: item[key] for key in allowed_assessment if key in item}
    provenance = result.get("provenance", {})
    safe_provenance = {
        key: provenance.get(key)
        for key in (
            "contract_version",
            "native_contract",
            "provider_id",
            "configured_model_id",
            "provider_model_id",
            "model_identity_source",
            "request_hash",
            "response_hash",
            "response_bytes",
            "candidate_hash",
            "evidence_hash",
            "question_hash",
            "snapshot_id",
            "snapshot_hash",
            "profile_id",
            "profile_hash",
            "base_sha",
            "head_sha",
            "http_status",
            "error_code",
            "elapsed_ms",
        )
        if key in provenance
    }
    usage = result.get("usage")
    safe_usage = {"provider_usage_known": False, "input_tokens": None, "output_tokens": None}
    if isinstance(usage, dict) and usage.get("known") is True:
        safe_usage = {
            "provider_usage_known": True,
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
        }
    safe_result = {
        "status": result.get("status", "FAILED"),
        "assessments": assessments,
        "provenance": safe_provenance,
        "usage": safe_usage,
        "billed_cost": "UNKNOWN",
        "elapsed_ms": result.get("elapsed_ms"),
        "decision": "ADVISORY_ONLY",
    }
    # The outer assessment contract is required by downstream triage. Preserve
    # only the version the adapter actually supplied; legacy/malformed results
    # must not be upgraded by this projection.
    if isinstance(result.get("contract_version"), str):
        safe_result["contract_version"] = result["contract_version"]
    return safe_result


def _worker_main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ScreenError("worker_input_exceeds_limit")
        envelope = json.loads(raw.decode("utf-8"))
        payload = envelope["payload"]
        config = envelope["transport_config"]
        if not isinstance(payload, dict) or not isinstance(config, dict):
            raise ScreenError("worker_input_invalid")
        case = payload["case"]
        limits = payload["limits"]
        if len(payload["prepared_request_hash"]) != 64:
            raise ScreenError("worker_input_invalid")
        transport = ClaimTransport(config)
        adapter = ClaimAssessmentAdapter(transport, transport.model)
        prepared = adapter.prepare(case["candidate"], case["evidence"], case["identity"], limits)
        if _sha256(prepared.request_bytes) != payload["prepared_request_hash"]:
            raise ScreenError("prepared_request_hash_mismatch")
        result = adapter.assess_prepared(prepared, limits)
        sys.stdout.write(
            json.dumps(
                {"worker_contract": "claim-screen-worker.1", "ok": True, "result": result},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or code not in _SAFE_ERROR_CODES:
            code = "assessment_failed"
        sys.stdout.write(
            json.dumps(
                {"worker_contract": "claim-screen-worker.1", "ok": False, "error_code": code},
                separators=(",", ":"),
            )
        )
        return 0


def run_claim_screen(artifact_dir: Path, transport_config_path: Path, output_path: Path) -> dict[str, Any]:
    cases = load_screen_cases(artifact_dir)
    config, config_raw = _load_transport_config(transport_config_path)
    transport = ClaimTransport(config)
    model = transport.model
    limits = _assessment_limits()
    results: list[dict[str, Any]] = []
    for case in cases:
        row_started = time.monotonic()
        base = {
            "case_id": case.case_id,
            "candidate_id": case.candidate_id,
            "candidate_kind": case.kind,
            "sealed_result_sha256": case.result_sha256,
            "snapshot_id": case.snapshot_id,
            "snapshot_hash": case.snapshot_hash,
            "profile_id": case.profile_id,
            "profile_hash": case.profile_hash,
            "profile_source_sha256": case.profile_source_sha256,
            "base_sha": case.base_sha,
            "head_sha": case.head_sha,
            "configured_model_id": model,
            "provider_model_id": None,
            "model_identity_source": "operator_configured",
            "status": "FAILED",
            "error_code": None,
            "request_hash": None,
            "input_bytes": None,
            "max_output_bytes": MAX_OUTPUT_BYTES,
            "deadline_seconds": PER_CANDIDATE_DEADLINE_SECONDS,
            "retry_count": 0,
            "usage": {"known": False, "input_tokens": None, "output_tokens": None},
            "billed_cost": "UNKNOWN",
            "assessments": {},
            "elapsed_ms": None,
        }
        try:
            identity = case.assessment_identity()
            adapter = ClaimAssessmentAdapter(lambda *_args: b"", model)
            prepared = adapter.prepare(case.candidate, case.evidence, identity, limits)
            estimate = transport.estimate_call(prepared.request_bytes, limits)
            if estimate["input_bytes"] > MAX_INPUT_BYTES or estimate["max_output_bytes"] > MAX_OUTPUT_BYTES:
                raise ScreenError("call_limit_exceeded")
            base["request_hash"] = _sha256(prepared.request_bytes)
            base["input_bytes"] = estimate["input_bytes"]
            payload = {
                "case": {"candidate": case.candidate, "evidence": list(case.evidence), "identity": identity},
                "limits": limits,
                "prepared_request_hash": base["request_hash"],
            }
            status, worker_result = _run_worker(payload, config, PER_CANDIDATE_DEADLINE_SECONDS)
            if status != "ok" or worker_result is None:
                base["error_code"] = status
            else:
                safe = _safe_result(worker_result)
                base.update(
                    status=safe["status"],
                    error_code=safe["provenance"].get("error_code"),
                    assessments=safe["assessments"],
                    usage=safe["usage"],
                    provider_model_id=safe["provenance"].get("provider_model_id"),
                    model_identity_source=safe["provenance"].get("model_identity_source"),
                    billed_cost="UNKNOWN",
                    elapsed_ms=safe["elapsed_ms"],
                    response_hash=safe["provenance"].get("response_hash"),
                    response_bytes=safe["provenance"].get("response_bytes"),
                )
        except Exception as exc:
            code = getattr(exc, "code", None)
            base["error_code"] = code if isinstance(code, str) and len(code) <= 80 else "preflight_failed"
        if base["elapsed_ms"] is None:
            base["elapsed_ms"] = round((time.monotonic() - row_started) * 1000, 2)
        results.append(base)

    manifest = {
        "contract_version": "native-claim-screen.1",
        "experiment": "e22a085-advisory-development-candidates",
        "runner_source_sha256": _sha256(Path(__file__).read_bytes()),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "model": {
            "provider_id": "typesafe",
            "configured_model_id": model,
            "model_identity_source": "operator_configured",
            "provider_model_ids": sorted({row["provider_model_id"] for row in results if row.get("provider_model_id")}),
            "transport_config_sha256": _sha256(config_raw),
        },
        "limits": {
            "candidate_calls_max": MAX_CANDIDATES,
            "max_input_bytes_per_call": MAX_INPUT_BYTES,
            "max_output_bytes_per_call": MAX_OUTPUT_BYTES,
            "deadline_seconds_per_call": PER_CANDIDATE_DEADLINE_SECONDS,
            "retries": 0,
            "billing": "UNKNOWN unless provider reports authoritative billing; this adapter does not claim spend bounds.",
        },
        "interpretation": "Advisory uncalibrated screening only. These are development examples, not held-out cases or truth labels. No gate promotion or quality claim.",
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp = output_path.with_suffix(output_path.suffix + ".tmp")
    raw_output = json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(raw_output) > 1_000_000:
        raise ScreenError("summary_exceeds_limit")
    temp.write_bytes(raw_output)
    os.chmod(temp, 0o600)
    os.replace(temp, output_path)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, help="Preserved e22a085 result and local fixture bundle")
    parser.add_argument(
        "--transport-config", type=Path, help="TypeSafe JSON config with model and credential environment-variable name"
    )
    parser.add_argument("--output", type=Path, help="Path for the bounded advisory summary JSON")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        return _worker_main()
    if not args.artifact_dir or not args.transport_config or not args.output:
        parser.error("--artifact-dir, --transport-config and --output are required")
    try:
        result = run_claim_screen(args.artifact_dir, args.transport_config, args.output)
    except ScreenError as exc:
        print(json.dumps({"status": "NOT_RUN", "error_code": exc.code}), file=sys.stderr)
        return 2
    print(json.dumps({"status": "COMPLETE", "result_count": len(result["results"]), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
