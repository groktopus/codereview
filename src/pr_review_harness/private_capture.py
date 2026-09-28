"""Opt-in private capture of exact writer exchanges for local shadow audits.

This module deliberately stores only request-body bytes and the provider's
structured message-content bytes. It never stores transport headers or an HTTP
envelope. Call receipts contain hashes and bounded identifiers only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path
from typing import Any

MAX_CAPTURE_CALLS = 64
MAX_REQUEST_BYTES = 2_000_000
MAX_RESPONSE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 64_000_000
CONTENT_TRANSFORM = "openai-chat-completions.message-content.utf8.v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _reconciled_candidate_pairs(findings: list[dict]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        assessment_records = finding.get("assessment_records")
        if isinstance(assessment_records, list):
            for record in assessment_records:
                if (
                    isinstance(record, dict)
                    and isinstance(record.get("candidate_id"), str)
                    and isinstance(record.get("task_id"), str)
                ):
                    pairs.add((record["candidate_id"], record["task_id"]))
        elif isinstance(finding.get("candidate_id"), str) and isinstance(finding.get("task_id"), str):
            pairs.add((finding["candidate_id"], finding["task_id"]))
    return pairs


def _safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) or ".." in value:
        raise ValueError(f"invalid {label}")
    return value


def _write_private(path: Path, data: bytes, *, limit: int) -> None:
    if not isinstance(data, bytes) or len(data) > limit:
        raise ValueError("capture byte limit exceeded")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("capture artifact is not a regular file")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _read_bounded_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("capture file is not bounded regular data")
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(fd)
        if (
            len(chunks) > limit or not stat.S_ISREG(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or after.st_size != len(chunks) or before.st_size != after.st_size
        ):
            raise ValueError("capture file changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


class PrivateShadowCapture:
    """Owns a new private capture directory and its bounded call receipts."""

    def __init__(self, root: str | os.PathLike[str], *, case_id: str, snapshot: dict, source_task: str,
                 provider: Any, request_byte_limit: int, response_byte_limit: int,
                 corpus_case_id: str | None = None):
        self.root = Path(root).expanduser()
        if self.root.exists() or self.root.is_symlink():
            raise ValueError("capture directory must be new")
        self.case_id = _safe_id(case_id, "case_id")
        self.corpus_case_id = _safe_id(corpus_case_id, "corpus_case_id") if corpus_case_id is not None else None
        self.source_task = _safe_id(source_task, "source_task")
        self.snapshot = snapshot
        self.snapshot_id = _safe_id(snapshot.get("snapshot_id"), "snapshot_id")
        self.snapshot_hash = snapshot.get("snapshot_hash")
        if not isinstance(self.snapshot_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", self.snapshot_hash):
            raise ValueError("invalid snapshot hash")
        collector_payload = {
            key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}
        }
        if self.snapshot_hash != _sha(_canonical(collector_payload)):
            raise ValueError("stale or mismatched snapshot")
        for sha_name in ("base_sha", "head_sha"):
            sha_value = snapshot.get(sha_name)
            if sha_value is not None and (
                not isinstance(sha_value, str) or not re.fullmatch(r"[0-9a-f]{40}", sha_value)
            ):
                raise ValueError("invalid snapshot revision")
        evidence = snapshot.get("evidence", {})
        if not isinstance(evidence, dict):
            raise ValueError("invalid snapshot evidence map")
        for evidence_id, item in evidence.items():
            if not isinstance(item, dict) or item.get("evidence_id") != evidence_id:
                raise ValueError("snapshot evidence identity mismatch")
            if item.get("snapshot_id") != self.snapshot_id:
                raise ValueError("snapshot evidence snapshot mismatch")
        self.root.mkdir(mode=0o700, parents=False)
        os.chmod(self.root, 0o700)
        self._lock = threading.Lock()
        self._calls: dict[str, dict] = {}
        self._reconciled: set[str] = set()
        self._total_bytes = 0
        identity = getattr(provider, "identity", {})
        safe_identity = {
            key: identity.get(key)
            for key in ("provider", "provider_id", "model", "model_id", "adapter_version")
            if isinstance(identity, dict)
            and isinstance(identity.get(key), str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", identity[key])
        }
        self.provider_identity = safe_identity
        self._source_task_rows: dict[str, dict] = {}
        self._profile_id: str | None = None
        if (
            isinstance(request_byte_limit, bool) or not isinstance(request_byte_limit, int)
            or not 1 <= request_byte_limit <= MAX_REQUEST_BYTES
            or isinstance(response_byte_limit, bool) or not isinstance(response_byte_limit, int)
            or not 1 <= response_byte_limit <= MAX_RESPONSE_BYTES
        ):
            raise ValueError("capture capacity invalid")
        self.request_byte_limit = request_byte_limit
        self.response_byte_limit = response_byte_limit
        for name in ("requests", "responses", "calls"):
            child = self.root / name
            child.mkdir(mode=0o700)
            os.chmod(child, 0o700)
        self._write_json("snapshot.json", snapshot)
        self._write_json("manifest.json", {
            "contract_version": "model-only-shadow-case.v1",
            "case_id": self.case_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_hash": self.snapshot_hash,
            "source_task": self.source_task,
            "provider": self.provider_identity,
            "calls": [],
            "private_artifacts": True,
        })

    def _write_json(self, relative: str, value: Any) -> None:
        path = self.root / relative
        _write_private(path, _canonical(value) + b"\n", limit=MAX_TOTAL_BYTES)

    def _replace_json(self, path: Path, value: Any) -> None:
        temp = self.root / (".tmp-" + _sha(os.urandom(24))[:20])
        _write_private(temp, _canonical(value) + b"\n", limit=MAX_TOTAL_BYTES)
        os.replace(temp, path)

    def begin_call(self, *, run_id: str, task_id: str, attempt: int) -> dict:
        run_id = _safe_id(run_id, "run_id")
        task_id = _safe_id(task_id, "task_id")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            raise ValueError("invalid attempt")
        call_id = "call-" + _sha(_canonical([self.case_id, run_id, task_id, attempt]))[:24]
        with self._lock:
            if call_id in self._calls or len(self._calls) >= MAX_CAPTURE_CALLS:
                raise ValueError("capture call limit or duplicate call")
            receipt = {
                "call_id": call_id, "case_id": self.case_id, "run_id": run_id,
                "snapshot_id": self.snapshot_id, "snapshot_hash": self.snapshot_hash,
                "task_id": task_id, "attempt": attempt, "provider": self.provider_identity,
                "status": "incomplete", "request_artifact_id": None,
                "request_sha256": None, "response_artifact_id": None,
                "response_sha256": None, "response_envelope_sha256": None,
                "content_transform": None,
            }
            self._calls[call_id] = receipt
            self._write_call_receipt(receipt)
        return {"case_id": self.case_id, "run_id": run_id, "snapshot_id": self.snapshot_id,
                "snapshot_hash": self.snapshot_hash, "task_id": task_id, "call_id": call_id,
                "attempt": attempt, "request_byte_limit": self.request_byte_limit,
                "response_byte_limit": self.response_byte_limit}

    def export_source_tasks(self, rows: list[dict], *, profile_id: str) -> None:
        profile_id = _safe_id(profile_id, "profile_id")
        if not isinstance(rows, list) or len(rows) > MAX_CAPTURE_CALLS:
            raise ValueError("source task export exceeds limit")
        seen = set()
        safe_rows = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"task", "evidence"}:
                raise ValueError("invalid source task row")
            task = row["task"]
            evidence = row["evidence"]
            if not isinstance(task, dict) or not isinstance(evidence, list):
                raise ValueError("invalid source task content")
            task_id = _safe_id(task.get("task_id"), "task_id")
            if task_id in seen or task.get("task_kind", "SPECIALIST_FINDINGS") != "SPECIALIST_FINDINGS":
                raise ValueError("duplicate or non-writer source task")
            seen.add(task_id)
            if any(not isinstance(item, dict) or item.get("snapshot_id") != self.snapshot_id for item in evidence):
                raise ValueError("source evidence snapshot mismatch")
            safe_rows.append({"task": task, "evidence": evidence})
        self._write_json("source_tasks.json", {
            "contract_version": "model-only-shadow-source-tasks.v1",
            "case_id": self.case_id, "snapshot_id": self.snapshot_id,
            "snapshot_hash": self.snapshot_hash, "profile_id": profile_id, "tasks": safe_rows,
        })
        self._source_task_rows = {row["task"]["task_id"]: row for row in safe_rows}
        self._profile_id = profile_id

    def export_case_packets(self, result: dict, *, profile: dict) -> list[Path]:
        """Export one runner packet per admitted writer task from sealed engine findings."""
        if not self._source_task_rows or self._profile_id is None:
            return []
        if not isinstance(result, dict) or result.get("snapshot_id") != self.snapshot_id:
            raise ValueError("case packet result snapshot mismatch")
        findings = result.get("findings", [])
        task_results = result.get("task_results", {})
        if not isinstance(findings, list) or not isinstance(task_results, dict):
            raise ValueError("case packet findings invalid")
        reconciled_pairs = _reconciled_candidate_pairs(findings)
        packet_dir = self.root / "case-packets"
        packet_dir.mkdir(mode=0o700)
        os.chmod(packet_dir, 0o700)
        call_values = list(self._calls.values())
        packets: list[Path] = []
        provider_id = self.provider_identity.get("provider_id", self.provider_identity.get("provider", "openai-compatible"))
        model_id = self.provider_identity.get("model_id", self.provider_identity.get("model", "unreported"))
        version = self.provider_identity.get("adapter_version", "0.2")
        observed_profile_hash = _sha(_canonical(profile))
        if self.snapshot.get("profile_hash") != observed_profile_hash:
            raise ValueError("case packet profile hash mismatch")
        rubric_revision = "profile-sha256-" + observed_profile_hash
        for task_id, row in self._source_task_rows.items():
            task_calls = [call for call in call_values if call.get("task_id") == task_id]
            task_result = task_results.get(task_id, {})
            if not task_calls:
                writer_status = "not_run"
                calls = []
                calls_manifest_hash = None
            else:
                statuses = [call.get("status") for call in task_calls]
                if task_result.get("status") == "SUCCEEDED" and all(status == "completed" for status in statuses):
                    writer_status = "completed"
                else:
                    writer_status = (
                        "unavailable" if all(status == "unavailable" for status in statuses)
                        else "failed" if all(status == "failed" for status in statuses)
                        else "incomplete"
                    )
                calls = [
                    {
                        "call_id": call["call_id"],
                        "request_sha256": call.get("request_sha256"),
                        "request_artifact_id": call.get("request_artifact_id"),
                        "response_sha256": call.get("response_sha256"),
                        "response_artifact_id": call.get("response_artifact_id"),
                    }
                    for call in task_calls
                ]
                calls_manifest_hash = _sha(json.dumps(
                    calls, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
                ).encode("utf-8"))
            candidates: list[dict | None] = []
            task_payload = task_result.get("payload", {}) if isinstance(task_result, dict) else {}
            raw_candidates = task_payload.get("finding_candidates", []) if isinstance(task_payload, dict) else []
            if task_result.get("status") == "SUCCEEDED" and isinstance(raw_candidates, list):
                for index, raw in enumerate(raw_candidates):
                    if not isinstance(raw, dict):
                        continue
                    candidate_id = _sha(_canonical({"task_id": task_id, "index": index, "raw": raw}))[:24]
                    if (candidate_id, task_id) not in reconciled_pairs:
                        continue
                    required = ("title", "observation", "consequence", "rule_or_contract", "evidence_refs")
                    if all(field in raw for field in required):
                        candidates.append({"candidate_id": candidate_id, **{field: raw[field] for field in required}})
            if not candidates:
                candidates = [None]
            for candidate in candidates:
                candidate_id = str(candidate["candidate_id"]) if candidate else "none"
                suffix = _sha(_canonical([task_id, candidate_id]))[:12]
                packet_file_id = f"{self.corpus_case_id or self.case_id}-{suffix}"
                calls_digest = calls_manifest_hash
                if writer_status == "not_run":
                    calls_digest = None
                writer_run = {
                    "role": "writer", "status": writer_status,
                    "run_id": result.get("run_id") if writer_status != "not_run" else None,
                    "provider_id": provider_id if writer_status != "not_run" else None,
                    "model_id": model_id if writer_status != "not_run" else None,
                    "runtime_id": f"pr-review-harness/{version}" if writer_status != "not_run" else None,
                    "prompt_revision": "specialist-findings.v4" if writer_status != "not_run" else None,
                    "rubric_revision": rubric_revision if writer_status != "not_run" else None,
                    "calls": calls, "calls_manifest_sha256": calls_digest,
                }
                evidence_rows = row["evidence"]
                packet = {
                    "contract_version": "model-only-shadow-case.v1",
                    "case_id": self.corpus_case_id or packet_file_id,
                    "snapshot": json.loads((self.root / "snapshot.json").read_text(encoding="utf-8")),
                    "source_task": row["task"], "source_evidence": evidence_rows,
                    "writer_run": writer_run, "writer_candidate": candidate,
                    "profile_id": self._profile_id,
                }
                path = packet_dir / f"{packet_file_id}.json"
                self._write_packet(path, packet)
                packets.append(path)
        return packets

    def _write_packet(self, path: Path, packet: dict) -> None:
        _write_private(path, _canonical(packet) + b"\n", limit=MAX_TOTAL_BYTES)

    def _write_call_receipt(self, receipt: dict) -> None:
        self._replace_json(self.root / "calls" / f"{receipt['call_id']}.json", receipt)
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["calls"] = [*manifest["calls"], receipt] if not any(
            row.get("call_id") == receipt["call_id"] for row in manifest["calls"]
        ) else [receipt if row.get("call_id") == receipt["call_id"] else row for row in manifest["calls"]]
        self._replace_json(manifest_path, manifest)

    def reconcile(self, spec: dict) -> dict | None:
        """Admit a child-written receipt only when every pending identity matches."""
        call_id = _safe_id(spec.get("call_id"), "call_id")
        final_path = self.root / "calls" / f"{call_id}.final.json"
        with self._lock:
            if call_id in self._reconciled:
                raise ValueError("capture receipt already reconciled")
        try:
            receipt_bytes = _read_bounded_regular(final_path, 64_000)
            receipt = json.loads(receipt_bytes.decode("utf-8"))
        except FileNotFoundError:
            return None
        with self._lock:
            pending = self._calls.get(call_id)
            if pending is None or any(receipt.get(k) != pending.get(k) for k in (
                "call_id", "case_id", "run_id", "snapshot_id", "snapshot_hash", "task_id", "attempt"
            )):
                raise ValueError("capture receipt identity mismatch")
            if receipt.get("status") not in {"completed", "incomplete", "failed", "unavailable"}:
                raise ValueError("capture receipt status invalid")
            for hash_field in ("request_sha256", "response_sha256", "response_envelope_sha256"):
                value = receipt.get(hash_field)
                if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)):
                    raise ValueError("capture receipt hash invalid")
            for artifact_field in ("request_artifact_id", "response_artifact_id"):
                value = receipt.get(artifact_field)
                if value is not None and not re.fullmatch(r"(?:request|response)-call-[0-9a-f]{24}", value):
                    raise ValueError("capture receipt artifact invalid")
            for kind, hash_field in (("request", "request_sha256"), ("response", "response_sha256")):
                digest = receipt.get(hash_field)
                artifact = self.root / f"{kind}s" / f"{call_id}.bin"
                if digest is None:
                    if artifact.exists() or artifact.is_symlink():
                        raise ValueError("unbound capture artifact")
                    continue
                cap = self.request_byte_limit if kind == "request" else self.response_byte_limit
                raw = _read_bounded_regular(artifact, cap)
                if _sha(raw) != digest:
                    raise ValueError("capture artifact hash mismatch")
                if self._total_bytes + len(raw) > MAX_TOTAL_BYTES:
                    raise ValueError("capture aggregate byte limit exceeded")
                self._total_bytes += len(raw)
            allowed = {
                "call_id", "case_id", "run_id", "snapshot_id", "snapshot_hash", "task_id", "attempt",
                "provider", "status", "request_artifact_id", "request_sha256", "response_artifact_id",
                "response_sha256", "response_envelope_sha256", "content_transform",
            }
            if set(receipt) != allowed:
                raise ValueError("capture receipt shape invalid")
            if receipt.get("response_sha256") is not None and receipt.get("content_transform") != CONTENT_TRANSFORM:
                raise ValueError("capture response transform invalid")
            self._calls[call_id] = receipt
            self._reconciled.add(call_id)
            self._write_call_receipt(receipt)
            return {key: receipt[key] for key in (
                "call_id", "request_sha256", "request_artifact_id", "response_sha256", "response_artifact_id", "status"
            )}

    def finalize_pending(self, call_id: str, status: str = "incomplete") -> None:
        if status not in {"incomplete", "failed", "unavailable"}:
            raise ValueError("invalid final status")
        with self._lock:
            receipt = self._calls.get(call_id)
            if receipt is not None and receipt.get("status") == "incomplete":
                receipt["status"] = status
                self._write_call_receipt(receipt)


def write_provider_exchange(capture_spec: dict, request_bytes: bytes | None, response_content_bytes: bytes | None,
                            status: str, response_envelope_sha256: str | None = None,
                            content_transform: str | None = None) -> dict:
    """Spawn-safe provider callback; the parent-owned directory is addressed by spec."""
    root = Path(capture_spec["root"])
    if root.is_symlink() or not root.is_dir():
        raise ValueError("capture root unavailable")
    call_id = _safe_id(capture_spec.get("call_id"), "call_id")
    if not re.fullmatch(r"call-[0-9a-f]{24}", call_id):
        raise ValueError("invalid call id")
    pending_path = root / "calls" / f"{call_id}.json"
    if pending_path.is_symlink() or not pending_path.is_file() or pending_path.stat().st_size > 64_000:
        raise ValueError("capture pending receipt unavailable")
    pending = json.loads(pending_path.read_text(encoding="utf-8"))
    if any(capture_spec.get(key) != pending.get(key) for key in (
        "case_id", "run_id", "snapshot_id", "snapshot_hash", "task_id", "attempt"
    )) or pending.get("status") != "incomplete":
        raise ValueError("capture call identity mismatch")
    request_limit = capture_spec.get("request_byte_limit")
    response_limit = capture_spec.get("response_byte_limit")
    if (
        isinstance(request_limit, bool) or not isinstance(request_limit, int)
        or not 1 <= request_limit <= MAX_REQUEST_BYTES
        or isinstance(response_limit, bool) or not isinstance(response_limit, int)
        or not 1 <= response_limit <= MAX_RESPONSE_BYTES
    ):
        raise ValueError("capture limits invalid")
    if status not in {"completed", "incomplete", "failed", "unavailable"}:
        raise ValueError("capture status invalid")
    if request_bytes is None:
        raise ValueError("exact provider request bytes are required")
    if content_transform not in {None, CONTENT_TRANSFORM}:
        raise ValueError("structured response transformation invalid")
    if response_envelope_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", response_envelope_sha256):
        raise ValueError("invalid response envelope hash")
    if request_bytes is not None and (not isinstance(request_bytes, bytes) or len(request_bytes) > request_limit):
        raise ValueError("request capture limit exceeded")
    if response_content_bytes is not None and (
        not isinstance(response_content_bytes, bytes) or len(response_content_bytes) > response_limit
    ):
        raise ValueError("response capture limit exceeded")
    receipt = {
        "call_id": call_id, "case_id": _safe_id(capture_spec.get("case_id"), "case_id"),
        "run_id": _safe_id(capture_spec.get("run_id"), "run_id"),
        "snapshot_id": _safe_id(capture_spec.get("snapshot_id"), "snapshot_id"),
        "snapshot_hash": capture_spec.get("snapshot_hash"),
        "task_id": _safe_id(capture_spec.get("task_id"), "task_id"),
        "attempt": capture_spec.get("attempt"), "provider": capture_spec.get("provider", {}),
        "status": status,
    }
    # Child writes use unique paths reserved by the parent. A pending receipt
    # already exists, so a worker crash remains visible as incomplete.
    if request_bytes is not None:
        _write_private(root / "requests" / f"{call_id}.bin", request_bytes, limit=MAX_REQUEST_BYTES)
        receipt["request_artifact_id"] = "request-" + call_id
        receipt["request_sha256"] = _sha(request_bytes)
    else:
        receipt.update(request_artifact_id=None, request_sha256=None)
    if response_content_bytes is not None:
        if content_transform != CONTENT_TRANSFORM:
            raise ValueError("structured response transformation is required")
        _write_private(root / "responses" / f"{call_id}.bin", response_content_bytes, limit=MAX_RESPONSE_BYTES)
        receipt["response_artifact_id"] = "response-" + call_id
        receipt["response_sha256"] = _sha(response_content_bytes)
    else:
        receipt.update(response_artifact_id=None, response_sha256=None)
    receipt["response_envelope_sha256"] = response_envelope_sha256
    receipt["content_transform"] = content_transform if response_content_bytes is not None else None
    _write_private(root / "calls" / f"{call_id}.final.json", _canonical(receipt) + b"\n", limit=64_000)
    return {key: receipt.get(key) for key in (
        "call_id", "request_sha256", "request_artifact_id", "response_sha256", "response_artifact_id", "status"
    )}
