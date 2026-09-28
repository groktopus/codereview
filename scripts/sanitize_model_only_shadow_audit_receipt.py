#!/usr/bin/env python3
"""Validate and copy the allowlisted hash-only shadow audit receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


class ReceiptError(ValueError):
    pass


ROLES = {"source_auditor", "jev", "claim_auditor"}
HASH = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
ROLE_STATES = {"completed", "abstained", "failed", "incomplete", "not_run", "unavailable"}


def _read(path: Path) -> tuple[dict[str, Any], bytes]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 64_000:
        raise ReceiptError("receipt_file_invalid")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ReceiptError("receipt_file_invalid")
        raw = os.read(fd, 64_001)
    finally:
        os.close(fd)
    if len(raw) > 64_000:
        raise ReceiptError("receipt_file_invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ReceiptError("receipt_json_invalid") from None
    if not isinstance(value, dict):
        raise ReceiptError("receipt_shape_invalid")
    return value, raw


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _valid(receipt: dict[str, Any]) -> None:
    base = {"schema", "case_id", "terminal_state", "reason", "audit_provider_calls", "candidate_packet_count",
            "selected_packet_sha256", "capture_manifest_sha256", "roles", "role_call_counts"}
    optional = {"selected_candidate_sha256", "shadow_manifest_sha256"}
    if frozenset(receipt) not in {frozenset(base), frozenset(base | optional)}:
        raise ReceiptError("receipt_fields_invalid")
    if (receipt.get("schema") != "model-only-shadow-audit-receipt.v1"
            or receipt.get("case_id") != "PR-464"
            or receipt.get("terminal_state") not in {"completed", "claim_audit_abstained", "incomplete", "source_audit_failed", "jev_assessment_failed", "claim_audit_failed"}
            or receipt.get("reason") not in {"no_writer_candidate", "one_candidate_selected", "bounded_single_candidate_selection"}):
        raise ReceiptError("receipt_identity_invalid")
    calls = receipt.get("audit_provider_calls")
    count = receipt.get("candidate_packet_count")
    if isinstance(calls, bool) or not isinstance(calls, int) or not 0 <= calls <= 3:
        raise ReceiptError("receipt_budget_invalid")
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 128:
        raise ReceiptError("receipt_candidate_count_invalid")
    for field in ("selected_packet_sha256", "capture_manifest_sha256"):
        if not isinstance(receipt.get(field), str) or not HASH.fullmatch(receipt[field]):
            raise ReceiptError("receipt_hash_invalid")
    roles = receipt.get("roles")
    if not isinstance(roles, dict) or set(roles) != ROLES or any(value not in ROLE_STATES for value in roles.values()):
        raise ReceiptError("receipt_role_states_invalid")
    role_calls = receipt.get("role_call_counts")
    if (not isinstance(role_calls, dict) or set(role_calls) != ROLES
            or any(isinstance(value, bool) or not isinstance(value, int) or value not in {0, 1}
                   for value in role_calls.values())
            or sum(role_calls.values()) != calls):
        raise ReceiptError("receipt_role_call_counts_invalid")
    if any(roles[role] == "not_run" and role_calls[role] != 0 for role in ROLES):
        raise ReceiptError("not_run_role_has_call")
    if count == 0:
        if (set(receipt) != base or receipt["terminal_state"] != "incomplete" or calls != 0
                or receipt["reason"] != "no_writer_candidate" or set(roles.values()) != {"not_run"}):
            raise ReceiptError("zero_candidate_receipt_invalid")
    else:
        if (set(receipt) != base | optional or not isinstance(receipt["selected_candidate_sha256"], str)
                or not HASH.fullmatch(receipt["selected_candidate_sha256"])
                or not isinstance(receipt["shadow_manifest_sha256"], str)
                or not HASH.fullmatch(receipt["shadow_manifest_sha256"])):
            raise ReceiptError("selected_candidate_receipt_invalid")
        if receipt["reason"] != ("one_candidate_selected" if count == 1 else "bounded_single_candidate_selection"):
            raise ReceiptError("candidate_selection_reason_mismatch")
        terminal = receipt["terminal_state"]
        source, jev, claim = (roles["source_auditor"], roles["jev"], roles["claim_auditor"])
        source_calls, jev_calls, claim_calls = (
            role_calls["source_auditor"], role_calls["jev"], role_calls["claim_auditor"]
        )
        eligible = {"completed", "abstained"}
        consistent = (
            (terminal == "completed" and source in eligible and jev in eligible and claim == "completed"
             and (source_calls, jev_calls, claim_calls) == (1, 1, 1))
            or (terminal == "claim_audit_abstained" and source in eligible and jev in eligible and claim == "abstained"
                and (source_calls, jev_calls, claim_calls) == (1, 1, 1))
            or (terminal == "source_audit_failed" and source == "failed" and jev == "not_run" and claim == "not_run"
                and source_calls in {0, 1} and jev_calls == claim_calls == 0)
            or (terminal == "jev_assessment_failed" and source in eligible and jev in {"failed", "incomplete"} and claim == "not_run"
                and source_calls == 1 and jev_calls in {0, 1} and claim_calls == 0)
            or (terminal == "claim_audit_failed" and source in eligible and jev in eligible and claim == "failed"
                and source_calls == jev_calls == 1 and claim_calls in {0, 1})
        )
        if not consistent:
            raise ReceiptError("terminal_role_accounting_mismatch")


def sanitize(input_path: Path, output_dir: Path) -> dict[str, Any]:
    receipt, raw = _read(input_path)
    _valid(receipt)
    if output_dir.exists() or output_dir.is_symlink():
        raise ReceiptError("output_directory_exists")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output_dir, 0o700)
    output = output_dir / "shadow-audit-receipt.json"
    data = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return {"sha256": hashlib.sha256(data).hexdigest(), "input_sha256": hashlib.sha256(raw).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = sanitize(args.input, args.output_dir)
    except (OSError, ReceiptError):
        print('{"ok":false,"error_code":"audit_receipt_invalid"}')
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
