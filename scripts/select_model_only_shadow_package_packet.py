#!/usr/bin/env python3
"""Select the candidate packet only for a completed, fully bound audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

HASH = re.compile(r"[0-9a-f]{64}\Z")
PACKET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json\Z")
ROLES = {"source_auditor", "jev", "claim_auditor"}


class SelectionError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _read(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise SelectionError("selection_input_invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_size > limit):
                raise SelectionError("selection_input_invalid")
            chunks = bytearray()
            while len(chunks) <= limit:
                block = os.read(fd, min(65_536, limit + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            after = os.fstat(fd)
            if (len(chunks) > limit or len(chunks) != opened.st_size
                    or before.st_size != after.st_size or after.st_size != len(chunks)):
                raise SelectionError("selection_input_invalid")
            raw = bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise SelectionError("selection_input_invalid") from None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SelectionError("selection_json_invalid") from None
    if not isinstance(value, dict):
        raise SelectionError("selection_json_invalid")
    return value, raw


def select(capture_root: Path, audit_receipt_path: Path, case_id: str) -> dict[str, object]:
    manifest, manifest_raw = _read(capture_root / "manifest.json", 256_000)
    receipt, _receipt_raw = _read(audit_receipt_path, 64_000)
    if (case_id not in {"PR-457", "PR-464"}
            or receipt.get("schema") != "model-only-shadow-audit-receipt.v1"
            or receipt.get("case_id") != case_id):
        raise SelectionError("selection_receipt_identity_invalid")
    if receipt.get("terminal_state") != "completed":
        return {"eligible": False, "reason": "audit_not_completed"}
    if (not isinstance(receipt.get("candidate_packet_count"), int)
            or isinstance(receipt.get("candidate_packet_count"), bool)
            or receipt["candidate_packet_count"] < 1
            or receipt.get("reason") not in {"one_candidate_selected", "bounded_single_candidate_selection"}
            or not isinstance(receipt.get("selected_candidate_sha256"), str)
            or not HASH.fullmatch(receipt["selected_candidate_sha256"])):
        raise SelectionError("completed_receipt_candidate_invalid")
    if (not isinstance(receipt.get("capture_manifest_sha256"), str)
            or receipt["capture_manifest_sha256"] != hashlib.sha256(manifest_raw).hexdigest()):
        raise SelectionError("selection_capture_binding_invalid")
    roles = receipt.get("roles")
    if not isinstance(roles, dict) or set(roles) != ROLES or any(state != "completed" for state in roles.values()):
        raise SelectionError("completed_receipt_roles_invalid")
    packet_sha = receipt.get("selected_packet_sha256")
    if not isinstance(packet_sha, str) or not HASH.fullmatch(packet_sha):
        raise SelectionError("selection_packet_hash_invalid")
    inventory = manifest.get("case_packet_inventory")
    packets = inventory.get("packets") if isinstance(inventory, dict) else None
    if not isinstance(packets, list):
        raise SelectionError("selection_packet_inventory_invalid")
    matches = [item for item in packets if isinstance(item, dict) and item.get("sha256") == packet_sha]
    if len(matches) != 1:
        raise SelectionError("selection_packet_binding_invalid")
    name = matches[0].get("path")
    if not isinstance(name, str) or not PACKET_NAME.fullmatch(name):
        raise SelectionError("selection_packet_path_invalid")
    packet_path = capture_root / "case-packets" / name
    _packet, packet_raw = _read(packet_path, 4_000_000)
    if hashlib.sha256(packet_raw).hexdigest() != packet_sha:
        raise SelectionError("selection_packet_binding_invalid")
    if _packet.get("case_id") != case_id:
        raise SelectionError("selection_packet_identity_invalid")
    candidate = _packet.get("writer_candidate")
    candidate_id = candidate.get("candidate_id") if isinstance(candidate, dict) else None
    if not isinstance(candidate_id, str) or not candidate_id:
        raise SelectionError("completed_packet_candidate_invalid")
    return {"eligible": True, "reason": "completed_candidate_audit", "selected_packet": name}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--audit-receipt", type=Path, required=True)
    parser.add_argument("--case-id", choices=("PR-457", "PR-464"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = select(args.capture_root, args.audit_receipt, args.case_id)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    except (OSError, SelectionError):
        print('{"ok":false,"error_code":"package_selection_invalid"}')
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
