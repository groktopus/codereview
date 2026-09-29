#!/usr/bin/env python3
"""Validate and copy the allowlisted source HTTP-attempt receipt."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

SCHEMA = "source-dispatch-accounting.v1"
STATES = {"0", "1", "unknown"}


class ReceiptError(ValueError):
    pass


def _read(path: Path) -> dict[str, Any]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 4096:
        raise ReceiptError("receipt_file_invalid")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ReceiptError("receipt_file_invalid")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    if len(raw) > 4096:
        raise ReceiptError("receipt_file_invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ReceiptError("receipt_json_invalid") from None
    if not isinstance(value, dict):
        raise ReceiptError("receipt_shape_invalid")
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def validate(receipt: dict[str, Any]) -> None:
    if (set(receipt) != {"schema", "case_id", "source_http_attempts"}
            or receipt.get("schema") != SCHEMA
            or receipt.get("case_id") != "PR-464"
            or receipt.get("source_http_attempts") not in STATES):
        raise ReceiptError("receipt_contract_invalid")


def sanitize(input_path: Path, output_dir: Path) -> Path:
    receipt = _read(input_path)
    validate(receipt)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output_dir, 0o700)
    output = output_dir / "source-dispatch-accounting.json"
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        sanitize(args.input, args.output_dir)
    except (OSError, ReceiptError):
        print('{"ok":false,"error_code":"source_dispatch_receipt_invalid"}')
        return 2
    print('{"ok":true}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
