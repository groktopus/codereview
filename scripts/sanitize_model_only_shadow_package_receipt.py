#!/usr/bin/env python3
"""Project the private cross-model packager's summary into a bounded receipt.

The comparison package remains on the runner. This receipt records only that
the fixed PR-464 v2 package passed byte verification and its bounded counts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path


class ReceiptError(ValueError):
    pass


HASH_ID = re.compile(r"pkg-[0-9a-f]{64}\Z")


def project(source: Path, output: Path) -> dict[str, object]:
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > 16_384:
            raise ReceiptError("package_summary_invalid")
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_size > 16_384):
                raise ReceiptError("package_summary_invalid")
            raw = os.read(fd, 16_385)
            if len(raw) > 16_384 or len(raw) != opened.st_size:
                raise ReceiptError("package_summary_invalid")
        finally:
            os.close(fd)
    except OSError:
        raise ReceiptError("package_summary_invalid") from None
    try:
        summary = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ReceiptError("package_summary_invalid") from None
    if not isinstance(summary, dict) or set(summary) != {
        "ok", "comparison_id", "case_count", "verified_artifact_count",
        "verified_structured_relation_count", "claims", "comparison_path", "report_path",
    }:
        raise ReceiptError("package_summary_invalid")
    if (summary.get("ok") is not True
            or not isinstance(summary.get("comparison_id"), str)
            or not HASH_ID.fullmatch(summary["comparison_id"])
            or summary.get("case_count") != 1
            or isinstance(summary.get("case_count"), bool)
            or summary.get("verified_artifact_count") != 8
            or isinstance(summary.get("verified_artifact_count"), bool)
            or isinstance(summary.get("verified_structured_relation_count"), bool)
            or not isinstance(summary.get("verified_structured_relation_count"), int)
            or not 0 <= summary["verified_structured_relation_count"] <= 128
            or summary.get("claims") != {
                "accuracy": None, "ground_truth": None,
                "calibration": None, "correctness": None,
            }
            or not isinstance(summary.get("comparison_path"), str)
            or not isinstance(summary.get("report_path"), str)):
        raise ReceiptError("package_summary_invalid")
    receipt = {
        "schema": "model-only-shadow-cross-model-package-receipt.v1",
        "case_id": "PR-464",
        "package_status": "byte_verified",
        "comparison_id": summary["comparison_id"],
        "case_count": 1,
        "verified_artifact_count": 8,
        "verified_structured_relation_count": summary["verified_structured_relation_count"],
        "semantic_accuracy_claimed": False,
        "ground_truth_claimed": False,
        "calibration_claimed": False,
        "correctness_claimed": False,
    }
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700 or output.exists():
        raise ReceiptError("receipt_output_invalid")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return receipt


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        project(args.summary, args.output)
    except (OSError, ReceiptError):
        print('{"ok":false,"error_code":"package_receipt_invalid"}')
        return 2
    print('{"ok":true,"receipt":"byte_verified"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
