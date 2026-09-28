#!/usr/bin/env python3
"""Verify v2 structured relation assertions against bounded local response bytes."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

try:
    from pr_review_harness.cross_model_v2 import compare_cross_model_v2
    from pr_review_harness.evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from pr_review_harness.cross_model_v2 import compare_cross_model_v2
    from pr_review_harness.evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        print('{"error":"invalid_arguments"}')
        raise SystemExit(2)


def load_json(path: str, label: str) -> tuple[object, bytes]:
    source = Path(path)
    try:
        if source.is_symlink() or not stat.S_ISREG(source.lstat().st_mode):
            raise EvaluationError(f"invalid_{label}_file_type")
        if source.stat().st_size > MAX_INPUT_BYTES:
            raise EvaluationError(f"{label}_too_large")
        fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise EvaluationError(f"invalid_{label}_file_type")
            data = bytearray()
            while len(data) <= MAX_INPUT_BYTES:
                block = os.read(fd, min(64 * 1024, MAX_INPUT_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(fd)
    except OSError:
        raise EvaluationError(f"cannot_read_{label}") from None
    if len(data) > MAX_INPUT_BYTES:
        raise EvaluationError(f"{label}_too_large")
    raw = bytes(data)
    return parse_bounded_json(raw, label), raw


def main(argv: list[str] | None = None) -> int:
    parser = SafeParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--comparison", required=True, help="review-cross-model-comparison.v2 JSON")
    parser.add_argument("--artifact", action="append", default=[], metavar="ARTIFACT_ID=PATH")
    parser.add_argument("--json", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        corpus, _ = load_json(args.corpus, "corpus")
        comparison, _ = load_json(args.comparison, "comparison")
        artifacts: dict[str, Path] = {}
        for item in args.artifact:
            artifact_id, sep, path = item.partition("=")
            if not sep or not artifact_id or not path or artifact_id in artifacts:
                raise EvaluationError("invalid_artifact_argument")
            artifacts[artifact_id] = Path(path)
        report = compare_cross_model_v2(comparison, corpus, artifacts=artifacts)
    except EvaluationError as exc:
        print(json.dumps({"error": exc.code}, separators=(",", ":")))
        return 2
    except (OSError, ValueError, TypeError):
        print('{"error":"invalid_cross_model_input"}')
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
