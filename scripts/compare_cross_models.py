#!/usr/bin/env python3
"""Validate and summarize advisory cross-model evidence without provider calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

try:
    from pr_review_harness.cross_model import compare_cross_model, parse_cross_model_json
    from pr_review_harness.evaluation import MAX_INPUT_BYTES, EvaluationError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from pr_review_harness.cross_model import compare_cross_model, parse_cross_model_json
    from pr_review_harness.evaluation import MAX_INPUT_BYTES, EvaluationError


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        print('{"error":"invalid_arguments"}')
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, help="validated review-evaluation-corpus.v1 JSON")
    parser.add_argument("--comparison", required=True, help="review-cross-model-comparison.v1 JSON")
    parser.add_argument(
        "--snapshot",
        action="append",
        default=[],
        metavar="CASE_ID=REPOSITORY_PATH",
        help="optional exact-head Git checkout used for deterministic anchor checks; repeat per case",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=PATH",
        help="optional local request/response artifact used to verify its declared SHA-256",
    )
    parser.add_argument("--json", action="store_true", required=True, help="emit exactly one JSON object")
    return parser


def _load(path: str, label: str) -> tuple[object, bytes]:
    source_path = Path(path)
    try:
        if source_path.is_symlink():
            raise EvaluationError(f"invalid_{label}_file_type")
        info = source_path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise EvaluationError(f"invalid_{label}_file_type")
        if info.st_size > MAX_INPUT_BYTES:
            raise EvaluationError(f"{label}_too_large")
        descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise EvaluationError(f"invalid_{label}_file_type")
            if opened.st_size > MAX_INPUT_BYTES:
                raise EvaluationError(f"{label}_too_large")
            data = bytearray()
            while len(data) <= MAX_INPUT_BYTES:
                block = os.read(descriptor, min(64 * 1024, MAX_INPUT_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(descriptor)
    except OSError:
        raise EvaluationError(f"cannot_read_{label}") from None
    return parse_cross_model_json(bytes(data), label), bytes(data)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        corpus, raw_corpus = _load(args.corpus, "corpus")
        comparison, raw_comparison = _load(args.comparison, "comparison")
        roots: dict[str, Path] = {}
        for spec in args.snapshot:
            case_id, separator, path = spec.partition("=")
            if not separator or not case_id or not path or case_id in roots:
                raise EvaluationError("invalid_snapshot_argument")
            roots[case_id] = Path(path)
        artifacts: dict[str, Path] = {}
        for spec in args.artifact:
            artifact_id, separator, path = spec.partition("=")
            if not separator or not artifact_id or not path or artifact_id in artifacts:
                raise EvaluationError("invalid_artifact_argument")
            artifacts[artifact_id] = Path(path)
        report = compare_cross_model(
            comparison,
            corpus,
            snapshot_roots=roots,
            artifacts=artifacts,
            corpus_sha256=hashlib.sha256(raw_corpus).hexdigest(),
            input_sha256=hashlib.sha256(raw_comparison).hexdigest(),
        )
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
