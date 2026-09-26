#!/usr/bin/env python3
"""Validate a frozen evaluation corpus and emit deterministic summary metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from pr_review_harness.evaluation import (
        MAX_INPUT_BYTES,
        EvaluationError,
        evaluate,
        parse_bounded_json,
    )
except ModuleNotFoundError:
    # Permit running from a source checkout without installing the package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from pr_review_harness.evaluation import MAX_INPUT_BYTES, EvaluationError, evaluate, parse_bounded_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare explicitly labeled review outputs on frozen snapshots")
    parser.add_argument("--corpus", required=True, help="versioned immutable case corpus JSON")
    parser.add_argument("--predictions", required=True, help="arm outputs bound to the corpus snapshots")
    parser.add_argument("--labels", required=True, help="explicit adjudications and outcome evidence")
    parser.add_argument(
        "--json", action="store_true", required=True, help="emit exactly one machine-readable JSON object"
    )
    return parser


def _load(path: str, label: str):
    try:
        with Path(path).open("rb") as source:
            data = source.read(MAX_INPUT_BYTES + 1)
        return parse_bounded_json(data, label)
    except OSError:
        raise EvaluationError(f"cannot_read_{label}") from None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        corpus = _load(args.corpus, "corpus")
        predictions = _load(args.predictions, "predictions")
        labels = _load(args.labels, "labels")
        report = evaluate(corpus, predictions, labels)
    except EvaluationError as exc:
        print(json.dumps({"error": exc.code}, separators=(",", ":")))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
