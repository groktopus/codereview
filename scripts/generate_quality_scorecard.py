#!/usr/bin/env python3
"""Generate a deterministic quality scorecard from corpus, predictions, and labels.

The scorecard never infers labels, matches, or accuracy. It reports missing
labels and missing arms as missing, with explicit reasons and null values.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from experiments.harness.evaluation import (
        MAX_INPUT_BYTES,
        EvaluationError,
        parse_bounded_json,
        sha256_bytes,
    )
    from experiments.harness.scorecard import build_scorecard, canonical_bytes
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from experiments.harness.evaluation import (
        MAX_INPUT_BYTES,
        EvaluationError,
        parse_bounded_json,
        sha256_bytes,
    )
    from experiments.harness.scorecard import build_scorecard, canonical_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, help="versioned immutable case corpus JSON")
    parser.add_argument("--predictions", required=True, help="arm outputs bound to the corpus snapshots")
    parser.add_argument("--labels", required=True, help="explicit adjudications and outcome evidence")
    parser.add_argument("--output", help="write the same canonical scorecard JSON to this path")
    parser.add_argument(
        "--json", action="store_true", required=True, help="emit exactly one machine-readable JSON object"
    )
    return parser


def _load(path: str, label: str) -> tuple[object, str]:
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise EvaluationError(f"cannot_read_{label}") from None
    if len(data) > MAX_INPUT_BYTES:
        raise EvaluationError(f"{label}_too_large")
    return parse_bounded_json(data, label), sha256_bytes(data)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        corpus, corpus_hash = _load(args.corpus, "corpus")
        predictions, predictions_hash = _load(args.predictions, "predictions")
        labels, labels_hash = _load(args.labels, "labels")
        scorecard = build_scorecard(
            corpus,
            predictions,
            labels,
            input_hashes={
                "corpus": corpus_hash,
                "predictions": predictions_hash,
                "labels": labels_hash,
            },
        )
    except EvaluationError as exc:
        print(json.dumps({"error": exc.code}, separators=(",", ":")))
        return 2
    encoded = canonical_bytes(scorecard) + b"\n"
    if args.output:
        Path(args.output).write_bytes(encoded)
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
