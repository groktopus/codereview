#!/usr/bin/env python3
"""Compare two quality scorecards and fail on deterministic metric regressions.

Missing labels or arms are reported as ``MISSING_DATA``/``NOT_EVALUATED`` and
do not fail the gate. They are never converted into zero-valued observations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from experiments.harness.evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json
    from experiments.harness.scorecard import canonical_bytes, regression_gate
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from experiments.harness.evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json
    from experiments.harness.scorecard import canonical_bytes, regression_gate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="accepted baseline scorecard JSON")
    parser.add_argument("--current", required=True, help="current scorecard JSON")
    parser.add_argument("--json", action="store_true", required=True, help="emit exactly one machine-readable JSON object")
    return parser


def _load(path: str, label: str):
    try:
        data = Path(path).read_bytes()
    except OSError:
        raise EvaluationError(f"cannot_read_{label}") from None
    if len(data) > MAX_INPUT_BYTES:
        raise EvaluationError(f"{label}_too_large")
    result = parse_bounded_json(data, label)
    if not isinstance(result, dict) or result.get("contract_version") is None:
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(result.get("data_state"), dict) or not isinstance(result.get("arms"), dict):
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(result.get("data_state", {}).get("state"), str):
        raise EvaluationError("invalid_scorecard_schema")
    return result


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        baseline = _load(args.baseline, "baseline")
        current = _load(args.current, "current")
        result = regression_gate(current, baseline)
    except EvaluationError as exc:
        print(json.dumps({"error": exc.code}, separators=(",", ":")))
        return 2
    print(canonical_bytes(result).decode("utf-8"))
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
