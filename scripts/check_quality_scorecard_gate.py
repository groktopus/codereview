#!/usr/bin/env python3
"""Compare two quality scorecards and fail on deterministic metric regressions.

Missing labels or arms are reported as ``MISSING_DATA``/``NOT_EVALUATED`` and
do not fail the gate. They are never converted into zero-valued observations.
"""

from __future__ import annotations

import argparse
import json
import re
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
    _validate_scorecard(result)
    return result


def _validate_scorecard(value: object) -> None:
    if not isinstance(value, dict):
        raise EvaluationError("invalid_scorecard_schema")
    required = ("contract_version", "data_state", "arms", "completion", "claims", "input_hashes")
    if any(key not in value for key in required):
        raise EvaluationError("invalid_scorecard_schema")
    data_state = value["data_state"]
    if not isinstance(data_state, dict) or data_state.get("state") not in {"COMPLETE", "PARTIAL", "MISSING_DATA"}:
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(data_state.get("reasons"), list):
        raise EvaluationError("invalid_scorecard_schema")
    arms = value["arms"]
    if not isinstance(arms, dict) or any(
        not isinstance(arm, dict) or arm.get("status") not in {"complete", "partial", "missing"}
        for arm in arms.values()
    ):
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(value["completion"], dict) or not isinstance(value["claims"], dict):
        raise EvaluationError("invalid_scorecard_schema")
    hashes = value["input_hashes"]
    if not isinstance(hashes, dict) or not isinstance(hashes.get("corpus"), str) or not re.fullmatch(r"[0-9a-f]{64}", hashes["corpus"]):
        raise EvaluationError("invalid_scorecard_schema")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        baseline = _load(args.baseline, "baseline")
        current = _load(args.current, "current")
        result = regression_gate(current, baseline)
    except EvaluationError as exc:
        print(json.dumps({"error": exc.code}, separators=(",", ":")))
        return 2
    except (AttributeError, KeyError, TypeError, ValueError):
        print(json.dumps({"error": "invalid_scorecard_schema"}, separators=(",", ":")))
        return 2
    print(canonical_bytes(result).decode("utf-8"))
    return 1 if result["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
