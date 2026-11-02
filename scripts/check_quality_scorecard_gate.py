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
    from experiments.harness.scorecard import SCORECARD_VERSION, canonical_bytes, regression_gate
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from experiments.harness.evaluation import MAX_INPUT_BYTES, EvaluationError, parse_bounded_json
    from experiments.harness.scorecard import SCORECARD_VERSION, canonical_bytes, regression_gate


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
    if any(key not in value for key in required) or value["contract_version"] != SCORECARD_VERSION:
        raise EvaluationError("invalid_scorecard_schema")
    data_state = value["data_state"]
    if not isinstance(data_state, dict) or data_state.get("state") not in {"COMPLETE", "PARTIAL", "MISSING_DATA"}:
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(data_state.get("reasons"), list):
        raise EvaluationError("invalid_scorecard_schema")
    label_state = data_state.get("label_state")
    required_label = (
        "status",
        "rubric_version",
        "accepted_quality_method",
        "human_labels_required",
        "synthetic_is_human_truth",
        "arms",
    )
    if not isinstance(label_state, dict) or any(key not in label_state for key in required_label):
        raise EvaluationError("invalid_scorecard_schema")
    if label_state["status"] not in {"missing", "partial", "present"}:
        raise EvaluationError("invalid_scorecard_schema")
    if label_state["accepted_quality_method"] != "synthetic_model_teacher_adjudication":
        raise EvaluationError("invalid_scorecard_schema")
    if label_state["human_labels_required"] is not False:
        raise EvaluationError("invalid_scorecard_schema")
    if label_state["synthetic_is_human_truth"] is not False:
        raise EvaluationError("invalid_scorecard_schema")
    label_arms = label_state.get("arms")
    if not isinstance(label_arms, dict) or set(label_arms) != {"human", "synthetic"}:
        raise EvaluationError("invalid_scorecard_schema")
    for kind, arm_state in label_arms.items():
        if not isinstance(arm_state, dict) or arm_state.get("status") not in {"missing", "partial", "present"}:
            raise EvaluationError("invalid_scorecard_schema")
        if arm_state.get("label_arm") != kind or arm_state.get("is_human_truth") is not (kind == "human"):
            raise EvaluationError("invalid_scorecard_schema")
        if arm_state.get("scope") != ("human_adjudicated" if kind == "human" else "synthetic_only"):
            raise EvaluationError("invalid_scorecard_schema")
        for key in (
            "packets",
            "independent_packets",
            "adjudicated_packets",
            "complete_adjudicated_packets",
            "labeled_cases",
            "complete_adjudicated_labeled_cases",
        ):
            if not isinstance(arm_state.get(key), int):
                raise EvaluationError("invalid_scorecard_schema")
    if data_state["state"] == "COMPLETE" and (
        label_state["status"] != "present"
        or data_state["reasons"]
        or all(arm_state["status"] != "present" for arm_state in label_arms.values())
        or any(arm_state["status"] == "partial" for arm_state in label_arms.values())
    ):
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(data_state.get("expected_cases"), int) or not isinstance(data_state.get("missing_arms"), list):
        raise EvaluationError("invalid_scorecard_schema")
    arms = value["arms"]
    if not isinstance(arms, dict):
        raise EvaluationError("invalid_scorecard_schema")
    for arm in arms.values():
        if not isinstance(arm, dict) or arm.get("status") not in {"complete", "partial", "missing"}:
            raise EvaluationError("invalid_scorecard_schema")
        arm_blocks = arm.get("label_arms")
        if not isinstance(arm_blocks, dict) or set(arm_blocks) != {"human", "synthetic"}:
            raise EvaluationError("invalid_scorecard_schema")
        for kind, block in arm_blocks.items():
            if not isinstance(block, dict) or block.get("status") not in {"present", "missing_labels", "missing"}:
                raise EvaluationError("invalid_scorecard_schema")
            if block.get("label_arm") != kind or block.get("is_human_truth") is not (kind == "human"):
                raise EvaluationError("invalid_scorecard_schema")
    completion = value["completion"]
    if not isinstance(completion, dict) or any(
        key not in completion for key in ("expected_cases", "expected_case_arms", "by_status", "completed_of_expected")
    ):
        raise EvaluationError("invalid_scorecard_schema")
    if not isinstance(completion["expected_cases"], int) or not isinstance(completion["expected_case_arms"], int):
        raise EvaluationError("invalid_scorecard_schema")
    claims = value["claims"]
    if not isinstance(claims, dict) or any(
        key not in claims
        for key in (
            "quality_claim",
            "release_gate",
            "accuracy",
            "model_teacher_is_truth",
            "synthetic_is_human_truth",
            "human_labels_required",
            "label_arm_policy",
        )
    ):
        raise EvaluationError("invalid_scorecard_schema")
    if (
        claims["quality_claim"] is not False
        or claims["release_gate"] is not None
        or claims["accuracy"] is not None
        or claims["model_teacher_is_truth"] is not False
        or claims["synthetic_is_human_truth"] is not False
        or claims["human_labels_required"] is not False
        or claims["label_arm_policy"] != "synthetic_primary_human_optional"
    ):
        raise EvaluationError("invalid_scorecard_schema")
    hashes = value["input_hashes"]
    if not isinstance(hashes, dict):
        raise EvaluationError("invalid_scorecard_schema")
    for key in ("corpus", "predictions", "labels"):
        if not isinstance(hashes.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", hashes[key]):
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
