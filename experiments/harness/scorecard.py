"""Deterministic quality scorecards and regression gates for review evaluation.

The scorecard is a presentation layer over ``evaluation.evaluate``. It does not
infer labels, matches, or correctness. Missing labels, missing arms, and missing
runs are represented as missing data; they are never converted into a zero rate
or a passing observation.

Human and synthetic adjudication are separate label arms. The owner-accepted
quality method is synthetic model-teacher adjudication; the human arm is
optional. Synthetic completion, precision, and recall are reported only under
the synthetic arm and are never described as human accuracy.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.harness.evaluation import (
    CORPUS_VERSION,
    LABELS_VERSION,
    PREDICTIONS_VERSION,
    EvaluationError,
    evaluate,
    sha256_bytes,
)

SCORECARD_VERSION = "review-evaluation-scorecard.v2"
GATE_VERSION = "review-evaluation-scorecard-gate.v2"
EVALUATOR_REVISION = "pr-review-evaluation-toolkit.v2"
LABEL_ARMS = ("human", "synthetic")

EVALUATOR_SOURCE_SHA256 = sha256_bytes(Path(__file__).with_name("evaluation.py").read_bytes())

_RUN_STATUSES = ("completed", "incomplete", "failed", "unavailable", "abstained", "missing")


def canonical_bytes(value: Any) -> bytes:
    """Return canonical JSON bytes used for deterministic output and hashing."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def file_sha256(data: bytes) -> str:
    """Return the SHA-256 of exact input bytes."""

    return hashlib.sha256(data).hexdigest()


def _rate(numerator: int | None, denominator: int | None, reason: str) -> dict[str, Any]:
    if numerator is None or denominator is None:
        return {"numerator": None, "denominator": None, "value": None, "undefined_reason": reason}
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": round(numerator / denominator, 6) if denominator else None,
        "undefined_reason": None if denominator else reason,
    }


def _missing_rate(reason: str) -> dict[str, Any]:
    return {"numerator": None, "denominator": None, "value": None, "undefined_reason": reason}


def _run_status_counts(metric: dict[str, Any]) -> dict[str, int]:
    raw = metric.get("run_status_counts", {})
    counts = {status: int(raw.get(status, 0)) for status in _RUN_STATUSES}
    for key, value in raw.items():
        if key not in counts:
            counts[str(key)] = int(value)
    return counts


def _arm_status(present_runs: int, expected_cases: int, completed_runs: int) -> str:
    if present_runs == 0:
        return "missing"
    if present_runs == expected_cases and completed_runs == expected_cases:
        return "complete"
    return "partial"


def _accuracy(complete_cases: dict[str, int], present_runs: int, missing_cases: int) -> dict[str, Any]:
    reasons = [
        f"accuracy_not_computed_by_{SCORECARD_VERSION}",
        "synthetic_is_not_human_accuracy",
    ]
    if complete_cases["human"] == 0 and complete_cases["synthetic"] == 0:
        reasons.append("no_complete_adjudicated_human_or_synthetic_labels")
    if present_runs == 0:
        reasons.append("no_runs_for_arm")
    elif missing_cases:
        reasons.append("missing_runs_for_arm")
    return {"value": None, "status": "refused", "scope": "none", "reasons": reasons}


def _label_arm_rates(
    kind: str,
    status: str,
    metric: dict[str, Any],
    candidate_findings: int | None,
    complete_cases: int,
    present_runs: int,
    missing_cases: int,
    missing_case_ids: list[str],
) -> dict[str, Any]:
    """Return one adjudication arm's rates, never mixing in the other arm."""

    scope = "human_adjudicated" if kind == "human" else "synthetic_only"
    summary: dict[str, Any] = {
        "label_arm": kind,
        "scope": scope,
        "is_human_truth": kind == "human",
        "status": status,
        "complete_adjudicated_cases": complete_cases,
    }
    if status == "missing":
        summary.update(
            {
                "precision": {
                    "status": "missing",
                    "resolved": _missing_rate("no_runs_for_arm"),
                    "lower_bound": _missing_rate("no_runs_for_arm"),
                    "upper_bound": _missing_rate("no_runs_for_arm"),
                    "correlated_duplicates_excluded": None,
                },
                "recall": {
                    "status": "missing",
                    "lower_bound": _missing_rate("no_runs_for_arm"),
                    "upper_bound": _missing_rate("no_runs_for_arm"),
                    "completed_run_conditional": _missing_rate("no_completed_runs_for_arm"),
                    "eligible_material_introduced_findings": None,
                    "definitively_unmatched_findings": None,
                    "unresolved_findings_upper_bound_addition": None,
                    "findings_without_final_adjudication": None,
                },
                "abstention": {
                    "status": "missing",
                    "adjudicated_abstentions": None,
                    "adjudicated_findings_denominator": None,
                    "rate": _missing_rate("no_adjudicated_predictions_for_arm"),
                    "abstained_runs": None,
                    "run_denominator": None,
                    "run_rate": _missing_rate("no_runs_for_arm"),
                },
                "duplicates": {
                    "status": "missing",
                    "correlated_duplicates_excluded": None,
                    "denominator": None,
                    "rate": _missing_rate("no_adjudicated_predictions_for_arm"),
                },
                "unadjudicated": {
                    "status": "missing",
                    "findings_without_final_adjudication": None,
                    "denominator": None,
                    "rate": _missing_rate("no_candidate_findings_for_arm"),
                },
                "approve_with_known_defect": {
                    "status": "missing",
                    "cases": None,
                    "denominator": None,
                    "rate": _missing_rate(f"no_complete_adjudicated_{kind}_label_cases"),
                    "complete_adjudicated_cases": complete_cases,
                },
            }
        )
        return summary
    if complete_cases == 0:
        reason = f"no_complete_adjudicated_{kind}_labels"
        summary["status"] = "missing_labels"
        summary.update(
            {
                "precision": {
                    "status": "missing_labels",
                    "resolved": _missing_rate(reason),
                    "lower_bound": _missing_rate(reason),
                    "upper_bound": _missing_rate(reason),
                    "correlated_duplicates_excluded": None,
                },
                "recall": {
                    "status": "missing_labels",
                    "lower_bound": _missing_rate(reason),
                    "upper_bound": _missing_rate(reason),
                    "completed_run_conditional": _missing_rate(reason),
                    "eligible_material_introduced_findings": None,
                    "definitively_unmatched_findings": None,
                    "unresolved_findings_upper_bound_addition": None,
                    "findings_without_final_adjudication": None,
                },
                "abstention": {
                    "status": "missing_labels",
                    "adjudicated_abstentions": None,
                    "adjudicated_findings_denominator": None,
                    "rate": _missing_rate(reason),
                    "abstained_runs": _metric_run_count(metric, "abstained"),
                    "run_denominator": present_runs,
                    "run_rate": _rate(_metric_run_count(metric, "abstained"), present_runs, "no_runs_for_arm"),
                },
                "duplicates": {
                    "status": "missing_labels",
                    "correlated_duplicates_excluded": None,
                    "denominator": None,
                    "rate": _missing_rate(reason),
                },
                "unadjudicated": {
                    "status": "missing_labels",
                    "findings_without_final_adjudication": None,
                    "denominator": candidate_findings,
                    "rate": _missing_rate(reason),
                },
                "approve_with_known_defect": {
                    "status": "missing_labels",
                    "cases": None,
                    "denominator": None,
                    "rate": _missing_rate(reason),
                    "complete_adjudicated_cases": 0,
                },
            }
        )
        return summary

    block = metric[f"{kind}_adjudication"]
    matched = int(block["matched_predictions"])
    rejected = int(block["rejected_predictions"])
    abstained = int(block["abstained_predictions"])
    duplicates = int(block["correlated_duplicates_excluded"])
    unadjudicated = int(block["unadjudicated_predictions"])
    resolved_denominator = matched + rejected
    unresolved = abstained + unadjudicated
    precision_denominator = resolved_denominator + unresolved
    recall = block["known_material_finding_recall"]
    eligible = int(recall["eligible_material_introduced_findings"])
    verified = int(recall["verified_matches_lower_bound"])
    unresolved_recall = int(recall["unresolved_findings_upper_bound_addition"])
    adjudicated_denominator = matched + rejected + abstained + duplicates
    approve_cases = int(block["approve_with_known_material_defect_cases"])
    approve_denominator = int(recall["expected_cases_with_eligible_findings"])
    conditional = recall["completed_run_recall_conditional"]
    recall_reason = f"no_complete_{kind}_labeled_introduced_material_findings"
    summary.update(
        {
            "status": "present",
            "precision": {
                "status": "present",
                "resolved": _rate(matched, resolved_denominator, "no_matched_or_rejected_predictions"),
                "lower_bound": _rate(matched, precision_denominator, "no_adjudicated_or_unresolved_predictions"),
                "upper_bound": _rate(
                    matched + unresolved, precision_denominator, "no_adjudicated_or_unresolved_predictions"
                ),
                "matched_predictions": matched,
                "rejected_predictions": rejected,
                "abstained_predictions": abstained,
                "unadjudicated_predictions": unadjudicated,
                "correlated_duplicates_excluded": duplicates,
            },
            "recall": {
                "status": "present",
                "lower_bound": _rate(verified, eligible, recall_reason),
                "upper_bound": _rate(verified + unresolved_recall, eligible, recall_reason),
                "completed_run_conditional": _rate(
                    int(conditional["numerator"]),
                    int(conditional["denominator"]),
                    "no_completed_runs_with_full_finding_adjudication",
                ),
                "eligible_material_introduced_findings": eligible,
                "verified_matches_lower_bound": verified,
                "unresolved_findings_upper_bound_addition": unresolved_recall,
                "definitively_unmatched_findings": int(recall["definitively_unmatched_findings"]),
                "findings_without_final_adjudication": int(recall["findings_without_final_adjudication"]),
                "completed_fully_adjudicated_runs": int(recall["completed_fully_adjudicated_runs"]),
            },
            "abstention": {
                "status": "present",
                "adjudicated_abstentions": abstained,
                "adjudicated_findings_denominator": adjudicated_denominator,
                "rate": _rate(abstained, adjudicated_denominator, "no_adjudicated_predictions_for_arm"),
                "abstained_runs": _metric_run_count(metric, "abstained"),
                "run_denominator": present_runs,
                "run_rate": _rate(_metric_run_count(metric, "abstained"), present_runs, "no_runs_for_arm"),
            },
            "duplicates": {
                "status": "present",
                "correlated_duplicates_excluded": duplicates,
                "denominator": adjudicated_denominator,
                "rate": _rate(duplicates, adjudicated_denominator, "no_adjudicated_predictions_for_arm"),
            },
            "unadjudicated": {
                "status": "present",
                "findings_without_final_adjudication": int(recall["findings_without_final_adjudication"]),
                "denominator": candidate_findings,
                "rate": _rate(
                    int(recall["findings_without_final_adjudication"]),
                    candidate_findings,
                    "no_candidate_findings_for_arm",
                ),
            },
            "approve_with_known_defect": {
                "status": "unresolved_missing_runs" if missing_case_ids else "present",
                "cases": None if missing_case_ids else approve_cases,
                "denominator": None if missing_case_ids else approve_denominator,
                "rate": (
                    None
                    if missing_case_ids
                    else _rate(approve_cases, approve_denominator, f"no_complete_adjudicated_{kind}_label_cases")
                ),
                "complete_adjudicated_cases": complete_cases,
            },
        }
    )
    return summary


def _metric_run_count(metric: dict[str, Any], status: str) -> int:
    """Return one run-status count from a per-split metric block."""

    return int(_run_status_counts(metric).get(status, 0))


def _summarize_arm(
    expected_case_ids: list[str],
    arm: str,
    metric: dict[str, Any],
    complete_cases: dict[str, set[str]],
) -> dict[str, Any]:
    expected_cases = len(expected_case_ids)
    statuses = _run_status_counts(metric)
    missing_cases = statuses.get("missing", 0)
    present_runs = expected_cases - missing_cases
    completed_runs = statuses.get("completed", 0)
    status = _arm_status(present_runs, expected_cases, completed_runs)
    missing_case_ids = list(metric.get("_missing_case_ids", []))
    complete_by_kind = {kind: len(set(expected_case_ids) & complete_cases[kind]) for kind in LABEL_ARMS}
    candidate_findings: int | None = None if status == "missing" else int(metric["candidate_findings"])
    label_arms = {
        kind: _label_arm_rates(
            kind,
            status,
            {} if status == "missing" else metric,
            candidate_findings,
            complete_by_kind[kind],
            present_runs,
            missing_cases,
            missing_case_ids,
        )
        for kind in LABEL_ARMS
    }
    return {
        "status": "missing" if status == "missing" else status,
        "missing": status == "missing",
        "expected_cases": expected_cases,
        "present_runs": present_runs,
        "missing_cases": missing_cases,
        "missing_case_ids": missing_case_ids,
        "completed_runs": completed_runs,
        "candidate_findings": candidate_findings,
        "label_arms": label_arms,
        "accuracy": _accuracy(complete_by_kind, present_runs, missing_cases),
        "completion": {
            "status": status,
            "expected_cases": expected_cases,
            "present_runs": present_runs,
            "missing_runs": missing_cases,
            "completed_runs": completed_runs,
            "completed_of_expected": (
                _missing_rate("no_runs_for_arm")
                if status == "missing"
                else _rate(completed_runs, expected_cases, "no_expected_cases")
            ),
            "completed_of_present": (
                _missing_rate("no_runs_for_arm")
                if status == "missing"
                else _rate(completed_runs, present_runs, "no_runs_for_arm")
            ),
            "run_status_counts": statuses,
        },
    }


def _kind_label_state(packets: list[dict[str, Any]], kind: str, corpus_case_ids: set[str]) -> dict[str, Any]:
    kind_packets = [packet for packet in packets if packet["reviewer"]["reviewer_kind"] == kind]
    independent = [packet for packet in kind_packets if packet["label_role"] == "independent"]
    adjudicated = [packet for packet in kind_packets if packet["label_role"] == "adjudicated"]
    complete_adjudicated = [packet for packet in adjudicated if packet["case_completeness"] == "COMPLETE"]
    labeled_cases = {packet["case_id"] for packet in kind_packets} & corpus_case_ids
    complete_cases = {packet["case_id"] for packet in complete_adjudicated} & corpus_case_ids
    if not kind_packets:
        status = "missing"
    elif complete_cases == corpus_case_ids:
        status = "present"
    else:
        status = "partial"
    return {
        "label_arm": kind,
        "scope": "human_adjudicated" if kind == "human" else "synthetic_only",
        "is_human_truth": kind == "human",
        "status": status,
        "packets": len(kind_packets),
        "independent_packets": len(independent),
        "adjudicated_packets": len(adjudicated),
        "complete_adjudicated_packets": len(complete_adjudicated),
        "labeled_cases": len(labeled_cases),
        "complete_adjudicated_labeled_cases": len(complete_cases),
        "complete_case_ids": sorted(complete_cases),
    }


def _label_state(labels: dict[str, Any], corpus_case_ids: set[str]) -> dict[str, Any]:
    packets = labels["packets"]
    arms = {kind: _kind_label_state(packets, kind, corpus_case_ids) for kind in LABEL_ARMS}
    statuses = {kind: arms[kind]["status"] for kind in LABEL_ARMS}
    if "partial" in statuses.values():
        status = "partial"
    elif "present" in statuses.values():
        status = "present"
    else:
        status = "missing"
    teacher = [packet for packet in packets if packet["reviewer"]["reviewer_kind"] == "model_teacher"]
    unknown = [packet for packet in packets if packet["reviewer"]["reviewer_kind"] == "unknown"]
    return {
        "status": status,
        "rubric_version": labels["rubric_version"],
        "accepted_quality_method": "synthetic_model_teacher_adjudication",
        "human_labels_required": False,
        "synthetic_is_human_truth": False,
        "arms": arms,
        "model_teacher_screening_packets": len(teacher),
        "unknown_provenance_packets": len(unknown),
    }


_ADJUDICATION_COUNT_KEYS = (
    "complete_cases",
    "matched_predictions",
    "rejected_predictions",
    "abstained_predictions",
    "correlated_duplicates_excluded",
    "unadjudicated_predictions",
    "approve_with_known_material_defect_cases",
)
_ADJUDICATION_RECALL_KEYS = (
    "eligible_material_introduced_findings",
    "verified_matches_lower_bound",
    "unresolved_findings_upper_bound_addition",
    "definitively_unmatched_findings",
    "findings_without_final_adjudication",
    "completed_fully_adjudicated_runs",
    "expected_cases_with_eligible_findings",
)


def _empty_adjudication() -> dict[str, Any]:
    return {
        "complete_cases": 0,
        "matched_predictions": 0,
        "rejected_predictions": 0,
        "abstained_predictions": 0,
        "correlated_duplicates_excluded": 0,
        "unadjudicated_predictions": 0,
        "approve_with_known_material_defect_cases": 0,
        "known_material_finding_recall": {
            "eligible_material_introduced_findings": 0,
            "verified_matches_lower_bound": 0,
            "unresolved_findings_upper_bound_addition": 0,
            "definitively_unmatched_findings": 0,
            "findings_without_final_adjudication": 0,
            "completed_fully_adjudicated_runs": 0,
            "expected_cases_with_eligible_findings": 0,
            "completed_run_recall_conditional": {"numerator": 0, "denominator": 0},
        },
    }


def build_scorecard(
    corpus: dict[str, Any],
    predictions: dict[str, Any],
    labels: dict[str, Any],
    *,
    input_hashes: dict[str, str],
    evaluator_revision: str = EVALUATOR_REVISION,
) -> dict[str, Any]:
    """Build a deterministic scorecard from validated evaluation inputs."""

    report = evaluate(corpus, predictions, labels)
    case_by_id = {case["identity"]["case_id"]: case for case in corpus["cases"]}
    run_by_key = {(run["case_id"], run["arm"]): run for run in predictions["runs"]}
    label_state = _label_state(labels, set(case_by_id))
    complete_cases = {kind: set(label_state["arms"][kind]["complete_case_ids"]) for kind in LABEL_ARMS}
    metrics = report["metrics"]
    splits: dict[str, Any] = {}
    arms: dict[str, Any] = {}
    for split in sorted({case["identity"]["split"] for case in corpus["cases"]}):
        split_case_ids = [case["identity"]["case_id"] for case in corpus["cases"] if case["identity"]["split"] == split]
        split_arms: dict[str, Any] = {}
        for arm in corpus["expected_arms"]:
            key = f"{split}/{arm}"
            if key not in metrics:
                continue
            metric = dict(metrics[key])
            metric["_missing_case_ids"] = [case_id for case_id in split_case_ids if (case_id, arm) not in run_by_key]
            split_arms[arm] = _summarize_arm(split_case_ids, arm, metric, complete_cases)
        splits[split] = {"expected_cases": len(split_case_ids), "arms": split_arms}

    all_case_ids = list(case_by_id)
    for arm in corpus["expected_arms"]:
        combined: dict[str, Any] = {
            "expected_cases": len(all_case_ids),
            "run_status_counts": {},
            "candidate_findings": 0,
            "human_adjudication": _empty_adjudication(),
            "synthetic_adjudication": _empty_adjudication(),
        }
        status_counts = combined["run_status_counts"]
        for split in splits:
            metric = metrics.get(f"{split}/{arm}")
            if metric is None:
                continue
            for status, value in metric["run_status_counts"].items():
                status_counts[status] = status_counts.get(status, 0) + int(value)
            combined["candidate_findings"] += int(metric["candidate_findings"])
            for kind in LABEL_ARMS:
                block = metric[f"{kind}_adjudication"]
                target = combined[f"{kind}_adjudication"]
                for key in _ADJUDICATION_COUNT_KEYS:
                    target[key] += int(block[key])
                recall = block["known_material_finding_recall"]
                target_recall = target["known_material_finding_recall"]
                for key in _ADJUDICATION_RECALL_KEYS:
                    target_recall[key] += int(recall[key])
                target_recall["completed_run_recall_conditional"]["numerator"] += int(
                    recall["completed_run_recall_conditional"]["numerator"]
                )
                target_recall["completed_run_recall_conditional"]["denominator"] += int(
                    recall["completed_run_recall_conditional"]["denominator"]
                )
        combined["_missing_case_ids"] = [case_id for case_id in all_case_ids if (case_id, arm) not in run_by_key]
        arms[arm] = _summarize_arm(all_case_ids, arm, combined, complete_cases)

    expected_case_arms = len(all_case_ids) * len(corpus["expected_arms"])
    by_status = {status: 0 for status in _RUN_STATUSES}
    for arm_summary in arms.values():
        for status, value in arm_summary["completion"]["run_status_counts"].items():
            by_status[status] = by_status.get(status, 0) + int(value)
    present_runs = sum(arm["present_runs"] for arm in arms.values())
    completed_runs = sum(arm["completed_runs"] for arm in arms.values())
    missing_arm_cases = sum(arm["missing_cases"] for arm in arms.values())
    complete_adjudicated_packets = sum(label_state["arms"][kind]["complete_adjudicated_packets"] for kind in LABEL_ARMS)
    reasons: list[str] = []
    if complete_adjudicated_packets == 0:
        reasons.append("no_complete_adjudicated_human_or_synthetic_label_packets")
    if any(label_state["arms"][kind]["status"] == "partial" for kind in LABEL_ARMS):
        reasons.append("partial_adjudicated_labels")
    if present_runs == 0:
        reasons.append("no_prediction_runs")
    if missing_arm_cases:
        reasons.append("missing_case_arm_runs")
    if any(arm["status"] == "missing" for arm in arms.values()):
        reasons.append("missing_arm")
    if complete_adjudicated_packets == 0 or present_runs == 0:
        data_state = "MISSING_DATA"
    elif reasons or label_state.get("status") != "present":
        data_state = "PARTIAL"
    else:
        data_state = "COMPLETE"

    top_level_missing_arms = sorted(arm for arm, summary in arms.items() if summary["status"] == "missing")
    public_label_state = {
        "status": label_state["status"],
        "rubric_version": label_state["rubric_version"],
        "accepted_quality_method": label_state["accepted_quality_method"],
        "human_labels_required": label_state["human_labels_required"],
        "synthetic_is_human_truth": label_state["synthetic_is_human_truth"],
        "model_teacher_screening_packets": label_state["model_teacher_screening_packets"],
        "unknown_provenance_packets": label_state["unknown_provenance_packets"],
        "arms": {
            kind: {key: value for key, value in label_state["arms"][kind].items() if key != "complete_case_ids"}
            for kind in LABEL_ARMS
        },
    }
    scorecard = {
        "contract_version": SCORECARD_VERSION,
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "rubric_version": labels["rubric_version"],
        "evaluator_revision": evaluator_revision,
        "evaluator_source_sha256": EVALUATOR_SOURCE_SHA256,
        "contract_versions": {
            "corpus": CORPUS_VERSION,
            "predictions": PREDICTIONS_VERSION,
            "labels": LABELS_VERSION,
            "scorecard": SCORECARD_VERSION,
        },
        "input_hashes": {
            "corpus": input_hashes["corpus"],
            "predictions": input_hashes["predictions"],
            "labels": input_hashes["labels"],
        },
        "data_state": {
            "state": data_state,
            "reasons": reasons,
            "label_state": public_label_state,
            "expected_cases": len(all_case_ids),
            "expected_case_arms": expected_case_arms,
            "present_runs": present_runs,
            "completed_runs": completed_runs,
            "missing_case_arm_runs": missing_arm_cases,
            "missing_arms": top_level_missing_arms,
        },
        "completion": {
            "expected_cases": len(all_case_ids),
            "expected_case_arms": expected_case_arms,
            "by_status": by_status,
            "completed_of_expected": (
                _rate(completed_runs, expected_case_arms, "no_expected_case_arms")
                if present_runs
                else _missing_rate("no_runs")
            ),
            "completed_of_present": _rate(completed_runs, present_runs, "no_runs"),
            "by_arm": {
                arm: {
                    "status": arm_summary["status"],
                    "expected_cases": arm_summary["expected_cases"],
                    "present_runs": arm_summary["present_runs"],
                    "missing_runs": arm_summary["missing_cases"],
                    "completed_runs": arm_summary["completed_runs"],
                    "missing_case_ids": arm_summary["missing_case_ids"],
                    "run_status_counts": arm_summary["completion"]["run_status_counts"],
                }
                for arm, arm_summary in arms.items()
            },
        },
        "arms": arms,
        "splits": splits,
        "missing_data": {
            "status": data_state,
            "reasons": reasons,
            "arms": top_level_missing_arms,
            "complete_adjudicated_human_packets": label_state["arms"]["human"]["complete_adjudicated_packets"],
            "complete_adjudicated_synthetic_packets": label_state["arms"]["synthetic"]["complete_adjudicated_packets"],
            "present_runs": present_runs,
            "missing_case_arm_runs": missing_arm_cases,
        },
        "claims": {
            "quality_claim": False,
            "accuracy": None,
            "release_gate": None,
            "model_teacher_is_truth": False,
            "synthetic_is_human_truth": False,
            "human_labels_required": False,
            "label_arm_policy": "synthetic_primary_human_optional",
            "statistical_caveat": (
                "Counts and bounds are descriptive for this frozen subset and label set; "
                "they are not a prevalence estimate or a single-scalar release signal."
            ),
        },
    }
    encoded = canonical_bytes(scorecard)
    if len(encoded) > 4 * 1024 * 1024:
        raise EvaluationError("scorecard_too_large")
    return scorecard


def _check(
    check_id: str,
    status: str,
    *,
    reason: str | None = None,
    baseline: Any = None,
    current: Any = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "reason": reason,
        "baseline": baseline,
        "current": current,
    }


def _compare_label_arm(
    checks: list[dict[str, Any]],
    arm: str,
    kind: str,
    current_arm: dict[str, Any],
    baseline_arm: dict[str, Any],
) -> None:
    current_node = (current_arm.get("label_arms") or {}).get(kind)
    baseline_node = (baseline_arm.get("label_arms") or {}).get(kind)
    if current_node is None and baseline_node is not None:
        checks.append(_check(f"label_arm:{arm}:{kind}", "FAIL", reason="label_arm_absent_since_baseline"))
        return
    if current_node is None or baseline_node is None:
        checks.append(_check(f"label_arm:{arm}:{kind}", "NOT_EVALUATED", reason="label_arm_missing"))
        return
    if baseline_node["status"] == "present" and current_node["status"] != "present":
        checks.append(_check(f"label_arm:{arm}:{kind}", "FAIL", reason="label_arm_missing_since_baseline"))
        return
    if current_node["status"] != "present" or baseline_node["status"] != "present":
        checks.append(_check(f"label_arm:{arm}:{kind}", "NOT_EVALUATED", reason="label_arm_missing"))
        return
    comparisons = (
        ("recall_lower_bound", ("recall", "lower_bound"), "higher"),
        ("precision_lower_bound", ("precision", "lower_bound"), "higher"),
        ("approve_with_known_defect", ("approve_with_known_defect", "cases"), "lower"),
        ("unadjudicated_findings", ("unadjudicated", "findings_without_final_adjudication"), "lower"),
        ("duplicate_findings", ("duplicates", "correlated_duplicates_excluded"), "lower"),
        ("abstentions", ("abstention", "adjudicated_abstentions"), "lower"),
    )
    for check_id, path, direction in comparisons:
        current_value: Any = current_node
        baseline_value: Any = baseline_node
        for key in path:
            current_value = current_value[key]
            baseline_value = baseline_value[key]
        if isinstance(current_value, dict):
            current_denominator = current_value.get("denominator")
            baseline_denominator = baseline_value.get("denominator")
            current_value = current_value.get("value")
            baseline_value = baseline_value.get("value")
        else:
            current_denominator = baseline_denominator = None
        if current_value is None or baseline_value is None:
            checks.append(_check(f"{check_id}:{arm}:{kind}", "NOT_EVALUATED", reason="missing_metric_or_denominator"))
            continue
        if direction == "higher":
            regressed = float(current_value) + 1e-9 < float(baseline_value)
        else:
            regressed = float(current_value) > float(baseline_value) + 1e-9
        checks.append(
            _check(
                f"{check_id}:{arm}:{kind}",
                "FAIL" if regressed else "PASS",
                baseline={"value": baseline_value, "denominator": baseline_denominator},
                current={"value": current_value, "denominator": current_denominator},
            )
        )


def regression_gate(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Compare two scorecards and fail on deterministic metric regressions.

    Missing labels or arms produce ``MISSING_DATA``/``NOT_EVALUATED`` checks and
    do not fail the gate. They also do not become zero-valued observations.
    Human and synthetic label arms are compared separately.
    """

    checks: list[dict[str, Any]] = []
    if current.get("contract_version") != SCORECARD_VERSION or baseline.get("contract_version") != SCORECARD_VERSION:
        return {
            "contract_version": GATE_VERSION,
            "status": "FAIL",
            "checks": [_check("scorecard_contract", "FAIL", reason="unsupported_scorecard_contract")],
            "regressions": ["unsupported_scorecard_contract"],
            "missing": [],
        }
    identity_fields = (
        "corpus_id",
        "dataset_version",
        "rubric_version",
        "evaluator_revision",
        "evaluator_source_sha256",
    )
    mismatches = [field for field in identity_fields if current.get(field) != baseline.get(field)]
    if (current.get("input_hashes") or {}).get("corpus") != (baseline.get("input_hashes") or {}).get("corpus"):
        mismatches.append("corpus_input_hash")
    if mismatches:
        return {
            "contract_version": GATE_VERSION,
            "status": "FAIL",
            "checks": [
                _check(
                    "scorecard_identity",
                    "FAIL",
                    reason="corpus_or_rubric_identity_mismatch",
                    baseline={field: baseline.get(field) for field in identity_fields},
                    current={field: current.get(field) for field in identity_fields},
                )
            ],
            "regressions": ["corpus_or_rubric_identity_mismatch"],
            "missing": [],
        }

    arm_names = sorted(set(current.get("arms", {})) | set(baseline.get("arms", {})))
    for arm in arm_names:
        current_arm = current.get("arms", {}).get(arm)
        baseline_arm = baseline.get("arms", {}).get(arm)
        if current_arm is None and baseline_arm is not None:
            checks.append(_check(f"arm:{arm}", "FAIL", reason="arm_absent_since_baseline"))
            continue
        if current_arm is None or baseline_arm is None:
            checks.append(_check(f"arm:{arm}", "NOT_EVALUATED", reason="arm_missing"))
            continue
        if current_arm["status"] == "missing" and baseline_arm["status"] != "missing":
            checks.append(_check(f"arm:{arm}", "FAIL", reason="arm_missing_since_baseline"))
            continue
        if current_arm["status"] == "missing" or baseline_arm["status"] == "missing":
            checks.append(_check(f"arm:{arm}", "NOT_EVALUATED", reason="arm_missing"))
            continue
        checks.append(
            _check(
                f"completion:{arm}",
                "PASS" if int(current_arm["completed_runs"]) >= int(baseline_arm["completed_runs"]) else "FAIL",
                baseline=baseline_arm["completed_runs"],
                current=current_arm["completed_runs"],
            )
        )
        for kind in LABEL_ARMS:
            _compare_label_arm(checks, arm, kind, current_arm, baseline_arm)

    current_state = current.get("data_state", {}).get("state")
    baseline_state = baseline.get("data_state", {}).get("state")
    if current_state == "PARTIAL":
        checks.append(_check("data_state", "FAIL", reason="partial_coverage"))
    failed = [check for check in checks if check["status"] == "FAIL"]
    evaluated = [check for check in checks if check["status"] in {"PASS", "FAIL"}]
    missing_state = current_state == "MISSING_DATA" or baseline_state == "MISSING_DATA"
    if failed:
        status = "FAIL"
    elif missing_state or not evaluated:
        status = "MISSING_DATA"
    else:
        status = "PASS"
    return {
        "contract_version": GATE_VERSION,
        "current_data_state": current_state,
        "baseline_data_state": baseline_state,
        "status": status,
        "checks": checks,
        "regressions": [check["id"] for check in failed],
        "missing": [check["id"] for check in checks if check["status"] == "NOT_EVALUATED"],
    }
