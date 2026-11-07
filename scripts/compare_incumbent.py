#!/usr/bin/env python3
"""Offline QM-4 paired evidence report. No provider, network, or target execution."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.harness.evaluation import (  # noqa: E402
    EvaluationError,
    evaluate,
    parse_bounded_json,
    validate_corpus,
    validate_labels,
    validate_predictions,
)

VERSION = "qm4-paired-comparison.v1"
MANIFEST_VERSION = "qm4-incumbent-manifest.v1"
DEFAULT_MANIFEST = "examples/evaluation/qm4-incumbent-v1/manifest.json"
LIMIT = 16 * 1024 * 1024


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvaluationError(reason)


def load(path: Path) -> Any:
    with path.open("rb") as source:
        return parse_bounded_json(source.read(LIMIT + 1), "comparison_input")


def pinned(root: Path, reference: dict[str, str]) -> Any:
    path = (root / reference["path"]).resolve()
    require(path.is_relative_to(root.resolve()), "input_outside_root")
    with path.open("rb") as source:
        data = source.read(LIMIT + 1)
    require(len(data) <= LIMIT, "comparison_input_too_large")
    require(digest(data) == reference["sha256"], "input_hash_mismatch")
    return parse_bounded_json(data, "comparison_input")


def unknown(reason: str) -> dict[str, Any]:
    return {"value": None, "numerator": None, "denominator": None, "unknown_reason": reason}


def recall(corpus: dict, runs: list[dict], labels: dict, arm: str, kind: str) -> dict:
    run = next((item for item in runs if item["arm"] == arm), None)
    if run is None:
        return unknown("missing_output")
    packet = next(
        (
            p
            for p in labels["packets"]
            if p["reviewer"]["reviewer_kind"] == kind
            and p["label_role"] == "adjudicated"
            and p["case_completeness"] == "COMPLETE"
        ),
        None,
    )
    if packet is None:
        return unknown("missing_complete_" + kind + "_labels")
    final = {
        a["finding_id"]
        for a in packet["adjudications"]
        if a["arm"] == arm and a["outcome"] in {"MATCHED", "REJECTED", "DUPLICATE_OF"}
    }
    if run["status"] != "completed" or final != {f["finding_id"] for f in run["findings"]}:
        return unknown("incomplete_run_or_unresolved_adjudications")
    predictions = {
        "contract_version": "review-evaluation-predictions.v1",
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "runs": runs,
    }
    report = evaluate(corpus, predictions, labels)
    split = corpus["cases"][0]["identity"]["split"]
    metric = report["metrics"][f"{split}/{arm}"][f"{kind}_adjudication"]["known_material_finding_recall"][
        "completed_run_recall_conditional"
    ]
    return {
        "value": metric["value"],
        "numerator": metric["numerator"],
        "denominator": metric["denominator"],
        "unknown_reason": metric.get("undefined_reason"),
    }


def paired_delta(left: dict, right: dict) -> dict:
    if left["value"] is None or right["value"] is None:
        return unknown("not_both_comparable")
    return {
        "value": round(left["value"] - right["value"], 6),
        "numerator": None,
        "denominator": 1,
        "unknown_reason": None,
    }


def validate_output_provenance(output: dict) -> None:
    """Validate retained attribution syntax, not authenticity of provider execution."""
    captured = output.get("captured_at")
    require(isinstance(captured, str) and "T" in captured, "invalid_capture_timestamp")
    try:
        timestamp = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError:
        raise EvaluationError("invalid_capture_timestamp") from None
    require(timestamp.tzinfo is not None and timestamp.utcoffset() is not None, "capture_timestamp_requires_timezone")
    source = output.get("source_url")
    require(isinstance(source, str) and not any(c.isspace() or ord(c) < 32 for c in source), "invalid_source_url")
    try:
        url = urlsplit(source)
        host = url.hostname
        port = url.port
    except ValueError:
        raise EvaluationError("invalid_source_url") from None
    require(
        url.scheme == "https" and bool(host) and url.username is None and url.password is None, "invalid_source_url"
    )
    require(port is None or 1 <= port <= 65535, "invalid_source_url")
    require(isinstance(host, str) and len(host) <= 253, "invalid_source_hostname")
    labels = host.split(".")
    require(
        all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels),
        "invalid_source_hostname",
    )
    require("model_identity" in output, "missing_model_identity_or_explicit_null")
    model = output["model_identity"]
    require(model is None or (isinstance(model, str) and bool(model.strip())), "invalid_model_identity")


def comparison_row(record: dict, identities: dict, harness: dict, corpus: dict, labels: dict, root: Path) -> dict:
    cid = record["identity"]["case_id"]
    require(record["identity"] == identities[cid], "baseline_snapshot_mismatch")
    incumbent = record["incumbent"]
    require(incumbent["arm"] == "droid", "wrong_incumbent_arm")
    baseline = None
    if incumbent["status"] == "missing":
        require(
            incumbent["output"] is None and bool(incumbent["reason"]) and bool(incumbent["access"]),
            "invalid_missing_baseline",
        )
    else:
        require(incumbent["status"] == "retained", "invalid_baseline_status")
        output = pinned(root, incumbent["output"])
        require(output["evidence_kind"] == "retained_provider_output", "authored_fixture_not_incumbent")
        validate_output_provenance(output)
        baseline = output["run"]
        require(
            baseline["arm"] == "droid" and baseline["identity"] == identities[cid] and baseline["case_id"] == cid,
            "retained_snapshot_mismatch",
        )
    current = harness.get(cid)
    runs = [r for r in (current, baseline) if r is not None]
    one = copy.deepcopy(corpus)
    one["cases"] = [c for c in corpus["cases"] if c["identity"]["case_id"] == cid]
    one_predictions = {
        "contract_version": "review-evaluation-predictions.v1",
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "runs": runs,
    }
    validate_predictions(one_predictions, one)
    one_labels = copy.deepcopy(labels)
    one_labels["corpus_id"] = corpus["corpus_id"]
    one_labels["packets"] = [p for p in labels["packets"] if p["case_id"] == cid]
    if baseline is not None and incumbent.get("adjudication") is not None:
        comparison_labels = pinned(root, incumbent["adjudication"])
        require(
            comparison_labels["corpus_id"] == corpus["corpus_id"]
            and comparison_labels["dataset_version"] == corpus["dataset_version"],
            "comparison_labels_corpus_mismatch",
        )
        require(all(p["case_id"] == cid for p in comparison_labels["packets"]), "comparison_labels_case_mismatch")
        one_labels = comparison_labels
    validate_labels(one_labels, one, one_predictions)
    metrics = {}
    for kind in ("human", "synthetic"):
        h = recall(one, runs, one_labels, "harness", kind)
        b = recall(one, runs, one_labels, "droid", kind)
        delta = paired_delta(h, b)
        metrics[kind + "_recall"] = {
            "harness": h,
            "incumbent": b,
            "harness_minus_incumbent": delta,
            "incumbent_better": delta["value"] < 0 if delta["value"] is not None else None,
        }
    # v1 findings carry materiality but not blocking severity, and predictions
    # carry no cost accounting. Never infer either from disposition or counts.
    for name, reason in (
        ("false_blockers", "blocking_severity_adjudication_not_retained"),
        ("cost", "comparable_cost_accounting_not_retained"),
    ):
        metrics[name] = {
            "harness": unknown(reason),
            "incumbent": unknown(reason),
            "harness_minus_incumbent": unknown(reason),
            "incumbent_better": None,
        }
    hd = current["disposition"] if current else None
    bd = baseline["disposition"] if baseline else None
    comparable = all(
        r is not None and r["status"] == "completed" and r["disposition"] != "UNKNOWN" for r in (current, baseline)
    )
    metrics["disposition"] = {
        "harness": hd,
        "incumbent": bd,
        "equal": hd == bd if comparable else None,
        "denominator": 1 if comparable else None,
        "unknown_reason": None if comparable else "not_both_completed_known_dispositions",
        "incumbent_better": None,
    }
    return {
        "identity": record["identity"],
        "harness": {
            "status": current["status"] if current else "missing",
            "run_id": current["run_id"] if current else None,
            "missing_reason": None if current else "no_retained_live_harness_run_for_frozen_identity",
        },
        "incumbent": incumbent,
        "paired_outputs": current is not None and baseline is not None,
        "metrics": metrics,
    }


def build_report(manifest: dict, root: Path = ROOT) -> dict:
    require(manifest["schema_version"] == MANIFEST_VERSION, "unsupported_incumbent_manifest")
    inputs = {name: pinned(root, ref) for name, ref in manifest["inputs"].items()}
    require(
        manifest["evaluator_source_sha256"] == digest((ROOT / "experiments/harness/evaluation.py").read_bytes()),
        "evaluator_source_mismatch",
    )
    corpus = validate_corpus(inputs["corpus"])
    sources = inputs["sources"]
    require(
        manifest["corpus_id"] == corpus["corpus_id"] and manifest["dataset_version"] == corpus["dataset_version"],
        "manifest_corpus_mismatch",
    )
    identities = {c["identity"]["case_id"]: c["identity"] for c in corpus["cases"]}
    require(set(sources["manifests"]) == set(identities), "source_case_set_mismatch")
    for cid, identity in identities.items():
        source = sources["manifests"][cid]
        require(digest(canonical(source)) == identity["source_manifest"]["sha256"], "source_identity_mismatch")
        for key in ("case_id", "base_sha", "head_sha", "repository", "profile", "snapshot_id"):
            require(source[key] == identity[key], "source_identity_mismatch")
    pilot = validate_corpus(inputs["harness_corpus"])
    predictions = validate_predictions(inputs["harness_predictions"], pilot)
    labels = validate_labels(inputs["labels"], pilot, predictions)
    require(pilot["dataset_version"] == corpus["dataset_version"], "harness_dataset_mismatch")
    for case in pilot["cases"]:
        require(case["identity"] == identities.get(case["identity"]["case_id"]), "harness_snapshot_mismatch")
    evidence_runs = {(r["case_id"], r["run_id"]) for r in inputs["harness_live_evidence"]["runs"]}
    harness = {}
    for run in predictions["runs"]:
        require(run["arm"] == "harness", "non_harness_prediction_input")
        require((run["case_id"], run["run_id"]) in evidence_runs, "harness_live_provenance_missing")
        harness[run["case_id"]] = run
    records = manifest["cases"]
    require(
        len(records) == len(identities) and {r["identity"]["case_id"] for r in records} == set(identities),
        "missing_or_duplicate_baseline_arm",
    )
    rows = [
        comparison_row(record, identities, harness, corpus, labels, root)
        for record in sorted(records, key=lambda r: r["identity"]["case_id"])
    ]
    summaries = {}
    for name in ("human_recall", "synthetic_recall", "false_blockers", "cost"):
        values = [r["metrics"][name]["harness_minus_incumbent"]["value"] for r in rows]
        known = [v for v in values if v is not None]
        summaries[name] = {
            "available_paired_cases": len(known),
            "unavailable_cases": len(rows) - len(known),
            "mean_harness_minus_incumbent": round(sum(known) / len(known), 6) if known else None,
            "denominator_cases": len(known) if known else None,
            "incumbent_better_case_ids": [
                r["identity"]["case_id"] for r in rows if r["metrics"][name]["incumbent_better"] is True
            ],
        }
    comparable_dispositions = [r for r in rows if r["metrics"]["disposition"]["denominator"] == 1]
    summaries["disposition"] = {
        "available_paired_cases": len(comparable_dispositions),
        "agreement_numerator": sum(r["metrics"]["disposition"]["equal"] for r in comparable_dispositions)
        if comparable_dispositions
        else None,
        "denominator_cases": len(comparable_dispositions) if comparable_dispositions else None,
        "quality_ordering": None,
    }
    return {
        "schema_version": VERSION,
        "manifest_sha256": digest(canonical(manifest)),
        "implementation_sha256": digest(Path(__file__).read_bytes()),
        "inputs": manifest["inputs"],
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "case_count": len(rows),
        "retained_harness_outputs": len(harness),
        "retained_incumbent_outputs": sum(r["incumbent"]["status"] == "retained" for r in rows),
        "actual_paired_output_count": sum(r["paired_outputs"] for r in rows),
        "summaries": summaries,
        "rows": rows,
        "claims": {
            "parity_established": False,
            "equivalence_established": False,
            "improvement_established": False,
            "pre_specified_equivalence_margin": None,
            "authored_droid_fixtures_counted_as_live": False,
        },
        "uncertainty": "Descriptive paired observations only; no confidence interval or equivalence test. "
        "Missingness is not random; synthetic labels are not human truth. "
        "Disposition agreement is not accuracy; cost and false blockers remain unknown.",
    }


def markdown(report: dict) -> str:
    lines = [
        "# QM-4 incumbent paired evidence v1",
        "",
        f"Frozen cases: **{report['case_count']}**. Retained harness outputs: **{report['retained_harness_outputs']}**. "
        f"Retained incumbent outputs: **{report['retained_incumbent_outputs']}**. "
        f"Actual paired output count: **{report['actual_paired_output_count']}**.",
        "",
        "Unknown is not zero. No parity, equivalence, improvement, or replacement claim is established.",
        "",
        "| Measure | Comparable paired cases | Estimand denominator |",
        "|---|---:|---|",
    ]
    for name, summary in report["summaries"].items():
        lines.append(
            f"| {name} | {summary['available_paired_cases']} | {summary['denominator_cases'] or 'unknown/null'} |"
        )
    lines += [
        "",
        "## Every frozen case (including pr770)",
        "",
        "Exact base/head, snapshot, profile, source identities, missing reasons/access, and each metric's "
        "numerator/denominator are retained in the companion JSON and manifest.",
        "",
        "| Case | Harness | Droid | Paired outputs | Recall / false blockers / disposition / cost denominators |",
        "|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        denoms = [
            row["metrics"][m]["harness_minus_incumbent"]["denominator"] for m in ("synthetic_recall", "false_blockers")
        ]
        denoms += [
            row["metrics"]["disposition"]["denominator"],
            row["metrics"]["cost"]["harness_minus_incumbent"]["denominator"],
        ]
        lines.append(
            f"| {row['identity']['case_id']} | {row['harness']['status']} | {row['incumbent']['status']} | "
            f"{'yes' if row['paired_outputs'] else 'no'} | "
            + " / ".join(str(d) if d is not None else "null" for d in denoms)
            + " |"
        )
    better = sorted(
        {
            cid
            for name in ("human_recall", "synthetic_recall")
            for cid in report["summaries"][name]["incumbent_better_case_ids"]
        }
    )
    if better:
        observation = "Observed incumbent-better recall cases: " + ", ".join(better) + ". See JSON for label-arm scope."
    elif report["actual_paired_output_count"] == 0:
        observation = "No incumbent-better case is observed because no paired incumbent output is retained."
    else:
        observation = "No incumbent-better recall case is observed within the available adjudicated comparisons."
    lines += [
        "",
        "## Limitations and issue exit",
        "",
        report["uncertainty"],
        "",
        observation + " This is not evidence that the incumbent is never better; unknown measures remain unknown.",
        "",
        "Issue #245 explicitly permits a baseline arm record **or explicit missing** for each corpus case. "
        "This packet can satisfy that documentary/reporting exit with explicit missing; it does not satisfy "
        "the broader ambition of measured incumbent performance. Maintainer review decides closure; no issue is auto-closed.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        report = build_report(load(args.root / args.manifest), args.root)
        print(
            json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
            if args.format == "json"
            else markdown(report),
            end="\n" if args.format == "json" else "",
        )
    except (EvaluationError, OSError, KeyError, TypeError, ValueError) as exc:
        code = exc.code if isinstance(exc, EvaluationError) else "invalid_or_unreadable_comparison_input"
        print(json.dumps({"error": code}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
