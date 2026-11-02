"""Deterministic scorecard, labeling-pilot structure, and regression-gate tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from experiments.harness.evaluation import (
    EvaluationError,
    evaluate,
    validate_corpus,
    validate_labels,
    validate_predictions,
)
from experiments.harness.scorecard import (
    EVALUATOR_REVISION,
    SCORECARD_VERSION,
    build_scorecard,
    canonical_bytes,
    regression_gate,
)

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "examples/evaluation/qm2-labeling-pilot-v1"
FROZEN = ROOT / "examples/evaluation/frozen-corpus-v1/corpus.json"
FIXTURE = ROOT / "tests/fixtures/quality_scorecard"


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scorecard(corpus: Path, predictions: Path, labels: Path) -> dict:
    return build_scorecard(
        _load(corpus),
        _load(predictions),
        _load(labels),
        input_hashes={
            "corpus": _hash(corpus),
            "predictions": _hash(predictions),
            "labels": _hash(labels),
        },
    )


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_labeling_pilot_is_valid_empty_and_derived_from_the_frozen_subset():
    corpus = _load(PILOT / "corpus.json")
    predictions = _load(PILOT / "predictions.json")
    labels = _load(PILOT / "labels.json")
    manifest = _load(PILOT / "manifest.json")
    assert validate_corpus(corpus) == corpus
    assert validate_predictions(predictions, corpus) == predictions
    assert validate_labels(labels, corpus, predictions) == labels
    assert predictions["runs"] == []
    assert labels["packets"] == []
    assert labels["rubric_version"] == "qm2-labeling-rubric.v1"
    assert manifest["content_hashes"]["corpus.json"] == _hash(PILOT / "corpus.json")
    assert manifest["content_hashes"]["predictions.json"] == _hash(PILOT / "predictions.json")
    assert manifest["content_hashes"]["labels.json"] == _hash(PILOT / "labels.json")
    assert manifest["label_packet_state"]["state"] == "missing"
    assert manifest["label_packet_state"]["human_packets"] == 0
    assert manifest["label_packet_state"]["model_teacher_screening_packets"] == 0
    source = _load(FROZEN)
    source_by_id = {case["identity"]["case_id"]: case for case in source["cases"]}
    assert [case["identity"]["case_id"] for case in corpus["cases"]] == manifest["selection"]["case_ids"]
    for case in corpus["cases"]:
        assert case == source_by_id[case["identity"]["case_id"]]
    assert {case["identity"]["split"] for case in corpus["cases"]} == {"development", "heldout", "challenge"}
    assert {
        f"{case['identity']['repository']['owner']}/{case['identity']['repository']['name']}"
        for case in corpus["cases"]
    } == {"groktopus/codereview", "magnus919/SlopSearX"}


def test_empty_labels_and_predictions_produce_missing_not_zero():
    scorecard = _scorecard(PILOT / "corpus.json", PILOT / "predictions.json", PILOT / "labels.json")
    assert scorecard["contract_version"] == SCORECARD_VERSION
    assert scorecard["evaluator_revision"] == EVALUATOR_REVISION
    assert scorecard["data_state"]["state"] == "MISSING_DATA"
    assert "no_complete_adjudicated_human_label_packets" in scorecard["data_state"]["reasons"]
    assert "no_prediction_runs" in scorecard["data_state"]["reasons"]
    assert scorecard["missing_data"]["arms"] == ["droid", "harness"]
    assert scorecard["claims"]["accuracy"] is None
    assert scorecard["claims"]["quality_claim"] is False
    assert scorecard["claims"]["release_gate"] is None
    assert scorecard["completion"]["completed_of_expected"]["value"] is None
    assert scorecard["completion"]["completed_of_expected"]["undefined_reason"] == "no_runs"
    for arm in ("harness", "droid"):
        summary = scorecard["arms"][arm]
        assert summary["status"] == "missing"
        assert summary["missing"] is True
        assert summary["candidate_findings"] is None
        assert summary["precision"]["lower_bound"]["value"] is None
        assert summary["precision"]["upper_bound"]["value"] is None
        assert summary["recall"]["lower_bound"]["value"] is None
        assert summary["recall"]["upper_bound"]["value"] is None
        assert summary["abstention"]["adjudicated_abstentions"] is None
        assert summary["duplicates"]["correlated_duplicates_excluded"] is None
        assert summary["unadjudicated"]["findings_without_final_adjudication"] is None
        assert summary["approve_with_known_defect"]["cases"] is None
        assert summary["accuracy"]["value"] is None
    for digest in scorecard["input_hashes"].values():
        assert len(digest) == 64


def test_predictions_without_labels_report_missing_labels_not_zero():
    corpus = _load(FIXTURE / "corpus.json")
    predictions = _load(FIXTURE / "predictions-baseline.json")
    labels = {
        "contract_version": "review-evaluation-labels.v1",
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "rubric_version": "qm2-labeling-rubric.v1",
        "packets": [],
    }
    scorecard = build_scorecard(
        corpus,
        predictions,
        labels,
        input_hashes={"corpus": _hash(FIXTURE / "corpus.json"), "predictions": "b" * 64, "labels": "c" * 64},
    )
    assert scorecard["data_state"]["state"] == "MISSING_DATA"
    assert "no_complete_adjudicated_human_label_packets" in scorecard["data_state"]["reasons"]
    harness = scorecard["arms"]["harness"]
    assert harness["status"] == "complete"
    assert harness["candidate_findings"] == 1
    assert harness["precision"]["status"] == "missing_labels"
    assert harness["precision"]["lower_bound"]["value"] is None
    assert harness["recall"]["lower_bound"]["value"] is None
    assert harness["abstention"]["adjudicated_abstentions"] is None
    assert harness["duplicates"]["correlated_duplicates_excluded"] is None
    assert harness["unadjudicated"]["findings_without_final_adjudication"] is None
    assert harness["approve_with_known_defect"]["cases"] is None
    assert regression_gate(scorecard, scorecard)["status"] == "MISSING_DATA"


def test_scorecard_publishes_bounds_counts_and_denominators():
    scorecard = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    assert scorecard["data_state"]["state"] == "COMPLETE"
    assert scorecard["data_state"]["label_state"]["status"] == "present"
    harness = scorecard["arms"]["harness"]
    assert harness["status"] == "complete"
    assert harness["precision"]["lower_bound"] == {
        "numerator": 1,
        "denominator": 1,
        "value": 1.0,
        "undefined_reason": None,
    }
    assert harness["precision"]["upper_bound"] == {
        "numerator": 1,
        "denominator": 1,
        "value": 1.0,
        "undefined_reason": None,
    }
    assert harness["recall"]["lower_bound"]["numerator"] == 1
    assert harness["recall"]["lower_bound"]["denominator"] == 1
    assert harness["recall"]["upper_bound"]["value"] == 1.0
    assert harness["abstention"]["adjudicated_abstentions"] == 0
    assert harness["abstention"]["rate"]["denominator"] == 1
    assert harness["duplicates"]["correlated_duplicates_excluded"] == 0
    assert harness["unadjudicated"]["findings_without_final_adjudication"] == 0
    assert harness["approve_with_known_defect"]["cases"] == 0
    assert harness["accuracy"]["value"] is None
    assert harness["accuracy"]["status"] == "refused"
    assert scorecard["input_hashes"]["corpus"] == _hash(FIXTURE / "corpus.json")


def test_gate_reports_empty_pilot_as_missing_data_without_failure(tmp_path: Path):
    scorecard = _scorecard(PILOT / "corpus.json", PILOT / "predictions.json", PILOT / "labels.json")
    gate = regression_gate(scorecard, scorecard)
    assert gate["status"] == "MISSING_DATA"
    assert gate["regressions"] == []
    path = tmp_path / "scorecard.json"
    path.write_bytes(canonical_bytes(scorecard) + b"\n")
    result = _run(
        [
            sys.executable,
            str(ROOT / "scripts/check_quality_scorecard_gate.py"),
            "--baseline",
            str(path),
            "--current",
            str(path),
            "--json",
        ]
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "MISSING_DATA"


def test_seeded_regression_fails_the_gate():
    baseline = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    regressed = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-regressed.json", FIXTURE / "labels-regressed.json"
    )
    assert baseline["arms"]["harness"]["recall"]["lower_bound"]["value"] == 1.0
    assert regressed["arms"]["harness"]["recall"]["lower_bound"]["value"] == 0.0
    gate = regression_gate(regressed, baseline)
    assert gate["status"] == "FAIL"
    assert "recall_lower_bound:harness" in gate["regressions"]
    assert "precision_lower_bound:harness" in gate["regressions"]
    assert "approve_with_known_defect:harness" in gate["regressions"]
    assert any(check["status"] == "NOT_EVALUATED" for check in gate["checks"])


def test_gate_rejects_cross_corpus_comparison():
    baseline = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    current = deepcopy(baseline)
    current["corpus_id"] = "different-corpus"
    gate = regression_gate(current, baseline)
    assert gate["status"] == "FAIL"
    assert gate["regressions"] == ["corpus_or_rubric_identity_mismatch"]


def test_scorecard_cli_is_deterministic_and_rejects_invalid_labels(tmp_path: Path):
    command = [
        sys.executable,
        str(ROOT / "scripts/generate_quality_scorecard.py"),
        "--corpus",
        str(FIXTURE / "corpus.json"),
        "--predictions",
        str(FIXTURE / "predictions-baseline.json"),
        "--labels",
        str(FIXTURE / "labels.json"),
        "--json",
    ]
    first = _run(command)
    second = _run(command)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    scorecard = json.loads(first.stdout)
    assert scorecard["input_hashes"]["labels"] == _hash(FIXTURE / "labels.json")
    output = tmp_path / "scorecard.json"
    with_output = _run([*command, "--output", str(output)])
    assert with_output.returncode == 0
    assert output.read_bytes() == canonical_bytes(scorecard) + b"\n"
    bad = _load(FIXTURE / "labels.json")
    bad["corpus_id"] = "other-corpus"
    bad_path = tmp_path / "bad-labels.json"
    bad_path.write_text(json.dumps(bad), encoding="utf-8")
    rejected = _run(
        [
            sys.executable,
            str(ROOT / "scripts/generate_quality_scorecard.py"),
            "--corpus",
            str(FIXTURE / "corpus.json"),
            "--predictions",
            str(FIXTURE / "predictions-baseline.json"),
            "--labels",
            str(bad_path),
            "--json",
        ]
    )
    assert rejected.returncode == 2
    assert json.loads(rejected.stdout) == {"error": "labels_corpus_mismatch"}


def test_gate_cli_fails_on_seeded_regression(tmp_path: Path):
    baseline = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    regressed = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-regressed.json", FIXTURE / "labels-regressed.json"
    )
    baseline_path = tmp_path / "baseline.json"
    regressed_path = tmp_path / "regressed.json"
    baseline_path.write_bytes(canonical_bytes(baseline) + b"\n")
    regressed_path.write_bytes(canonical_bytes(regressed) + b"\n")
    result = _run(
        [
            sys.executable,
            str(ROOT / "scripts/check_quality_scorecard_gate.py"),
            "--baseline",
            str(baseline_path),
            "--current",
            str(regressed_path),
            "--json",
        ]
    )
    assert result.returncode == 1
    gate = json.loads(result.stdout)
    assert gate["status"] == "FAIL"
    assert "recall_lower_bound:harness" in gate["regressions"]


def test_labels_contract_forbids_model_teacher_adjudication():
    corpus = _load(FIXTURE / "corpus.json")
    predictions = _load(FIXTURE / "predictions-baseline.json")
    labels = _load(FIXTURE / "labels.json")
    packet = labels["packets"][0]
    packet["reviewer"] = {
        "reviewer_kind": "model_teacher",
        "provider_id": "test-provider",
        "model_id": "test-model",
        "prompt_revision": "prompt-1",
        "output_sha256": "d" * 64,
        "labeled_at": "2026-11-02T00:00:00Z",
    }
    packet["label_role"] = "adjudicated"
    with pytest.raises(EvaluationError, match="reviewer_role_mismatch"):
        validate_labels(labels, corpus, predictions)


def test_human_adjudication_remains_unmet_without_a_human_packet():
    corpus = _load(PILOT / "corpus.json")
    predictions = _load(PILOT / "predictions.json")
    labels = _load(PILOT / "labels.json")
    report = evaluate(corpus, predictions, labels)
    for metric in report["metrics"].values():
        assert metric["human_adjudication"]["complete_cases"] == 0
        assert metric["human_adjudication"]["precision"]["value"] is None
        assert metric["human_adjudication"]["known_material_finding_recall"]["corpus_recall_lower_bound"]["value"] is None
    assert report["claims"] == {"release_gate": None, "heldout_quality_claim": False}


def test_gate_fails_when_an_arm_disappears(tmp_path: Path) -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    predictions = deepcopy(json.loads((FIXTURE / "predictions-baseline.json").read_text()))
    predictions["runs"] = [run for run in predictions["runs"] if run["arm"] == "harness"]
    path = tmp_path / "predictions-harness-only.json"
    path.write_text(json.dumps(predictions))
    current = build_scorecard(
        json.loads((FIXTURE / "corpus.json").read_text()),
        predictions,
        json.loads((FIXTURE / "labels.json").read_text()),
        input_hashes={"corpus": _hash(FIXTURE / "corpus.json"), "predictions": "b" * 64, "labels": "c" * 64},
    )
    gate = regression_gate(current, baseline)
    assert gate["status"] == "FAIL"
    assert any(check["id"] == "arm:droid" and check["status"] == "FAIL" for check in gate["checks"])


def test_gate_cli_rejects_malformed_scorecard(tmp_path: Path) -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    malformed = deepcopy(baseline)
    del malformed["data_state"]
    baseline_path = tmp_path / "baseline.json"
    malformed_path = tmp_path / "malformed.json"
    baseline_path.write_bytes(canonical_bytes(baseline) + b"\n")
    malformed_path.write_bytes(canonical_bytes(malformed) + b"\n")
    result = _run(
        [
            sys.executable,
            str(ROOT / "scripts/check_quality_scorecard_gate.py"),
            "--baseline",
            str(baseline_path),
            "--current",
            str(malformed_path),
            "--json",
        ]
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["error"] == "invalid_scorecard_schema"
