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
SYNTHETIC_LABELS = PILOT / "labels-synthetic-v1.json"
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


def test_labeling_pilot_has_retained_synthetic_packets_and_frozen_subset():
    corpus = _load(PILOT / "corpus.json")
    predictions = _load(PILOT / "predictions.json")
    labels = _load(SYNTHETIC_LABELS)
    manifest = _load(PILOT / "manifest.json")
    assert validate_corpus(corpus) == corpus
    assert validate_predictions(predictions, corpus) == predictions
    assert validate_labels(labels, corpus, predictions) == labels
    assert predictions["runs"] == []
    assert len(labels["packets"]) == 6
    assert {packet["reviewer"]["reviewer_kind"] for packet in labels["packets"]} == {"synthetic"}
    assert {packet["label_role"] for packet in labels["packets"]} == {"adjudicated"}
    assert labels["rubric_version"] == "qm2-labeling-rubric.v1"
    assert manifest["content_hashes"]["corpus.json"] == _hash(PILOT / "corpus.json")
    assert manifest["content_hashes"]["predictions.json"] == _hash(PILOT / "predictions.json")
    assert manifest["content_hashes"]["labels.json"] == _hash(PILOT / "labels.json")
    assert manifest["content_hashes"]["labels-synthetic-v1.json"] == _hash(SYNTHETIC_LABELS)
    for relative, digest in manifest["content_hashes"].items():
        assert digest == _hash(PILOT / relative)
    assert manifest["label_packet_state"]["state"] == "present"
    assert manifest["label_packet_state"]["label_source"] == "synthetic"
    assert manifest["label_packet_state"]["human_packets"] == 0
    assert manifest["label_packet_state"]["synthetic_adjudicated_packets"] == 6
    assert manifest["label_packet_state"]["synthetic_complete_packets"] == 5
    assert manifest["label_packet_state"]["synthetic_incomplete_packets"] == 1
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


def test_synthetic_labels_and_empty_predictions_produce_missing_not_zero():
    scorecard = _scorecard(PILOT / "corpus.json", PILOT / "predictions.json", SYNTHETIC_LABELS)
    assert scorecard["contract_version"] == SCORECARD_VERSION
    assert scorecard["evaluator_revision"] == EVALUATOR_REVISION
    assert scorecard["data_state"]["state"] == "MISSING_DATA"
    assert "no_prediction_runs" in scorecard["data_state"]["reasons"]
    assert "partial_adjudicated_labels" in scorecard["data_state"]["reasons"]
    label_state = scorecard["data_state"]["label_state"]
    assert label_state["status"] == "partial"
    assert label_state["arms"]["synthetic"]["status"] == "partial"
    assert label_state["arms"]["synthetic"]["adjudicated_packets"] == 6
    assert label_state["arms"]["synthetic"]["complete_adjudicated_packets"] == 5
    assert label_state["arms"]["human"]["status"] == "missing"
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
        assert summary["label_arms"]["human"]["precision"]["lower_bound"]["value"] is None
        assert summary["label_arms"]["human"]["precision"]["upper_bound"]["value"] is None
        assert summary["label_arms"]["human"]["recall"]["lower_bound"]["value"] is None
        assert summary["label_arms"]["human"]["recall"]["upper_bound"]["value"] is None
        assert summary["label_arms"]["human"]["abstention"]["adjudicated_abstentions"] is None
        assert summary["label_arms"]["human"]["duplicates"]["correlated_duplicates_excluded"] is None
        assert summary["label_arms"]["human"]["unadjudicated"]["findings_without_final_adjudication"] is None
        assert summary["label_arms"]["human"]["approve_with_known_defect"]["cases"] is None
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
    assert "no_complete_adjudicated_human_or_synthetic_label_packets" in scorecard["data_state"]["reasons"]
    harness = scorecard["arms"]["harness"]
    assert harness["status"] == "complete"
    assert harness["candidate_findings"] == 1
    assert harness["label_arms"]["human"]["precision"]["status"] == "missing_labels"
    assert harness["label_arms"]["human"]["precision"]["lower_bound"]["value"] is None
    assert harness["label_arms"]["human"]["recall"]["lower_bound"]["value"] is None
    assert harness["label_arms"]["human"]["abstention"]["adjudicated_abstentions"] is None
    assert harness["label_arms"]["human"]["duplicates"]["correlated_duplicates_excluded"] is None
    assert harness["label_arms"]["human"]["unadjudicated"]["findings_without_final_adjudication"] is None
    assert harness["label_arms"]["human"]["approve_with_known_defect"]["cases"] is None
    assert regression_gate(scorecard, scorecard)["status"] == "MISSING_DATA"


def test_scorecard_publishes_bounds_counts_and_denominators():
    scorecard = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    assert scorecard["data_state"]["state"] == "COMPLETE"
    assert scorecard["data_state"]["label_state"]["status"] == "present"
    harness = scorecard["arms"]["harness"]
    assert harness["status"] == "complete"
    assert harness["label_arms"]["human"]["precision"]["lower_bound"] == {
        "numerator": 1,
        "denominator": 1,
        "value": 1.0,
        "undefined_reason": None,
    }
    assert harness["label_arms"]["human"]["precision"]["upper_bound"] == {
        "numerator": 1,
        "denominator": 1,
        "value": 1.0,
        "undefined_reason": None,
    }
    assert harness["label_arms"]["human"]["recall"]["lower_bound"]["numerator"] == 1
    assert harness["label_arms"]["human"]["recall"]["lower_bound"]["denominator"] == 1
    assert harness["label_arms"]["human"]["recall"]["upper_bound"]["value"] == 1.0
    assert harness["label_arms"]["human"]["abstention"]["adjudicated_abstentions"] == 0
    assert harness["label_arms"]["human"]["abstention"]["rate"]["denominator"] == 1
    assert harness["label_arms"]["human"]["duplicates"]["correlated_duplicates_excluded"] == 0
    assert harness["label_arms"]["human"]["unadjudicated"]["findings_without_final_adjudication"] == 0
    assert harness["label_arms"]["human"]["approve_with_known_defect"]["cases"] == 0
    assert harness["accuracy"]["value"] is None
    assert harness["accuracy"]["status"] == "refused"
    assert scorecard["input_hashes"]["corpus"] == _hash(FIXTURE / "corpus.json")


def test_gate_reports_retained_pilot_as_missing_data_without_failure(tmp_path: Path):
    scorecard = _scorecard(PILOT / "corpus.json", PILOT / "predictions.json", SYNTHETIC_LABELS)
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
    assert baseline["arms"]["harness"]["label_arms"]["human"]["recall"]["lower_bound"]["value"] == 1.0
    assert regressed["arms"]["harness"]["label_arms"]["human"]["recall"]["lower_bound"]["value"] == 0.0
    gate = regression_gate(regressed, baseline)
    assert gate["status"] == "FAIL"
    assert "recall_lower_bound:harness:human" in gate["regressions"]
    assert "precision_lower_bound:harness:human" in gate["regressions"]
    assert "approve_with_known_defect:harness:human" in gate["regressions"]
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
    assert "recall_lower_bound:harness:human" in gate["regressions"]


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
    labels = _load(SYNTHETIC_LABELS)
    report = evaluate(corpus, predictions, labels)
    for metric in report["metrics"].values():
        assert metric["human_adjudication"]["complete_cases"] == 0
        assert metric["human_adjudication"]["precision"]["value"] is None
        assert metric["human_adjudication"]["known_material_finding_recall"]["corpus_recall_lower_bound"]["value"] is None
    assert report["claims"] == {
        "release_gate": None,
        "heldout_quality_claim": False,
        "synthetic_is_human_truth": False,
        "human_labels_required": False,
    }


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


def test_gate_fails_on_partial_current_coverage() -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    current = deepcopy(baseline)
    current["data_state"]["state"] = "PARTIAL"
    gate = regression_gate(current, baseline)
    assert gate["status"] == "FAIL"
    assert gate["current_data_state"] == "PARTIAL"


def test_gate_fails_when_baseline_arm_key_is_absent() -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    current = deepcopy(baseline)
    del current["arms"]["droid"]
    gate = regression_gate(current, baseline)
    assert gate["status"] == "FAIL"
    assert any(check["id"] == "arm:droid" and check["reason"] == "arm_absent_since_baseline" for check in gate["checks"])


@pytest.mark.parametrize("mutator", ["completion", "label_state", "hashes"])
def test_gate_rejects_deeply_incomplete_scorecard(tmp_path: Path, mutator: str) -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    malformed = deepcopy(baseline)
    if mutator == "completion":
        malformed["completion"] = {}
    elif mutator == "label_state":
        del malformed["data_state"]["label_state"]
    else:
        malformed["input_hashes"] = {"corpus": malformed["input_hashes"]["corpus"]}
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


@pytest.mark.parametrize("mutator", ["claims", "complete_with_partial_labels"])
def test_gate_rejects_contract_invalid_scorecard(tmp_path: Path, mutator: str) -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    malformed = deepcopy(baseline)
    if mutator == "claims":
        malformed["claims"].update({"quality_claim": True, "accuracy": 1.0, "release_gate": "PASS"})
    else:
        malformed["data_state"]["state"] = "COMPLETE"
        malformed["data_state"]["label_state"]["status"] = "partial"
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


def test_partial_baseline_to_complete_current_passes() -> None:
    baseline = _scorecard(FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json")
    current = deepcopy(baseline)
    baseline["data_state"]["state"] = "PARTIAL"
    gate = regression_gate(current, baseline)
    assert gate["current_data_state"] == "COMPLETE"
    assert gate["status"] in {"PASS", "MISSING_DATA"}


def test_synthetic_only_scorecard_is_complete_without_human_packets():
    scorecard = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels-synthetic.json"
    )
    assert scorecard["data_state"]["state"] == "COMPLETE"
    assert scorecard["data_state"]["reasons"] == []
    label_state = scorecard["data_state"]["label_state"]
    assert label_state["status"] == "present"
    assert label_state["human_labels_required"] is False
    assert label_state["synthetic_is_human_truth"] is False
    assert label_state["arms"]["human"]["status"] == "missing"
    assert label_state["arms"]["synthetic"]["status"] == "present"
    harness = scorecard["arms"]["harness"]["label_arms"]
    assert harness["human"]["status"] == "missing_labels"
    assert harness["synthetic"]["status"] == "present"
    assert harness["synthetic"]["scope"] == "synthetic_only"
    assert harness["synthetic"]["is_human_truth"] is False
    assert harness["synthetic"]["precision"]["lower_bound"]["value"] == 1.0
    assert harness["synthetic"]["recall"]["lower_bound"]["value"] == 1.0
    assert scorecard["claims"]["accuracy"] is None
    assert scorecard["claims"]["quality_claim"] is False
    assert scorecard["claims"]["synthetic_is_human_truth"] is False
    assert scorecard["claims"]["human_labels_required"] is False
    accuracy = scorecard["arms"]["harness"]["accuracy"]
    assert accuracy["status"] == "refused"
    assert "synthetic_is_not_human_accuracy" in accuracy["reasons"]
    assert regression_gate(scorecard, scorecard)["status"] == "PASS"


def test_synthetic_packet_validates_and_cannot_be_mislabelled_human():
    corpus = _load(FIXTURE / "corpus.json")
    predictions = _load(FIXTURE / "predictions-baseline.json")
    labels = _load(FIXTURE / "labels-synthetic.json")
    assert validate_labels(labels, corpus, predictions) == labels

    human_marked = deepcopy(labels)
    reviewer = human_marked["packets"][0]["reviewer"]
    reviewer["reviewer_kind"] = "human"
    reviewer["reviewer_id"] = "not-a-synthetic-run"
    reviewer["source_kind"] = "independent_reviewer"
    del reviewer["synthetic"]
    with pytest.raises(EvaluationError, match="invalid_reviewer_provenance"):
        validate_labels(human_marked, corpus, predictions)

    not_marked = deepcopy(labels)
    not_marked["packets"][0]["reviewer"]["synthetic"] = False
    with pytest.raises(EvaluationError, match="invalid_synthetic_provenance"):
        validate_labels(not_marked, corpus, predictions)

    wrong_rubric = deepcopy(labels)
    wrong_rubric["packets"][0]["reviewer"]["rubric_revision"] = "qm2-labeling-rubric.v999"
    with pytest.raises(EvaluationError, match="synthetic_rubric_mismatch"):
        validate_labels(wrong_rubric, corpus, predictions)

    missing_run = deepcopy(labels)
    del missing_run["packets"][0]["reviewer"]["run_id"]
    with pytest.raises(EvaluationError, match="invalid_reviewer_provenance"):
        validate_labels(missing_run, corpus, predictions)


def test_synthetic_packet_cannot_adjudicate_attack_outcomes():
    corpus = _load(FIXTURE / "corpus.json")
    predictions = _load(FIXTURE / "predictions-baseline.json")
    labels = _load(FIXTURE / "labels-synthetic.json")
    labels["packets"][0]["attack_outcomes"] = [{}]
    with pytest.raises(EvaluationError, match="synthetic_cannot_adjudicate_attack_outcomes"):
        validate_labels(labels, corpus, predictions)


def test_human_and_synthetic_adjudication_are_separate_arms():
    corpus = _load(FIXTURE / "corpus.json")
    predictions = _load(FIXTURE / "predictions-baseline.json")
    labels = _load(FIXTURE / "labels.json")
    labels["packets"].extend(deepcopy(_load(FIXTURE / "labels-synthetic.json")["packets"]))
    assert validate_labels(labels, corpus, predictions) == labels
    scorecard = build_scorecard(
        corpus,
        predictions,
        labels,
        input_hashes={"corpus": _hash(FIXTURE / "corpus.json"), "predictions": "b" * 64, "labels": "c" * 64},
    )
    assert scorecard["data_state"]["state"] == "COMPLETE"
    label_state = scorecard["data_state"]["label_state"]
    assert label_state["arms"]["human"]["status"] == "present"
    assert label_state["arms"]["synthetic"]["status"] == "present"
    harness = scorecard["arms"]["harness"]["label_arms"]
    assert harness["human"]["is_human_truth"] is True
    assert harness["human"]["precision"]["lower_bound"]["value"] == 1.0
    assert harness["synthetic"]["is_human_truth"] is False
    assert harness["synthetic"]["precision"]["lower_bound"]["value"] == 1.0


def test_gate_fails_synthetic_only_regression_and_disappearance():
    baseline = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels-synthetic.json"
    )
    regressed = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-regressed.json", FIXTURE / "labels-synthetic.json"
    )
    gate = regression_gate(regressed, baseline)
    assert gate["status"] == "FAIL"
    assert "approve_with_known_defect:harness:synthetic" in gate["regressions"]

    human_only = _scorecard(
        FIXTURE / "corpus.json", FIXTURE / "predictions-baseline.json", FIXTURE / "labels.json"
    )
    assert human_only["data_state"]["state"] == "COMPLETE"
    dropped = regression_gate(human_only, baseline)
    assert dropped["status"] == "FAIL"
    assert any(
        check["id"] == "label_arm:harness:synthetic" and check["status"] == "FAIL"
        for check in dropped["checks"]
    )
