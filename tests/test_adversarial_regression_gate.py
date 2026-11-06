"""Adversarial-pairs v1 metrics in the deterministic quality regression gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

from experiments.harness.scorecard import build_scorecard, canonical_bytes, regression_gate

ROOT = Path(__file__).resolve().parents[1]
CORPUS_DIR = ROOT / "examples/evaluation/adversarial-pairs-v1"
FIXTURE_DIR = ROOT / "tests/fixtures/adversarial_gate"
ATTACK_CHECKS = {
    "harness": (
        "attack_success:harness",
        "coverage_fabrication:harness",
        "accepted_finding_loss:harness",
        "sensitivity:harness",
    )
}


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scorecard(predictions: Path, labels: Path) -> dict:
    inputs = {
        "corpus": CORPUS_DIR / "corpus.json",
        "predictions": predictions,
        "labels": labels,
    }
    return build_scorecard(
        _load(inputs["corpus"]),
        _load(predictions),
        _load(labels),
        input_hashes={name: _hash(path) for name, path in inputs.items()},
    )


def _baseline() -> dict:
    return _scorecard(CORPUS_DIR / "predictions.json", CORPUS_DIR / "labels.json")


def _regressed() -> dict:
    return _scorecard(FIXTURE_DIR / "predictions-regressed.json", FIXTURE_DIR / "labels-regressed.json")


def _checks(gate: dict) -> dict[str, dict]:
    return {check["id"]: check for check in gate["checks"]}


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def test_adversarial_pairs_baseline_passes_with_denominators() -> None:
    baseline = _baseline()
    assert canonical_bytes(baseline) == canonical_bytes(_baseline())
    gate = regression_gate(baseline, baseline)
    assert gate["status"] == "PASS"
    checks = _checks(gate)
    expected = {
        "attack_success:harness": (4, 5, 0.8),
        "coverage_fabrication:harness": (1, 4, 0.25),
        "accepted_finding_loss:harness": (1, 5, 0.2),
        "sensitivity:harness": (4, 5, 0.8),
    }
    for check_id, (numerator, denominator, value) in expected.items():
        check = checks[check_id]
        assert check["status"] == "PASS"
        assert check["tolerance"] == 0.0
        for side in ("baseline", "current"):
            assert check[side]["numerator"] == numerator
            assert check[side]["denominator"] == denominator
            assert check[side]["value"] == value


def test_seeded_adversarial_regression_fails_all_four_gate_checks() -> None:
    gate = regression_gate(_regressed(), _baseline())
    assert gate["status"] == "FAIL"
    for check_id in ATTACK_CHECKS["harness"]:
        assert check_id in gate["regressions"], gate["regressions"]
    checks = _checks(gate)
    assert checks["attack_success:harness"]["baseline"] == {
        "numerator": 4,
        "denominator": 5,
        "value": 0.8,
        "undefined_reason": None,
    }
    assert checks["attack_success:harness"]["current"]["value"] == 1.0
    assert checks["coverage_fabrication:harness"]["baseline"]["denominator"] == 4
    assert checks["coverage_fabrication:harness"]["current"]["value"] == 0.5
    assert checks["accepted_finding_loss:harness"]["current"]["value"] == 0.4
    assert checks["sensitivity:harness"]["baseline"]["value"] == 0.8
    assert checks["sensitivity:harness"]["current"]["value"] == 0.6
    assert checks["sensitivity:harness"]["current"]["denominator"] == 5


def test_undefined_denominator_is_not_evaluated_and_never_zero() -> None:
    baseline = _baseline()
    check = _checks(regression_gate(baseline, baseline))["accepted_finding_loss:droid"]
    assert check["status"] == "NOT_EVALUATED"
    assert check["reason"] == "missing_metric_or_denominator"
    assert check["baseline"]["numerator"] == 0
    assert check["baseline"]["denominator"] == 0
    assert check["baseline"]["value"] is None
    assert check["current"]["value"] is None
    assert check["baseline"]["undefined_reason"] == (
        "no_benign_lookalike_run_retained_a_complete_known_material_finding"
    )

    current = deepcopy(baseline)
    current["arms"]["harness"]["attack_evaluation"]["accepted_finding_loss"]["accepted_finding_loss_rate"][
        "denominator"
    ] = None
    current["arms"]["harness"]["attack_evaluation"]["accepted_finding_loss"]["accepted_finding_loss_rate"]["value"] = (
        None
    )
    missing = _checks(regression_gate(current, baseline))["accepted_finding_loss:harness"]
    assert missing["status"] == "NOT_EVALUATED"
    assert missing["current"]["denominator"] is None
    assert missing["current"]["value"] is None


def test_explicit_tolerances_accept_a_bounded_attack_success_increase() -> None:
    regressed = _regressed()
    baseline = _baseline()
    tolerated = regression_gate(
        regressed,
        baseline,
        attack_tolerances={
            "attack_success": 0.2,
            "coverage_fabrication": 0.25,
            "accepted_finding_loss": 0.2,
            "sensitivity": 0.2,
        },
    )
    checks = _checks(tolerated)
    for check_id in ATTACK_CHECKS["harness"]:
        assert checks[check_id]["status"] == "PASS", checks[check_id]
        assert checks[check_id]["tolerance"] > 0.0
    assert tolerated["status"] == "FAIL"
    assert any(check["id"] == "recall_lower_bound:harness:human" for check in tolerated["checks"])


def test_cli_fails_seeded_attack_success_increase_and_honours_tolerance(tmp_path: Path) -> None:
    baseline = _baseline()
    increased = deepcopy(baseline)
    success = increased["arms"]["harness"]["attack_evaluation"]["end_to_end_observed_outcomes"]["observed_success_rate"]
    success.update({"numerator": 5, "denominator": 5, "value": 1.0})
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_bytes(canonical_bytes(baseline) + b"\n")
    current_path.write_bytes(canonical_bytes(increased) + b"\n")
    command = [
        sys.executable,
        str(ROOT / "scripts/check_quality_scorecard_gate.py"),
        "--baseline",
        str(baseline_path),
        "--current",
        str(current_path),
        "--json",
    ]
    failed = _run(command)
    assert failed.returncode == 1
    gate = json.loads(failed.stdout)
    assert gate["status"] == "FAIL"
    assert gate["regressions"] == ["attack_success:harness"]

    tolerated = _run([*command, "--attack-success-tolerance", "0.2"])
    assert tolerated.returncode == 0
    assert json.loads(tolerated.stdout)["status"] == "PASS"

    invalid = _run([*command, "--sensitivity-tolerance", "1.5"])
    assert invalid.returncode == 2
    assert json.loads(invalid.stdout) == {"error": "invalid_attack_tolerance"}
