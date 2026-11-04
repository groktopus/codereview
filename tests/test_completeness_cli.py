"""CLI coverage for the completeness gate: inputs, summary, baseline, verdicts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/completeness"
sys.path.insert(0, str(ROOT / "scripts"))

import check_completeness as gate  # noqa: E402


def test_summary_only_text_and_json(capsys):
    assert gate.main(["--result", str(FIXTURES / "good-result.json"), "--summary-only"]) == 0
    assert "Completeness (" in capsys.readouterr().out

    assert gate.main(["--result", str(FIXTURES / "good-result.json"), "--summary-only", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "SUMMARY"
    assert payload["results"][0]["completeness_summary"]["schema"]

    assert gate.main(["--result", str(FIXTURES / "good-result.json"), "--summary-only", "--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_write_baseline_from_results(tmp_path, capsys):
    target = tmp_path / "baseline.json"
    code = gate.main(
        [
            "--result",
            str(FIXTURES / "good-result.json"),
            "--write-baseline",
            str(target),
            "--corpus-name",
            "unit",
            "--corpus-provenance",
            "fixture",
        ]
    )
    assert code == 0
    baseline = json.loads(target.read_text())
    assert baseline["schema"]
    assert baseline["corpus"]["name"] == "unit"


def test_results_dir_and_manifest_inputs(tmp_path, capsys):
    directory = tmp_path / "results"
    directory.mkdir()
    (directory / "one.json").write_text((FIXTURES / "good-result.json").read_text())
    assert gate.main(["--results-dir", str(directory), "--summary-only", "--quiet"]) == 0

    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"results": ["results/one.json"]}))
    assert gate.main(["--results-manifest", str(manifest), "--summary-only", "--quiet"]) == 0


def test_input_errors_exit_two(tmp_path, capsys):
    assert gate.main([]) == 2
    assert "no result inputs" in capsys.readouterr().err
    assert gate.main(["--results-dir", str(tmp_path / "missing"), "--summary-only"]) == 2
    assert "does not exist" in capsys.readouterr().err

    bad_manifest = tmp_path / "bad.json"
    bad_manifest.write_text(json.dumps({"results": "not-a-list"}))
    assert gate.main(["--results-manifest", str(bad_manifest), "--summary-only"]) == 2
    assert "results array" in capsys.readouterr().err

    bad_result = tmp_path / "bad-result.json"
    bad_result.write_text("{not json")
    assert gate.main(["--result", str(bad_result), "--summary-only"]) == 2
    assert "cannot read input" in capsys.readouterr().err

    array_result = tmp_path / "array.json"
    array_result.write_text("[]")
    assert gate.main(["--result", str(array_result), "--summary-only"]) == 2
    assert "JSON object" in capsys.readouterr().err


def test_compare_pass_fail_and_json(capsys):
    baseline = str(FIXTURES / "baseline.v1.json")
    good = str(FIXTURES / "good-result.json")
    assert gate.main(["--baseline", baseline, "--result", good]) == 0
    assert "PASS" in capsys.readouterr().out

    assert gate.main(["--baseline", baseline, "--result", good, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"

    seeded = str(FIXTURES / "seeded-regression-result.json")
    assert gate.main(["--baseline", baseline, "--result", seeded]) == 1
    assert "FAIL" in capsys.readouterr().out
