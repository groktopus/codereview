"""Contract tests for the CI coverage ratchet and its rendered summary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "scripts" / "coverage_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("coverage_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _report(**modules: tuple[int, int]) -> dict:
    files = {
        f"/checkout/src/pr_review_harness/{name}": {
            "summary": {
                "covered_lines": covered,
                "num_statements": statements,
                "percent_covered": 100.0 * covered / statements,
            }
        }
        for name, (covered, statements) in modules.items()
    }
    covered = sum(value[0] for value in modules.values())
    statements = sum(value[1] for value in modules.values())
    return {
        "totals": {
            "covered_lines": covered,
            "num_statements": statements,
            "percent_covered": 100.0 * covered / statements,
        },
        "files": files,
    }


def test_gate_enforces_the_declared_critical_modules_and_targets():
    assert set(gate.CRITICAL_MODULES) == {
        "github.py",
        "publisher.py",
        "checks.py",
        "actions_publication.py",
        "cli.py",
    }
    assert gate.TARGET_OVERALL == 85.0
    assert gate.TARGET_CRITICAL == 90.0
    assert set(gate.FLOORS) == {"overall", *gate.CRITICAL_MODULES}


def test_gate_measures_overall_and_each_module_from_coverage_json():
    report = _report(
        **{
            "github.py": (90, 100),
            "publisher.py": (80, 100),
            "checks.py": (95, 100),
            "actions_publication.py": (85, 100),
            "cli.py": (70, 100),
        }
    )
    measured = gate.collect_measurements(report)
    assert measured["overall"]["percent"] == pytest.approx(84.0)
    assert measured["github.py"]["percent"] == pytest.approx(90.0)
    assert measured["publisher.py"]["covered"] == 80
    assert measured["publisher.py"]["statements"] == 100


def test_gate_fails_exactly_the_modules_below_their_floor():
    measured = gate.collect_measurements(
        _report(
            **{
                "github.py": (89, 100),
                "publisher.py": (80, 100),
                "checks.py": (95, 100),
                "actions_publication.py": (85, 100),
                "cli.py": (70, 100),
            }
        )
    )
    floors = {
        "overall": 50.0,
        "github.py": 90.0,
        "publisher.py": 80.0,
        "checks.py": 95.0,
        "actions_publication.py": 85.0,
        "cli.py": 70.0,
    }
    rows = gate.evaluate(measured, floors)
    failed = [row["module"] for row in rows if not row["passed"]]
    assert failed == ["github.py"]


def test_gate_fails_a_missing_critical_module_instead_of_skipping_it():
    measured = gate.collect_measurements(_report(**{"github.py": (90, 100)}))
    rows = gate.evaluate(measured, {"overall": 0.0, "publisher.py": 70.0})
    assert rows[1]["passed"] is False
    assert rows[1]["missing"] is True
    assert "MISSING" in gate.render_markdown(rows)


def test_gate_summary_renders_a_row_per_module_with_targets_and_status():
    measured = gate.collect_measurements(
        _report(
            **{
                "github.py": (61, 100),
                "publisher.py": (71, 100),
                "checks.py": (74, 100),
                "actions_publication.py": (78, 100),
                "cli.py": (76, 100),
            }
        )
    )
    rows = gate.evaluate(measured, {"overall": 85.0, "github.py": 61.0})
    table = gate.render_markdown(rows)
    assert "| `overall` |" in table
    assert "| `github.py` | 61 | 100 | 61.00% | 61.00% | 90% | PASS |" in table
    assert "**Coverage gate failed:** `overall`" in table


def test_gate_main_returns_nonzero_below_floor_and_writes_the_job_summary(tmp_path, capsys):
    report = _report(**{"github.py": (89, 100)})
    coverage_json = tmp_path / "coverage.json"
    coverage_json.write_text(json.dumps(report), encoding="utf-8")
    summary = tmp_path / "summary.md"
    code = gate.main(
        [
            "--coverage-json",
            str(coverage_json),
            "--summary",
            str(summary),
            "--no-summary-env",
        ]
    )
    # Every declared module except the one fixture module is absent, so the
    # gate must fail rather than silently skip the unexplained modules.
    assert code == 1
    assert "MISSING" in summary.read_text(encoding="utf-8")
    assert "coverage gate:" in capsys.readouterr().err


def test_gate_main_fails_closed_when_the_coverage_report_is_missing(tmp_path):
    code = gate.main(["--coverage-json", str(tmp_path / "absent.json"), "--no-summary-env"])
    assert code == 2
