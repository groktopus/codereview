"""Execute the checked-in provider-free adversarial workflow steps, not replicas."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path("examples/evaluation/adversarial-pairs-v1")
ATTACK_CHECKS = {
    "attack_success:harness",
    "coverage_fabrication:harness",
    "accepted_finding_loss:harness",
    "sensitivity:harness",
}
WORKFLOW_STEPS = (
    (
        "test.yml",
        "quality-scorecard",
        "Gate adversarial-pairs-v1 and prove a seeded adversarial regression fails",
        "adversarial-gate.json",
    ),
    (
        "quality-scorecard-schedule.yml",
        "scorecard",
        "Gate the adversarial-pairs-v1 baseline",
        "adversarial-pairs-gate.json",
    ),
)


def _step(workflow: str, job: str, name: str) -> str:
    document = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8"))
    matches = [step for step in document["jobs"][job]["steps"] if step.get("name") == name]
    assert len(matches) == 1
    return matches[0]["run"]


def _prepare(root: Path) -> dict[str, str]:
    # Copy only the deterministic evaluator/CLI and authored fixture inputs.
    for relative in (
        "scripts/generate_quality_scorecard.py",
        "scripts/check_quality_scorecard_gate.py",
        "experiments/harness/__init__.py",
        "experiments/harness/evaluation.py",
        "experiments/harness/scorecard.py",
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for relative in (CORPUS, Path("tests/fixtures/adversarial_gate")):
        shutil.copytree(ROOT / relative, root / relative)
    binaries = root / "bin"
    binaries.mkdir()
    (binaries / "python").symlink_to(sys.executable)
    # Do not pass provider credentials, endpoint configuration, or user startup files.
    return {
        "PATH": os.pathsep.join((str(binaries), os.defpath)),
        "HOME": str(root),
        "TMPDIR": str(root),
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
    }


def _execute(step: str, root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("GitHub Actions bash step requires bash")
    return subprocess.run(
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize("workflow,job,name,gate_file", WORKFLOW_STEPS)
def test_exact_adversarial_workflow_step_passes_and_checks_seeded_regression(
    tmp_path: Path, workflow: str, job: str, name: str, gate_file: str
) -> None:
    env = _prepare(tmp_path)
    result = _execute(_step(workflow, job, name), tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    gate = json.loads((tmp_path / gate_file).read_text(encoding="utf-8"))
    assert gate["status"] == "PASS"
    checks = {check["id"]: check for check in gate["checks"]}
    for check_id in ATTACK_CHECKS:
        assert checks[check_id]["status"] == "PASS"
        assert checks[check_id]["current"]["denominator"] > 0
    assert checks["accepted_finding_loss:droid"]["status"] == "NOT_EVALUATED"
    assert checks["accepted_finding_loss:droid"]["current"]["value"] is None
    if workflow == "test.yml":
        # The exact step checks exit 1 before accepting these seeded FAIL checks.
        regressed = json.loads((tmp_path / "adversarial-regressed-gate.json").read_text(encoding="utf-8"))
        assert regressed["status"] == "FAIL"
        assert ATTACK_CHECKS <= set(regressed["regressions"])
        regressed_checks = {check["id"]: check for check in regressed["checks"]}
        assert all(regressed_checks[check_id]["status"] == "FAIL" for check_id in ATTACK_CHECKS)


@pytest.mark.parametrize("workflow,job,name,gate_file", WORKFLOW_STEPS)
def test_exact_adversarial_workflow_cmp_rejects_modified_checked_in_baseline(
    tmp_path: Path, workflow: str, job: str, name: str, gate_file: str
) -> None:
    env = _prepare(tmp_path)
    baseline = tmp_path / CORPUS / "scorecard.json"
    # Semantically identical JSON must still fail the byte-for-byte cmp ratchet.
    baseline.write_bytes(baseline.read_bytes() + b"\n")
    result = _execute(_step(workflow, job, name), tmp_path, env)
    assert result.returncode == 1, result.stdout + result.stderr
    diagnostic = result.stdout + result.stderr
    assert "differ" in diagnostic or "EOF" in diagnostic, diagnostic
    assert not (tmp_path / gate_file).exists(), "baseline cmp must stop execution before the gate"
