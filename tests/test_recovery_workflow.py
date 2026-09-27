from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/test.yml"
UPLOAD_ARTIFACT_ACTION = "ea165f8d65b6e75b540449e92b4886f43607fa02"


def _job(source: str, name: str) -> str:
    jobs = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", source))
    selected = next(match for match in jobs if match.group(1) == name)
    end = next((match.start() for match in jobs if match.start() > selected.start()), len(source))
    return source[selected.start() : end]


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


def test_installed_wheel_recovery_runs_against_same_matrix_cli_and_retains_outputs():
    source = WORKFLOW.read_text(encoding="utf-8")
    job = _job(source, "installed-wheel")
    run = _step(job, "Run installed CLI recovery rehearsal with local fakes")
    upload = _step(job, "Retain bounded recovery rehearsal evidence")
    smoke = _step(job, "Install wheel in a fresh environment and smoke it outside the checkout")

    assert "python-version: ['3.11', '3.14']" in job
    assert "timeout-minutes: 10" in job
    assert job.index(smoke) < job.index(run) < job.index(upload)
    assert '"$WHEEL_ENV/bin/python" scripts/run_recovery_rehearsal.py' in run
    assert '--cli "$WHEEL_ENV/bin/pr-review"' in run
    assert '--output-dir "$RECOVERY_OUTPUT_DIR"' in run
    assert "RECOVERY_OUTPUT_DIR: ${{ runner.temp }}/pr-review-recovery-${{ matrix.python-version }}" in run
    assert "secrets." not in job
    assert "OPENAI_API_KEY" not in job and "GITHUB_TOKEN" not in job

    assert "if: always()" in upload
    assert f"uses: actions/upload-artifact@{UPLOAD_ARTIFACT_ACTION}" in upload
    assert "name: pr-review-recovery-${{ github.run_id }}-${{ matrix.python-version }}" in upload
    assert "recovery-rehearsal-summary.json" in upload
    assert "/artifacts/" in upload
    assert "retention-days: 7" in upload
    assert "if-no-files-found: warn" in upload
    assert "${{ runner.temp }}/" in upload
    assert "path: ${{ runner.temp }}" not in upload
