"""RS-4 supply-chain invariants: hash-locked dev deps and zero runtime deps.

These tests read repository metadata, the two lock artifacts, built wheel
metadata, and the security/test workflow definitions. They do not contact a
package index or run provider/target code except the local lock freshness command
(``scripts/check_dev_lock.py``), which skips when the pinned ``uv`` is not
installed in the test environment.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements-dev.lock"
UV_LOCK = ROOT / "uv.lock"
CHECK_SCRIPT = ROOT / "scripts" / "check_dev_lock.py"
SHA_PIN_RE = re.compile(r"^[0-9a-f]{40}$")

sys.path.insert(0, str(ROOT / "scripts"))

import check_dev_lock  # noqa: E402

DIRECT_DEV_REQUIREMENTS = {
    "build",
    "pytest",
    "pytest-cov",
    "ruff",
    "mypy",
    "setuptools",
    "pyjwt",
    "pyyaml",
    "jsonschema",
    "uv",
}


def _pyproject() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _project() -> dict[str, object]:
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    return project


def _exported_names() -> list[str]:
    return [check_dev_lock.normalise_name(requirement.name) for requirement in check_dev_lock.parse_requirements(REQUIREMENTS)]


def test_runtime_dependency_set_is_empty_in_project_metadata():
    project = _project()
    assert project["dependencies"] == [], "the harness must keep zero runtime dependencies"
    assert project["requires-python"] == ">=3.11"
    extras = project["optional-dependencies"]
    assert isinstance(extras, dict)
    assert set(extras) == {"dev", "github-app"}, "only explicit optional extras may declare dependencies"


def test_locked_dev_set_is_exactly_pinned_and_hash_verified():
    requirements = check_dev_lock.parse_requirements(REQUIREMENTS)
    assert len(requirements) == len({check_dev_lock.normalise_name(item.name) for item in requirements})
    assert len(requirements) >= len(DIRECT_DEV_REQUIREMENTS)
    for requirement in requirements:
        assert requirement.version
        assert re.fullmatch(r"[0-9][A-Za-z0-9.*+!-]*", requirement.version), requirement
        assert requirement.hashes, requirement
        assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in requirement.hashes), requirement
    assert set(_exported_names()) >= DIRECT_DEV_REQUIREMENTS
    project_name = check_dev_lock.normalise_name(str(_project()["name"]))
    assert project_name not in set(_exported_names()), "the lock must not install the project itself"
    text = REQUIREMENTS.read_text(encoding="utf-8")
    for forbidden in ("-e ", "--editable", "--index-url", "--extra-index-url", "--find-links", " @ "):
        assert forbidden not in text, f"requirements-dev.lock contains an unpinned directive: {forbidden!r}"


@pytest.mark.parametrize(
    "body",
    [
        "pytest>=8\n",
        "pytest==9.2.0\n",
        "-e .\n",
        "example-package @ https://example.com/example-1.0.whl\n",
    ],
)
def test_lock_parser_rejects_unpinned_unhashed_or_unhashed_directives(tmp_path: Path, body: str):
    path = tmp_path / "requirements-dev.lock"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(check_dev_lock.CheckFailure):
        check_dev_lock.parse_requirements(path)


def test_uv_lock_records_the_dev_extra_and_no_runtime_dependencies():
    lock = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    assert lock["version"] == 1
    assert lock["requires-python"] == ">=3.11"
    packages = {package["name"]: package for package in lock["package"]}
    project = packages[str(_project()["name"])]
    assert "dependencies" not in project, "uv.lock must record no runtime dependencies"
    metadata = project["metadata"]
    assert all("extra ==" in spec["marker"] for spec in metadata["requires-dist"]), metadata
    assert set(project["optional-dependencies"]) == {"dev", "github-app"}
    optional = {spec["name"] for spec in project["optional-dependencies"]["dev"]}
    assert {check_dev_lock.normalise_name(name) for name in optional} == DIRECT_DEV_REQUIREMENTS
    for name in _exported_names():
        assert any(check_dev_lock.normalise_name(package) == name for package in packages), f"{name} missing from uv.lock"


def test_built_wheel_declares_no_runtime_requirements(tmp_path: Path):
    if importlib.util.find_spec("build.__main__") is None:
        pytest.skip("the build frontend is not installed; the hash-locked dev set provides it")
    dist = tmp_path / "dist"
    completed = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(dist)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    wheels = sorted(dist.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    requires_dist = [line.split(": ", 1)[1] for line in metadata.splitlines() if line.startswith("Requires-Dist: ")]
    assert requires_dist, "extras must still be declared in the wheel metadata"
    runtime = [requirement for requirement in requires_dist if "extra ==" not in requirement]
    assert runtime == [], f"wheel declares runtime requirements: {runtime}"
    assert "Requires-Python: >=3.11" in metadata
    assert "Provides-Extra: dev" in metadata


@pytest.mark.skipif(importlib.util.find_spec("uv") is None, reason="pinned uv is not installed in this environment")
def test_dev_lock_is_fresh_and_reproducible(tmp_path: Path):
    env = dict(os.environ)
    env["UV_CACHE_DIR"] = str(tmp_path / "uv-cache")
    completed = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--json"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    result = json.loads(completed.stdout)
    assert completed.returncode == 0, result["failures"]
    assert result["status"] == "pass"
    assert result["uv_lock"]["sha256"]
    assert result["requirements"]["packages"] >= len(DIRECT_DEV_REQUIREMENTS)
    assert result["requirements"]["hashes"] > result["requirements"]["packages"]


def _workflow(name: str) -> dict[str, object]:
    import yaml

    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def _job_steps(job: dict[str, object]) -> list[dict[str, object]]:
    steps = job["steps"]
    assert isinstance(steps, list)
    return [step for step in steps if isinstance(step, dict)]


def test_test_workflow_installs_the_hash_locked_dev_set_for_tests_and_coverage():
    workflow = _workflow("test.yml")
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    for job_name in ("tests", "coverage", "compatibility"):
        runs = "\n".join(str(step.get("run", "")) for step in _job_steps(jobs[job_name]))
        assert "--require-hashes" in runs, job_name
        assert "-r requirements-dev.lock" in runs, job_name
        assert "--no-build-isolation" in runs, job_name
    lock_job = jobs["lock-freshness"]
    lock_runs = "\n".join(str(step.get("run", "")) for step in _job_steps(lock_job))
    assert "scripts/check_dev_lock.py" in lock_runs
    install_matrix = jobs["install-matrix"]
    matrix = install_matrix["strategy"]["matrix"]
    assert set(matrix["python-version"]) >= {"3.11", "3.14"}
    assert "ubuntu-latest" in matrix["os"]
    matrix_runs = "\n".join(str(step.get("run", "")) for step in _job_steps(install_matrix))
    assert "pr-review" in matrix_runs and "--help" in matrix_runs
    assert "importlib.metadata" in matrix_runs


def test_security_workflow_dependency_review_is_actionable_and_scan_is_scheduled_only():
    workflow = _workflow("security.yml")
    jobs = workflow["jobs"]
    review = jobs["dependency-review"]
    assert review["if"] == "${{ github.event_name == 'pull_request' && vars.DEPENDENCY_GRAPH_ENABLED == 'true' }}"
    review_text = json.dumps(review)
    assert "actions/dependency-review-action@" in review_text
    action_ref = re.search(r"actions/dependency-review-action@([0-9a-f]{40})", review_text)
    assert action_ref is not None, "dependency-review-action must be pinned to a full commit SHA"
    assert '"comment-summary-in-pr": "never"' in review_text
    assert "DEPENDENCY_GRAPH_ENABLED" in review_text
    guidance = jobs["dependency-review-guidance"]
    guidance_steps = _job_steps(guidance)
    guidance_text = json.dumps(guidance_steps)
    assert "DEPENDENCY_GRAPH_ENABLED" in guidance_text
    assert "GITHUB_STEP_SUMMARY" in guidance_text
    scan = jobs["vulnerability-scan"]
    assert scan["if"] == "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}"
    scan_runs = "\n".join(str(step.get("run", "")) for step in _job_steps(scan))
    assert "uv audit --locked" in scan_runs
    docs = (ROOT / "docs" / "SUPPORT-MATRIX.md").read_text(encoding="utf-8")
    assert "DEPENDENCY_GRAPH_ENABLED" in docs
    assert "gh variable set DEPENDENCY_GRAPH_ENABLED" in docs


@pytest.mark.parametrize("workflow_name", ["test.yml", "security.yml"])
def test_all_workflow_actions_are_pinned_to_full_commit_shas(workflow_name: str):
    workflow = _workflow(workflow_name)
    for job_name, job in workflow["jobs"].items():
        for step in _job_steps(job):
            uses = step.get("uses")
            if not uses:
                continue
            assert "@" in uses, f"{workflow_name}:{job_name}: action has no ref: {uses}"
            ref = uses.rsplit("@", 1)[1]
            assert SHA_PIN_RE.fullmatch(ref), f"{workflow_name}:{job_name}: action is not SHA-pinned: {uses}"
