import hashlib
import json
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_distribution_declares_supported_python_and_entry_point():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    metadata = project["project"]
    assert metadata["requires-python"] == ">=3.11"
    assert all(
        f"Programming Language :: Python :: {version}" in metadata["classifiers"]
        for version in ("3.11", "3.12", "3.13", "3.14")
    )
    assert metadata["scripts"]["pr-review"] == "pr_review_harness.cli:main"


def test_wheel_smoke_refuses_a_cli_outside_its_install_environment(tmp_path):
    fake_cli = tmp_path / "pr-review"
    fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_cli.chmod(0o755)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/package_smoke.py"), "--cli", str(fake_cli)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 1
    assert json.loads(completed.stderr) == {
        "error": "installed_cli_not_in_current_environment",
        "status": "failed",
    }


def test_reusable_pr_workflow_pins_harness_before_installing_and_never_checks_out_target():
    workflow = (ROOT / ".github/workflows/pr-analysis.yml").read_text(encoding="utf-8")
    preflight = workflow.index("Reject mutable or malformed harness and target identities before checkout")
    checkout = workflow.index("Check out the separately pinned trusted harness and profiles")
    verify = workflow.index("Verify exact harness commit before installing or importing it")
    install = workflow.index("python -m pip install .")
    acquire = workflow.index("Validate pinned source and PR identity, then acquire bare target objects")
    assert preflight < checkout < verify < install < acquire
    assert "git', 'check-ref-format', 'refs/heads/' + base_ref" in workflow[:checkout]
    assert "repository: ${{ inputs.harness_repository }}" in workflow
    assert "ref: ${{ inputs.harness_sha }}" in workflow
    assert "'git', 'init', '--bare'" in workflow
    assert "actions/checkout" not in workflow[acquire:]
    assert "git checkout" not in workflow
    assert "pull_request_target:" not in workflow


def test_manual_historical_workflow_exposes_only_explicit_free_model_choices():
    workflow = (ROOT / ".github/workflows/review-commits.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "- solar" in workflow and "- stepfun" in workflow
    assert '--model "$TEST_MODEL"' in workflow
    assert "historical-pilot-v1" in workflow
    assert "--matrix-timeout-seconds 1300" in workflow


def test_built_source_archive_contains_authored_source_test_support_without_polluting_wheel(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--wheel",
            "--outdir",
            str(dist),
            str(ROOT),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]

    sdists = list(dist.glob("*.tar.gz"))
    wheels = list(dist.glob("*.whl"))
    assert len(sdists) == len(wheels) == 1
    with tarfile.open(sdists[0], "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        root_prefix = sdists[0].name.removesuffix(".tar.gz")
        expected = {
            "MANIFEST.in",
            "docs/PACKAGING-VERIFICATION.md",
            ".github/workflows/pr-analysis.yml",
            ".github/workflows/review-commits.yml",
            "scripts/package_smoke.py",
            "scripts/evaluate_reviews.py",
            "scripts/run_injection_trials.py",
            "scripts/run_test_matrix.py",
            "scripts/actions-artifact-uploader/action.yml",
            "scripts/actions-artifact-uploader/canary.mjs",
            "scripts/actions-artifact-uploader/upload.mjs",
            "scripts/actions-artifact-uploader/package.json",
            "scripts/actions-artifact-uploader/package-lock.json",
            "examples/injection/fixture-suite.v1.json",
            "examples/injection/fixture-suite.v2.json",
            "examples/evaluation/corpus.json",
            "examples/evaluation/predictions.json",
            "examples/evaluation/labels.json",
            "examples/provider.nous-test-solar.json",
            "examples/provider.nous-test-stepfun.json",
            "profiles/generic.json",
            "profiles/slopsearx.json",
            "profiles/targets.json",
            "scripts/resolve_target_profile.py",
            "tests/test_checks.py",
            "tests/test_injection_trials.py",
            "tests/test_test_matrix.py",
            "tests/test_packaging.py",
            "tests/fixtures/pr464-check-evidence.json",
        }
        archived_paths = {
            name.removeprefix(f"{root_prefix}/") for name in members if name.startswith(f"{root_prefix}/")
        }
        assert expected <= archived_paths
        assert not any("/artifacts/" in name for name in members)
        assert not any("node_modules" in name.split("/") for name in archived_paths)
        assert not any(
            path_part.lower().startswith(".env")
            or path_part.lower() in {"credentials", "credentials.json", "secrets", "secrets.json", "runtime-secrets"}
            or path_part.lower().endswith((".pem", ".key", ".p12", ".pfx"))
            for name in archived_paths
            for path_part in name.split("/")
        )
        assert not any(
            path_part in {"build", "dist", "__pycache__"} for name in archived_paths for path_part in name.split("/")
        )

        bridge_files = {
            "scripts/actions-artifact-uploader/action.yml",
            "scripts/actions-artifact-uploader/canary.mjs",
            "scripts/actions-artifact-uploader/upload.mjs",
            "scripts/actions-artifact-uploader/package.json",
            "scripts/actions-artifact-uploader/package-lock.json",
        }
        for relative_path in bridge_files:
            archived_file = archive.extractfile(members[f"{root_prefix}/{relative_path}"])
            assert archived_file is not None
            assert archived_file.read() == (ROOT / relative_path).read_bytes()

        fixture_name = f"{root_prefix}/tests/fixtures/pr464-check-evidence.json"
        fixture_file = archive.extractfile(members[fixture_name])
        assert fixture_file is not None
        fixture_bytes = fixture_file.read()
        fixture = json.loads(fixture_bytes)
        assert len(fixture["runs"]) == 20
        assert len({run["id"] for run in fixture["runs"]}) == 20
        assert fixture["fixture_provenance"]["source_capture_sha256"]
        assert (
            hashlib.sha256(fixture_bytes).digest()
            == hashlib.sha256((ROOT / "tests/fixtures/pr464-check-evidence.json").read_bytes()).digest()
        )

    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_paths = set(archive.namelist())
    assert not any(path.startswith(("tests/", "examples/", "profiles/", "scripts/", "docs/")) for path in wheel_paths)
