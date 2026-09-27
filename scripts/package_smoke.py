#!/usr/bin/env python3
"""Exercise an installed wheel entry point from a temporary external directory."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


def _run(command: list[str], *, cwd: Path, env: dict[str, str], expected: int = 0) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("package_smoke_subprocess_failed") from None
    if result.returncode != expected:
        raise RuntimeError(f"package_smoke_exit_mismatch:{expected}:{result.returncode}")
    return result


def _git(repo: Path, *args: str, cwd: Path, env: dict[str, str]) -> str:
    return _run(["git", "-C", str(repo), *args], cwd=cwd, env=env).stdout.strip()


def _write_fixture(root: Path, env: dict[str, str]) -> tuple[Path, str, str, Path]:
    repo = root / "fixture.git"
    _run(["git", "init", str(repo)], cwd=root, env=env)
    _git(repo, "config", "user.name", "Package Smoke", cwd=root, env=env)
    _git(repo, "config", "user.email", "package-smoke@example.invalid", cwd=root, env=env)
    source = repo / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "sample.py", cwd=root, env=env)
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base", cwd=root, env=env)
    base = _git(repo, "rev-parse", "HEAD", cwd=root, env=env)
    source.write_text("VALUE = 2\n", encoding="utf-8")
    _git(repo, "add", "sample.py", cwd=root, env=env)
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head", cwd=root, env=env)
    head = _git(repo, "rev-parse", "HEAD", cwd=root, env=env)
    profile = root / "profile.json"
    profile.write_text(json.dumps({"version": "wheel-smoke-v1", "context_paths": []}), encoding="utf-8")
    return repo, base, head, profile


def smoke(cli: Path) -> dict[str, str]:
    cli = cli.resolve(strict=True)
    scripts_dir = Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")
    if cli.parent != scripts_dir.resolve():
        raise RuntimeError("installed_cli_not_in_current_environment")
    from pr_review_harness.selected_model_trial import _case_result_summary

    with tempfile.TemporaryDirectory(prefix="pr-review-wheel-smoke-") as temp:
        root = Path(temp).resolve()
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("GITHUB_EVENT_PATH", None)
        env.pop("GH_TOKEN", None)
        help_result = _run([str(cli), "--help"], cwd=root, env=env)
        if "review" not in help_result.stdout or help_result.stderr:
            raise RuntimeError("installed_cli_help_invalid")

        repo, base, head, profile = _write_fixture(root, env)
        preview = _run(
            [
                str(cli),
                "review",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--profile",
                str(profile),
                "--dry-run",
                "--json",
            ],
            cwd=root,
            env=env,
        )
        preview_data = json.loads(preview.stdout)
        if preview_data.get("base") != base or preview_data.get("head") != head:
            raise RuntimeError("installed_cli_dry_run_invalid")

        rejected = _run(
            [
                str(cli),
                "review",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--profile",
                str(profile),
                "--effect-policy",
                "PUBLISH_REVIEW",
                "--json",
            ],
            cwd=root,
            env=env,
            expected=2,
        )
        if json.loads(rejected.stdout).get("error") != "PUBLISH_REVIEW is disabled":
            raise RuntimeError("installed_cli_read_only_gate_invalid")

        reviewed = _run(
            [
                str(cli),
                "review",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--profile",
                str(profile),
                "--run-id",
                "wheel-smoke",
                "--output",
                str(root / "artifacts"),
                "--json",
            ],
            cwd=root,
            env=env,
        )
        result = json.loads(reviewed.stdout)
        artifact = Path(result.get("artifact_path", ""))
        report = Path(result.get("report_path", ""))
        if result.get("run_id") != "wheel-smoke" or not artifact.is_file() or not report.is_file():
            raise RuntimeError("installed_cli_provider_free_report_missing")
        if not artifact.resolve().is_relative_to(root) or not report.resolve().is_relative_to(root):
            raise RuntimeError("installed_cli_wrote_outside_smoke_directory")
        durable_result = json.loads(artifact.read_text(encoding="utf-8"))
        smoke_case = SimpleNamespace(
            case_id="installed-wheel-provider-free-smoke",
            variant={"kind": "provider_free_smoke", "vector": None},
            snapshot={"snapshot_id": durable_result.get("snapshot_id"), "snapshot_hash": None},
            base_sha=base,
            head_sha=head,
            anchor={
                "label_id": "no-oracle-package-smoke",
                "oracle_sha256": "0" * 64,
                "unit_id": "not-an-observed-unit",
                "path": "sample.py",
                "side": "HEAD",
                "line": 1,
                "evidence_refs": [],
            },
        )
        projected = _case_result_summary(
            durable_result,
            smoke_case,
            {"result_sha256": "0" * 64, "result_bytes": artifact.stat().st_size},
            raw_output_secret_match=False,
            canary_match=False,
            expected_profile_id=durable_result.get("project_profile_version"),
            expected_profile_hash=None,
        )
        if not projected["result_integrity_valid"] or not projected["result_identity_match"]:
            raise RuntimeError("installed_cli_durable_result_projection_invalid")
        if not projected["claim_projection_valid"]:
            raise RuntimeError("installed_cli_empty_claim_projection_invalid")
        if projected["snapshot_content_binding"] != "UNKNOWN_NO_CLAIM_PROVENANCE":
            raise RuntimeError("installed_cli_snapshot_provenance_overstated")
        return {
            "status": "passed",
            "python": sys.version.split()[0],
            "cli": str(cli),
            "provider_free_disposition": str(result.get("disposition", result.get("status", "UNKNOWN"))),
            "durable_result_projection": "passed",
            "claim_content_provenance": projected["snapshot_content_binding"],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, help="installed pr-review executable from the wheel environment")
    args = parser.parse_args(argv)
    try:
        result = smoke(Path(args.cli))
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        code = (
            str(exc)
            if str(exc).startswith("package_smoke_") or str(exc).startswith("installed_cli_")
            else "package_smoke_failed"
        )
        print(json.dumps({"status": "failed", "error": code}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
