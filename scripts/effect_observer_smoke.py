#!/usr/bin/env python3
"""Measure installed review preparation through the bounded Linux observer."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.external_effect_observer import observe_cli, preflight  # noqa: E402


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def main() -> int:
    identity = preflight()
    cli = shutil.which("pr-review")
    if identity.get("status") != "AVAILABLE" or cli is None:
        raise SystemExit("effect_observer_preflight_unavailable")
    with tempfile.TemporaryDirectory(prefix="effect-observer-prepare-") as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        _git(repo, "config", "user.email", "observer-smoke@example.invalid")
        _git(repo, "config", "user.name", "Observer Smoke")
        target = repo / "src" / "example.py"
        target.parent.mkdir()
        target.write_text("def value():\n    return 1\n", encoding="utf-8")
        _git(repo, "add", "src/example.py")
        _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD")
        target.write_text("def value():\n    return 2\n", encoding="utf-8")
        _git(repo, "add", "src/example.py")
        _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
        head = _git(repo, "rev-parse", "HEAD")

        profile = root / "profile.json"
        profile.write_text(
            json.dumps({"version": "effect-observer-smoke-v1", "required_lenses": ["correctness"]}),
            encoding="utf-8",
        )
        provider = root / "provider.json"
        provider.write_text(
            json.dumps(
                {
                    "kind": "openai_compatible",
                    "base_url": "https://provider.example.invalid/v1",
                    "model": "observer-smoke-model",
                    "api_key_env": "OBSERVER_SMOKE_PROVIDER_KEY",
                }
            ),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["OBSERVER_SMOKE_PROVIDER_KEY"] = "synthetic-canary-never-send"
        result = observe_cli(
            [
                cli,
                "review",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--profile",
                str(profile),
                "--provider-config",
                str(provider),
                "--output",
                str(root / "output"),
                "--prepare-only",
                "--json",
            ],
            cwd=root,
            env=env,
            timeout_seconds=30,
        )

    observed = result.get("observer", {})
    invocation = result.get("invocation", {})
    cli_result = result.get("cli_result") or {}
    if (
        observed.get("observer_id") != "linux-strace-syscall-observer.v2"
        or
        observed.get("coverage") != "SCOPED_COMPLETE"
        or invocation.get("run_status") != "CLI_COMPLETED"
        or cli_result.get("status") != "PREPARED_ONLY"
        or cli_result.get("no_provider_calls") is not True
        or cli_result.get("no_target_code_execution") is not True
    ):
        raise SystemExit("effect_observer_installed_prepare_incomplete")
    if "synthetic-canary-never-send" in json.dumps(result, sort_keys=True):
        raise SystemExit("effect_observer_smoke_secret_redaction_failed")
    summary = {
        "smoke": "INSTALLED_CLI_PREPARE_ONLY_COMPLETED",
        "observer_id": observed.get("observer_id"),
        "overall_state": observed.get("overall_state"),
        "coverage": observed.get("coverage"),
        "channel_state": observed.get("channel_state"),
        "event_count": observed.get("event_count"),
        "event_sample_count": observed.get("event_sample_count"),
        "event_sample_truncated": observed.get("event_sample_truncated"),
        "event_aggregates_complete": observed.get("event_aggregates_complete"),
        "trace_bytes": observed.get("trace_bytes"),
        "strace_version": observed.get("strace_version"),
        "strace_executable_sha256": observed.get("strace_executable_sha256"),
        "observer_source_sha256": observed.get("source_sha256"),
        "no_provider_calls": cli_result["no_provider_calls"],
        "no_target_code_execution": cli_result["no_target_code_execution"],
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
