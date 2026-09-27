#!/usr/bin/env python3
"""Run a provider-free installed CLI help command under the Linux observer."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.external_effect_observer import observe_cli, preflight  # noqa: E402


def main() -> int:
    identity = preflight()
    cli = shutil.which("pr-review")
    if identity.get("status") != "AVAILABLE" or cli is None:
        raise SystemExit("effect_observer_preflight_unavailable")
    with tempfile.TemporaryDirectory(prefix="effect-observer-help-") as temporary:
        result = observe_cli([cli, "--help"], cwd=Path(temporary), env=os.environ.copy(), timeout_seconds=15)
    observer = result.get("observer", {})
    invocation = result.get("invocation", {})
    if observer.get("coverage") != "SCOPED_COMPLETE" or invocation.get("run_status") not in {
        "CLI_COMPLETED",
        "INVALID_CLI_OUTPUT",
    }:
        raise SystemExit("effect_observer_installed_cli_help_incomplete")
    if not observer.get("root_exec_evidence") or observer.get("event_count", 0) < 1:
        raise SystemExit("effect_observer_root_exec_evidence_missing")
    summary = {
        "smoke": "INSTALLED_CLI_HELP_COMPLETED",
        "observer_id": observer.get("observer_id"),
        "overall_state": observer.get("overall_state"),
        "coverage": observer.get("coverage"),
        "channel_state": observer.get("channel_state"),
        "event_count": observer.get("event_count"),
        "trace_bytes": observer.get("trace_bytes"),
        "strace_version": observer.get("strace_version"),
        "strace_executable_sha256": observer.get("strace_executable_sha256"),
        "observer_source_sha256": observer.get("source_sha256"),
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
