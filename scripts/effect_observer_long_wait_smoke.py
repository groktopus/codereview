#!/usr/bin/env python3
"""Run a bounded 75-second fake-provider response through the installed CLI observer.

This dedicated Linux probe keeps the ordinary short observer smoke unchanged. It
configures a loopback fake provider and does not request external provider dispatch.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.external_effect_observer import OBSERVER_ID, SYSCALL_SCOPE, TRACE_MAX_BYTES  # noqa: E402
from scripts.effect_observer_smoke import (  # noqa: E402
    LONG_WAIT_ENGINE_DEADLINE_SECONDS,
    LONG_WAIT_OBSERVER_TIMEOUT_SECONDS,
    LONG_WAIT_PROVIDER_DELAY_SECONDS,
    LONG_WAIT_PROVIDER_TIMEOUT_SECONDS,
    _full_review_smoke,
    preflight,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, help="installed pr-review executable; defaults to current environment")
    args = parser.parse_args(argv)
    cli = args.cli or Path(sysconfig.get_path("scripts")) / ("pr-review.exe" if os.name == "nt" else "pr-review")
    identity = preflight()
    if identity.get("status") != "AVAILABLE" or not cli.is_file() or not os.access(cli, os.X_OK):
        print(json.dumps({"status": "UNAVAILABLE", "reason": "installed_cli_or_observer_unavailable"}, separators=(",", ":")))
        return 2
    result = _full_review_smoke(
        cli,
        response_delay_seconds=LONG_WAIT_PROVIDER_DELAY_SECONDS,
        engine_deadline_seconds=LONG_WAIT_ENGINE_DEADLINE_SECONDS,
        provider_timeout_seconds=LONG_WAIT_PROVIDER_TIMEOUT_SECONDS,
        observer_timeout_seconds=LONG_WAIT_OBSERVER_TIMEOUT_SECONDS,
    )
    payload = {
        "probe": "INSTALLED_CLI_LONG_FAKE_RESPONSE",
        "observer_source_sha256": identity.get("source_sha256")
        if isinstance(identity.get("source_sha256"), str)
        else "UNKNOWN",
        "observer_id": OBSERVER_ID,
        "strace_version": identity.get("version") if isinstance(identity.get("version"), str) else "UNKNOWN",
        "strace_executable_sha256": identity.get("executable_sha256")
        if isinstance(identity.get("executable_sha256"), str)
        else "UNKNOWN",
        "syscall_scope": list(SYSCALL_SCOPE),
        "trace_byte_cap": TRACE_MAX_BYTES,
        "provider_calls_max": 8,
        "retry_limit": 0,
        "max_concurrent_scopes": 4,
        "target_execution_marker_present": result.get("target_execution_marker_present")
        if isinstance(result.get("target_execution_marker_present"), bool)
        else False
        if result.get("status") == "NORMAL_REVIEW_COMPLETED"
        else None,
        "provider_endpoint_kind": "LOOPBACK_FAKE",
        "external_provider_dispatch_requested": False,
        "result": result,
    }
    status = result.get("status")
    payload["status"] = "COMPLETED" if status == "NORMAL_REVIEW_COMPLETED" else "FAILED_OR_INCOMPLETE"
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if status == "NORMAL_REVIEW_COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
