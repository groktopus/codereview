#!/usr/bin/env python3
"""Prepare or run the opt-in two-case configured Jev injection diagnostic."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from pr_review_harness.configured_jev_injection_trial import (  # noqa: E402
    ConfiguredJevTrialError,
    prepare_trial,
    run_trial,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--run-provider-trial", action="store_true")
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli-executable", type=Path, required=True)
    parser.add_argument("--preparation", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.prepare_only:
            if args.preparation is not None:
                raise ConfiguredJevTrialError("preparation_argument_unexpected")
            summary = prepare_trial(
                root=ROOT,
                cli_executable=args.cli_executable,
                expected_source_revision=args.expected_source_revision,
                output=args.output,
            )
        else:
            if args.preparation is None:
                raise ConfiguredJevTrialError("preparation_required")
            summary = run_trial(
                root=ROOT,
                cli_executable=args.cli_executable,
                expected_source_revision=args.expected_source_revision,
                preparation=args.preparation,
                output=args.output,
            )
    except ConfiguredJevTrialError as exc:
        print(f"configured_jev_injection_trial: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("configured_jev_injection_trial: failed", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
