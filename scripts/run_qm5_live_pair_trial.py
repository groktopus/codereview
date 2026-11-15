#!/usr/bin/env python3
"""Prepare one QM5 reciprocal pair without dispatching to a provider."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPOSITORY_ROOT / "src"), str(REPOSITORY_ROOT)]

from experiments.harness.qm5_live_pair_trial import PAIR_IDS, PreparationError, prepare_pair  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair-id", choices=PAIR_IDS, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.prepare_only:
        parser.error("live_execution_not_implemented; pass --prepare-only")
    try:
        result = prepare_pair(
            args.pair_id,
            output_dir=args.output_dir,
            source_revision=args.source_revision,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
        )
    except (PreparationError, OSError, ValueError) as exc:
        print(f"QM5 preparation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
