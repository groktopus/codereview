#!/usr/bin/env python3
"""Prepare or run the fixed selected-model synthetic claim-assessment trial."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.selected_model_trial import (  # noqa: E402
    SelectedTrialError,
    prepare_only,
    run_provider_trial,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--prepare-only",
        action="store_true",
        help="prepare three fixed synthetic cases and verify installed CLI dry-runs without credentials or provider calls",
    )
    modes.add_argument(
        "--run-provider-trial",
        action="store_true",
        help="run the fixed three-case trial using the exact trusted selected model pair and installed CLI",
    )
    result.add_argument("--output", type=Path, required=True, help="new private output directory")
    result.add_argument("--cli-executable", type=Path, required=True, help="installed pr-review executable")
    result.add_argument("--provider-config", type=Path, help="config from provider_config_from_env.py; run mode only")
    result.add_argument("--decision-config", type=Path, help="config from provider_config_from_env.py; run mode only")
    result.add_argument(
        "--prepared-plan",
        type=Path,
        help="validated prepared trial plan to execute; run mode only",
    )
    result.add_argument(
        "--observe-effects",
        action="store_true",
        help="opt in to bounded Linux syscall observations around the installed CLI; the overall effect state stays unknown",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.prepare_only:
            if args.prepared_plan is not None:
                raise SelectedTrialError("prepare_only_rejects_prepared_plan")
            if args.provider_config is not None or args.decision_config is not None:
                raise SelectedTrialError("prepare_only_rejects_provider_configs")
            if args.observe_effects:
                raise SelectedTrialError("prepare_only_rejects_effect_observer")
            result = prepare_only(output=args.output, cli_executable=args.cli_executable, repo_support_root=ROOT)
        else:
            if args.provider_config is None or args.decision_config is None:
                raise SelectedTrialError("provider_trial_requires_trusted_configs")
            run_kwargs = dict(
                output=args.output,
                cli_executable=args.cli_executable,
                provider_config=args.provider_config,
                decision_config=args.decision_config,
                repo_support_root=ROOT,
                observe_effects=args.observe_effects,
            )
            if args.prepared_plan is not None:
                run_kwargs["prepared_plan"] = args.prepared_plan
            result = run_provider_trial(**run_kwargs)
    except SelectedTrialError as exc:
        print(json.dumps({"status": "FAILED", "error": exc.code}, sort_keys=True, separators=(",", ":")))
        return 2
    except Exception:
        print(json.dumps({"status": "FAILED", "error": "selected_trial_failed"}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("status") in {"PREPARED_NOT_RUN", "PROCESS_COMPLETED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
