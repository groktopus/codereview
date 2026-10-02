#!/usr/bin/env python3
"""Prepare or run the fixed synthetic trial against the checked-out source revision."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.selected_model_trial import (  # noqa: E402
    SelectedTrialError,
    prepare_current_source_trial,
    run_current_provider_trial,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_mutually_exclusive_group(required=True)
    modes.add_argument("--prepare-only", action="store_true")
    modes.add_argument("--run-provider-trial", action="store_true")
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--cli-executable", type=Path, required=True)
    result.add_argument("--expected-source-revision", required=True)
    result.add_argument("--trial-version", choices=("v1", "v2"), default="v1")
    result.add_argument("--preparation-dir", type=Path)
    result.add_argument("--provider-config", type=Path)
    result.add_argument("--decision-config", type=Path)
    result.add_argument("--observe-effects", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.prepare_only:
            if args.preparation_dir or args.provider_config or args.decision_config or args.observe_effects:
                raise SelectedTrialError("current_prepare_arguments_invalid")
            from prepare_selected_pair_clean_control_trial import prepare_trial

            plan_output = args.output / "prepared"
            plan_output.mkdir(parents=True, mode=0o700)
            plan_output.chmod(0o700)
            prepared = prepare_trial(plan_output, root=ROOT, version=args.trial_version)
            result = prepare_current_source_trial(
                prepared_plan=plan_output / f"selected-pair-clean-control-trial-{args.trial_version}.json",
                cli_executable=args.cli_executable,
                expected_source_revision=args.expected_source_revision,
                output=args.output,
                repo_support_root=ROOT,
                environ=dict(os.environ),
                version=args.trial_version,
            )
            result["prepared_plan_sha256"] = prepared["plan_sha256"]
        else:
            if (
                args.preparation_dir is None
                or args.provider_config is None
                or args.decision_config is None
                or not args.observe_effects
            ):
                raise SelectedTrialError("current_provider_trial_arguments_invalid")
            result = run_current_provider_trial(
                output=args.output,
                cli_executable=args.cli_executable,
                preparation_dir=args.preparation_dir,
                provider_config=args.provider_config,
                decision_config=args.decision_config,
                expected_source_revision=args.expected_source_revision,
                repo_support_root=ROOT,
                environ=dict(os.environ),
                observe_effects=True,
                version=args.trial_version,
            )
    except SelectedTrialError as exc:
        print(json.dumps({"status": "FAILED", "error": exc.code}, sort_keys=True, separators=(",", ":")))
        return 2
    except Exception:
        print(json.dumps({"status": "FAILED", "error": "current_trial_failed"}, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("status") in {"PREPARED_NOT_RUN", "PROCESS_COMPLETED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
