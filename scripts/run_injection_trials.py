#!/usr/bin/env python3
"""Prepare or explicitly run bounded local prompt-injection review trials."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.injection_trials import (  # noqa: E402
    OUTPUT_EXPERIMENT_ID,
    V3_CAUSAL_ROLE_EXPERIMENT_ID,
    InjectionTrialError,
    recover_existing_trials,
    run_trials,
)


def _decision_provider(path: Path | None):
    if path is None:
        return None
    try:
        from pr_review_harness.providers import load_provider_config, make_decision_provider

        config = load_provider_config(path)
        if (
            config.get("kind") not in {"typesafe", "jev"}
            or config.get("endpoint") != "https://api.typesafe.ai/v1/systemone"
            or config.get("model") != "jev-1.13.0"
            or config.get("primitive") != "choice-injection-v1"
        ):
            raise InjectionTrialError("detector_config_not_allowlisted")
        return make_decision_provider(config)
    except InjectionTrialError:
        raise
    except Exception:
        raise InjectionTrialError("detector_configuration_invalid") from None


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--prepare-only", action="store_true", help="build fixtures and evaluation-v1 corpus without provider calls"
    )
    modes.add_argument(
        "--run-provider-trials", action="store_true", help="explicitly invoke the installed CLI and configured provider"
    )
    modes.add_argument(
        "--recover-existing",
        action="store_true",
        help="export validated summaries from existing trial records and sealed CLI artifacts without provider calls",
    )
    result.add_argument("--output", type=Path, required=True, help="new private local output directory")
    result.add_argument(
        "--fixture-suite",
        choices=("v1", "v2"),
        default="v1",
        help="authored immutable fixture suite version; v2 adds unchanged caller and contract context",
    )
    result.add_argument(
        "--experiment-profile",
        choices=("default-v1", OUTPUT_EXPERIMENT_ID, V3_CAUSAL_ROLE_EXPERIMENT_ID),
        default="default-v1",
        help="versioned finite trial budget; the v3 causal-role profile is one bounded Solar comparison",
    )
    result.add_argument(
        "--model", choices=("solar", "stepfun"), default="solar", help="existing free-model allowlist key"
    )
    result.add_argument(
        "--model-catalog", type=Path, help="fresh captured Nous /models artifact; required for provider trials"
    )
    result.add_argument(
        "--cli-executable", type=Path, help="installed pr-review executable; required for provider trials"
    )
    result.add_argument("--decision-config", type=Path, help="optional allowlisted Jev Choice detector config")
    result.add_argument(
        "--repetitions", type=int, default=1, help="repeat each paired fixture without retry-until-green"
    )
    result.add_argument(
        "--trial-case",
        action="append",
        help="for provider trials, select exactly one control and one attack/benign pair by case ID",
    )
    result.add_argument("--run-timeout-seconds", type=float)
    result.add_argument("--matrix-timeout-seconds", type=float)
    result.add_argument("--model-catalog-max-age-seconds", type=int, default=300)
    result.add_argument("--original-exit-code", type=int, default=1)
    result.add_argument("--original-failure-code", default="validation_failed")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.recover_existing:
        try:
            outcome = recover_existing_trials(
                output=args.output,
                original_exit_code=args.original_exit_code,
                original_failure_code=args.original_failure_code,
            )
        except InjectionTrialError as exc:
            print(
                json.dumps({"status": "RECOVERY_FAILED", "error": str(exc)}, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
            return 2
        print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
        return 0
    if args.run_provider_trials and (args.model_catalog is None or args.cli_executable is None):
        print(
            json.dumps({"status": "PREFLIGHT_FAILED", "error": "provider_trials_require_catalog_and_installed_cli"}),
            file=sys.stderr,
        )
        return 2
    if args.prepare_only and args.decision_config:
        print(
            json.dumps({"status": "PREFLIGHT_FAILED", "error": "detector_config_requires_provider_trials"}),
            file=sys.stderr,
        )
        return 2
    try:
        run_timeout = args.run_timeout_seconds
        matrix_timeout = args.matrix_timeout_seconds
        if run_timeout is None:
            run_timeout = (
                300
                if args.experiment_profile == V3_CAUSAL_ROLE_EXPERIMENT_ID
                else (90 if args.experiment_profile == OUTPUT_EXPERIMENT_ID else 180)
            )
        if matrix_timeout is None:
            matrix_timeout = (
                900
                if args.experiment_profile == V3_CAUSAL_ROLE_EXPERIMENT_ID
                else (300 if args.experiment_profile == OUTPUT_EXPERIMENT_ID else 3600)
            )
        outcome = run_trials(
            output=args.output,
            suite_path=ROOT / "examples/injection" / f"fixture-suite.{args.fixture_suite}.json",
            experiment_profile=args.experiment_profile,
            model_key=args.model,
            model_catalog_path=args.model_catalog or Path(""),
            cli_executable=args.cli_executable or Path(""),
            repetitions=args.repetitions,
            run_timeout_seconds=run_timeout,
            matrix_timeout_seconds=matrix_timeout,
            model_catalog_max_age_seconds=args.model_catalog_max_age_seconds,
            execute_provider_trials=args.run_provider_trials,
            detector_provider=_decision_provider(args.decision_config),
            trial_case_ids=args.trial_case,
        )
    except InjectionTrialError as exc:
        print(
            json.dumps({"status": "PREFLIGHT_FAILED", "error": str(exc)}, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
