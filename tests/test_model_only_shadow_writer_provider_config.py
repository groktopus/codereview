from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_model_only_shadow_writer_provider_config",
    ROOT / "scripts" / "build_model_only_shadow_writer_provider_config.py",
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def _env(path: Path) -> dict[str, str]:
    return {
        "RUNNER_TEMP": str(path),
        "LLM_BASE_URL": "https://inference-api.nousresearch.com/v1",
        "LLM_MODEL": "openai/gpt-6-luna",
        "LLM_API_KEY": "secret-value-must-not-be-written",
    }


def test_builder_materializes_only_the_reviewed_pilot_configuration(tmp_path: Path):
    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    os.chmod(runner, 0o700)
    digest = builder.build(
        ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json",
        runner / "private-shadow-runtime-config", _env(runner),
    )
    config_path = runner / "private-shadow-runtime-config/provider.json"
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes)
    plan = json.loads((ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json").read_text())
    assert digest == plan["runtime"]["writer_provider_config_sha256"]
    assert config["base_url"] == "https://inference-api.nousresearch.com/v1"
    assert config["model"] == "openai/gpt-6-luna"
    assert config["api_key_env"] == "LLM_API_KEY"
    assert b"secret-value-must-not-be-written" not in config_bytes
    assert stat.S_IMODE(config_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600


def test_builder_accepts_the_fixed_six_call_pr457_plan_without_changing_provider_caps(tmp_path: Path):
    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    os.chmod(runner, 0o700)
    plan_path = ROOT / "experiments/model-only-shadow-live-pr457-plan-v2.json"
    digest = builder.build(plan_path, runner / "private-shadow-runtime-config", _env(runner))
    plan = json.loads(plan_path.read_text())
    config = json.loads((runner / "private-shadow-runtime-config/provider.json").read_text())
    assert plan["budget"]["writer_exact_call_count"] == 6
    assert plan["budget"]["writer_max_provider_calls"] == 10
    assert digest == plan["runtime"]["writer_provider_config_sha256"]
    assert config["max_request_bytes"] == 128000
    assert config["max_output_tokens"] == 1800


def test_builder_fails_closed_on_changed_endpoint_before_writing_config(tmp_path: Path):
    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    os.chmod(runner, 0o700)
    env = _env(runner)
    env["LLM_BASE_URL"] = "https://attacker.example/v1"
    with pytest.raises(builder.ConfigBuildError, match="writer_provider_identity_mismatch"):
        builder.build(ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json", runner / "config", env)
    assert not (runner / "config").exists()
