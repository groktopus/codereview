import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/provider_config_from_env.py"
SENTINEL_LLM = "llm-secret-value-that-must-not-appear"
SENTINEL_JEV = "jev-secret-value-that-must-not-appear"


def _environment(**overrides):
    values = {
        "LLM_BASE_URL": "https://llm.example.invalid/v1",
        "LLM_MODEL": "model-one",
        "LLM_API_KEY": SENTINEL_LLM,
        "JEV_BASE_URL": "https://decision.example.invalid/v1",
        "JEV_MODEL": "jev-one",
        "JEV_API_KEY": SENTINEL_JEV,
        "PYTHONPATH": str(ROOT / "src"),
    }
    values.update(overrides)
    return values


def _run(tmp_path, env):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path / "private-config"), "--json"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_generator_writes_private_reference_only_configs(tmp_path):
    result = _run(tmp_path, _environment())
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    provider = json.loads(Path(paths["provider_config"]).read_text(encoding="utf-8"))
    decision = json.loads(Path(paths["decision_config"]).read_text(encoding="utf-8"))

    assert provider == {
        "api_key_env": "LLM_API_KEY",
        "base_url": "https://llm.example.invalid/v1",
        "kind": "openai_compatible",
        "model": "model-one",
        "provider_id": "operator_openai_compatible",
    }
    assert decision == {
        "api_key_env": "JEV_API_KEY",
        "endpoint": "https://decision.example.invalid/v1/systemone",
        "kind": "typesafe",
        "model": "jev-one",
    }
    assert SENTINEL_LLM not in result.stdout + result.stderr
    assert SENTINEL_JEV not in result.stdout + result.stderr
    serialized = Path(paths["provider_config"]).read_text() + Path(paths["decision_config"]).read_text()
    assert SENTINEL_LLM not in serialized
    assert SENTINEL_JEV not in serialized
    assert os.stat(tmp_path / "private-config").st_mode & 0o777 == 0o700
    assert os.stat(paths["provider_config"]).st_mode & 0o777 == 0o600
    assert os.stat(paths["decision_config"]).st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("override", "error_code"),
    [
        ({"LLM_API_KEY": ""}, "llm_api_key_required"),
        ({"JEV_MODEL": "\nsecret"}, "jev_model_invalid"),
        ({"LLM_BASE_URL": "https://user:password@llm.example.invalid/v1"}, "llm_base_url_invalid"),
        ({"LLM_BASE_URL": "https://llm.example.invalid/v1?token=hidden"}, "llm_base_url_invalid"),
        ({"LLM_BASE_URL": "http://llm.example.invalid/v1"}, "llm_base_url_remote_http_forbidden"),
        ({"LLM_BASE_URL": "https://llm.example.invalid/v1/chat/completions"}, "llm_base_url_must_be_api_root"),
        ({"JEV_BASE_URL": "https://decision.example.invalid/v1/systemone"}, "jev_base_url_must_be_api_root"),
    ],
)
def test_generator_rejects_invalid_configuration_before_writing(tmp_path, override, error_code):
    result = _run(tmp_path, _environment(**override))
    assert result.returncode == 2
    assert result.stdout == ""
    assert error_code in result.stderr
    assert not (tmp_path / "private-config").exists()
    assert SENTINEL_LLM not in result.stderr
    assert SENTINEL_JEV not in result.stderr


def test_loopback_http_is_available_for_local_provider_adapters(tmp_path):
    result = _run(
        tmp_path,
        _environment(
            LLM_BASE_URL="http://127.0.0.1:8000/v1",
            JEV_BASE_URL="http://localhost:8001/v1",
        ),
    )
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    provider = json.loads(Path(paths["provider_config"]).read_text())
    decision = json.loads(Path(paths["decision_config"]).read_text())
    assert provider["base_url"] == "http://127.0.0.1:8000/v1"
    assert decision["endpoint"] == "http://localhost:8001/v1/systemone"


def test_custom_provider_api_root_paths_are_preserved_without_scheme_guessing(tmp_path):
    result = _run(
        tmp_path,
        _environment(
            LLM_BASE_URL="https://llm.example.invalid/openai-proxy",
            JEV_BASE_URL="https://jev.example.invalid/native/v2",
        ),
    )
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    provider = json.loads(Path(paths["provider_config"]).read_text())
    decision = json.loads(Path(paths["decision_config"]).read_text())
    assert provider["base_url"] == "https://llm.example.invalid/openai-proxy"
    assert decision["endpoint"] == "https://jev.example.invalid/native/v2/systemone"


def test_optional_llm_compatibility_options_are_operator_config_and_secret_free(tmp_path):
    result = _run(
        tmp_path,
        _environment(
            LLM_RESPONSE_FORMAT="prompted_json",
            LLM_TOKEN_LIMIT_PARAMETER="max_tokens",
            LLM_REASONING_EFFORT="omit",
        ),
    )
    assert result.returncode == 0, result.stderr
    paths = json.loads(result.stdout)
    provider = json.loads(Path(paths["provider_config"]).read_text(encoding="utf-8"))
    assert provider["response_format"] == "prompted_json"
    assert provider["token_limit_parameter"] == "max_tokens"
    assert provider["reasoning_effort"] is None
    assert SENTINEL_LLM not in Path(paths["provider_config"]).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "value", "error_code"),
    [
        ("LLM_RESPONSE_FORMAT", "xml", "llm_response_format_invalid"),
        ("LLM_TOKEN_LIMIT_PARAMETER", "max_new_tokens", "llm_token_limit_parameter_invalid"),
        ("LLM_REASONING_EFFORT", "ultra", "llm_reasoning_effort_invalid"),
    ],
)
def test_invalid_compatibility_options_fail_before_config_creation(tmp_path, name, value, error_code):
    env = _environment(**{name: value})
    env.pop("LLM_API_KEY")
    result = _run(tmp_path, env)
    assert result.returncode == 2
    assert error_code in result.stderr
    assert not (tmp_path / "private-config").exists()
    assert SENTINEL_LLM not in result.stderr


def test_generator_refuses_to_overwrite_existing_directory(tmp_path):
    output = tmp_path / "private-config"
    output.mkdir()
    marker = output / "preserve-me"
    marker.write_text("existing", encoding="utf-8")

    result = _run(tmp_path, _environment())
    assert result.returncode == 2
    assert "config_write_failed" in result.stderr
    assert marker.read_text(encoding="utf-8") == "existing"
