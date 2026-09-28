from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
EXPERIMENTS = ROOT / "experiments"


def _load(name: str) -> dict:
    return json.loads((EXPERIMENTS / name).read_text())


def test_synth_001_writer_configs_bound_prepare_only_source_and_provider_work():
    profile = _load("synth-001-writer-profile-v1.json")
    limits = _load("synth-001-writer-limits-v1.json")
    provider = _load("synth-001-writer-provider-v1.json")

    assert profile["version"] == "synth-001-writer-prepare-v1"
    assert profile["context_paths"] == ["caller.py", "contract.md"]
    assert profile["retrieval_context_patterns"] == []
    assert profile["trusted_policy_paths"] == []
    assert profile["required_lenses"] == ["correctness"]
    assert profile["effect_policy"] == "READ_ONLY"
    criterion = profile["review_criteria"]["correctness"].lower()
    for required_boundary in (
        "review the changed source",
        "source-supported defects introduced by the change",
        "empty finding list",
        "execute code or tests",
        "invoke external checks",
        "fetch additional context",
        "publish anything",
        "downstream model adjudication",
    ):
        assert required_boundary in criterion

    assert limits["max_provider_calls"] == 1
    assert limits["max_retries_per_task"] == 0
    assert limits["max_context_retrievals"] == 0
    assert limits["max_followup_tasks"] == 0
    assert limits["max_concurrent_scopes"] == 1
    assert limits["max_input_bytes_per_task"] == provider["max_request_bytes"]
    assert limits["max_output_bytes_per_task"] == provider["max_response_bytes"]
    assert limits["max_output_tokens"] == provider["max_output_tokens"]

    assert provider["kind"] == "openai_compatible"
    assert provider["api_key_env"] == "LLM_API_KEY"
    assert provider["timeout_seconds"] <= limits["deadline_seconds"]
    assert provider["max_output_items"] > 0
