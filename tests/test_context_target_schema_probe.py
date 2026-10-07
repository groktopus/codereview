from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import jsonschema
import pytest

from pr_review_harness.context_targets import build_context_target_manifest, validate_context_target_manifest
from pr_review_harness.providers import OpenAIProvider, ProviderError

_SCRIPT_PATH = Path(__file__).parents[1] / "scripts/run_context_target_schema_probe.py"
_SPEC = importlib.util.spec_from_file_location("context_target_schema_probe", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_PROBE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PROBE)
_request_schema_pair = _PROBE._request_schema_pair
_provider_config_from_environment = _PROBE._provider_config_from_environment
_run_variant = _PROBE._run_variant


def _profile():
    return {
        "version": "probe-fixture",
        "retrieval_context_patterns": ["engines/*.py"],
        "trusted_policy_paths": ["AGENTS.md"],
        "retrieval_revisions": {"implementation": "head"},
        "context_target_manifest": {
            "version": "context-target-manifest.v1",
            "max_entries": 8,
            "max_bytes": 16_384,
        },
    }


def _fixture():
    base, head = "a" * 40, "b" * 40
    snapshot = {
        "snapshot_id": "snap-probe",
        "base_sha": base,
        "head_sha": head,
        "inventory": [
            {"unit_id": "unit-engine", "path": "engines/exa.py"},
            {"unit_id": "unit-policy", "path": "AGENTS.md"},
        ],
        "evidence": {
            "ev-engine": {
                "source_kind": "head_file",
                "path": "engines/exa.py",
                "source_revision": head,
                "source_object_id": "c" * 40,
                "source_object_format": "sha1",
                "trust": "untrusted_pr_content",
            }
        },
    }
    task = {
        "task_id": "probe-task",
        "task_kind": "SPECIALIST_FINDINGS",
        "unit_ids": ["unit-engine"],
        "evidence_ids": ["ev-engine"],
        "request_input_contract": "specialist-input.v2",
        "unit_evidence_bindings": [
            {"unit_id": "unit-engine", "binding_status": "VERIFIED", "evidence_ids": ["ev-engine"]}
        ],
    }
    task["context_target_manifest"] = build_context_target_manifest(task, snapshot, _profile())
    evidence = [{"evidence_id": "ev-engine", "content": "def call(): pass\n"}]
    return task, evidence


def test_probe_requests_differ_only_at_target_schema_and_fit_the_fixed_cap(monkeypatch):
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
            "max_request_bytes": 96_000,
        }
    )
    limits = {
        "max_input_bytes_per_task": 96_000,
        "max_output_bytes_per_task": 16_000,
        "max_output_tokens": 1_800,
        "deadline_seconds": 30,
    }
    task, evidence = _fixture()
    def archived_control(_root, source_task, source_evidence, source_limits, model):
        system, user, schema = provider._review_parts(source_task, source_evidence)
        legacy = copy.deepcopy(schema)
        pairs = sorted({(choice["kind"], choice["value"]) for choice in validate_context_target_manifest(source_task["context_target_manifest"])})
        target = legacy["schema"]["properties"]["context_gap_proposals"]["items"]["properties"]
        target["target"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "value"],
            "enum": [{"kind": kind, "value": value} for kind, value in pairs],
            "properties": {
                "kind": {"type": "string", "enum": sorted({kind for kind, _ in pairs})},
                "value": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2000,
                    "enum": sorted({value for _, value in pairs}),
                },
            },
        }
        return provider._request_bytes(system, user, legacy, source_limits)

    monkeypatch.setattr(_PROBE, "_legacy_request_from_archived_provider", archived_control)
    _system, _user, old_schema, new_schema, old_body, new_body = _request_schema_pair(
        Path("/unused-by-fixture"), provider, task, evidence, limits
    )
    old_target = old_schema["schema"]["properties"]["context_gap_proposals"]["items"]["properties"]["target"]
    new_target = new_schema["schema"]["properties"]["context_gap_proposals"]["items"]["properties"]["target"]
    jsonschema.Draft202012Validator.check_schema(old_schema["schema"])
    jsonschema.Draft202012Validator.check_schema(new_schema["schema"])
    assert "enum" in old_target
    assert "anyOf" in new_target
    assert len(old_body) <= 96_000 and len(new_body) <= 96_000
    assert hashlib.sha256(old_body).digest() != hashlib.sha256(new_body).digest()


def test_probe_error_receipt_drops_untrusted_text_and_keeps_only_safe_fields():
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
        }
    )

    def fail(**_kwargs):
        raise ProviderError(
            "http_status_400",
            meta={
                "error_text": "do not echo this or sk-secret",
                "local_http_exchange": {
                    "http_status": 400,
                    "request_attempted": True,
                    "request_bytes": 100,
                    "request_sha256": "a" * 64,
                    "response_bytes": 211,
                    "response_sha256": "b" * 64,
                    "elapsed_ms": 12.5,
                },
            },
        )

    provider._call = fail
    result = _run_variant(
        provider,
        system="unused",
        user={},
        schema={},
        limits={},
        body=b"request",
    )
    serialized = json.dumps(result)
    assert result["state"] == "PROVIDER_ERROR"
    assert result["http_status"] == 400
    assert result["response_sha256"] == "b" * 64
    assert "do not echo" not in serialized
    assert "sk-secret" not in serialized

    def fail_after_attempt(**_kwargs):
        error = RuntimeError("private failure text")
        error.meta = {
            "local_http_exchange": {
                "http_status": 502,
                "request_attempted": True,
                "request_bytes": 100,
                "request_sha256": "c" * 64,
            }
        }
        raise error

    provider._call = fail_after_attempt
    result = _run_variant(
        provider,
        system="unused",
        user={},
        schema={},
        limits={},
        body=b"request",
    )
    assert result["state"] == "LOCAL_ERROR"
    assert result["http_status"] == 502
    assert result["request_attempted"] is True
    assert "private failure text" not in json.dumps(result)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://provider.example/v1",
        "https://user:password@provider.example/v1",
        "https://provider.example/v1?token=secret",
        "https://provider.example/v1/chat/completions",
    ],
)
def test_probe_rejects_unsafe_or_non_api_root_endpoints(monkeypatch, base_url):
    monkeypatch.setenv("LLM_BASE_URL", base_url)
    monkeypatch.setenv("LLM_MODEL", "fixture-model")
    monkeypatch.setenv("LLM_API_KEY", "fixture-key")
    with pytest.raises(ValueError, match="probe_provider_configuration_invalid"):
        _provider_config_from_environment(
            {
                "max_input_bytes_per_task": 96_000,
                "max_output_bytes_per_task": 16_000,
                "max_output_tokens": 1_800,
                "deadline_seconds": 30,
            }
        )


def test_probe_config_keeps_credential_as_environment_reference(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("LLM_MODEL", "fixture-model")
    monkeypatch.setenv("LLM_API_KEY", "fixture-key")
    config = _provider_config_from_environment(
        {
            "max_input_bytes_per_task": 96_000,
            "max_output_bytes_per_task": 16_000,
            "max_output_tokens": 1_800,
            "deadline_seconds": 30,
        }
    )
    assert config["api_key_env"] == "LLM_API_KEY"
    assert "fixture-key" not in repr(config)


def test_probe_workflow_is_manual_main_only_read_only_and_disabled_by_default():
    path = Path(__file__).parents[1] / ".github/workflows/context-target-schema-compatibility-probe.yml"
    text = path.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "default: false" in text
    assert "github.repository == 'groktopus/codereview'" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "git init --bare" in text
    assert "--filter=blob:none" in text
    assert "timeout 120s" in text
    assert "90165dd65be3595006171d7abef34a082c90a71d" in text
    assert "--prepare-only" in text
    assert text.index("--prepare-only") < text.index("Compare the fixed old and candidate schema encodings")
    assert "path: target-source" not in text
    assert "permissions:\n  contents: read" in text
    assert "LLM_BASE_URL: ${{ secrets.LLM_BASE_URL }}" in text
    assert "LLM_MODEL: ${{ secrets.LLM_MODEL }}" in text
    assert "LLM_API_KEY: ${{ secrets.LLM_API_KEY }}" in text
    assert "JEV_API_KEY" not in text
    assert "pulls: write" not in text
