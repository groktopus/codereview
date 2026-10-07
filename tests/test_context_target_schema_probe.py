from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import jsonschema
import pytest

from pr_review_harness.context_targets import build_context_target_manifest, validate_context_target_manifest
from pr_review_harness.providers import OpenAIProvider

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


def test_probe_reads_real_provider_success_and_error_receipt_shapes_without_leaking_text(monkeypatch):
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "http://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "TEST_SCHEMA_PROBE_KEY",
            "max_response_bytes": 4096,
        }
    )
    limits = {
        "max_input_bytes_per_task": 4096,
        "max_output_bytes_per_task": 4096,
        "max_output_tokens": 64,
        "deadline_seconds": 5,
    }
    success_body = json.dumps(
        {
            "id": "fixture-response",
            "model": "fixture-model",
            "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        },
        separators=(",", ":"),
    ).encode()
    error_body = b'{"error":"do not echo this or sk-secret"}'

    class FakeResponse:
        status = 200

        def __init__(self, body):
            self._body = io.BytesIO(body)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read1(self, size):
            return self._body.read(size)

    class FakeOpener:
        def __init__(self):
            self.requests = []

        def open(self, request, timeout):
            self.requests.append(request)
            if len(self.requests) == 1:
                return FakeResponse(success_body)
            raise HTTPError(request.full_url, 400, "fixture failure", None, io.BytesIO(error_body))

    opener = FakeOpener()
    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", opener)
    monkeypatch.setenv("TEST_SCHEMA_PROBE_KEY", "dummy-test-only")

    success = _run_variant(
        provider,
        system="unused",
        user={},
        schema={"type": "object"},
        limits=limits,
        body=b'{"fixture":"success"}',
    )
    failure = _run_variant(
        provider,
        system="unused",
        user={},
        schema={"type": "object"},
        limits=limits,
        body=b'{"fixture":"failure"}',
    )
    assert len(opener.requests) == 2
    assert success["state"] == "HTTP_RESPONSE"
    assert success["receipt_state"] == "RECORDED"
    assert success["http_status"] == 200
    assert success["request_attempted"] is True
    assert success["response_bytes"] == len(success_body)
    assert success["response_sha256"] == hashlib.sha256(success_body).hexdigest()
    assert failure["state"] == "PROVIDER_ERROR"
    assert failure["receipt_state"] == "RECORDED"
    assert failure["http_status"] == 400
    assert failure["request_attempted"] is True
    assert failure["response_bytes"] == len(error_body)
    assert failure["response_sha256"] == hashlib.sha256(error_body).hexdigest()
    assert "do not echo" not in json.dumps(failure)
    assert "sk-secret" not in json.dumps(failure)


def test_missing_success_exchange_receipt_is_unknown_not_false():
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
        }
    )
    provider._call = lambda **_kwargs: (
        {},
        {"provenance": {"configured_model_alias": "fixture-model", "local_http_exchange": {}}},
    )
    result = _run_variant(
        provider,
        system="unused",
        user={},
        schema={},
        limits={},
        body=b"request",
    )
    assert result["state"] == "HTTP_RESPONSE"
    assert result["receipt_state"] == "UNKNOWN"
    assert result["request_attempted"] is None
    assert result["http_status"] is None


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
