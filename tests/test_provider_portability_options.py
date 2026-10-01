from __future__ import annotations

import hashlib
import json
from urllib.error import HTTPError

import pytest

from pr_review_harness.providers import OpenAIProvider, ProviderError


def _provider(**options):
    return OpenAIProvider(
        {
            "kind": "openai_compatible",
            "provider_id": "portable-test",
            "base_url": "https://provider.example.invalid/v1",
            "model": "test-model",
            "api_key_env": "TEST_PROVIDER_KEY",
            "max_output_tokens": 64,
            "max_request_bytes": 100_000,
            **options,
        }
    )


def _parts(provider):
    return provider._review_parts({"task_id": "t1", "unit_ids": ["u1"]}, [{"evidence_id": "ev1"}])


def _limits():
    return {"max_output_tokens": 32, "max_input_bytes_per_task": 100_000, "deadline_seconds": 2}


def test_default_body_matches_legacy_chat_completions_shape_byte_for_byte():
    provider = _provider()
    system, user, schema = _parts(provider)
    old_body = {
        "model": "test-model",
        "max_completion_tokens": 32,
        "reasoning_effort": "low",
        "response_format": {"type": "json_schema", "json_schema": schema},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False, separators=(",", ":"))},
        ],
    }
    expected = json.dumps(old_body, ensure_ascii=False, separators=(",", ":")).encode()
    actual = provider.serialize_review_request({"task_id": "t1", "unit_ids": ["u1"]}, [{"evidence_id": "ev1"}], _limits())
    assert actual == expected
    assert hashlib.sha256(actual).hexdigest() == hashlib.sha256(expected).hexdigest()
    assert len(actual) == provider.review_input_bytes(
        {"task_id": "t1", "unit_ids": ["u1"]}, [{"evidence_id": "ev1"}], _limits()
    )


@pytest.mark.parametrize("mode", ["json_object", "prompted_json"])
def test_alternate_json_modes_include_authoritative_schema_and_are_measured(mode):
    provider = _provider(response_format=mode)
    task = {"task_id": "t1", "unit_ids": ["u1"]}
    evidence = [{"evidence_id": "ev1"}]
    body_bytes = provider.serialize_review_request(task, evidence, _limits())
    body = json.loads(body_bytes)
    schema_text = json.dumps(_parts(provider)[2], ensure_ascii=False, separators=(",", ":"))
    assert schema_text in body["messages"][0]["content"]
    if mode == "json_object":
        assert body["response_format"] == {"type": "json_object"}
    else:
        assert "response_format" not in body
    assert len(body_bytes) == provider.review_input_bytes(task, evidence, _limits())
    assert provider.estimate_call("SPECIALIST_FINDINGS", task, evidence, _limits())["input_bytes"] == len(body_bytes)
    assert provider.identity["request_compatibility"]["response_format"] == mode


def test_token_parameter_and_reasoning_omission_are_explicit_and_bounded():
    provider = _provider(token_limit_parameter="max_tokens", reasoning_effort=None)
    body = json.loads(provider.serialize_review_request({"task_id": "t1", "unit_ids": ["u1"]}, [], _limits()))
    assert body["max_tokens"] == 32
    assert "max_completion_tokens" not in body
    assert "reasoning_effort" not in body
    assert provider.identity["request_compatibility"] == {
        "response_format": "json_schema",
        "token_limit_parameter": "max_tokens",
        "reasoning_effort": None,
    }


@pytest.mark.parametrize(
    ("option", "value", "code"),
    [
        ("response_format", "xml", "invalid_response_format"),
        ("response_format", [], "invalid_response_format"),
        ("token_limit_parameter", "max_output_tokens", "invalid_token_limit_parameter"),
        ("reasoning_effort", "ultra", "invalid_reasoning_effort"),
        ("reasoning_effort", {}, "invalid_reasoning_effort"),
    ],
)
def test_invalid_request_compatibility_fails_at_construction(option, value, code):
    with pytest.raises(ProviderError, match=code):
        _provider(**{option: value})


def test_http_rejection_does_not_change_format_or_retry(monkeypatch):
    provider = _provider(response_format="json_object")
    seen = []

    class RejectingOpener:
        def open(self, request, timeout):
            seen.append((request.data, timeout))
            raise HTTPError(request.full_url, 400, "bad request", {}, None)

    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", RejectingOpener())
    monkeypatch.setenv("TEST_PROVIDER_KEY", "configured-test-token")
    with pytest.raises(ProviderError, match="http_status_400"):
        provider.review({"task_id": "t1", "unit_ids": ["u1"]}, [], _limits())
    assert len(seen) == 1
    sent = json.loads(seen[0][0])
    assert sent["response_format"] == {"type": "json_object"}
    assert provider.identity["request_compatibility"]["response_format"] == "json_object"


def test_alternate_formats_obey_request_byte_cap_before_credential_lookup(monkeypatch):
    provider = _provider(response_format="prompted_json", max_request_bytes=32)
    monkeypatch.delenv("TEST_PROVIDER_KEY", raising=False)
    with pytest.raises(ProviderError, match="request_exceeds_limit"):
        provider.review({"task_id": "t1", "unit_ids": ["u1"]}, [], _limits())
