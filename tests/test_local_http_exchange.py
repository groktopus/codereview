"""Fake-transport coverage for provider-local HTTP exchange receipts."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from email.message import Message

import pytest

from pr_review_harness import providers
from pr_review_harness.budget import IsolatedCallError, IsolatedInvocation, _safe_provider_metadata
from pr_review_harness.providers import DecisionProvider, OpenAIProvider, ProviderError

TOKEN = "exchange-canary-token"
ENDPOINT = "https://provider.example.invalid/private/path"


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return self.response


def _openai() -> OpenAIProvider:
    return OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": ENDPOINT,
            "model": "test-model",
            "provider_id": "fixture-provider",
            "api_key_env": "EXCHANGE_TEST_KEY",
            "timeout_seconds": 1,
            "max_response_bytes": 1024,
        }
    )


def _decision() -> DecisionProvider:
    return DecisionProvider(
        {
            "kind": "typesafe",
            "endpoint": ENDPOINT,
            "model": "test-model",
            "api_key_env": "EXCHANGE_TEST_KEY",
            "timeout_seconds": 1,
            "max_response_bytes": 1024,
        }
    )


def _limits():
    return {
        "max_input_bytes_per_task": 20_000,
        "max_output_bytes_per_task": 1024,
        "max_output_tokens": 20,
        "deadline_seconds": 1,
    }


def _openai_call(provider):
    return provider._call(
        system="system-private-canary",
        user={"text": "request-private-canary"},
        schema={"name": "response"},
        limits=_limits(),
        contract_version="fixture.v1",
    )


def _decision_call(provider):
    return provider.assess("question-private-canary", "input-private-canary", _limits())


@pytest.mark.parametrize("adapter,call", [(_openai, _openai_call), (_decision, _decision_call)])
def test_success_receipt_binds_exact_bytes_without_exposing_endpoint_or_content(monkeypatch, adapter, call):
    body = (
        b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}'
        if adapter is _openai
        else b'{"model":"test-model","answers":{"review_claim":{"type":"noul","noul":0.25}}}'
    )
    opener = FakeOpener(FakeResponse(body))
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)

    result = call(adapter())
    provenance = result[1]["provenance"] if adapter is _openai else result["provenance"]
    receipt = provenance["local_http_exchange"]
    sent_request = opener.calls[0][0].data
    assert receipt["contract_version"] == "local-http-exchange.v1"
    assert receipt["state"] == "HTTP_RESPONSE_RECEIVED"
    assert receipt["delivery_observation"] == "UNKNOWN"
    assert receipt["request_attempted"] is True
    assert receipt["request_sha256"] == hashlib.sha256(sent_request).hexdigest()
    assert receipt["response_sha256"] == hashlib.sha256(body).hexdigest()
    assert receipt["response_complete"] is True
    assert receipt["http_status"] == 200
    serialized = json.dumps(receipt)
    for private in (ENDPOINT, TOKEN, "system-private-canary", "request-private-canary", "input-private-canary"):
        assert private not in serialized
    assert (
        receipt["endpoint_sha256"]
        == hashlib.sha256(
            b"https://provider.example.invalid/private/path/chat/completions"
            if adapter is _openai
            else b"https://provider.example.invalid/private/path"
        ).hexdigest()
    )


@pytest.mark.parametrize("adapter,call", [(_openai, _openai_call), (_decision, _decision_call)])
def test_http_error_receipt_hashes_bounded_error_body_and_preserves_status(monkeypatch, adapter, call):
    error_body = b'{"error":"private-response-canary"}'
    error = urllib.error.HTTPError(ENDPOINT, 503, "unavailable", Message(), io.BytesIO(error_body))
    opener = FakeOpener(error=error)
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)

    with pytest.raises(ProviderError) as caught:
        call(adapter())
    receipt = caught.value.meta["local_http_exchange"]
    assert receipt["state"] == "HTTP_ERROR_RESPONSE"
    assert receipt["http_status"] == 503
    assert receipt["request_attempted"] is True
    assert receipt["response_sha256"] == hashlib.sha256(error_body).hexdigest()
    assert receipt["response_complete"] is True
    assert "private-response-canary" not in repr(caught.value.meta)


@pytest.mark.parametrize("adapter,call", [(_openai, _openai_call), (_decision, _decision_call)])
def test_oversized_http_error_receipt_hashes_only_observed_prefix(monkeypatch, adapter, call):
    body = b"response-body-private-canary"
    error = urllib.error.HTTPError(ENDPOINT, 502, "unavailable", Message(), io.BytesIO(body))
    opener = FakeOpener(error=error)
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)
    provider = adapter()
    provider.max_response_bytes = 8

    with pytest.raises(ProviderError, match="http_status_502") as caught:
        call(provider)
    receipt = _safe_provider_metadata(caught.value.meta, 1024)["local_http_exchange"]
    observed = body[:9]  # bounded reader consumes cap + 1 to establish truncation
    assert receipt["state"] == "HTTP_ERROR_RESPONSE"
    assert receipt["http_status"] == 502
    assert receipt["response_sha256"] == hashlib.sha256(observed).hexdigest()
    assert receipt["response_bytes"] == len(observed)
    assert receipt["response_complete"] is False
    assert "response-body-private-canary" not in repr(receipt)


@pytest.mark.parametrize("adapter,call", [(_openai, _openai_call), (_decision, _decision_call)])
def test_transport_failure_is_recorded_as_local_failure_with_remote_delivery_unknown(monkeypatch, adapter, call):
    opener = FakeOpener(error=urllib.error.URLError("private-transport-canary"))
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)

    with pytest.raises(ProviderError) as caught:
        call(adapter())
    receipt = caught.value.meta["local_http_exchange"]
    assert receipt["state"] == "TRANSPORT_FAILURE"
    assert receipt["request_attempted"] is True
    assert receipt["delivery_observation"] == "UNKNOWN"
    assert "private-transport-canary" not in repr(caught.value.meta)


def test_unclassified_adapter_exception_preserves_type_and_marks_exchange_unknown(monkeypatch):
    opener = FakeOpener(error=RuntimeError("private-unknown-canary"))
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)

    with pytest.raises(RuntimeError) as caught:
        _openai_call(_openai())
    receipt = caught.value.meta["local_http_exchange"]
    assert receipt["state"] == "UNKNOWN"
    assert receipt["request_attempted"] is True
    assert receipt["delivery_observation"] == "UNKNOWN"
    assert "private-unknown-canary" not in repr(receipt)


def test_serialized_but_unattempted_request_survives_worker_metadata_redaction(monkeypatch):
    monkeypatch.delenv("EXCHANGE_TEST_KEY", raising=False)
    opener = FakeOpener(FakeResponse(b"{}"))
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    with pytest.raises(ProviderError) as caught:
        _openai_call(_openai())

    safe = _safe_provider_metadata(caught.value.meta, 1024)
    receipt = safe["local_http_exchange"]
    assert receipt["state"] == "REQUEST_SERIALIZED"
    assert receipt["request_serialized"] is True
    assert receipt["request_attempted"] is False
    assert receipt["request_sha256"] == caught.value.meta["local_http_exchange"]["request_sha256"]
    assert len(opener.calls) == 0
    assert TOKEN not in repr(safe)


def test_openai_credential_echo_failure_keeps_safe_http_exchange_receipt(monkeypatch):
    body = b'{"error":"' + TOKEN.encode() + b'"}'
    opener = FakeOpener(FakeResponse(body))
    monkeypatch.setattr(providers, "_HTTP_OPENER", opener)
    monkeypatch.setenv("EXCHANGE_TEST_KEY", TOKEN)

    with pytest.raises(ProviderError, match="provider_response_contains_credential") as caught:
        _openai_call(_openai())
    safe = _safe_provider_metadata(caught.value.meta, 1024)
    receipt = safe["local_http_exchange"]
    assert receipt["state"] == "HTTP_RESPONSE_RECEIVED"
    assert receipt["http_status"] == 200
    assert receipt["response_sha256"] == hashlib.sha256(body).hexdigest()
    assert receipt["response_complete"] is True
    assert TOKEN not in repr(caught.value.meta)
    assert TOKEN not in repr(safe)


def test_worker_metadata_allowlist_keeps_only_valid_receipt_fields():
    receipt = {
        "contract_version": "local-http-exchange.v1",
        "state": "TRANSPORT_FAILURE",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": True,
        "request_sha256": "a" * 64,
        "request_bytes": 23,
        "endpoint_sha256": "b" * 64,
        "provider_id": "fixture-provider",
        "model_id": "test-model",
        "raw_url": ENDPOINT,
        "authorization": TOKEN,
        "request_body": "sensitive prompt",
        "elapsed_ms": 2.5,
    }
    safe = _safe_provider_metadata({"local_http_exchange": receipt}, 1024)
    assert safe["local_http_exchange"] == {
        key: value for key, value in receipt.items() if key not in {"raw_url", "authorization", "request_body"}
    }
    invalid = {**receipt, "delivery_observation": "REMOTE_MODEL_CONSUMED"}
    assert "local_http_exchange" not in _safe_provider_metadata({"local_http_exchange": invalid}, 1024)
    malformed = {**receipt, "state": ["TRANSPORT_FAILURE"]}
    assert "local_http_exchange" not in _safe_provider_metadata({"local_http_exchange": malformed}, 1024)
    impossible = [
        {
            **receipt,
            "state": "REQUEST_SERIALIZED",
            "response_sha256": "c" * 64,
            "response_bytes": 1,
            "response_complete": True,
        },
        {**receipt, "state": "UNKNOWN", "http_status": 200},
        {**receipt, "state": "TRANSPORT_FAILURE", "http_status": 503},
        {**receipt, "state": "REQUEST_ATTEMPTED", "response_complete": False},
        {
            **receipt,
            "state": "HTTP_ERROR_RESPONSE",
            "http_status": 503,
            "response_sha256": None,
            "response_bytes": None,
            "response_complete": None,
        },
        {
            **receipt,
            "state": "HTTP_ERROR_RESPONSE",
            "http_status": 503,
            "response_sha256": None,
            "response_bytes": None,
            "response_complete": None,
        },
    ]
    for malformed_state in impossible:
        assert "local_http_exchange" not in _safe_provider_metadata({"local_http_exchange": malformed_state}, 1024)


class RaisesWithLocalReceipt:
    def __call__(self):
        error = RuntimeError("safe transport failure")
        error.meta = {
            "local_http_exchange": {
                "contract_version": "local-http-exchange.v1",
                "state": "TRANSPORT_FAILURE",
                "delivery_observation": "UNKNOWN",
                "request_serialized": True,
                "request_attempted": True,
                "request_sha256": "c" * 64,
                "request_bytes": 9,
                "endpoint_sha256": "d" * 64,
                "raw_url": ENDPOINT,
                "authorization": TOKEN,
                "prompt": "private-worker-canary",
            }
        }
        raise error


class RaisesWithUnhashableReceiptState:
    def __call__(self):
        raise ProviderError(
            "http_status_503",
            meta={
                "local_http_exchange": {
                    "contract_version": "local-http-exchange.v1",
                    "state": {"malformed": "unhashable"},
                    "delivery_observation": "UNKNOWN",
                    "request_serialized": True,
                    "request_attempted": True,
                    "request_sha256": "e" * 64,
                    "request_bytes": 9,
                    "endpoint_sha256": "f" * 64,
                }
            },
        )


def test_failed_receipt_survives_isolated_worker_serialization_without_private_fields():
    invocation = IsolatedInvocation(RaisesWithLocalReceipt(), "__call__", (), deadline_seconds=2, output_limit=1024)
    try:
        assert invocation.wait_for_ready(timeout=2)
        with pytest.raises(IsolatedCallError) as caught:
            invocation.result()
        receipt = caught.value.meta["local_http_exchange"]
        assert receipt["state"] == "TRANSPORT_FAILURE"
        assert receipt["request_sha256"] == "c" * 64
        serialized = repr(caught.value.meta)
        assert ENDPOINT not in serialized
        assert TOKEN not in serialized
        assert "private-worker-canary" not in serialized
    finally:
        invocation.cancel()


def test_unhashable_state_does_not_mask_original_isolated_worker_exception():
    invocation = IsolatedInvocation(
        RaisesWithUnhashableReceiptState(), "__call__", (), deadline_seconds=2, output_limit=1024
    )
    try:
        assert invocation.wait_for_ready(timeout=2)
        with pytest.raises(IsolatedCallError) as caught:
            invocation.result()
        assert caught.value.remote_type == "ProviderError"
        assert str(caught.value) == "http_status_503"
        assert "local_http_exchange" not in caught.value.meta
    finally:
        invocation.cancel()
