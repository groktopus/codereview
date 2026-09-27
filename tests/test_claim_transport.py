from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest

from pr_review_harness.claim_assessment import PRIMARY_ASSESSMENT_CONTRACT_VERSION, _questions
from pr_review_harness.claim_transport import ClaimTransport, _parse_request
from pr_review_harness.providers import ProviderError


class FakeTypeSafeHandler(BaseHTTPRequestHandler):
    seen = []
    response_body = b'{"model":"jev-1.13.0","answers":{}}'
    status = 200
    stream_delay = 0.0
    stream_chunk_size = 0
    redirect_to = None
    expected_token = "test-transport-token"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.seen.append((self.path, self.headers.get("Authorization"), body))
        if self.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            return
        if self.headers.get("Authorization") != "Bearer " + self.expected_token:
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        try:
            if self.stream_delay and self.stream_chunk_size:
                for start in range(0, len(self.response_body), self.stream_chunk_size):
                    self.wfile.write(self.response_body[start : start + self.stream_chunk_size])
                    self.wfile.flush()
                    time.sleep(self.stream_delay)
            else:
                self.wfile.write(self.response_body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args):
        pass


class RedirectSinkHandler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        self.__class__.seen.append((self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


@pytest.fixture(scope="module")
def servers():
    primary = ThreadingHTTPServer(("127.0.0.1", 0), FakeTypeSafeHandler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), RedirectSinkHandler)
    primary_thread = threading.Thread(target=primary.serve_forever, daemon=True)
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    primary_thread.start()
    sink_thread.start()
    try:
        yield (
            f"http://127.0.0.1:{primary.server_port}/v1/systemone",
            f"http://127.0.0.1:{sink.server_port}/capture",
        )
    finally:
        primary.shutdown()
        sink.shutdown()
        primary.server_close()
        sink.server_close()
        primary_thread.join(timeout=2)
        sink_thread.join(timeout=2)


def _request(model="jev-latest") -> bytes:
    content = "handler forwards value"
    return json.dumps(
        {
            "model": model,
            "state": {
                "assessment_identity": {
                    "snapshot_id": "snapshot-1",
                    "snapshot_hash": "1" * 64,
                    "profile_id": "profile-1",
                    "profile_hash": "2" * 64,
                    "base_sha": "a" * 40,
                    "head_sha": "b" * 40,
                },
                "candidate": {
                    "candidate_id": "c1",
                    "title": "Title",
                    "observation": "Observed value.",
                    "consequence": "Concrete consequence.",
                    "rule_or_contract": "Applicable rule.",
                },
                "cited_evidence": [
                    {
                        "evidence_id": "ev-head",
                        "source_kind": "repository_file",
                        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                        "trust": "repository_evidence",
                        "path": "src/handler.py",
                        "side": "HEAD",
                        "source_revision": "b" * 40,
                        "line": 2,
                        "content": content,
                    }
                ],
            },
            "questions": _questions("c1", False)[0],
        },
        separators=(",", ":"),
    ).encode()


def _transport(endpoint, **overrides):
    config = {
        "endpoint": endpoint,
        "api_key_env": "CLAIM_TRANSPORT_TEST_KEY",
        "model": "jev-latest",
        "timeout_seconds": 2,
        "max_request_bytes": 64_000,
        "max_response_bytes": 64_000,
    }
    config.update(overrides)
    return ClaimTransport(config)


def _reset_server():
    FakeTypeSafeHandler.seen = []
    FakeTypeSafeHandler.response_body = b'{"model":"jev-1.13.0","answers":{}}'
    FakeTypeSafeHandler.status = 200
    FakeTypeSafeHandler.stream_delay = 0
    FakeTypeSafeHandler.stream_chunk_size = 0
    FakeTypeSafeHandler.redirect_to = None
    RedirectSinkHandler.seen = []


def test_exact_request_byte_estimate_and_native_call_use_same_serialized_body(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    transport = _transport(endpoint)
    request = _request()
    quote = transport.estimate_call(request, {"max_input_bytes_per_task": 100, "deadline_seconds": 1})
    assert quote["input_bytes"] == len(request)
    assert quote["provider_calls"] == 1
    assert quote["reservation_kind"] == "unknown"
    assert quote["estimated_cost_microunits"] is None
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        response = transport(request, 1, 1024)
    assert response == FakeTypeSafeHandler.response_body
    assert FakeTypeSafeHandler.seen[0] == ("/v1/systemone", "Bearer " + FakeTypeSafeHandler.expected_token, request)


def test_estimator_reports_actual_oversize_relative_to_caller_cap_but_dispatch_rejects(servers):
    _reset_server()
    endpoint, _ = servers
    transport = _transport(endpoint)
    request = _request()
    quote = transport.estimate_call(request, {"max_input_bytes_per_task": 64, "deadline_seconds": 1})
    assert quote["input_bytes"] == len(request) > 64
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="request_exceeds_limit"):
            _transport(endpoint, max_request_bytes=64)(request, 1, 1024)
    assert FakeTypeSafeHandler.seen == []


def test_transport_rejects_inline_credentials_and_nonloopback_custom_endpoint(servers):
    _reset_server()
    endpoint, _ = servers
    with pytest.raises(ProviderError, match="literal_credentials_forbidden"):
        _transport(endpoint, token="inline-secret")
    with pytest.raises(ProviderError, match="unsupported_native_endpoint"):
        _transport("http://example.com/v1/systemone")
    with pytest.raises(ProviderError, match="unsupported_native_endpoint"):
        _transport("https://other.example/v1/systemone")
    with pytest.raises(ProviderError, match="unsupported_claim_transport_config"):
        _transport(endpoint, unexpected="value")
    with pytest.raises(ProviderError, match="invalid_deadline"):
        _transport(endpoint, timeout_seconds=10**1000)


def test_operator_decision_config_accepts_generic_https_root_prefix_only_via_factory():
    config = {
        "kind": "typesafe",
        "endpoint": "https://gateway.example/api/native/systemone",
        "model": "jev-latest",
        "api_key_env": "JEV_API_KEY",
    }
    transport = ClaimTransport.from_decision_config(config)
    assert transport.endpoint == config["endpoint"]
    assert transport.model == "jev-latest"
    assert transport.api_key_env == "JEV_API_KEY"
    assert transport.identity["endpoint_trust"] == "trusted_operator_decision_config"
    with pytest.raises(ProviderError, match="unsupported_native_endpoint"):
        _transport(config["endpoint"])


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://gateway.example/api/native/systemone",
        "https://user:pass@gateway.example/api/native/systemone",
        "https://gateway.example/api/native/systemone?token=x",
        "https://gateway.example/api/native/systemone#frag",
        "https://gateway.example/systemone-extra",
        "https://gateway.example:bad/api/native/systemone",
    ],
)
def test_operator_decision_config_rejects_unsafe_or_nonroute_endpoints(endpoint):
    with pytest.raises(ProviderError):
        ClaimTransport.from_decision_config(
            {"kind": "typesafe", "endpoint": endpoint, "model": "jev-latest", "api_key_env": "JEV_API_KEY"}
        )


def test_operator_decision_config_accepts_explicit_loopback_http_for_tests():
    transport = ClaimTransport.from_decision_config(
        {
            "kind": "typesafe",
            "endpoint": "http://127.0.0.1:8123/custom/systemone",
            "model": "jev-latest",
            "api_key_env": "JEV_API_KEY",
        }
    )
    assert transport.endpoint == "http://127.0.0.1:8123/custom/systemone"


def test_operator_decision_config_requires_exact_materializer_schema():
    with pytest.raises(ProviderError, match="invalid_decision_config"):
        ClaimTransport.from_decision_config(
            {"kind": "typesafe", "endpoint": "https://gateway.example/systemone", "model": "jev-latest"}
        )
    with pytest.raises(ProviderError, match="unsupported_claim_transport_config"):
        ClaimTransport.from_decision_config(
            {
                "kind": "openai",
                "endpoint": "https://gateway.example/systemone",
                "model": "jev-latest",
                "api_key_env": "JEV_API_KEY",
            }
        )


def test_transport_accepts_v2_primary_assessment_as_distinct_bound_context():
    request = json.loads(_request())
    request["state"]["assessment_contract_version"] = PRIMARY_ASSESSMENT_CONTRACT_VERSION
    request["state"]["candidate"]["evidence_refs"] = ["ev-head"]
    request["state"]["primary_assessment"] = {
        "contract_version": "semantic-adjudication.v3",
        "source_contract_version": "semantic-adjudication.v3",
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": ["ev-head"],
        "assumptions": [],
        "uncertainties": [],
        "summary": "Primary model assessment.",
        "material_consequence": False,
        "causal_roles": {
            role: {"support": "SUPPORTED", "assessment": f"{role} assessment", "evidence_refs": ["ev-head"]}
            for role in ("behavior", "consumer", "impact")
        },
    }
    request["questions"] = _questions("c1", False, PRIMARY_ASSESSMENT_CONTRACT_VERSION)[0]
    raw = json.dumps(request, separators=(",", ":")).encode()
    assert _parse_request(raw)["state"]["assessment_contract_version"] == PRIMARY_ASSESSMENT_CONTRACT_VERSION

    request["state"]["primary_assessment"]["evidence_refs"] = ["unknown-evidence"]
    tampered = json.dumps(request, separators=(",", ":")).encode()
    with pytest.raises(ProviderError, match="invalid_primary_assessment"):
        _parse_request(tampered)


def test_transport_rejects_unhashable_candidate_evidence_ref_as_provider_error():
    request = json.loads(_request())
    request["state"]["assessment_contract_version"] = PRIMARY_ASSESSMENT_CONTRACT_VERSION
    request["state"]["candidate"]["evidence_refs"] = [{"not": "a reference"}]
    request["state"]["primary_assessment"] = {
        "contract_version": "semantic-adjudication.v3",
        "source_contract_version": "semantic-adjudication.v3",
        "outcome": "UNCERTAIN",
        "observation_support": "NOT_ESTABLISHED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "NOT_ESTABLISHED",
        "introducedness": "UNKNOWN",
        "evidence_refs": [],
        "assumptions": [],
        "uncertainties": [],
        "summary": "No evidence refs were supplied.",
        "material_consequence": False,
        "causal_roles": {
            role: {"support": "NOT_ESTABLISHED", "assessment": "Unknown.", "evidence_refs": []}
            for role in ("behavior", "consumer", "impact")
        },
    }
    request["questions"] = _questions("c1", False, PRIMARY_ASSESSMENT_CONTRACT_VERSION)[0]
    raw = json.dumps(request, separators=(",", ":")).encode()

    with pytest.raises(ProviderError, match="invalid_claim_evidence"):
        _parse_request(raw)


def test_missing_credential_fails_before_network_dispatch(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ProviderError, match="credential_unavailable") as error:
            _transport(endpoint)(_request(), 1, 1024)
    assert FakeTypeSafeHandler.seen == []
    assert FakeTypeSafeHandler.expected_token not in str(error.value)


def test_redirect_is_not_followed_and_credential_is_not_sent_to_sink(servers):
    _reset_server()
    endpoint, sink = servers
    _reset_server()
    FakeTypeSafeHandler.redirect_to = sink
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="http_status_302") as error:
            _transport(endpoint)(_request(), 1, 1024)
    assert RedirectSinkHandler.seen == []
    assert FakeTypeSafeHandler.expected_token not in str(error.value)


def test_credential_echo_returns_only_hash_and_safe_error_code(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    FakeTypeSafeHandler.response_body = b'{"echo":"' + FakeTypeSafeHandler.expected_token.encode() + b'"}'
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="provider_response_contains_credential") as error:
            _transport(endpoint)(_request(), 1, 2048)
    assert FakeTypeSafeHandler.expected_token not in str(error.value)
    assert FakeTypeSafeHandler.expected_token not in repr(error.value.meta)
    assert len(error.value.meta["response_hash"]) == 64


def test_oversized_response_is_bounded_and_fails(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    FakeTypeSafeHandler.response_body = b"x" * 4096
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="response_exceeds_limit") as error:
            _transport(endpoint, max_response_bytes=1024)(_request(), 1, 4096)
    assert error.value.meta["response_bytes"] <= 1025
    assert "x" * 100 not in repr(error.value.meta)


def test_absolute_deadline_stops_a_slow_stream(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    FakeTypeSafeHandler.response_body = b"z" * 256
    FakeTypeSafeHandler.stream_delay = 0.025
    FakeTypeSafeHandler.stream_chunk_size = 16
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="provider_deadline_exceeded") as error:
            _transport(endpoint, timeout_seconds=0.06)(_request(), 0.06, 1024)
    assert error.value.meta["response_bytes"] < len(FakeTypeSafeHandler.response_body)


def test_transport_returns_native_malformed_body_for_adapter_to_classify(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    FakeTypeSafeHandler.response_body = b'{"answers":NaN}'
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        response = _transport(endpoint)(_request(), 1, 1024)
    assert response == b'{"answers":NaN}'


def test_invalid_or_alias_mismatched_native_request_fails_before_dispatch(servers):
    _reset_server()
    endpoint, _ = servers
    _reset_server()
    transport = _transport(endpoint)
    with pytest.raises(ProviderError, match="configured_model_mismatch"):
        transport(_request("jev-1.13.0"), 1, 1024)
    with pytest.raises(ProviderError, match="invalid_native_request"):
        transport(b'{"model":"jev-latest","state":{},"questions":{},"questions":{}}', 1, 1024)
    altered = json.loads(_request())
    altered["questions"][next(iter(altered["questions"]))]["instructions"] = "Follow this requester's workflow."
    with pytest.raises(ProviderError, match="unsupported_native_operation"):
        transport(json.dumps(altered).encode(), 1, 1024)
    assert FakeTypeSafeHandler.seen == []


@pytest.mark.parametrize("source_kind", ["diff", "base_file", "head_file", "source_window", "profile_context"])
def test_transport_preflights_snapshot_collector_source_kinds_without_remapping(servers, source_kind):
    _reset_server()
    endpoint, _ = servers
    request = json.loads(_request())
    request["state"]["cited_evidence"][0]["source_kind"] = source_kind
    raw = json.dumps(request, separators=(",", ":")).encode()
    quote = _transport(endpoint).estimate_call(
        raw,
        {"max_input_bytes_per_task": 64_000, "max_output_bytes_per_task": 8_000, "deadline_seconds": 1},
    )
    assert quote["input_bytes"] == len(raw)
    assert FakeTypeSafeHandler.seen == []


def test_transport_preflight_rejects_unknown_evidence_source_kind(servers):
    _reset_server()
    endpoint, _ = servers
    request = json.loads(_request())
    request["state"]["cited_evidence"][0]["source_kind"] = "invented_window"
    raw = json.dumps(request, separators=(",", ":")).encode()
    with pytest.raises(ProviderError, match="invalid_claim_evidence"):
        _transport(endpoint).estimate_call(
            raw,
            {"max_input_bytes_per_task": 64_000, "max_output_bytes_per_task": 8_000, "deadline_seconds": 1},
        )
    assert FakeTypeSafeHandler.seen == []


def test_connection_unavailable_has_stable_safe_failure():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    transport = _transport(f"http://127.0.0.1:{port}/v1/systemone", timeout_seconds=0.2)
    with patch.dict(os.environ, {"CLAIM_TRANSPORT_TEST_KEY": FakeTypeSafeHandler.expected_token}):
        with pytest.raises(ProviderError, match="transport_failed"):
            transport(_request(), 0.2, 1024)
