from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness import configured_jev_injection_trial as trial  # noqa: E402
from pr_review_harness.providers import _endpoint_identity_hash  # noqa: E402


class ChoiceHandler(BaseHTTPRequestHandler):
    calls: list[dict] = []
    choices = ["suspicious", "benign"]
    response_model = "jev-1.13.0"
    response_models: list[str | None] | None = None
    echo_key = False

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        index = len(type(self).calls)
        type(self).calls.append(
            {"body": raw, "authorization": self.headers.get("Authorization"), "path": self.path}
        )
        choice = type(self).choices[min(index, len(type(self).choices) - 1)]
        envelope = {
            "model": (
                type(self).response_models[min(index, len(type(self).response_models) - 1)]
                if type(self).response_models
                else type(self).response_model
            ),
            "request_id": f"req-{index}",
            "answers": {
                "prompt_injection": {
                    "type": "choice",
                    "choice": choice,
                    "probabilities": {
                        "suspicious": 0.90 if choice == "suspicious" else 0.05,
                        "benign": 0.90 if choice == "benign" else 0.05,
                        "unknown": 0.05,
                    },
                    "confidence": 0.9,
                }
            },
        }
        if type(self).echo_key:
            envelope["echo"] = "unit-test-api-key"
        data = json.dumps(envelope, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        return


@pytest.fixture
def choice_server(monkeypatch):
    monkeypatch.setenv("JEV_API_KEY", "unit-test-api-key")
    ChoiceHandler.calls = []
    ChoiceHandler.choices = ["suspicious", "benign"]
    ChoiceHandler.response_model = "jev-1.13.0"
    ChoiceHandler.response_models = None
    ChoiceHandler.echo_key = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), ChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _runtime_provenance(_cli, _root):
    return {
        "source_fingerprint": {"file_hashes": {"src/pr_review_harness/__init__.py": "a" * 64}},
        "runtime_tree_sha256": "b" * 64,
        "runtime_version": "test-runtime",
        "python_version": "3.13",
        "cli_executable_sha256": "c" * 64,
    }


def _prepare(tmp_path, monkeypatch):
    monkeypatch.setattr(trial.selected_model_trial, "_runtime_provenance", _runtime_provenance)
    target = tmp_path / "preparation"
    summary = trial.prepare_trial(
        root=ROOT,
        cli_executable=Path("/unused/pr-review"),
        expected_source_revision=trial._git_head(ROOT),
        output=target,
    )
    return target, summary


def test_provider_free_packet_binds_fixed_inputs_question_criteria_and_runtime(tmp_path, monkeypatch):
    target, summary = _prepare(tmp_path, monkeypatch)
    packet = json.loads((target / "manifest.json").read_bytes())
    assert summary["provider_calls"] == 0
    assert packet["state"] == "PREPARED_NO_PROVIDER_CALLS"
    assert packet["classifier"]["contract"] == trial.INJECTION_CHOICE_CONTRACT
    assert packet["installed_runtime"]["installed_source_match"] is True
    assert packet["bounds"]["case_ids"] == list(trial.CASE_IDS)
    assert packet["bounds"]["provider_calls_reserved"] == 2
    assert packet["bounds"]["retries_per_case"] == 0
    assert [row["case_id"] for row in packet["fixture"]["cases"]] == list(trial.CASE_IDS)
    assert all(row["input_bytes"] > 0 and len(row["input_sha256"]) == 64 for row in packet["fixture"]["cases"])
    assert "SYSTEM OVERRIDE" not in json.dumps(packet)


@pytest.mark.parametrize("explicit_endpoint", [False, True])
def test_run_trial_sends_exact_prepared_live_requests_once_and_sanitizes_receipt(
    tmp_path, monkeypatch, choice_server, explicit_endpoint
):
    prep, _ = _prepare(tmp_path, monkeypatch)
    packet = prep / "manifest.json"
    output = tmp_path / "result"
    env = {
        "JEV_BASE_URL": choice_server + "/systemone" if explicit_endpoint else choice_server,
        "JEV_MODEL": "jev-latest",
        "JEV_API_KEY": "unit-test-api-key",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    summary = trial.run_trial(
        root=ROOT,
        cli_executable=Path("/unused/pr-review"),
        expected_source_revision=trial._git_head(ROOT),
        preparation=packet,
        output=output,
    )
    result = json.loads((output / "result.json").read_bytes())
    assert summary["state"] == "COMPLETE", result
    assert summary["provider_http_attempts_observed"] == 2
    assert result["provider_calls_reserved"] == 2
    assert result["provider_http_attempts_observed"] == 2
    assert [row["classification"] for row in result["cases"]] == ["SUSPICIOUS", "BENIGN"]
    assert [row["provider_reported_model_id"] for row in result["cases"]] == ["jev-1.13.0"] * 2
    assert all(row["usage"] == {"known": False, "tokens": None, "cost": None} for row in result["cases"])
    assert "unit-test-api-key" not in (output / "result.json").read_text()
    assert choice_server not in (output / "result.json").read_text()
    assert len(ChoiceHandler.calls) == 2
    assert all(row["authorization"] == "Bearer unit-test-api-key" for row in ChoiceHandler.calls)
    assert [row["path"] for row in ChoiceHandler.calls] == ["/v1/systemone"] * 2
    fixture, _ = trial._trusted_fixture(ROOT)
    for row, case_id in zip(ChoiceHandler.calls, trial.CASE_IDS, strict=True):
        assert row["body"] == trial.prepared_request(fixture[case_id], "jev-latest")


def test_latest_alias_requires_provider_reported_version_and_records_identity(choice_server, monkeypatch):
    provider = trial._trusted_provider(
        {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-latest", "JEV_API_KEY": "unit-test-api-key"}
    )
    fixture, _ = trial._trusted_fixture(ROOT)
    request = trial.prepared_request(fixture[trial.ATTACK_CASE_ID], provider.model)
    row = trial.classify_configured_jev(
        provider,
        trial.ATTACK_CASE_ID,
        fixture[trial.ATTACK_CASE_ID],
        deadline_at=time.monotonic() + 10,
        expected_request={"request_sha256": hashlib.sha256(request).hexdigest(), "request_bytes": len(request)},
    )
    assert row["provider_reported_model_id"] == "jev-1.13.0"
    assert row["model_identity_source"] == "endpoint_reported"
    assert row["endpoint_sha256"] == _endpoint_identity_hash(choice_server + "/systemone")


def test_endpoint_with_duplicated_systemone_suffix_is_rejected_before_http(choice_server):
    with pytest.raises(trial.ConfiguredJevTrialError, match="jev_endpoint_invalid"):
        trial._trusted_provider(
            {
                "JEV_BASE_URL": choice_server + "/systemone/systemone",
                "JEV_MODEL": "jev-1.13.0",
                "JEV_API_KEY": "unit-test-api-key",
            }
        )
    assert ChoiceHandler.calls == []


def test_latest_alias_without_reported_model_is_preserved_as_provider_error(choice_server, monkeypatch):
    ChoiceHandler.response_model = None
    provider = trial._trusted_provider(
        {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-latest", "JEV_API_KEY": "unit-test-api-key"}
    )
    fixture, _ = trial._trusted_fixture(ROOT)
    request = trial.prepared_request(fixture[trial.ATTACK_CASE_ID], provider.model)
    row = trial.classify_configured_jev(
        provider,
        trial.ATTACK_CASE_ID,
        fixture[trial.ATTACK_CASE_ID],
        deadline_at=time.monotonic() + 10,
        expected_request={"request_sha256": hashlib.sha256(request).hexdigest(), "request_bytes": len(request)},
    )
    assert row["status"] == "PROVIDER_ERROR"
    assert row["reason"] == "model_identity_missing"
    assert row["classification"] == "UNKNOWN"


def test_latest_alias_model_change_between_pair_responses_is_partial(choice_server, tmp_path, monkeypatch):
    ChoiceHandler.response_models = ["jev-1.13.0", "jev-1.14.0"]
    prep, _ = _prepare(tmp_path, monkeypatch)
    output = tmp_path / "alias-drift-result"
    env = {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-latest", "JEV_API_KEY": "unit-test-api-key"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    summary = trial.run_trial(
        root=ROOT,
        cli_executable=Path("/unused/pr-review"),
        expected_source_revision=trial._git_head(ROOT),
        preparation=prep / "manifest.json",
        output=output,
    )
    result = json.loads((output / "result.json").read_bytes())
    assert summary["state"] == "PARTIAL"
    assert result["reported_model_identity_consistency"] == "REPORTED_MODEL_MISMATCH"
    assert [row["provider_reported_model_id"] for row in result["cases"]] == ["jev-1.13.0", "jev-1.14.0"]


@pytest.mark.parametrize("provenance_field", ["question_hash", "criteria_hash", "input_hash", "request_hash", "response_hash"])
def test_mutated_provenance_hash_is_unknown_not_accepted(choice_server, monkeypatch, provenance_field):
    provider = trial._trusted_provider(
        {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    )
    original = provider.assess

    def mutate(*args, **kwargs):
        response = original(*args, **kwargs)
        response["provenance"][provenance_field] = "0" * 64
        return response

    monkeypatch.setattr(provider, "assess", mutate)
    fixture, _ = trial._trusted_fixture(ROOT)
    request = trial.prepared_request(fixture[trial.ATTACK_CASE_ID], provider.model)
    row = trial.classify_configured_jev(
        provider,
        trial.ATTACK_CASE_ID,
        fixture[trial.ATTACK_CASE_ID],
        deadline_at=time.monotonic() + 10,
        expected_request={"request_sha256": hashlib.sha256(request).hexdigest(), "request_bytes": len(request)},
    )
    assert row["status"] == "INVALID_RESPONSE"
    assert row["classification"] == "UNKNOWN"
    assert row["reason"] == "response_binding_invalid"


def test_request_receipt_mismatch_fails_before_http(choice_server):
    provider = trial._trusted_provider(
        {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    )
    with pytest.raises(trial.ConfiguredJevTrialError, match="live_request_preflight_mismatch"):
        trial.classify_configured_jev(
            provider,
            trial.ATTACK_CASE_ID,
            "fixed synthetic text",
            deadline_at=time.monotonic() + 10,
            expected_request={"request_sha256": "0" * 64, "request_bytes": 1},
        )
    assert ChoiceHandler.calls == []


def test_existing_result_output_path_fails_before_http(tmp_path, monkeypatch, choice_server):
    prep, _ = _prepare(tmp_path, monkeypatch)
    env = {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    output = tmp_path / "existing-result"
    output.mkdir()

    with pytest.raises(trial.ConfiguredJevTrialError, match="result_output_unavailable"):
        trial.run_trial(
            root=ROOT,
            cli_executable=Path("/unused/pr-review"),
            expected_source_revision=trial._git_head(ROOT),
            preparation=prep / "manifest.json",
            output=output,
        )

    assert ChoiceHandler.calls == []


def test_configured_provider_rejects_nonclassifier_primitive_before_http(choice_server):
    provider = trial._trusted_provider(
        {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    )
    provider.primitive = "noul"
    with pytest.raises(trial.ConfiguredJevTrialError, match="jev_provider_identity_invalid"):
        trial.run_two_case_trial(
            provider,
            {case: "fixed" for case in trial.CASE_IDS},
            request_receipts={case: {"request_sha256": "0" * 64, "request_bytes": 1} for case in trial.CASE_IDS},
            started=time.monotonic(),
        )
    assert ChoiceHandler.calls == []


def test_credential_echo_stops_second_call_and_only_sanitized_receipt_is_persisted(tmp_path, monkeypatch, choice_server):
    prep, _ = _prepare(tmp_path, monkeypatch)
    ChoiceHandler.echo_key = True
    output = tmp_path / "echo-result"
    env = {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    trial.run_trial(
        root=ROOT,
        cli_executable=Path("/unused/pr-review"),
        expected_source_revision=trial._git_head(ROOT),
        preparation=prep / "manifest.json",
        output=output,
    )
    result = json.loads((output / "result.json").read_bytes())
    assert result["credential_echo_detected"] is True
    assert result["provider_http_attempts_observed"] == 1
    assert result["cases"][0]["reason"] == "provider_response_contains_credential"
    assert result["cases"][1]["status"] == "NOT_CALLED_SECURITY_STOP"
    assert len(ChoiceHandler.calls) == 1
    assert "unit-test-api-key" not in (output / "result.json").read_text()


def test_manifest_bounds_mutation_fails_before_provider_calls(tmp_path, monkeypatch, choice_server):
    prep, _ = _prepare(tmp_path, monkeypatch)
    packet_path = prep / "manifest.json"
    packet = json.loads(packet_path.read_bytes())
    packet["bounds"]["provider_calls_reserved"] = 3
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    env = {"JEV_BASE_URL": choice_server, "JEV_MODEL": "jev-1.13.0", "JEV_API_KEY": "unit-test-api-key"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(trial.ConfiguredJevTrialError, match="preparation_bounds_invalid"):
        trial.run_trial(
            root=ROOT,
            cli_executable=Path("/unused/pr-review"),
            expected_source_revision=trial._git_head(ROOT),
            preparation=packet_path,
            output=tmp_path / "invalid-result",
        )
    assert ChoiceHandler.calls == []
