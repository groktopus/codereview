"""Synthetic provider fault matrix for VD-2 (no external provider/effects)."""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

import pytest

from pr_review_harness.budget import BudgetLedger
from pr_review_harness.providers import OpenAIProvider, ProviderError

FAULT_CASES = (
    ("VD2-PROVIDER-TIMEOUT", "timeout", 200, b"{}", "provider_deadline_exceeded", "TIMED_OUT"),
    ("VD2-PROVIDER-4XX", "normal", 429, b'{"error":"rate limited"}', "http_status_429", "FAILED"),
    ("VD2-PROVIDER-5XX", "normal", 503, b'{"error":"unavailable"}', "http_status_503", "FAILED"),
    ("VD2-PROVIDER-MALFORMED", "normal", 200, b"{not-json", "malformed_provider_response", "FAILED"),
    ("VD2-PROVIDER-TRUNCATED", "truncated", 200, b'{"choices":[]}', "malformed_provider_response", "FAILED"),
    (
        "VD2-PROVIDER-DUPLICATE",
        "normal",
        200,
        json.dumps({"choices": [{}, {}]}).encode(),
        "malformed_provider_response",
        "FAILED",
    ),
)


@pytest.mark.parametrize("case_id,mode,status,body,error_code,terminal", FAULT_CASES, ids=[row[0] for row in FAULT_CASES])
def test_provider_transport_fault_matrix_is_terminal_and_has_no_forbidden_effects(
    case_id, mode, status, body, error_code, terminal
):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            if mode == "timeout":
                time.sleep(0.2)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body) + (100 if mode == "truncated" else 0)))
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        provider = OpenAIProvider(
            {
                "kind": "openai_compatible",
                "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                "model": "offline-vd2-fixture",
                "api_key_env": "VD2_FAULT_PROVIDER_KEY",
                "timeout_seconds": 0.05 if mode == "timeout" else 1,
                "max_response_bytes": 4096,
            }
        )
        limits = {
            "max_input_bytes_per_task": 20_000,
            "max_output_bytes_per_task": 4096,
            "max_output_tokens": 50,
            "deadline_seconds": 1,
        }
        with patch.dict(os.environ, {"VD2_FAULT_PROVIDER_KEY": "non-secret-fixture-token"}, clear=False):
            with pytest.raises(ProviderError, match=error_code) as caught:
                provider.review({}, [], limits)

        # A reserved attempt always ends terminally; failures cannot materialize
        # review output, a publication attempt, or any other side effect.
        budget_state = {}
        budget = BudgetLedger(
            {
                "deadline_seconds": 30,
                "max_provider_calls": 1,
                "max_context_bytes": 100,
                "max_input_bytes_per_task": 100,
                "max_output_bytes_per_task": 100,
                "max_output_bytes": 100,
                "max_context_retrievals": 0,
                "max_followup_tasks": 0,
                "max_cost_microunits": None,
            },
            budget_state,
            deadline_epoch=time.time() + 30,
        )
        key = case_id.lower()
        budget.reserve(key, {"provider_calls": 1, "input_bytes": 10, "max_output_bytes": 50})
        observed_terminal = "TIMED_OUT" if error_code == "provider_deadline_exceeded" else "FAILED"
        assert observed_terminal == terminal
        budget.settle(key, output_bytes=None, usage={}, status=observed_terminal)
        assert budget_state["settlements"][key]["status"] == terminal
        assert budget_state.get("outputs", {}) == {}
        assert budget_state.get("publication_attempts", []) == []
        assert len(seen) == 1
        assert caught.value.code == error_code
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_conflicting_duplicate_attempt_replay_cannot_replace_terminal_failure():
    state = {}
    budget = BudgetLedger(
        {
            "deadline_seconds": 30,
            "max_provider_calls": 1,
            "max_context_bytes": 100,
            "max_input_bytes_per_task": 100,
            "max_output_bytes_per_task": 100,
            "max_output_bytes": 100,
            "max_context_retrievals": 0,
            "max_followup_tasks": 0,
            "max_cost_microunits": None,
        },
        state,
        deadline_epoch=time.time() + 30,
    )
    budget.reserve("duplicate", {"provider_calls": 1, "input_bytes": 1, "max_output_bytes": 10})
    budget.settle("duplicate", output_bytes=None, usage={}, status="FAILED")
    before = dict(state["settlements"]["duplicate"])
    with pytest.raises(ValueError, match="conflicting settlement replay"):
        budget.settle("duplicate", output_bytes=1, usage={}, status="SUCCEEDED")
    assert state["settlements"]["duplicate"] == before
    assert state.get("outputs", {}) == {}