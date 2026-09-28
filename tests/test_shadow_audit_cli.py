from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("legacy_shadow_audit_cli", ROOT / "scripts/run_shadow_audit.py")
CLI = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CLI)


def test_legacy_cli_supplies_finite_stage_guard_limits_without_dispatch(tmp_path, monkeypatch, capsys):
    observed = {}

    class FakeProvider:
        def __init__(self, _config):
            pass

    class FakeClaimTransport:
        @classmethod
        def from_decision_config(cls, _config):
            return object()

    def fake_run(_packet, **kwargs):
        observed.update(kwargs)
        guard = kwargs["before_dispatch"]
        guard("source_auditor", b'{"max_completion_tokens":1800}')
        guard("jev", b'{"native":"prepared"}')
        guard("claim_auditor", b'{"max_completion_tokens":1800}')
        return {"manifest": {"terminal_state": "completed", "case_id": "case-test"}}

    monkeypatch.setattr(CLI, "_read_json", lambda *_args: {})
    monkeypatch.setattr(CLI, "OpenAIProvider", FakeProvider)
    monkeypatch.setattr(CLI, "ClaimTransport", FakeClaimTransport)
    monkeypatch.setattr(CLI, "run_shadow_audit", fake_run)
    code = CLI.main([
        "--case", str(tmp_path / "case.json"),
        "--source-provider-config", str(tmp_path / "source.json"),
        "--claim-provider-config", str(tmp_path / "claim.json"),
        "--jev-config", str(tmp_path / "jev.json"),
        "--output-dir", str(tmp_path / "private"), "--live", "--json",
    ])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["terminal_state"] == "completed"
    assert observed["limits"] == CLI.LEGACY_AUDIT_LIMITS
    assert observed["limits"]["max_output_tokens"] == 1_800
    assert observed["limits"]["deadline_seconds"] == 12
    assert observed["limits"]["total_provider_deadline_seconds"] == 36
