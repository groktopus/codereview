from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_SPEC = importlib.util.spec_from_file_location(
    "source_dispatch_accounting", ROOT / "scripts/source_dispatch_accounting.py"
)
_SANITIZER_SPEC = importlib.util.spec_from_file_location(
    "sanitize_source_dispatch_accounting", ROOT / "scripts/sanitize_source_dispatch_accounting.py"
)
assert _SOURCE_SPEC and _SOURCE_SPEC.loader and _SANITIZER_SPEC and _SANITIZER_SPEC.loader
SOURCE = importlib.util.module_from_spec(_SOURCE_SPEC)
_SOURCE_SPEC.loader.exec_module(SOURCE)
SANITIZER = importlib.util.module_from_spec(_SANITIZER_SPEC)
_SANITIZER_SPEC.loader.exec_module(SANITIZER)


@pytest.mark.parametrize("state", ["0", "1", "unknown"])
def test_exact_allowlisted_accounting_sanitizes(tmp_path, state):
    receipt = tmp_path / "raw" / "source.json"
    SOURCE.write(receipt, "PR-464", "unknown", create=True)
    if state == "1":
        SOURCE.write(receipt, "PR-464", "1")
    elif state == "0":
        SOURCE.write(receipt, "PR-464", "0")
    output = SANITIZER.sanitize(receipt, tmp_path / "sanitized")
    assert json.loads(output.read_text()) == {
        "schema": "source-dispatch-accounting.v1",
        "case_id": "PR-464",
        "source_http_attempts": state,
    }


def test_crash_after_unknown_initialization_remains_unknown(tmp_path):
    receipt = tmp_path / "accounting.json"
    SOURCE.write(receipt, "PR-464", "unknown", create=True)
    assert json.loads(receipt.read_text())["source_http_attempts"] == "unknown"


def test_proven_http_attempt_cannot_be_downgraded(tmp_path):
    receipt = tmp_path / "accounting.json"
    SOURCE.write(receipt, "PR-464", "unknown", create=True)
    SOURCE.write(receipt, "PR-464", "1")
    SOURCE.write(receipt, "PR-464", "0")
    assert json.loads(receipt.read_text())["source_http_attempts"] == "1"


def test_source_call_classification_requires_unambiguous_evidence():
    assert SOURCE.classify_source_call({"source_auditor": {"calls": []}}) == "0"
    assert SOURCE.classify_source_call({"source_auditor": {"calls": [{"dispatch_state": "http_attempted"}]}}) == "1"
    assert SOURCE.classify_source_call({"source_auditor": {"calls": [{"dispatch_state": "guard_rejected"}]}}) == "0"
    assert SOURCE.classify_source_call({"source_auditor": {"calls": [{"dispatch_state": "unknown"}]}}) == "unknown"
    assert SOURCE.classify_source_call({"source_auditor": {"calls": [{}, {}]}}) == "unknown"


@pytest.mark.parametrize("receipt", [
    {"schema": "source-dispatch-accounting.v1", "case_id": "PR-464", "source_http_attempts": "1", "raw": "secret"},
    {"schema": "source-dispatch-accounting.v1", "case_id": "PR-464", "source_http_attempts": 1},
    {"schema": "source-dispatch-accounting.v1", "case_id": "PR-457", "source_http_attempts": "0"},
    {"schema": "source-dispatch-accounting.v1", "case_id": "PR-464", "source_http_attempts": "2"},
])
def test_sanitizer_rejects_invalid_or_sensitive_receipt_fields(receipt):
    with pytest.raises(SANITIZER.ReceiptError):
        SANITIZER.validate(receipt)


def test_missing_receipt_cannot_be_sanitized(tmp_path):
    with pytest.raises(FileNotFoundError):
        SANITIZER.sanitize(tmp_path / "missing.json", tmp_path / "out")
