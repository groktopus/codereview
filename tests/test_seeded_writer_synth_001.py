from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"


def _model_payload() -> bytes:
    seed = json.loads((FIXTURE / "seed.json").read_text())
    files = {
        relative: (FIXTURE / relative).read_text()
        for relative in seed["visible_files"]
    }
    return json.dumps(
        {"fixture_id": seed["fixture_id"], "seed": seed["seed"], "files": files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_synth_001_is_deterministic_and_truth_stays_out_of_model_payload():
    seed = json.loads((FIXTURE / "seed.json").read_text())
    truth_raw = (FIXTURE / "truth.json").read_bytes()
    truth = json.loads(truth_raw)
    payload = _model_payload()

    assert seed["fixture_id"] == truth["fixture_id"] == "SYNTH-001"
    assert seed["seed"] == 457001
    assert payload == _model_payload()
    assert hashlib.sha256(payload).hexdigest() == truth["model_payload_sha256"]

    visible = set(seed["visible_files"])
    assert "truth.json" not in visible
    assert truth["model_input"] is False
    for relative, expected_sha256 in truth["sha256"].items():
        actual = hashlib.sha256((FIXTURE / relative).read_bytes()).hexdigest()
        assert actual == expected_sha256

    assert truth["expected_changed_path"] == "auth.py"
    assert truth["expected_changed_line"] in (FIXTURE / "head/auth.py").read_text().splitlines()
    assert b"expected_changed_line" not in payload
    assert b"expected_behavior" not in payload
    assert truth["expected_behavior"].encode() not in payload
    assert truth_raw not in payload
