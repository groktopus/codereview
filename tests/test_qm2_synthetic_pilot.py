import hashlib
import json
from pathlib import Path

from experiments.harness.evaluation import validate_labels

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "examples/evaluation/qm2-labeling-pilot-v1"


def _load(name: str):
    return json.loads((PILOT / name).read_text())


def test_synthetic_pilot_labels_validate_and_bind_provenance():
    labels = validate_labels(_load("labels-synthetic-v1.json"), _load("corpus.json"), _load("predictions.json"))
    manifest = _load("manifest.json")
    run = manifest["synthetic_run"]
    teacher = (PILOT / run["teacher_output"]).read_bytes()
    assert hashlib.sha256(teacher).hexdigest() == run["teacher_output_sha256"]
    assert hashlib.sha256((PILOT / run["label_file"]).read_bytes()).hexdigest() == run["label_file_sha256"]
    assert len(labels["packets"]) == 6
    assert all(packet["reviewer"]["reviewer_kind"] == "synthetic" for packet in labels["packets"])
    assert all(packet["reviewer"]["output_sha256"] == run["teacher_output_sha256"] for packet in labels["packets"])
    assert all(packet["case_completeness"] == "COMPLETE" for packet in labels["packets"])
