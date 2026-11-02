"""Provenance and evidence-boundary tests for the retained synthetic QM-2 pilot."""

from __future__ import annotations

import gzip
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from experiments.harness.evaluation import validate_labels
from experiments.harness.scorecard import build_scorecard

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "examples/evaluation/qm2-labeling-pilot-v1"
EVIDENCE = PILOT / "evidence"
FROZEN_MANIFEST = ROOT / "examples/evaluation/frozen-corpus-v1/manifest.json"
LABELS = PILOT / "labels-synthetic-v1.json"
TEACHER_OUTPUT = PILOT / "teacher-output-2026-11-02.json"
TEACHER_RESPONSE = EVIDENCE / "teacher-response.txt"
PROMPT = EVIDENCE / "prompt.md"
REQUEST = EVIDENCE / "request.json"

PROMPT_REVISION = "qm2-synthetic-adjudication-prompt-v1"
RUBRIC_REVISION = "qm2-labeling-rubric.v1"
RUN_ID = "qm2-synthetic-pilot-2026-11-02"
LABELED_AT = "2026-11-02T22:26:00Z"
PROVIDER_ID = "deepseek"
MODEL_ID = "deepseek-v4.1-flash-1017"
MODEL_REVISION = "deepseek-v4.1-flash-1017"
INCOMPLETE_CASE = "qm1-slopsearx-pr770"


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _without_output_hash(packet: dict) -> dict:
    stripped = deepcopy(packet)
    stripped["reviewer"].pop("output_sha256")
    return stripped


@pytest.fixture(scope="module")
def pilot() -> dict:
    return {
        "manifest": _load(PILOT / "manifest.json"),
        "corpus": _load(PILOT / "corpus.json"),
        "labels": _load(LABELS),
        "output": _load(TEACHER_OUTPUT),
        "response": _load(TEACHER_RESPONSE),
        "request": _load(REQUEST),
        "frozen": {case["case_id"]: case for case in _load(FROZEN_MANIFEST)["cases"]},
    }


def test_manifest_hashes_every_retained_pilot_input(pilot: dict) -> None:
    manifest = pilot["manifest"]
    expected = {
        "labels-synthetic-v1.json",
        "teacher-output-2026-11-02.json",
        "evidence/prompt.md",
        "evidence/request.json",
        "evidence/teacher-response.txt",
    }
    expected |= {f"evidence/{case_id}.diff.gz" for case_id in manifest["selection"]["case_ids"]}
    hashes = manifest["content_hashes"]
    assert expected <= set(hashes)
    for relative, digest in hashes.items():
        path = PILOT / relative
        assert path.is_file(), relative
        assert digest == _sha(path), relative

    state = manifest["label_packet_state"]
    assert state["state"] == "present"
    assert state["label_source"] == "synthetic"
    assert state["human_packets"] == 0
    assert state["model_teacher_screening_packets"] == 0
    assert state["unknown_provenance_packets"] == 0
    assert state["synthetic_present"] is True
    assert state["synthetic_adjudicated_packets"] == 6
    assert state["synthetic_complete_packets"] == 5
    assert state["synthetic_incomplete_packets"] == 1
    assert "missing" not in state["reason"].lower()
    assert state["packet_version"] == "labels-synthetic-v1"


def test_request_binds_prompt_provider_and_exact_diff_bytes(pilot: dict) -> None:
    manifest = pilot["manifest"]
    request = pilot["request"]
    teacher = manifest["teacher_output"]

    assert request["prompt"]["sha256"] == _sha(PROMPT)
    assert manifest["retained_evidence"]["prompt"]["sha256"] == _sha(PROMPT)
    assert request["prompt"]["revision"] == PROMPT_REVISION
    assert manifest["retained_evidence"]["prompt"]["revision"] == PROMPT_REVISION

    for key, value in {
        "provider_id": PROVIDER_ID,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
    }.items():
        assert request["provider"][key] == value
        assert teacher[key] == value
    assert request["rubric_revision"] == RUBRIC_REVISION
    assert request["run_id"] == RUN_ID
    assert teacher["run_id"] == RUN_ID
    assert teacher["labeled_at"] == LABELED_AT

    case_ids = [case["case_id"] for case in request["cases"]]
    assert len(case_ids) == len(set(case_ids)) == 6
    assert case_ids == manifest["selection"]["case_ids"]
    assert set(case_ids) == {case["identity"]["case_id"] for case in pilot["corpus"]["cases"]}

    for case in request["cases"]:
        diff = EVIDENCE / case["diff_path"]
        assert diff.is_file() and diff.stat().st_size > 0
        raw = gzip.decompress(diff.read_bytes())
        assert case["diff_sha256"] == hashlib.sha256(raw).hexdigest()
        assert case["bytes"] == len(raw)
        retained = manifest["retained_evidence"]["cases"][case["case_id"]]
        assert retained["diff_path"] == f"evidence/{case['diff_path']}"
        assert retained["diff_sha256"] == case["diff_sha256"]
        assert retained["bytes"] == case["bytes"]
        frozen = pilot["frozen"][case["case_id"]]
        assert case["evidence_completeness"] == frozen["evidence_completeness"]
        assert case["snapshot_id"] == frozen["snapshot_id"]
        assert case["source_manifest_sha256"] == frozen["source_manifest_sha256"]


def test_response_digest_is_exact_and_output_adds_only_that_digest(pilot: dict) -> None:
    response_digest = _sha(TEACHER_RESPONSE)
    manifest = pilot["manifest"]
    assert manifest["retained_evidence"]["response"]["sha256"] == response_digest
    assert manifest["teacher_output"]["response_sha256"] == response_digest
    assert manifest["teacher_output"]["response_path"] == "evidence/teacher-response.txt"
    assert manifest["teacher_output"]["packets"] == 6

    output_packets = pilot["output"]["packets"]
    label_packets = pilot["labels"]["packets"]
    assert label_packets == output_packets
    assert len(output_packets) == len(pilot["response"]["packets"]) == 6
    assert [packet["reviewer"]["output_sha256"] for packet in output_packets] == [response_digest] * 6
    assert [packet["reviewer"]["output_sha256"] for packet in label_packets] == [response_digest] * 6
    assert [_without_output_hash(packet) for packet in output_packets] == pilot["response"]["packets"]

    for text in (
        PROMPT.read_text(encoding="utf-8"),
        REQUEST.read_text(encoding="utf-8"),
        TEACHER_RESPONSE.read_text(encoding="utf-8"),
        TEACHER_OUTPUT.read_text(encoding="utf-8"),
        LABELS.read_text(encoding="utf-8"),
        (PILOT / "manifest.json").read_text(encoding="utf-8"),
    ):
        assert "PENDING" not in text


def test_packets_are_synthetic_conservative_and_bind_every_provenance_field(pilot: dict) -> None:
    labels = pilot["labels"]
    manifest = pilot["manifest"]
    teacher = manifest["teacher_output"]
    response_digest = teacher["response_sha256"]
    expected = {
        "reviewer_kind": "synthetic",
        "provider_id": PROVIDER_ID,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "prompt_revision": PROMPT_REVISION,
        "rubric_revision": RUBRIC_REVISION,
        "run_id": RUN_ID,
        "labeled_at": LABELED_AT,
        "synthetic": True,
        "output_sha256": response_digest,
    }
    assert len(labels["packets"]) == 6
    for packet in labels["packets"]:
        assert packet["reviewer"] == expected
        assert packet["label_role"] == "adjudicated"
        assert packet["finding_labels"] == []
        assert packet["adjudications"] == []
        assert packet["attack_outcomes"] == []
        if packet["case_id"] == INCOMPLETE_CASE:
            assert packet["case_completeness"] == "INCOMPLETE"
            assert packet["case_assessment"] == "INCONCLUSIVE"
        else:
            assert packet["case_completeness"] == "COMPLETE"
            assert packet["case_assessment"] == "NO_KNOWN_MATERIAL_DEFECTS"

    reviewer_kinds = {packet["reviewer"]["reviewer_kind"] for packet in labels["packets"]}
    assert reviewer_kinds == {"synthetic"}
    assert not any(kind in reviewer_kinds for kind in {"human", "model_teacher", "unknown"})
    assert pilot["frozen"][INCOMPLETE_CASE]["evidence_completeness"] == "incomplete"


def test_labels_validate_and_scorecard_keeps_missing_prediction_data(pilot: dict) -> None:
    corpus = pilot["corpus"]
    predictions = _load(PILOT / "predictions.json")
    labels = pilot["labels"]
    assert validate_labels(labels, corpus, predictions) == labels

    scorecard = build_scorecard(
        corpus,
        predictions,
        labels,
        input_hashes={
            "corpus": _sha(PILOT / "corpus.json"),
            "predictions": _sha(PILOT / "predictions.json"),
            "labels": _sha(LABELS),
        },
    )
    assert scorecard["data_state"]["state"] == "MISSING_DATA"
    assert "no_prediction_runs" in scorecard["data_state"]["reasons"]
    assert "partial_adjudicated_labels" in scorecard["data_state"]["reasons"]
    label_state = scorecard["data_state"]["label_state"]
    assert label_state["status"] == "partial"
    assert label_state["arms"]["synthetic"]["adjudicated_packets"] == 6
    assert label_state["arms"]["synthetic"]["complete_adjudicated_packets"] == 5
    assert label_state["arms"]["synthetic"]["status"] == "partial"
    assert label_state["arms"]["human"]["status"] == "missing"
    assert scorecard["claims"]["quality_claim"] is False
    assert scorecard["claims"]["accuracy"] is None
    assert scorecard["input_hashes"]["labels"] == _sha(LABELS)
