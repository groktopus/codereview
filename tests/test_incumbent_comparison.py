"""QM-4 evidence contracts; test-only authored runs are never live measurements."""

from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest

from experiments.harness.evaluation import EvaluationError
from scripts.compare_incumbent import ROOT, build_report, canonical, digest, load, markdown

DATA = ROOT / "examples/evaluation/qm4-incumbent-v1"


def manifest():
    return load(DATA / "manifest.json")


def test_all_frozen_cases_have_explicit_baseline_records_and_no_false_claims():
    report = build_report(manifest())
    assert report["case_count"] == 41
    assert report["retained_harness_outputs"] == 5
    assert report["retained_incumbent_outputs"] == 0
    assert report["actual_paired_output_count"] == 0
    assert "qm1-slopsearx-pr770" in {r["identity"]["case_id"] for r in report["rows"]}
    assert all(r["incumbent"]["status"] == "missing" and r["incumbent"]["reason"] for r in report["rows"])
    assert not any(value for key, value in report["claims"].items() if key.endswith("established"))
    assert report["claims"]["pre_specified_equivalence_margin"] is None
    assert report["claims"]["authored_droid_fixtures_counted_as_live"] is False
    for row in report["rows"]:
        for name in ("human_recall", "synthetic_recall", "false_blockers", "cost"):
            metric = row["metrics"][name]["harness_minus_incumbent"]
            assert metric["value"] is None and metric["denominator"] is None
        assert row["metrics"]["disposition"]["denominator"] is None
    for summary in report["summaries"].values():
        assert summary["available_paired_cases"] == 0
        assert summary["denominator_cases"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_sha", "0" * 40),
        ("head_sha", "0" * 40),
        ("snapshot_id", "snap-wrong"),
        ("source_manifest", {"manifest_id": "wrong", "sha256": "0" * 64}),
        ("profile", {"profile_id": "wrong", "version": "wrong", "sha256": "0" * 64}),
        ("repository", {"owner": "wrong", "name": "wrong"}),
    ],
)
def test_wrong_snapshot_identity_rejected(field, value):
    data = manifest()
    data["cases"][0]["identity"][field] = value
    with pytest.raises(EvaluationError, match="baseline_snapshot_mismatch"):
        build_report(data)


def test_missing_duplicate_or_wrong_arm_rejected():
    for action in ("delete", "duplicate", "wrong_arm", "fake_zero"):
        data = manifest()
        if action == "delete":
            data["cases"].pop()
        elif action == "duplicate":
            data["cases"][-1] = copy.deepcopy(data["cases"][0])
        elif action == "wrong_arm":
            data["cases"][0]["incumbent"]["arm"] = "harness"
        else:
            data["cases"][0]["incumbent"]["output"] = {"findings": []}
        with pytest.raises(EvaluationError):
            build_report(data)


def test_input_hash_mismatch_rejected():
    data = manifest()
    data["inputs"]["corpus"]["sha256"] = "0" * 64
    with pytest.raises(EvaluationError, match="input_hash_mismatch"):
        build_report(data)


def test_byte_reproducibility_and_checked_in_report():
    data = manifest()
    first = build_report(data)
    assert first == build_report(data)
    assert load(DATA / "report.json") == first
    assert (DATA / "REPORT.md").read_text() == markdown(first)
    command = [sys.executable, str(ROOT / "scripts/compare_incumbent.py")]
    a = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
    b = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
    assert a.stdout == b.stdout == (DATA / "report.json").read_bytes()


def retained_test_packet(tmp_path, *, authored=False, wrong_head=False, matched=True):
    """Isolated protocol probe; never adds test values to the delivered evidence."""
    data = manifest()
    root = tmp_path
    # Copy only pinned JSON inputs. No calls to any model or provider.
    for ref in data["inputs"].values():
        destination = root / ref["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / ref["path"]).read_bytes())
    index = next(i for i, r in enumerate(data["cases"]) if r["identity"]["case_id"] == "qm1-codereview-pr112")
    record = data["cases"][index]
    identity = copy.deepcopy(record["identity"])
    if wrong_head:
        identity["head_sha"] = "0" * 40
    packet = {
        "evidence_kind": "authored_fixture" if authored else "retained_provider_output",
        "captured_at": "2026-11-01T00:00:00Z",
        "source_url": "https://example.invalid/test-only",
        "model_identity": None,
        "run": {
            "case_id": record["identity"]["case_id"],
            "identity": identity,
            "arm": "droid",
            "run_id": "TEST-ONLY-not-live",
            "status": "completed",
            "disposition": "REQUEST_CHANGES",
            "findings": [
                {
                    "finding_id": "test-finding",
                    "materiality": "MATERIAL",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": ["test-evidence"],
                }
            ],
            "detector_result": "NOT_RUN",
        },
    }
    path = root / "test-output.json"
    path.write_text(json.dumps(packet))
    record["incumbent"] = {
        "arm": "droid",
        "status": "retained",
        "output": {"path": path.name, "sha256": digest(path.read_bytes())},
    }
    label_ref = data["inputs"]["labels"]
    labels = load(root / label_ref["path"])
    label = next(p for p in labels["packets"] if p["case_id"] == record["identity"]["case_id"])
    label["case_assessment"] = "MATERIAL_DEFECTS_PRESENT"
    label["finding_labels"] = [
        {
            "label_id": "test-defect",
            "materiality": "MATERIAL",
            "introducedness": "INTRODUCED",
            "evidence_refs": ["test-evidence"],
        }
    ]
    label["adjudications"] = [
        {
            "arm": "droid",
            "finding_id": "test-finding",
            "outcome": "MATCHED" if matched else "ABSTAINED",
            "label_id": "test-defect" if matched else None,
            "canonical_finding_id": None,
            "evidence_refs": ["test-evidence"],
        }
    ]
    # Baseline adjudications are a separate hash-bound packet on the full corpus.
    comparison_labels = copy.deepcopy(labels)
    comparison_labels["corpus_id"] = data["corpus_id"]
    comparison_labels["packets"] = [copy.deepcopy(label)]
    label["adjudications"] = []
    comparison_path = root / "test-comparison-labels.json"
    comparison_path.write_text(json.dumps(comparison_labels))
    record["incumbent"]["adjudication"] = {"path": comparison_path.name, "sha256": digest(comparison_path.read_bytes())}
    (root / label_ref["path"]).write_text(json.dumps(labels))
    label_ref["sha256"] = digest((root / label_ref["path"]).read_bytes())
    return data


def test_authored_incumbent_output_and_wrong_head_fail_closed(tmp_path):
    data = retained_test_packet(tmp_path, authored=True)
    with pytest.raises(EvaluationError, match="authored_fixture_not_incumbent"):
        build_report(data, tmp_path)
    data = retained_test_packet(tmp_path, wrong_head=True)
    with pytest.raises(EvaluationError, match="retained_snapshot_mismatch"):
        build_report(data, tmp_path)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("captured_at", True, "invalid_capture_timestamp"),
        ("captured_at", "not-a-timestamp", "invalid_capture_timestamp"),
        ("captured_at", "2026-11-01T00:00:00", "capture_timestamp_requires_timezone"),
        ("source_url", {"not": "url"}, "invalid_source_url"),
        ("source_url", "http://example.invalid/output", "invalid_source_url"),
        ("source_url", "https:///missing-host", "invalid_source_url"),
        ("source_url", "https://bad_host.invalid/output", "invalid_source_hostname"),
        ("source_url", "https://-bad.invalid/output", "invalid_source_hostname"),
        ("source_url", "https://example.invalid:bad/output", "invalid_source_url"),
        ("source_url", "https://user:password@example.invalid/output", "invalid_source_url"),
        ("source_url", "https://example.invalid/space here", "invalid_source_url"),
        ("model_identity", [], "invalid_model_identity"),
        ("model_identity", "   ", "invalid_model_identity"),
        ("model_identity", True, "invalid_model_identity"),
    ],
)
def test_rehashed_malformed_retained_provenance_rejected(tmp_path, field, value, error):
    data = retained_test_packet(tmp_path)
    record = next(r for r in data["cases"] if r["incumbent"]["status"] == "retained")
    reference = record["incumbent"]["output"]
    path = tmp_path / reference["path"]
    envelope = load(path)
    envelope[field] = value
    path.write_text(json.dumps(envelope))
    reference["sha256"] = digest(path.read_bytes())  # valid hash must not bypass typed validation
    with pytest.raises(EvaluationError, match=error):
        build_report(data, tmp_path)


@pytest.mark.parametrize(
    "timestamp,model",
    [
        ("2026-11-01T00:00:00Z", None),
        ("2026-11-01T00:00:00-05:00", "attributed-model-revision"),
    ],
)
def test_typed_retained_attribution_is_not_authentication(tmp_path, timestamp, model):
    data = retained_test_packet(tmp_path)
    record = next(r for r in data["cases"] if r["incumbent"]["status"] == "retained")
    reference = record["incumbent"]["output"]
    path = tmp_path / reference["path"]
    envelope = load(path)
    envelope.update(captured_at=timestamp, model_identity=model)
    path.write_text(json.dumps(envelope))
    reference["sha256"] = digest(path.read_bytes())
    assert build_report(data, tmp_path)["actual_paired_output_count"] == 1  # test protocol, not live evidence


def test_retained_output_not_adjudicated_is_unknown_not_zero(tmp_path):
    data = retained_test_packet(tmp_path, matched=False)
    result = build_report(data, tmp_path)
    assert result["actual_paired_output_count"] == 1  # test-only input, not retained evidence
    row = next(r for r in result["rows"] if r["identity"]["case_id"] == "qm1-codereview-pr112")
    assert row["metrics"]["synthetic_recall"]["incumbent"]["value"] is None
    assert row["metrics"]["synthetic_recall"]["harness_minus_incumbent"]["denominator"] is None
    assert row["metrics"]["disposition"]["equal"] is False
    assert row["metrics"]["disposition"]["incumbent_better"] is None


def test_incumbent_better_recall_is_reported_without_quality_overclaim(tmp_path):
    data = retained_test_packet(tmp_path, matched=True)
    result = build_report(data, tmp_path)
    row = next(r for r in result["rows"] if r["identity"]["case_id"] == "qm1-codereview-pr112")
    metric = row["metrics"]["synthetic_recall"]
    assert metric["harness"]["numerator"] == 0
    assert metric["harness"]["denominator"] == 1
    assert metric["incumbent"]["numerator"] == metric["incumbent"]["denominator"] == 1
    assert metric["harness_minus_incumbent"]["value"] == -1
    assert metric["incumbent_better"] is True
    assert result["summaries"]["synthetic_recall"]["incumbent_better_case_ids"] == ["qm1-codereview-pr112"]
    assert result["claims"]["improvement_established"] is False
    rendered = markdown(result)
    assert "Observed incumbent-better recall cases: qm1-codereview-pr112" in rendered
    assert "no paired incumbent output is retained" not in rendered


def test_known_empty_recall_denominator_stays_undefined():
    result = build_report(manifest())
    row = next(r for r in result["rows"] if r["identity"]["case_id"] == "qm1-codereview-pr112")
    metric = row["metrics"]["synthetic_recall"]["harness"]
    assert metric["denominator"] == 0  # known empty label set, distinct from unknown
    assert metric["value"] is None
    assert metric["unknown_reason"]


def test_wrong_evaluator_source_pin_is_rejected():
    data = manifest()
    data["evaluator_source_sha256"] = "0" * 64
    with pytest.raises(EvaluationError, match="evaluator_source_mismatch"):
        build_report(data)


def test_cli_error_is_nonzero_machine_readable(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(canonical({"schema_version": "wrong"}))
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/compare_incumbent.py"), "--manifest", str(path)],
        cwd=ROOT,
        capture_output=True,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "unsupported_incumbent_manifest"}
