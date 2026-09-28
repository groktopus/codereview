from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from pathlib import Path

import pytest

from pr_review_harness.cross_model_v2 import (
    CONTRACT_VERSION,
    calls_manifest_sha256,
    compare_cross_model_v2,
    validate_cross_model_comparison_v2,
)
from pr_review_harness.evaluation import EvaluationError, validate_corpus

ROOT = Path(__file__).resolve().parents[1]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture() -> tuple[dict, dict, dict[str, bytes]]:
    corpus = json.loads((ROOT / "examples/evaluation/corpus.json").read_text())
    corpus = validate_corpus(corpus)
    corpus["cases"] = corpus["cases"][:1]
    case_id = corpus["cases"][0]["identity"]["case_id"]
    records = [
        {"role": role, "record_id": f"{role}-{case_id}"}
        for role in ("writer", "jev", "source_auditor", "claim_auditor")
    ]
    record_id = {item["role"]: item["record_id"] for item in records}
    body_by_role = {
        "writer": {"items": []},
        "jev": {"items": [{"relation": "MATCH", "left_record_id": record_id["writer"], "right_record_id": record_id["jev"]}]},
        "source_auditor": {"source_notes": [{"record_id": record_id["source_auditor"], "status": "reviewed_without_prior_claims"}]},
        "claim_auditor": {"items": [{"relation": "MATCH", "left_record_id": record_id["jev"], "right_record_id": record_id["claim_auditor"]}]},
    }
    roles = []
    bytes_by_id: dict[str, bytes] = {}
    call_id_by_role: dict[str, str] = {}
    response_id_by_role: dict[str, str] = {}
    for role in ("writer", "jev", "source_auditor", "claim_auditor"):
        request = f"request for {role}".encode()
        response = json.dumps(body_by_role[role], separators=(",", ":")).encode()
        call_id = f"call-{role}"
        request_id = f"request-{role}"
        response_id = f"response-{role}"
        call_id_by_role[role] = call_id
        response_id_by_role[role] = response_id
        bytes_by_id[request_id] = request
        bytes_by_id[response_id] = response
        calls = [{"call_id": call_id, "request_sha256": sha(request), "request_artifact_id": request_id, "response_sha256": sha(response), "response_artifact_id": response_id}]
        roles.append({
            "role": role,
            "status": "completed",
            "run_id": f"run-{role}",
            "provider_id": f"provider-{role}",
            "model_id": f"model-{role}-pinned",
            "runtime_id": f"runtime-{role}",
            "prompt_revision": f"prompt-{role}-v1",
            "rubric_revision": f"rubric-{role}-v1",
            "calls": calls,
            "calls_manifest_sha256": calls_manifest_sha256(calls),
        })
    assertions = [
        {"assertion_id": "assert-wj", "pair": "writer_jev", "relation": "MATCH", "reporter_role": "jev", "reporter_run_id": "run-jev", "reporter_call_id": call_id_by_role["jev"], "response_artifact_id": response_id_by_role["jev"], "json_pointer": "/items/0", "left_record_id": record_id["writer"], "right_record_id": record_id["jev"]},
        {"assertion_id": "assert-jc", "pair": "jev_claim_auditor", "relation": "MATCH", "reporter_role": "claim_auditor", "reporter_run_id": "run-claim_auditor", "reporter_call_id": call_id_by_role["claim_auditor"], "response_artifact_id": response_id_by_role["claim_auditor"], "json_pointer": "/items/0", "left_record_id": record_id["jev"], "right_record_id": record_id["claim_auditor"]},
    ]
    comparison = {
        "contract_version": CONTRACT_VERSION,
        "comparison_id": "comparison-v2",
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "procedure": {"revision": "typed-pointer-v1", "frozen_sha256": "a" * 64},
        "cases": [{"case_id": case_id, "identity": deepcopy(corpus["cases"][0]["identity"]), "runs": roles, "records": records, "assertions": assertions}],
    }
    return corpus, comparison, bytes_by_id


def artifact_paths(tmp_path: Path, values: dict[str, bytes]) -> dict[str, Path]:
    paths = {}
    for artifact_id, body in values.items():
        path = tmp_path / artifact_id
        path.write_bytes(body)
        paths[artifact_id] = path
    return paths


def test_v2_verifies_structured_relation_pointer_and_separates_audit_roles(tmp_path):
    corpus, comparison, bodies = fixture()
    report = compare_cross_model_v2(comparison, corpus, artifacts=artifact_paths(tmp_path, bodies))
    assert report["assertion_verification"]["verified_structured_relation_count"] == 2
    assert sum(assertion["relation_emitted"] for case in report["cases"] for assertion in case["assertions"]) == 2
    assert "jev_source_auditor" not in report["relation_counts"]
    assert report["relation_counts"]["jev_claim_auditor"]["denominator"] == 1
    assert report["role_run_counts"]["source_auditor"]["denominator"] == 1
    assert report["role_record_counts"]["source_auditor"]["record_denominator"] == 1
    assert report["claims"] == {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None}
    assert "semantic truth" in report["relation_semantics"]


def test_forged_declared_only_and_response_claim_mismatch_fail_closed(tmp_path):
    corpus, comparison, bodies = fixture()
    comparison["cases"][0]["assertions"][0]["relation"] = "DECLARED_ONLY"
    with pytest.raises(EvaluationError, match="invalid_pair_or_relation"):
        validate_cross_model_comparison_v2(comparison, corpus)

    corpus, comparison, bodies = fixture()
    bodies["response-jev"] = json.dumps({"items": [{"relation": "DISAGREEMENT", "left_record_id": "writer-" + comparison["cases"][0]["case_id"], "right_record_id": "jev-" + comparison["cases"][0]["case_id"]}]}).encode()
    # Declared digest must bind the actual bytes before the response contents are checked.
    call = comparison["cases"][0]["runs"][1]["calls"][0]
    call["response_sha256"] = sha(bodies["response-jev"])
    comparison["cases"][0]["runs"][1]["calls_manifest_sha256"] = calls_manifest_sha256([call])
    report = compare_cross_model_v2(comparison, corpus, artifacts=artifact_paths(tmp_path, bodies))
    assert report["assertion_verification"]["status_counts"]["RESPONSE_MISMATCH"] == 1
    assert report["assertion_verification"]["verified_structured_relation_count"] == 1


@pytest.mark.parametrize("mode,expected", [("missing", "NOT_PROVIDED"), ("malformed", "MALFORMED_JSON"), ("hash_mismatch", "HASH_MISMATCH")])
def test_missing_malformed_and_hash_mismatched_responses_fail_closed(tmp_path, mode, expected):
    corpus, comparison, bodies = fixture()
    paths = artifact_paths(tmp_path, bodies)
    response_path = paths["response-jev"]
    if mode == "missing":
        paths.pop("response-jev")
    elif mode == "malformed":
        malformed = b"{not-json"
        response_path.write_bytes(malformed)
        call = comparison["cases"][0]["runs"][1]["calls"][0]
        call["response_sha256"] = sha(malformed)
        comparison["cases"][0]["runs"][1]["calls_manifest_sha256"] = calls_manifest_sha256([call])
    else:
        response_path.write_bytes(b"different response bytes")
    report = compare_cross_model_v2(comparison, corpus, artifacts=paths)
    assert report["assertion_verification"]["status_counts"][expected] == 1
    assert report["assertion_verification"]["verified_structured_relation_count"] < 2


def test_multiple_provider_calls_are_bound_individually_by_manifest_and_pointer(tmp_path):
    corpus, comparison, bodies = fixture()
    run = comparison["cases"][0]["runs"][1]
    call = {"call_id": "call-jev-2", "request_sha256": sha(b"second request"), "request_artifact_id": "request-jev-2", "response_sha256": sha(bodies["response-jev"]), "response_artifact_id": "response-jev-2"}
    run["calls"].append(call)
    run["calls_manifest_sha256"] = calls_manifest_sha256(run["calls"])
    assertion = comparison["cases"][0]["assertions"][0]
    assertion["reporter_call_id"] = call["call_id"]
    assertion["response_artifact_id"] = call["response_artifact_id"]
    bodies["request-jev-2"] = b"second request"
    bodies["response-jev-2"] = bodies["response-jev"]
    report = compare_cross_model_v2(comparison, corpus, artifacts=artifact_paths(tmp_path, bodies))
    assert report["assertion_verification"]["status_counts"]["VERIFIED_STRUCTURED_RELATION"] == 2
    assert report["artifact_verification"]["denominator"] == 10


def test_null_record_id_must_be_explicit_in_response_object(tmp_path):
    corpus, comparison, bodies = fixture()
    assertion = comparison["cases"][0]["assertions"][0]
    assertion.update({"relation": "NO_COUNTERPART", "left_record_id": None})
    target = json.loads(bodies["response-jev"])
    target["items"][0].pop("left_record_id")
    response = json.dumps(target, separators=(",", ":")).encode()
    bodies["response-jev"] = response
    run = comparison["cases"][0]["runs"][1]
    run["calls"][0]["response_sha256"] = sha(response)
    run["calls_manifest_sha256"] = calls_manifest_sha256(run["calls"])
    report = compare_cross_model_v2(comparison, corpus, artifacts=artifact_paths(tmp_path, bodies))
    assert report["assertion_verification"]["status_counts"]["RESPONSE_MISMATCH"] == 1


@pytest.mark.parametrize("kind,expected", [("traversal", "PATH_TRAVERSAL"), ("symlink", "SYMLINK"), ("fifo", "NOT_REGULAR"), ("oversize", "TOO_LARGE")])
def test_response_artifact_filesystem_attacks_fail_closed(tmp_path, kind, expected):
    corpus, comparison, bodies = fixture()
    paths = artifact_paths(tmp_path, bodies)
    artifact_id = "response-jev"
    target = paths[artifact_id]
    if kind == "traversal":
        paths[artifact_id] = tmp_path / "nested" / ".." / target.name
    elif kind == "symlink":
        link = tmp_path / "linked-response"
        link.symlink_to(target)
        paths[artifact_id] = link
    elif kind == "fifo":
        target.unlink()
        os.mkfifo(target)
    else:
        target.write_bytes(b" " * (4 * 1024 * 1024 + 1))
    report = compare_cross_model_v2(comparison, corpus, artifacts=paths)
    status = report["assertion_verification"]["status_counts"]
    assert status.get(expected, 0) == 1
    assert report["assertion_verification"]["verified_structured_relation_count"] < 3


def test_duplicate_assertion_record_and_manifest_ids_are_rejected():
    corpus, comparison, _ = fixture()
    case = comparison["cases"][0]
    case["assertions"].append(deepcopy(case["assertions"][0]))
    with pytest.raises(EvaluationError, match="duplicate_assertion_id"):
        validate_cross_model_comparison_v2(comparison, corpus)

    corpus, comparison, _ = fixture()
    case = comparison["cases"][0]
    case["records"].append(deepcopy(case["records"][0]))
    with pytest.raises(EvaluationError, match="duplicate_record_id"):
        validate_cross_model_comparison_v2(comparison, corpus)

    corpus, comparison, _ = fixture()
    comparison["cases"][0]["runs"][0]["calls_manifest_sha256"] = "f" * 64
    with pytest.raises(EvaluationError, match="calls_manifest_mismatch"):
        validate_cross_model_comparison_v2(comparison, corpus)


def test_reporter_role_contamination_and_snapshot_mismatch_are_rejected():
    corpus, comparison, _ = fixture()
    comparison["cases"][0]["assertions"][0]["reporter_role"] = "source_auditor"
    with pytest.raises(EvaluationError, match="relation_reporter_mismatch"):
        validate_cross_model_comparison_v2(comparison, corpus)

    corpus, comparison, _ = fixture()
    comparison["cases"][0]["identity"]["head_sha"] = "f" * 40
    with pytest.raises(EvaluationError, match="cross_model_snapshot_mismatch"):
        validate_cross_model_comparison_v2(comparison, corpus)


def test_empty_and_incomplete_evidence_keeps_denominators_and_never_becomes_success():
    corpus, comparison, bodies = fixture()
    case = comparison["cases"][0]
    case["assertions"] = []
    case["records"] = []
    run = case["runs"][2]
    request = b"source auditor request with incomplete response"
    incomplete_call = {"call_id": "source-call-incomplete", "request_sha256": sha(request), "request_artifact_id": "source-request-incomplete", "response_sha256": None, "response_artifact_id": None}
    run.update({"status": "incomplete", "calls": [incomplete_call], "calls_manifest_sha256": calls_manifest_sha256([incomplete_call])})
    report = compare_cross_model_v2(comparison, corpus)
    assert report["role_run_counts"]["source_auditor"]["denominator"] == 1
    assert report["role_run_counts"]["source_auditor"]["status_counts"]["incomplete"] == 1
    assert report["role_run_counts"]["source_auditor"]["zero_call_runs"] == 0
    assert report["role_run_counts"]["source_auditor"]["calls_without_response"] == 1
    assert report["assertion_verification"]["denominator"] == 0
    assert report["cases"][0]["zero_assertions"] is True
