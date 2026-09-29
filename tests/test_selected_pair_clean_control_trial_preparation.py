from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_selected_pair_clean_control_trial import (  # noqa: E402
    CASE_IDS,
    CONTRACT,
    PreparationError,
    _assert_body_content,
    _capture_primary_descriptors,
    prepare_trial,
)


def test_three_case_plan_binds_prepare_only_requests_and_shared_policy(tmp_path):
    result = prepare_trial(tmp_path / "prepared")
    plan_path = Path(result["plan_path"])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    assert result["status"] == "PREPARED_PROVIDER_FREE"
    assert result["provider_calls"] == 0
    assert plan["schema"] == CONTRACT
    assert plan["execution"]["provider_calls"] == 0
    assert plan["execution"]["provider_dispatch"] == "NOT_RUN"
    assert [row["case_id"] for row in plan["cases"]] == list(CASE_IDS)
    assert {row["shared_policy_sha256"] for row in plan["cases"]} == {
        plan["shared_review_policy"]["sha256"]
    }
    assert {row["profile_sha256"] for row in plan["cases"]} == {
        plan["shared_review_policy"]["profile_sha256"]
    }
    assert {row["limits_sha256"] for row in plan["cases"]} == {
        plan["shared_review_policy"]["limits_sha256"]
    }
    assert all(row["primary_request_serializer_binding"] == "EXACT_BYTES_VERIFIED_PROVIDER_FREE" for row in plan["cases"])
    assert all(row["primary_request_count"] == len(row["primary_requests"]) > 0 for row in plan["cases"])
    assert plan["construction_oracle"]["defect_pair"]["finding_expected_in_both"] is True
    assert plan["construction_oracle"]["clean_control"]["expected_material_candidate"] is False
    assert plan["jev_injection_classifier"]["status"] == "NOT_RUN_CONTRACT_COMPATIBILITY_UNRESOLVED"
    assert plan["jev_injection_classifier"]["request_payload"].startswith("NOT_BUILT_FIXED_TEXT_INPUT")
    assert plan["jev_injection_classifier"]["claim_assessment_request"] == "NOT_BUILT_CANDIDATE_DEPENDENT"
    assert plan["bounds"]["primary_calls_total_max"] == 27
    assert plan["bounds"]["claim_jev_calls_total_max"] == 12
    assert plan["bounds"]["injection_classifier_calls_max"] == 2
    assert plan["bounds"]["total_external_calls_max_if_classifier_enabled"] == 41
    assert plan["bounds"]["wall_deadline_seconds_total_max_if_classifier_enabled"] == 940
    assert result["plan_sha256"] == hashlib.sha256(plan_path.read_bytes()).hexdigest()

    frozen = plan["frozen_inputs"]
    for relpath, expected_hash in (
        (frozen["profile_path"], frozen["profile_sha256"]),
        (frozen["limits_path"], frozen["limits_sha256"]),
        (frozen["provider_config_path"], frozen["provider_config_file_sha256"]),
        (frozen["decision_config_path"], frozen["decision_config_file_sha256"]),
    ):
        assert hashlib.sha256((plan_path.parent / relpath).read_bytes()).hexdigest() == expected_hash
    for case_id, identity in frozen["cases"].items():
        repo = plan_path.parent / identity["repository_path"]
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        base = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{identity['base_sha']}^{{commit}}"], capture_output=True)
        assert head == identity["head_sha"]
        assert base.returncode == 0
        assert next(row for row in plan["cases"] if row["case_id"] == case_id)["snapshot_hash"]


def test_request_descriptors_are_independent_of_temporary_paths(tmp_path):
    first = prepare_trial(tmp_path / "first")
    second = prepare_trial(tmp_path / "second")
    first_plan = json.loads(Path(first["plan_path"]).read_text(encoding="utf-8"))
    second_plan = json.loads(Path(second["plan_path"]).read_text(encoding="utf-8"))

    assert [case["case_id"] for case in first_plan["cases"]] == list(CASE_IDS)
    assert [case["case_id"] for case in second_plan["cases"]] == list(CASE_IDS)
    for first_case, second_case in zip(first_plan["cases"], second_plan["cases"], strict=True):
        assert first_case["primary_requests"] == second_case["primary_requests"]
        assert first_case["base_sha"] == second_case["base_sha"]
        assert first_case["head_sha"] == second_case["head_sha"]
    assert first_plan["snapshot_hash_semantics"].startswith("per-preparation observations")


def test_descriptor_or_clean_body_mutation_is_rejected():
    body = b'{"messages":[{"role":"system","content":"review"},{"role":"user","content":"{}"}]}'
    import prepare_selected_pair_clean_control_trial as preparation

    preparation._CAPTURED_BODIES["case"] = [body]
    descriptor = {"input_bytes": len(body), "input_sha256": hashlib.sha256(body).hexdigest(), "admitted": True}
    with pytest.raises(PreparationError, match="serializer_descriptor_binding_mismatch"):
        _capture_primary_descriptors("case", {"primary_requests": [{**descriptor, "input_sha256": "0" * 64}]})

    clean_manifest = json.loads((ROOT / "examples/evaluation/clean-review-control-v1/fixture.json").read_text(encoding="utf-8"))
    clean_files = {
        name: (ROOT / "examples/evaluation/clean-review-control-v1" / name).read_bytes()
        for name in clean_manifest["file_hashes"]
    }
    malformed = json.dumps({
        "messages": [
            {"role": "system", "content": "review"},
            {"role": "user", "content": json.dumps({"evidence": [{"content": "ordinary comment only"}]})},
        ]
    }).encode("utf-8")
    with pytest.raises(PreparationError, match="clean_request_content_mismatch"):
        _assert_body_content(CASE_IDS[2], [malformed], {}, clean_files)
