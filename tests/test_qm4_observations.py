"""Offline QM4 admission probes; mutations never alter retained source evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.check_qm4_observations import DEFAULT_PACKAGE, ROOT, strict_json, validate_package
from scripts.qm4_observation_schema import ObservationError


@pytest.fixture
def package(tmp_path: Path) -> Path:
    destination = tmp_path / "observations"
    shutil.copytree(DEFAULT_PACKAGE, destination)
    return destination


def read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def mutate(package: Path, relative: str, route: tuple[str | int, ...], value: Any) -> None:
    """Rehash structural attacks so rejection cannot rely on stale byte hashes."""
    path = package / relative
    data = read(path)
    target = data
    for part in route[:-1]:
        target = target[part]
    target[route[-1]] = value
    write(path, data)
    if relative != "index.json":
        index = read(package / "index.json")
        ref = next(r for r in index["cases"] + index["support"] if r["path"] == relative)
        ref["bytes"] = len(path.read_bytes())
        ref["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        write(package / "index.json", index)


def case_path(case: str) -> str:
    return f"cases/qm1-{case}.json"


def row_number(package: Path, case: str) -> int:
    return next(i for i, row in enumerate(read(package / "index.json")["cases"]) if row["case_id"] == f"qm1-{case}")


def test_real_package_conservatively_authenticates_all_frozen_identities_and_hashes() -> None:
    result = validate_package()
    assert result["identities_checked"] == 41
    assert result["hashed_files_checked"] == 45
    # Includes shared attribution support in every case's aggregate budget.
    assert result["largest_case_aggregate_bytes"] == 44865
    assert result["surface_status_counts"] == {"captured": 86, "response_over_capture_cap": 1}
    assert sorted(result["missing_reasons"].values()) == [1, 1, 1, 1, 1, 8, 28]
    assert result["complete_incumbent_outputs"] == result["actual_pairs"] == 0
    assert result["predictions_created"] is False
    assert result["provider_execution_authenticated"] is False
    assert result["qm4_closed"] is False


@pytest.mark.parametrize("section", ["cases", "support"])
def test_tampered_exact_bytes_rejected(package: Path, section: str) -> None:
    ref = read(package / "index.json")[section][0]
    path = package / ref["path"]
    data = path.read_bytes()
    path.write_bytes(data.replace(b"{", b"[", 1))
    with pytest.raises(ObservationError, match=r"reference_hash_mismatch"):
        validate_package(package)


@pytest.mark.parametrize("section", ["cases", "support"])
@pytest.mark.parametrize("field,value", [("bytes", 1), ("sha256", "0" * 64)])
def test_reference_size_and_digest_checked(package: Path, section: str, field: str, value: Any) -> None:
    mutate(package, "index.json", (section, 0, field), value)
    with pytest.raises(ObservationError, match=r"reference_(bytes|hash)_mismatch"):
        validate_package(package)


@pytest.mark.parametrize("escape", ["../outside.json", "/tmp/outside.json", "support/../outside.json"])
def test_reference_path_escape_rejected(package: Path, escape: str) -> None:
    mutate(package, "index.json", ("support", 0, "path"), escape)
    with pytest.raises(ObservationError, match=r"path_escape"):
        validate_package(package)


def test_symlink_escape_rejected(package: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_bytes((package / "support/attribution-pr464.json").read_bytes())
    # Replace only this test's verified private-copy path, never retained evidence.
    target = package / "support/attribution-pr464.json"
    assert target.resolve().is_relative_to(package.resolve())
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(ObservationError, match=r"path_escape"):
        validate_package(package)


@pytest.mark.parametrize("field", ["base_sha", "head_sha", "family_id", "snapshot_id", "split", "case_id"])
def test_full_identity_not_pr_number_matching(package: Path, field: str) -> None:
    value = "0" * 40 if field.endswith("sha") else "wrong"
    mutate(package, case_path("codereview-pr112"), ("identity", field), value)
    with pytest.raises(ObservationError, match=r"full_frozen_identity_mismatch"):
        validate_package(package)


@pytest.mark.parametrize(
    "route,value",
    [
        (("repository", "owner"), "impostor"),
        (("repository", "name"), "elsewhere"),
        (("profile", "profile_id"), "wrong"),
        (("profile", "version"), "wrong"),
        (("profile", "sha256"), "0" * 64),
        (("source_manifest", "manifest_id"), "wrong"),
        (("source_manifest", "sha256"), "0" * 64),
    ],
)
def test_nested_frozen_identity_checked(package: Path, route: tuple[str, ...], value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("identity", *route), value)
    with pytest.raises(ObservationError, match=r"full_frozen_identity_mismatch"):
        validate_package(package)


@pytest.mark.parametrize("operation", ["missing", "duplicate", "foreign"])
def test_all_41_unique_case_ids_required(package: Path, operation: str) -> None:
    index = read(package / "index.json")
    if operation == "missing":
        index["cases"].pop()
    elif operation == "duplicate":
        index["cases"][-1] = index["cases"][0]
    else:
        index["cases"][-1]["case_id"] = "qm1-foreign-pr112"
    write(package / "index.json", index)
    with pytest.raises(ObservationError, match=r"case_count|frozen_case_set_mismatch"):
        validate_package(package)


@pytest.mark.parametrize("value", [0, False, {}, [], "", "   "])
def test_model_requires_explicit_null_or_nonblank_string(package: Path, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("model_identity",), value)
    with pytest.raises(ObservationError, match=r"invalid_model_identity"):
        validate_package(package)


@pytest.mark.parametrize("value", [None, "documented-model"])
def test_model_null_or_string_accepted_without_inference(package: Path, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("model_identity",), value)
    assert validate_package(package)["actual_pairs"] == 0


@pytest.mark.parametrize("value", ["2026-11-07T19:39:01", "2026-11-07", "nonsense", 123, None])
def test_capture_requires_timezone(package: Path, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("surfaces", "reviews", "captured_at"), value)
    with pytest.raises(ObservationError):
        validate_package(package)


@pytest.mark.parametrize("value", ["2026-10-10T13:15:34", "bad", 123])
def test_source_timestamp_requires_timezone(package: Path, value: Any) -> None:
    mutate(package, case_path("slopsearx-pr759"), ("surfaces", "issue_comments", "records", 0, "created_at"), value)
    with pytest.raises(ObservationError):
        validate_package(package)


@pytest.mark.parametrize(
    "value",
    [
        123,
        None,
        "http://api.github.com/x",
        "https://evil.test/x",
        "https://user@api.github.com/x",
        "https://api.github.com:bad/x",
    ],
)
def test_https_source_url_typed_and_scoped(package: Path, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("surfaces", "reviews", "source_url"), value)
    with pytest.raises(ObservationError):
        validate_package(package)


@pytest.mark.parametrize(
    "field,value", [("id", "138933559"), ("id", True), ("login", 123), ("login", ""), ("type", "Service")]
)
def test_numeric_author_identity_and_login_required(package: Path, field: str, value: Any) -> None:
    mutate(package, case_path("slopsearx-pr759"), ("surfaces", "issue_comments", "records", 0, "user", field), value)
    with pytest.raises(ObservationError):
        validate_package(package)


def test_arbitrary_bot_attribution_is_not_droid(package: Path) -> None:
    row = row_number(package, "codereview-pr289")
    source = read(package / case_path("codereview-pr289"))["surfaces"]["reviews"]["records"][0]
    projected = {key: value for key, value in source.items() if key not in {"body", "state"}}
    mutate(package, "index.json", ("cases", row, "droid_records"), [{"surface": "reviews", **projected}])
    with pytest.raises(ObservationError, match=r"arbitrary_bot_attribution"):
        validate_package(package)


def test_attribution_support_cannot_relabel_an_arbitrary_bot(package: Path) -> None:
    mutate(package, "support/attribution-pr464.json", ("surfaces", 0, "records", 0, "user", "id"), 62310815)
    with pytest.raises(ObservationError, match=r"untrusted_droid_attribution"):
        validate_package(package)


@pytest.mark.parametrize("case", ["slopsearx-pr744", "slopsearx-pr747", "slopsearx-pr752", "slopsearx-pr874"])
def test_remapped_current_commit_cannot_become_original_head_match(package: Path, case: str) -> None:
    source = read(package / case_path(case))
    inline = source["surfaces"]["comments"]["records"][0]
    assert inline["commit_id"] == source["identity"]["head_sha"]
    assert inline["original_commit_id"] != source["identity"]["head_sha"]
    mutate(
        package,
        "index.json",
        ("cases", row_number(package, case), "head_matched_original_droid_record_ids"),
        [inline["id"]],
    )
    with pytest.raises(ObservationError, match=r"original_commit_not_current_head"):
        validate_package(package)


@pytest.mark.parametrize("case", ["slopsearx-pr759", "slopsearx-pr746", "slopsearx-pr745"])
def test_progress_success_or_head_only_evidence_not_final_output(package: Path, case: str) -> None:
    mutate(
        package,
        "index.json",
        ("cases", row_number(package, case), "complete_incumbent_output_status"),
        "completed_clean",
    )
    with pytest.raises(ObservationError, match=r"final_output_not_available"):
        validate_package(package)


def test_base_mismatch_cannot_be_reclassified_full_snapshot(package: Path) -> None:
    mutate(
        package, "index.json", ("cases", row_number(package, "slopsearx-pr746"), "reason"), "full_same_snapshot_review"
    )
    with pytest.raises(ObservationError, match=r"missingness_reason_mismatch"):
        validate_package(package)


def test_security_receipt_needs_immutable_base_and_head(package: Path) -> None:
    mutate(
        package,
        "support/slopsearx-pr759-receipt-links.json",
        ("job_log_excerpt", "lines", 0),
        "human says current candidate 6fbd067",
    )
    with pytest.raises(ObservationError, match=r"missing_immutable_checkout_binding"):
        validate_package(package)


def test_security_receipt_predates_final_job_and_stays_missing(package: Path) -> None:
    mutate(
        package,
        "support/slopsearx-pr759-receipt-links.json",
        ("jobs", "record", "jobs", 0, "completed_at"),
        "2026-10-10T13:15:30Z",
    )
    with pytest.raises(ObservationError, match=r"security_receipt_not_final"):
        validate_package(package)


@pytest.mark.parametrize(
    "field,value",
    [
        ("surface_counts", {"comments": 0, "reviews": 1}),
        ("reason", "no_attributable_droid_records_in_inspected_surfaces"),
    ],
)
def test_over_cap_gap_never_becomes_empty(package: Path, field: str, value: Any) -> None:
    mutate(package, "index.json", ("cases", row_number(package, "codereview-pr279"), field), value)
    with pytest.raises(ObservationError, match=r"surface_gap_or_count_mismatch|missingness_reason_mismatch"):
        validate_package(package)


@pytest.mark.parametrize("field,value", [("pagination", "more_pages_uninspected"), ("page", 2), ("per_page", 200)])
def test_uninspected_pagination_not_complete(package: Path, field: str, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("surfaces", "reviews", field), value)
    with pytest.raises(ObservationError, match=r"pagination"):
        validate_package(package)


def test_full_page_is_not_proof_of_complete_pagination(package: Path) -> None:
    source = read(package / case_path("slopsearx-pr741"))["surfaces"]["reviews"]["records"][0]
    mutate(package, case_path("codereview-pr112"), ("surfaces", "reviews", "records"), [source] * 100)
    with pytest.raises(ObservationError, match=r"pagination_gap"):
        validate_package(package)


def test_case_plus_support_budget_not_individual_files_only(package: Path) -> None:
    path = "support/slopsearx-pr759-receipt-links.json"
    mutate(package, path, ("job_log_excerpt", "selection"), "x" * 253000)
    assert (package / path).stat().st_size < 262144
    with pytest.raises(ObservationError, match=r"case_aggregate_over_cap"):
        validate_package(package)


@pytest.mark.parametrize(
    "relative,route",
    [
        ("index.json", ()),
        (case_path("codereview-pr112"), ()),
        ("support/slopsearx-pr745-receipt-links.json", ()),
        (case_path("slopsearx-pr741"), ("surfaces", "reviews", "records", 0)),
    ],
)
def test_allowlisted_shapes_reject_body_derived_truth_or_predictions(
    package: Path, relative: str, route: tuple[str, ...]
) -> None:
    mutate(package, relative, (*route, "adjudicated_truth"), "clean")
    with pytest.raises(ObservationError, match=r"unknown_fields"):
        validate_package(package)


@pytest.mark.parametrize(
    "field,value", [("actual_pairs", 1), ("complete_incumbent_outputs", 1), ("refused_accuracy", False)]
)
def test_no_invented_pairs_or_accuracy_claims(package: Path, field: str, value: Any) -> None:
    mutate(package, "index.json", ("summary", field), value)
    with pytest.raises(ObservationError, match=r"summary_not_supported"):
        validate_package(package)


def test_unindexed_support_rejected(package: Path) -> None:
    write(package / "support/invented.json", {})
    with pytest.raises(ObservationError, match=r"unindexed_or_missing_evidence"):
        validate_package(package)


@pytest.mark.parametrize(
    "relative,shape",
    [
        ("support/slopsearx-pr745-receipt-links.json", "empty_runs"),
        ("support/slopsearx-pr745-receipt-links.json", "missing_runs"),
        ("support/slopsearx-pr746-receipt-links.json", "empty_records"),
        ("support/slopsearx-pr746-receipt-links.json", "missing_records"),
        ("support/slopsearx-pr746-receipt-links.json", "short_records"),
        ("support/slopsearx-pr746-receipt-links.json", "empty_comments"),
        ("support/slopsearx-pr746-receipt-links.json", "short_checkout"),
        ("support/slopsearx-pr759-receipt-links.json", "empty_runs"),
        ("support/slopsearx-pr759-receipt-links.json", "missing_runs"),
        ("support/slopsearx-pr759-receipt-links.json", "remove_jobs"),
        ("support/slopsearx-pr759-receipt-links.json", "empty_jobs"),
        ("support/slopsearx-pr759-receipt-links.json", "empty_log"),
    ],
)
def test_rehashed_receipt_cardinality_attacks_rejected_without_traceback(
    package: Path, relative: str, shape: str
) -> None:
    path = package / relative
    value = read(path)
    if shape == "empty_runs":
        value["runs"] = []
    elif shape == "missing_runs":
        value.pop("runs", None)
    elif shape == "empty_records":
        value["records"] = []
    elif shape == "missing_records":
        value.pop("records", None)
    elif shape == "short_records":
        value["records"] = value["records"][:2]
    elif shape == "empty_comments":
        value["records"][1]["records"] = []
    elif shape == "short_checkout":
        value["records"][3]["lines"] = []
    elif shape == "remove_jobs":
        value.pop("jobs", None)
    elif shape == "empty_jobs":
        value["jobs"]["record"]["jobs"] = []
    else:
        value["job_log_excerpt"]["lines"] = []
    write(path, value)
    index = read(package / "index.json")
    ref = next(row for row in index["support"] if row["path"] == relative)
    data = path.read_bytes()
    ref["bytes"] = len(data)
    ref["sha256"] = hashlib.sha256(data).hexdigest()
    write(package / "index.json", index)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_qm4_observations.py"), "--package", str(package)],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert (
        payload["error"]
        == {
            ("support/slopsearx-pr745-receipt-links.json", "empty_runs"): "pr745_required_run",
            ("support/slopsearx-pr745-receipt-links.json", "missing_runs"): "pr745_required_run",
            ("support/slopsearx-pr746-receipt-links.json", "empty_records"): "pr746_record_cardinality",
            ("support/slopsearx-pr746-receipt-links.json", "missing_records"): "pr746_record_cardinality",
            ("support/slopsearx-pr746-receipt-links.json", "short_records"): "pr746_record_cardinality",
            ("support/slopsearx-pr746-receipt-links.json", "empty_comments"): "pr746_comment_cardinality",
            ("support/slopsearx-pr746-receipt-links.json", "short_checkout"): "pr746_checkout_log_incomplete",
            ("support/slopsearx-pr759-receipt-links.json", "empty_runs"): "pr759_required_run",
            ("support/slopsearx-pr759-receipt-links.json", "missing_runs"): "pr759_required_run",
            ("support/slopsearx-pr759-receipt-links.json", "remove_jobs"): "pr759_required_content",
            ("support/slopsearx-pr759-receipt-links.json", "empty_jobs"): "jobs_count",
            ("support/slopsearx-pr759-receipt-links.json", "empty_log"): "empty_pr759_job_log",
        }[(relative, shape)]
    )
    assert result.stderr == b""


@pytest.mark.parametrize("surface_value", [[], None, "bad", 7])
def test_rehashed_case_surface_shape_is_rejected_without_traceback(package: Path, surface_value: Any) -> None:
    relative = case_path("codereview-pr112")
    path = package / relative
    value = read(path)
    value["surfaces"]["reviews"] = surface_value
    write(path, value)
    index = read(package / "index.json")
    row = next(row for row in index["cases"] if row["path"] == relative)
    data = path.read_bytes()
    row["bytes"] = len(data)
    row["sha256"] = hashlib.sha256(data).hexdigest()
    write(package / "index.json", index)

    with pytest.raises(ObservationError, match=r"expected_surface_object"):
        validate_package(package)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_qm4_observations.py"), "--package", str(package)],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"valid": False, "error": "expected_surface_object"}
    assert result.stderr == b""


@pytest.mark.parametrize("raw", [b"[]\n", b"null\n", b"true\n", b"0\n"])
def test_rehashed_non_object_support_is_rejected_without_traceback(package: Path, raw: bytes) -> None:
    index = read(package / "index.json")
    ref = index["support"][0]
    target = package / ref["path"]
    target.write_bytes(raw)
    ref["bytes"] = len(raw)
    ref["sha256"] = hashlib.sha256(raw).hexdigest()
    write(package / "index.json", index)

    with pytest.raises(ObservationError, match=r"expected_object"):
        validate_package(package)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_qm4_observations.py"), "--package", str(package)],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"valid": False, "error": "expected_object"}
    assert result.stderr == b""


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'])
def test_nonstandard_json_rejected(raw: bytes) -> None:
    with pytest.raises(ObservationError):
        strict_json(raw)


def test_entrypoint_offline_reproducibility_and_raw_bytes_preserved() -> None:
    paths = [p for p in DEFAULT_PACKAGE.rglob("*") if p.is_file()]
    before = {p: p.read_bytes() for p in paths}
    command = [sys.executable, str(ROOT / "scripts/check_qm4_observations.py")]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
    second = subprocess.run(command, cwd=ROOT, capture_output=True, check=True)
    assert result.stdout == second.stdout
    assert json.loads(result.stdout)["valid"] is True
    assert {p: p.read_bytes() for p in paths} == before


@pytest.mark.parametrize(
    "route,value",
    [
        (("source_revision",), "0" * 40),
        (("summary", "actual_pairs"), False),
        (("summary", "frozen_cases"), "41"),
    ],
)
def test_source_revision_and_summary_types_are_strict(package: Path, route: tuple[str, ...], value: Any) -> None:
    mutate(package, "index.json", route, value)
    with pytest.raises(ObservationError):
        validate_package(package)


@pytest.mark.parametrize("field,value", [("source_url", {}), ("response_bytes", []), ("page", True)])
def test_structured_values_cannot_bypass_scalar_contract(package: Path, field: str, value: Any) -> None:
    mutate(package, case_path("codereview-pr112"), ("surfaces", "reviews", field), value)
    with pytest.raises(ObservationError):
        validate_package(package)


def test_entrypoint_rejects_invalid_package(package: Path) -> None:
    mutate(package, "index.json", ("summary", "actual_pairs"), 1)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_qm4_observations.py"), "--package", str(package)],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"valid": False, "error": "summary_not_supported"}
