from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import pr_review_harness.cross_model as cross_model
from pr_review_harness.cross_model import (
    CROSS_MODEL_VERSION,
    compare_cross_model,
    parse_cross_model_json,
    validate_cross_model_comparison,
)
from pr_review_harness.evaluation import EvaluationError, validate_corpus

ROOT = Path(__file__).resolve().parents[1]
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def sample_corpus() -> dict:
    value = json.loads((ROOT / "examples/evaluation/corpus.json").read_text())
    return validate_corpus(value)


def role_run(case_id: str, role: str, input_hash: str, *, status: str = "completed") -> dict:
    if status == "not_run":
        return {
            "role": role, "status": status, "run_id": None, "provider_id": None, "model_id": None,
            "runtime_id": None, "prompt_revision": "prompt-v1", "rubric_revision": "rubric-v1",
            "input_sha256": None, "input_artifact_id": None, "output_sha256": None, "artifact_id": None,
        }
    return {
        "role": role,
        "status": status,
        "run_id": f"run-{case_id}-{role}",
        "provider_id": f"provider-{role}",
        "model_id": f"model-{role}-exact-version",
        "runtime_id": f"runtime-{role}-v1",
        "prompt_revision": f"prompt-{role}-v1",
        "rubric_revision": f"rubric-{role}-v1",
        "input_sha256": input_hash,
        "input_artifact_id": f"input-{case_id}-{role}",
        "output_sha256": HASH_C,
        "artifact_id": f"artifact-{case_id}-{role}",
    }


def fixture(*, one_case: bool = False) -> tuple[dict, dict]:
    corpus = sample_corpus()
    if one_case:
        corpus["cases"] = corpus["cases"][:1]
    cases = []
    for corpus_case in corpus["cases"]:
        identity = deepcopy(corpus_case["identity"])
        case_id = identity["case_id"]
        records = [
            {
                "role": role,
                "record_id": f"rec-{case_id}-{role}",
                "record_kind": {"writer": "finding", "jev": "classification", "auditor": "audit"}[role],
                "anchor_ids": [f"anchor-{case_id}"],
            }
            for role in ("writer", "jev", "auditor")
        ]
        by_role = {r["role"]: r["record_id"] for r in records}
        cases.append({
            "case_id": case_id,
            "identity": identity,
            "runs": [role_run(case_id, role, hashlib.sha256(f"{case_id}:{role}".encode()).hexdigest()) for role in ("writer", "jev", "auditor")],
            "anchors": [{"anchor_id": f"anchor-{case_id}", "path": "src/review.py", "line_start": 2, "line_end": 2}],
            "records": records,
            "units": [
                {
                    "pair": "writer_jev", "unit_id": f"unit-wj-{case_id}",
                    "left": {"state": "record", "record_id": by_role["writer"]},
                    "right": {"state": "record", "record_id": by_role["jev"]},
                    "relation": "MATCH",
                    "relation_reporter": "jev",
                    "reporter_record_id": by_role["jev"],
                },
                {
                    "pair": "jev_auditor", "unit_id": f"unit-ja-{case_id}",
                    "left": {"state": "record", "record_id": by_role["jev"]},
                    "right": {"state": "record", "record_id": by_role["auditor"]},
                    "relation": "DISAGREEMENT",
                    "relation_reporter": "auditor",
                    "reporter_record_id": by_role["auditor"],
                },
            ],
        })
    comparison = {
        "contract_version": CROSS_MODEL_VERSION,
        "comparison_id": "comparison-2026-09-27-v1",
        "corpus_id": corpus["corpus_id"],
        "dataset_version": corpus["dataset_version"],
        "procedure": {"revision": "procedure-v1", "relation_origin": "declared_reporter_relation", "frozen_sha256": HASH_B},
        "cases": cases,
    }
    return corpus, comparison


def test_report_accounts_for_all_roles_units_and_unchecked_anchors_without_quality_claims():
    corpus, comparison = fixture()
    report = compare_cross_model(comparison, corpus, input_sha256=HASH_C, corpus_sha256=HASH_B)

    case_count = len(comparison["cases"])
    assert report["role_run_counts"]["writer"]["denominator"] == case_count
    assert report["all_role_runs"]["denominator"] == case_count * 3
    assert report["all_role_runs"]["status_counts"]["completed"] == case_count * 3
    assert report["pair_comparison_counts"]["writer_jev"]["denominator"] == case_count
    assert report["pair_comparison_counts"]["writer_jev"]["status_counts"]["MATCH"] == case_count
    assert report["pair_comparison_counts"]["jev_auditor"]["status_counts"]["DISAGREEMENT"] == case_count
    assert report["deterministic_anchor_counts"]["status_counts"]["NOT_RUN"] == case_count
    assert report["role_record_counts"]["writer"] == {
        "case_denominator": case_count,
        "cases_with_records": case_count,
        "cases_with_zero_records": 0,
        "record_denominator": case_count,
        "record_kind_counts": {"abstention": 0, "audit": 0, "classification": 0, "failure": 0, "finding": case_count, "no_counterpart": 0},
        "candidate_or_decision_count": case_count,
        "candidate_or_decision_cases_with_zero": 0,
    }
    assert report["corpus_sha256"] == HASH_B
    assert report["claims"] == {"accuracy": None, "ground_truth": None, "calibration": None, "correctness": None}
    assert all("path" not in anchor and "text" not in anchor for case in report["cases"] for anchor in case["anchors"])
    assert report["report_sha256"]


def test_comparison_identity_must_match_the_corpus_snapshot_exactly():
    corpus, comparison = fixture(one_case=True)
    comparison["cases"][0]["identity"]["head_sha"] = "f" * 40
    with pytest.raises(EvaluationError, match="cross_model_snapshot_mismatch"):
        validate_cross_model_comparison(comparison, corpus)


def test_every_case_requires_all_three_role_runs_including_explicit_not_run():
    corpus, comparison = fixture(one_case=True)
    comparison["cases"][0]["runs"].pop()
    with pytest.raises(EvaluationError, match="missing_or_duplicate_role_run"):
        validate_cross_model_comparison(comparison, corpus)

    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    case["runs"][1] = role_run(case["case_id"], "jev", "", status="not_run")
    case["records"] = [record for record in case["records"] if record["role"] != "jev"]
    unit = case["units"][0]
    unit["right"] = {"state": "not_run", "record_id": None}
    unit["reporter_record_id"] = None
    unit["relation"] = "NOT_RUN"
    case["units"][1]["left"] = {"state": "not_run", "record_id": None}
    case["units"][1]["relation"] = "NOT_RUN"
    case["units"][0]["relation"] = "MATCH"
    with pytest.raises(EvaluationError, match="relation_masks_missing_or_abstained_role"):
        validate_cross_model_comparison(comparison, corpus)


@pytest.mark.parametrize("bad_status", ["unsupported", [], {"status": "completed"}])
def test_malformed_role_status_is_rejected_with_a_bounded_contract_error(bad_status):
    corpus, comparison = fixture(one_case=True)
    comparison["cases"][0]["runs"][0]["status"] = bad_status
    with pytest.raises(EvaluationError):
        validate_cross_model_comparison(comparison, corpus)


def test_duplicate_record_and_duplicate_unit_ids_are_rejected():
    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    case["records"].append(deepcopy(case["records"][0]))
    with pytest.raises(EvaluationError, match="duplicate_record_id"):
        validate_cross_model_comparison(comparison, corpus)

    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    duplicate = deepcopy(case["units"][0])
    duplicate["relation"] = "DISAGREEMENT"
    case["units"].append(duplicate)
    with pytest.raises(EvaluationError, match="duplicate_unit_id"):
        validate_cross_model_comparison(comparison, corpus)


@pytest.mark.parametrize(
    ("run_status", "slot_state", "expected_relation"),
    [("abstained", "record", "ABSTAINED"), ("incomplete", "record", "INCOMPLETE")],
)
def test_match_cannot_mask_abstained_or_incomplete_role(run_status, slot_state, expected_relation):
    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    old_input_hash = case["runs"][1]["input_sha256"]
    case["runs"][1] = role_run(case["case_id"], "jev", old_input_hash, status=run_status)
    if run_status == "abstained":
        case["units"][0]["right"] = {"state": "abstained", "record_id": None}
        case["units"][1]["left"] = {"state": "abstained", "record_id": None}
    with pytest.raises(EvaluationError, match="relation_masks_missing_or_abstained_role"):
        validate_cross_model_comparison(comparison, corpus)
    case["units"][0]["relation"] = expected_relation
    if run_status == "abstained":
        case["units"][0]["right"] = {"state": "abstained", "record_id": None}
        case["units"][1]["left"] = {"state": "abstained", "record_id": None}
        case["units"][1]["relation"] = "ABSTAINED"
    else:
        case["units"][1]["relation"] = "INCOMPLETE"
    assert validate_cross_model_comparison(comparison, corpus)


def test_relations_are_never_inferred_from_or_supplied_with_raw_text():
    corpus, comparison = fixture(one_case=True)
    comparison["cases"][0]["records"][0]["text"] = "provider response content"
    with pytest.raises(EvaluationError, match="invalid_record"):
        validate_cross_model_comparison(comparison, corpus)


def test_duplicate_json_keys_are_rejected():
    with pytest.raises(EvaluationError, match="duplicate_json_key"):
        parse_cross_model_json(b'{"contract_version":"wrong","contract_version":"wrong"}', "comparison")


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()


def test_deterministic_anchor_checks_are_bound_to_head_and_changed_ranges(tmp_path):
    repo = tmp_path / "snapshot"
    repo.mkdir()
    git("init", "-q", cwd=repo)
    git("config", "user.email", "fixture@example.test", cwd=repo)
    git("config", "user.name", "Fixture", cwd=repo)
    (repo / "src").mkdir()
    source = repo / "src/review.py"
    source.write_text("def one():\n    return 1\n\ndef two():\n    return 2\n")
    git("add", "src/review.py", cwd=repo)
    git("commit", "-qm", "base", cwd=repo)
    base = git("rev-parse", "HEAD", cwd=repo)
    source.write_text("def one():\n    return 3\n\ndef two():\n    return 2\n")
    git("commit", "-qam", "head", cwd=repo)
    head = git("rev-parse", "HEAD", cwd=repo)

    corpus, comparison = fixture(one_case=True)
    identity = comparison["cases"][0]["identity"]
    identity["base_sha"] = base
    identity["head_sha"] = head
    identity["snapshot_id"] = "snapshot-git-fixture"
    corpus["cases"][0]["identity"] = deepcopy(identity)
    comparison["cases"][0]["anchors"] = [
        {"anchor_id": "changed-line", "path": "src/review.py", "line_start": 2, "line_end": 2},
        {"anchor_id": "unchanged-line", "path": "src/review.py", "line_start": 5, "line_end": 5},
        {"anchor_id": "past-end", "path": "src/review.py", "line_start": 99, "line_end": 99},
    ]
    for record in comparison["cases"][0]["records"]:
        record["anchor_ids"] = ["changed-line"]
    # The existing manifest's independent identity must be updated with the same exact values.
    corpus = deepcopy(json.loads((ROOT / "examples/evaluation/corpus.json").read_text()))
    corpus["cases"] = [corpus["cases"][0]]
    corpus["cases"][0]["identity"].update({"base_sha": base, "head_sha": head, "snapshot_id": "snapshot-git-fixture"})
    comparison["cases"][0]["identity"] = deepcopy(corpus["cases"][0]["identity"])
    report = compare_cross_model(comparison, corpus, snapshot_roots={comparison["cases"][0]["case_id"]: repo})
    statuses = {row["anchor_id"]: row["status"] for row in report["cases"][0]["anchors"]}
    assert statuses == {
        "changed-line": "CHANGED_RANGE",
        "unchanged-line": "EXISTING_HEAD_RANGE",
        "past-end": "LINE_OUT_OF_RANGE",
    }

    wrong_repo = tmp_path / "wrong"
    wrong_repo.mkdir()
    git("init", "-q", cwd=wrong_repo)
    git("config", "user.email", "fixture@example.test", cwd=wrong_repo)
    git("config", "user.name", "Fixture", cwd=wrong_repo)
    (wrong_repo / "different.txt").write_text("different source\n")
    git("add", "different.txt", cwd=wrong_repo)
    git("commit", "-qm", "wrong snapshot", cwd=wrong_repo)
    mismatch = compare_cross_model(comparison, corpus, snapshot_roots={comparison["cases"][0]["case_id"]: wrong_repo})
    assert {a["status"] for a in mismatch["cases"][0]["anchors"]} == {"SNAPSHOT_MISMATCH"}


def test_reporter_provenance_and_role_specific_artifact_bytes_are_verified(tmp_path):
    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    assert len({run["input_sha256"] for run in case["runs"]}) == 3
    unit = case["units"][0]
    unit["relation_reporter"] = "writer"
    with pytest.raises(EvaluationError, match="relation_reporter_mismatch"):
        validate_cross_model_comparison(comparison, corpus)
    unit["relation_reporter"] = "jev"

    request = tmp_path / "request.bin"
    request.write_bytes(b"secret-bearing request bytes stay local")
    output = tmp_path / "response.bin"
    output.write_bytes(b"bounded response record")
    jev = case["runs"][1]
    jev["input_sha256"] = hashlib.sha256(request.read_bytes()).hexdigest()
    jev["output_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    report = compare_cross_model(
        comparison,
        corpus,
        artifacts={jev["input_artifact_id"]: request, jev["artifact_id"]: output},
    )
    verified = [a for a in report["artifact_verification"]["artifacts"] if a["role"] == "jev"]
    assert {row["status"] for row in verified} == {"VERIFIED"}
    assert "secret-bearing request bytes stay local" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)
    assert report["hashes_are_authentication"] is False


@pytest.mark.parametrize("artifact_kind", ["symlink", "directory", "too_large", "mismatch"])
def test_artifact_verification_rejects_symlink_nonregular_oversized_and_wrong_hash(tmp_path, artifact_kind):
    corpus, comparison = fixture(one_case=True)
    run = comparison["cases"][0]["runs"][0]
    target = tmp_path / "target"
    target.write_bytes(b"x")
    path = tmp_path / "candidate"
    if artifact_kind == "symlink":
        path.symlink_to(target)
        expected = hashlib.sha256(b"x").hexdigest()
        status = "SYMLINK"
    elif artifact_kind == "directory":
        path.mkdir()
        expected = HASH_A
        status = "NOT_REGULAR"
    elif artifact_kind == "too_large":
        with path.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        expected = HASH_A
        status = "TOO_LARGE"
    else:
        path.write_bytes(b"different")
        expected = HASH_A
        status = "HASH_MISMATCH"
    run["input_sha256"] = expected
    report = compare_cross_model(comparison, corpus, artifacts={run["input_artifact_id"]: path})
    row = next(row for row in report["artifact_verification"]["artifacts"] if row["artifact_id"] == run["input_artifact_id"])
    assert row["status"] == status
    assert str(path) not in json.dumps(report)


def test_offline_cli_reports_corpus_hash_and_never_echoes_artifact_path(tmp_path):
    corpus, comparison = fixture(one_case=True)
    corpus_path = tmp_path / "corpus.json"
    comparison_path = tmp_path / "comparison.json"
    artifact_path = tmp_path / "request.bin"
    artifact_path.write_bytes(b"a private request body")
    writer = comparison["cases"][0]["runs"][0]
    writer["input_sha256"] = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    corpus_path.write_text(json.dumps(corpus))
    comparison_path.write_text(json.dumps(comparison))
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/compare_cross_models.py"),
            "--corpus", str(corpus_path),
            "--comparison", str(comparison_path),
            "--artifact", f"{writer['input_artifact_id']}={artifact_path}",
            "--json",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["corpus_sha256"] == hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    assert next(a for a in report["artifact_verification"]["artifacts"] if a["artifact_id"] == writer["input_artifact_id"])["status"] == "VERIFIED"
    assert str(tmp_path) not in result.stdout
    assert "a private request body" not in result.stdout
    assert result.stderr == ""


def test_cli_rejects_fifo_inputs_without_blocking(tmp_path):
    corpus_path = tmp_path / "corpus.json"
    fifo = tmp_path / "comparison.json"
    corpus_path.write_text("{}")
    os.mkfifo(fifo)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/compare_cross_models.py"), "--corpus", str(corpus_path), "--comparison", str(fifo), "--json"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=2,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "invalid_comparison_file_type"}
    assert result.stderr == ""


def test_git_probe_strips_git_overrides_and_disables_lazy_fetch(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_git = bindir / "git"
    fake_git.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'git_env': sorted(k for k in os.environ if k.startswith('GIT_'))}))\n"
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("GIT_DIR", "/untrusted/override")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/untrusted/objects")
    observed = cross_model._git(tmp_path, "rev-parse", "HEAD")
    payload = json.loads(observed)
    assert payload["argv"][:3] == ["--no-lazy-fetch", "--no-replace-objects", "-C"]
    assert payload["git_env"] == [
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
        "GIT_OPTIONAL_LOCKS", "GIT_PAGER", "GIT_TERMINAL_PROMPT",
    ]


def test_git_probe_times_out_when_child_emits_no_output(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_git = bindir / "git"
    fake_git.write_text("#!/bin/sh\nsleep 5\n")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setattr(cross_model, "MAX_GIT_CALL_SECONDS", 0.1)
    started = cross_model.time.monotonic()
    observed = cross_model._git(tmp_path, "rev-parse", "HEAD")
    assert observed == cross_model._GIT_CHECK_FAILED
    assert cross_model.time.monotonic() - started < 1.5


def test_anchor_path_budget_is_explicit_for_unchecked_paths(tmp_path, monkeypatch):
    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    case["anchors"] = [
        {"anchor_id": "one", "path": "one.py", "line_start": 1, "line_end": 1},
        {"anchor_id": "two", "path": "two.py", "line_start": 1, "line_end": 1},
    ]
    for record in case["records"]:
        record["anchor_ids"] = ["one"]
    monkeypatch.setattr(cross_model, "MAX_ANCHOR_PATHS", 1)
    def fake_git(root, *args, deadline=None):
        del root, deadline
        if args[:2] == ("rev-parse", "HEAD"):
            return (case["identity"]["head_sha"] + "\n").encode()
        if args[:2] == ("cat-file", "-e"):
            return b""
        if args[0] == "show":
            return b"line\n"
        return b""
    monkeypatch.setattr(cross_model, "_git", fake_git)
    report = compare_cross_model(comparison, corpus, snapshot_roots={case["case_id"]: tmp_path})
    statuses = {row["anchor_id"]: row["status"] for row in report["cases"][0]["anchors"]}
    assert "CHECK_LIMIT" in statuses.values()


def test_missing_output_role_is_a_zero_candidate_denominator_not_an_implicit_success():
    corpus, comparison = fixture(one_case=True)
    case = comparison["cases"][0]
    case["records"] = []
    case["units"] = []
    report = compare_cross_model(comparison, corpus)
    for role in ("writer", "jev", "auditor"):
        assert report["role_record_counts"][role]["record_denominator"] == 0
        assert report["role_record_counts"][role]["candidate_or_decision_count"] == 0
        assert report["role_record_counts"][role]["candidate_or_decision_cases_with_zero"] == 1
