from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pr_review_harness.claim_assessment import ClaimAssessmentAdapter
from pr_review_harness.claim_triage import ClaimTriagePolicy, triage_claim
from pr_review_harness.snapshot import collect_snapshot
from scripts import run_claim_screen as screen


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _sealed_bundle(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[dict, ...]:
    work = root / ".injection-fixture-work"
    profile = {
        "version": "claim-screen-test-v1",
        "context_paths": [],
        "required_lenses": ["correctness"],
        "docs_lenses": ["correctness"],
        "risk_rules": [],
        "generated_patterns": [],
    }
    limits = {"max_context_bytes": 64_000}
    (work / "trusted-profile.json").parent.mkdir(parents=True)
    (work / "trusted-profile.json").write_text(json.dumps(profile), encoding="utf-8")
    (work / "limits.json").write_text(json.dumps(limits), encoding="utf-8")
    specs = []
    for index, case_id in enumerate(("case-control", "case-attack", "case-comment")):
        repo = work / "fixtures" / case_id
        repo.mkdir(parents=True)
        _git(repo, "init", "--quiet")
        _git(repo, "config", "user.name", "Fixture")
        _git(repo, "config", "user.email", "fixture@example.invalid")
        _git(repo, "config", "core.hooksPath", "/dev/null")
        (repo / "src").mkdir()
        auth = repo / "src/auth.py"
        auth.write_text("def may_read(user, owner):\n    return user == owner\n", encoding="utf-8")
        _git(repo, "add", "--all")
        _git(repo, "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD")
        auth.write_text("def may_read(user, owner):\n    return True\n", encoding="utf-8")
        _git(repo, "add", "--all")
        _git(repo, "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "head")
        head = _git(repo, "rev-parse", "HEAD")
        snapshot = collect_snapshot(str(repo), base, head, profile, limits)
        cited = [item for item in snapshot["evidence"].values() if item.get("source_kind") in {"diff", "head_file"}]
        refs = [item["evidence_id"] for item in cited]
        candidate_id = f"candidate-{index}"
        candidate = {
            "candidate_id": candidate_id,
            "title": "Access predicate changed",
            "observation": "The head implementation returns true for every caller.",
            "consequence": "A non-owner may pass the access predicate.",
            "rule_or_contract": "The predicate is expected to check ownership.",
            "evidence_refs": refs,
        }
        sealed = {
            "snapshot_id": snapshot["snapshot_id"],
            "base_sha": base,
            "head_sha": head,
            "evidence_index": {
                key: {
                    k: v for k, v in value.items() if k not in {"content", "evidence_id", "snapshot_id", "source_url"}
                }
                for key, value in snapshot["evidence"].items()
            },
            "findings": [candidate],
        }
        result_raw = json.dumps(sealed, sort_keys=True, separators=(",", ":")).encode()
        run_dir = root / "runs" / case_id
        run_dir.mkdir(parents=True)
        (run_dir / f"{case_id}.json").write_bytes(result_raw)
        specs.append(
            {
                "case_id": case_id,
                "candidate_id": candidate_id,
                "kind": f"test_case_{index}",
                "result_sha256": hashlib.sha256(result_raw).hexdigest(),
            }
        )
    monkeypatch.setattr(screen, "SCREEN_CASES", tuple(specs))
    return tuple(specs)


def test_load_screen_cases_rebuilds_only_exact_cited_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    specs = _sealed_bundle(tmp_path, monkeypatch)
    cases = screen.load_screen_cases(tmp_path)
    assert len(cases) == 3
    assert [case.candidate_id for case in cases] == [item["candidate_id"] for item in specs]
    assert all(
        case.evidence and {item["evidence_id"] for item in case.evidence} == set(case.candidate["evidence_refs"])
        for case in cases
    )
    assert all(len(case.snapshot_hash) == 64 and len(case.profile_hash) == 64 for case in cases)


def test_sealed_result_hash_change_is_rejected_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sealed_bundle(tmp_path, monkeypatch)
    result = tmp_path / "runs/case-control/case-control.json"
    result.write_bytes(result.read_bytes() + b" ")
    with pytest.raises(screen.ScreenError, match="sealed_result_hash_mismatch"):
        screen.load_screen_cases(tmp_path)


def test_reconstructed_evidence_metadata_mismatch_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    specs = list(_sealed_bundle(tmp_path, monkeypatch))
    result_path = tmp_path / "runs/case-control/case-control.json"
    result = json.loads(result_path.read_text())
    candidate = result["findings"][0]
    cited_id = candidate["evidence_refs"][0]
    result["evidence_index"][cited_id]["content_hash"] = "0" * 64
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result_path.write_bytes(raw)
    specs[0] = {**specs[0], "result_sha256": hashlib.sha256(raw).hexdigest()}
    monkeypatch.setattr(screen, "SCREEN_CASES", tuple(specs))
    with pytest.raises(screen.ScreenError, match="cited_evidence_metadata_mismatch|cited_evidence_hash_mismatch"):
        screen.load_screen_cases(tmp_path)


def test_uncited_evidence_metadata_is_outside_claim_closure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    specs = list(_sealed_bundle(tmp_path, monkeypatch))
    result_path = tmp_path / "runs/case-control/case-control.json"
    result = json.loads(result_path.read_text())
    cited = set(result["findings"][0]["evidence_refs"])
    uncited = next(evidence_id for evidence_id in result["evidence_index"] if evidence_id not in cited)
    result["evidence_index"][uncited]["content_hash"] = "f" * 64
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result_path.write_bytes(raw)
    specs[0] = {**specs[0], "result_sha256": hashlib.sha256(raw).hexdigest()}
    monkeypatch.setattr(screen, "SCREEN_CASES", tuple(specs))
    assert len(screen.load_screen_cases(tmp_path)) == 3


def test_safe_result_drops_free_text_and_keeps_unknown_billing() -> None:
    safe = screen._safe_result(
        {
            "status": "COMPLETE",
            "assessments": {
                "observation_support": {
                    "status": "ANSWERED",
                    "choice": "SUPPORTED",
                    "confidence": 0.7,
                    "probabilities": {"SUPPORTED": 1.0},
                    "evidence_refs": ["ev-1"],
                    "rationale": "DO_NOT_RETAIN_THIS_UNTRUSTED_TEXT",
                    "question_id": "q-1",
                }
            },
            "usage": {"known": False, "input_tokens": None, "output_tokens": None},
            "provenance": {"request_hash": "a" * 64, "provider_model_id": "jev-v1", "raw_body": "DO_NOT_RETAIN"},
            "elapsed_ms": 120,
        }
    )
    serialized = json.dumps(safe)
    assert "DO_NOT_RETAIN" not in serialized
    assert safe["assessments"]["observation_support"]["choice"] == "SUPPORTED"
    assert safe["usage"]["provider_usage_known"] is False
    assert safe["billed_cost"] == "UNKNOWN"
    assert safe["decision"] == "ADVISORY_ONLY"
    assert "contract_version" not in safe


def test_actual_adapter_projection_preserves_contract_for_offline_triage() -> None:
    candidate = {
        "candidate_id": "candidate-screen-projection",
        "title": "Unchecked access predicate",
        "observation": "The changed predicate returns true for every caller.",
        "consequence": "A non-owner can satisfy the predicate.",
        "rule_or_contract": "Access is restricted to the resource owner.",
        "evidence_refs": ["ev-head"],
    }
    content = "def may_read(user, owner): return True"
    evidence = [
        {
            "evidence_id": "ev-head",
            "source_kind": "repository_file",
            "content": content,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(),
            "trust": "repository_evidence",
            "path": "src/auth.py",
            "source_revision": "b" * 40,
            "snapshot_id": "snapshot-screen-projection",
            "line": 1,
        }
    ]
    identity = {
        "snapshot_id": "snapshot-screen-projection",
        "snapshot_hash": "1" * 64,
        "profile_id": "profile-screen-projection",
        "profile_hash": "2" * 64,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    }
    limits = {
        "max_input_bytes_per_task": 60_000,
        "max_output_bytes_per_task": 50_000,
        "deadline_seconds": 2,
    }
    policy = ClaimTriagePolicy.from_mapping(
        {
            "contract_version": "claim-triage-policy.1",
            "policy_id": "projection-test-v1",
            "expected_provider_id": "typesafe",
            "configured_model_id": "jev-latest",
            "allowed_provider_model_ids": ["jev-1.13.0"],
            "required_dimensions": [
                "observation_support",
                "consequence_support",
                "rule_connection_support",
                "materiality",
                "missing_context",
            ],
            "required_choices": {
                "observation_support": "SUPPORTED",
                "consequence_support": "SUPPORTED",
                "rule_connection_support": "SUPPORTED",
                "materiality": "MATERIAL",
                "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
            },
            "contradiction_choices": {"observation_support": ["CONTRADICTED"]},
            "disagreement_rules": [],
        }
    )

    adapter = ClaimAssessmentAdapter(lambda *_args: b"", "jev-latest")
    prepared = adapter.prepare(candidate, evidence, identity, limits)
    desired = {
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "materiality": "MATERIAL",
        "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
    }
    choices_by_question = {
        question_id: desired[dimension] for dimension, question_id in prepared.question_ids if dimension in desired
    }

    def fake_native(raw: bytes, _deadline: float, _cap: int) -> bytes:
        request = json.loads(raw)
        answers = {}
        for question_id, question in request["questions"].items():
            choice = choices_by_question[question_id]
            probabilities = {option: float(option == choice) for option in question["criteria"]}
            answers[question_id] = {
                "type": "choice",
                "choice": choice,
                "probabilities": probabilities,
                "confidence": 1.0,
            }
        return json.dumps(
            {"model": "jev-1.13.0", "request_id": "screen-test", "answers": answers, "usage": {}}
        ).encode()

    adapter = ClaimAssessmentAdapter(fake_native, "jev-latest")
    raw_result = adapter.assess_prepared(prepared, limits)
    safe = screen._safe_result(raw_result)
    assert safe["contract_version"] == raw_result["contract_version"] == "claim-assessment.1"
    assert "rationale" not in json.dumps(safe)
    assert triage_claim(safe, policy)["status"] == "SUPPORTED_FOR_REVIEW"

    # A pre-fix/legacy projection without the adapter's outer version is not
    # silently upgraded and remains unavailable to the strict triage contract.
    legacy = dict(raw_result)
    legacy.pop("contract_version")
    legacy_safe = screen._safe_result(legacy)
    assert "contract_version" not in legacy_safe
    triage = triage_claim(legacy_safe, policy)
    assert triage["status"] == "UNAVAILABLE"
    assert {item["reason_code"] for item in triage["unavailable_reasons"]} >= {"assessment_contract_mismatch"}


def test_worker_has_hard_process_deadline_and_kills_noncooperative_child() -> None:
    started = time.monotonic()
    status, result = screen._run_worker(
        {"test": True},
        {"api_key_env": "CLAIM_SCREEN_TEST_KEY"},
        0.2,
        worker_command=[sys.executable, "-c", "import time; time.sleep(30)"],
    )
    assert status == "hard_deadline_exceeded"
    assert result is None
    assert time.monotonic() - started < 3


def test_runner_persists_each_failure_without_retries_or_secret_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = tuple(
        screen.ScreenCase(
            case_id=f"case-{i}",
            candidate_id=f"candidate-{i}",
            kind=f"kind-{i}",
            result_sha256="a" * 64,
            snapshot_id="snap-test",
            snapshot_hash="b" * 64,
            profile_id="profile-test",
            profile_hash="c" * 64,
            profile_source_sha256="e" * 64,
            base_sha="1" * 40,
            head_sha="2" * 40,
            candidate={
                "candidate_id": f"candidate-{i}",
                "title": "Test candidate",
                "observation": "One concrete observation.",
                "consequence": "One concrete consequence.",
                "rule_or_contract": "Supplied test rule.",
                "evidence_refs": ["ev-test"],
            },
            evidence=(
                {
                    "evidence_id": "ev-test",
                    "content": "A bounded source excerpt.",
                    "content_hash": hashlib.sha256(b"A bounded source excerpt.").hexdigest(),
                    "source_kind": "repository_file",
                    "trust": "repository_evidence",
                    "source_revision": "2" * 40,
                },
            ),
        )
        for i in range(3)
    )
    monkeypatch.setattr(screen, "load_screen_cases", lambda _path: cases)
    monkeypatch.setenv("CLAIM_SCREEN_TEST_KEY", "private-screen-secret-marker")
    config_path = tmp_path / "transport.json"
    config_path.write_text(
        json.dumps(
            {
                "endpoint": "https://api.typesafe.ai/v1/systemone",
                "api_key_env": "CLAIM_SCREEN_TEST_KEY",
                "model": "jev-screen-test",
                "timeout_seconds": 8,
                "max_request_bytes": 64_000,
                "max_response_bytes": 8_000,
            }
        ),
        encoding="utf-8",
    )
    calls: list[str] = []

    def fake_worker(payload, _config, _timeout):
        candidate_id = payload["case"]["candidate"]["candidate_id"]
        calls.append(candidate_id)
        if candidate_id == "candidate-1":
            return "hard_deadline_exceeded", None
        return "ok", {
            "status": "PARTIAL",
            "assessments": {"observation_support": {"status": "OMITTED", "error_code": "answer_omitted"}},
            "usage": {"known": False, "input_tokens": None, "output_tokens": None},
            "provenance": {"request_hash": "d" * 64, "provider_model_id": "jev-screen-test", "elapsed_ms": 15},
            "elapsed_ms": 15,
        }

    monkeypatch.setattr(screen, "_run_worker", fake_worker)
    output_path = tmp_path / "screen.json"
    manifest = screen.run_claim_screen(tmp_path, config_path, output_path)
    assert calls == [case.candidate_id for case in cases]
    assert [row["error_code"] for row in manifest["results"]] == [None, "hard_deadline_exceeded", None]
    assert all(row["retry_count"] == 0 and row["billed_cost"] == "UNKNOWN" for row in manifest["results"])
    stored = output_path.read_text()
    assert "private-screen-secret-marker" not in stored
    assert "rationale" not in stored
