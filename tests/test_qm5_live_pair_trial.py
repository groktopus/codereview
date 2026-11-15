from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from experiments.harness import qm5_live_pair_trial as qm5
from experiments.harness.selected_model_trial import _limits, trial_contract
from scripts.run_qm5_live_pair_trial import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "examples/evaluation/adversarial-pairs-v1"


@pytest.fixture(autouse=True)
def controlled_clean_source_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make clean-source preparation independent of the enclosing worktree state."""
    source_git = qm5._source_git

    def source_git_clean(*args: str, **kwargs: Any) -> bytes | str:
        if args and args[0] == "status":
            return ""
        return source_git(*args, **kwargs)

    monkeypatch.setattr(qm5, "_source_git", source_git_clean)


def _run_git(git_dir: Path, *args: str) -> str:
    return subprocess.run(
        ["git", f"--git-dir={git_dir}", *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _head() -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def _prepare(tmp_path: Path, pair_id: str = "adv-v1-diff", **kwargs: Any) -> dict[str, Any]:
    revision = _head()
    return qm5.prepare_pair(
        pair_id,
        output_dir=tmp_path / "prepared",
        source_revision=revision,
        run_id="unit-test",
        **kwargs,
    )


def _copy_corpus(path: Path) -> Path:
    dest = path / "corpus"
    shutil.copytree(CORPUS, dest)
    return dest


@pytest.mark.parametrize("pair_id", qm5.PAIR_IDS)
def test_prepares_allowlisted_pair_with_actual_reproducible_git_objects(tmp_path: Path, pair_id: str) -> None:
    authored_pair = next(
        pair for pair in json.loads((CORPUS / "pairs.json").read_text())["pairs"] if pair["pair_id"] == pair_id
    )
    first = _prepare(tmp_path, pair_id)
    assert first["schema"] == qm5.SCHEMA
    assert first["dispatch_status"] == "NOT_DISPATCHED"
    assert first["mode"] == "READ_ONLY"
    assert first["effect_observation"] == "UNKNOWN"
    assert first["pair"]["authored_pair_id"] == pair_id
    assert first["pair"]["provenance"]["known_defect"] == authored_pair["known_defect"]
    assert first["pair"]["provenance"]["family_id"] == authored_pair["family_id"]
    for kind, row in zip(("attack", "benign"), first["cases"], strict=True):
        assert row["authored_case_id"] == authored_pair[f"{kind}_case_id"]
        assert row["authored_run_id"] == authored_pair["runs"]["harness"][f"{kind}_run_id"]
    assert first["cases"][0]["case_id"].startswith("qm5live-v1:")
    assert first["cases"][0]["run_id"].startswith(first["preparation_id"])
    assert all(len(row["source"]["base_sha"]) == 40 for row in first["cases"])
    assert all(len(row["source"]["head_sha"]) == 40 for row in first["cases"])
    assert all(row["source"]["changed_hunks"] > 0 for row in first["cases"])
    for row in first["cases"]:
        git_dir = tmp_path / "prepared/snapshots" / row["source"]["git_dir"]
        assert _run_git(git_dir, "rev-parse", f"{row['source']['head_sha']}^{{tree}}") == row["source"]["head_tree_sha"]
        assert _run_git(git_dir, "rev-parse", f"{row['source']['head_sha']}^") == row["source"]["base_sha"]
        assert _run_git(git_dir, "remote") == ""
        assert all(
            anchor["path"] and anchor["base_start"] >= 0 and anchor["head_start"] >= 0
            for anchor in row["source"]["line_anchors"]
        )
        assert any(anchor["path"] == authored_pair["known_defect"]["path"] for anchor in row["source"]["line_anchors"])
        assert row["source"]["file_hashes"]["base"]
        assert row["source"]["file_hashes"]["head"]
    assert first["source"]["relevant_worktree_status"] == "CLEAN"
    assert first["source"]["source_identity_verified"] is True
    assert first["source"]["dispatch_eligible"] is False
    output = tmp_path / "second"
    second = qm5.prepare_pair(
        pair_id,
        output_dir=output,
        source_revision=first["source"]["repository_revision"],
        run_id="unit-test",
    )
    assert [case["source"]["head_sha"] for case in first["cases"]] == [
        case["source"]["head_sha"] for case in second["cases"]
    ]
    assert first["preparation_id"] == second["preparation_id"]
    third = qm5.prepare_pair(
        pair_id,
        output_dir=tmp_path / "third",
        source_revision=first["source"]["repository_revision"],
        run_id="unit-test",
        run_attempt=2,
    )
    assert third["preparation_id"] != first["preparation_id"]
    assert [case["source"]["head_sha"] for case in first["cases"]] == [
        case["source"]["head_sha"] for case in third["cases"]
    ]


def test_caps_match_current_native_v2_contract_exactly(tmp_path: Path) -> None:
    result = _prepare(tmp_path)
    contract = trial_contract("v2")
    assert result["contract"]["version"] == "v2"
    assert result["contract"]["caps"] == {
        "max_provider_calls": contract.max_provider_calls,
        "max_primary_requests": contract.max_primary_requests,
        "max_claim_assessments": contract.max_claim_assessments,
        "max_retries_per_task": 0,
        "pair_max_provider_calls": 10,
        "pair_max_primary_requests": 8,
        "pair_max_claim_assessments": 2,
        "engine_limits": _limits(contract),
    }
    assert (contract.max_provider_calls, contract.max_primary_requests, contract.max_claim_assessments) == (5, 4, 1)


def test_source_revision_mismatch_and_unallowlisted_pair_fail_before_output(tmp_path: Path) -> None:
    with pytest.raises(qm5.PreparationError, match="source_revision_mismatch"):
        qm5.prepare_pair("adv-v1-diff", output_dir=tmp_path / "bad", source_revision="0" * 40)
    with pytest.raises(qm5.PreparationError, match="pair_selection_invalid"):
        qm5.prepare_pair("adv-v1-unknown", output_dir=tmp_path / "bad2", source_revision=_head())
    assert not (tmp_path / "bad").exists()
    assert not (tmp_path / "bad2").exists()


def test_dirty_source_is_explicit_and_cli_rejects_it(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    source_git = qm5._source_git

    def source_git_dirty(*args: str, **kwargs: Any) -> bytes | str:
        if args and args[0] == "status":
            return " M tests/test_qm5_live_pair_trial.py"
        return source_git(*args, **kwargs)

    monkeypatch.setattr(qm5, "_source_git", source_git_dirty)
    with pytest.raises(qm5.PreparationError, match="source_worktree_dirty"):
        qm5.prepare_pair("adv-v1-diff", output_dir=tmp_path / "dirty", source_revision=_head())
    assert not (tmp_path / "dirty").exists()
    assert "source_worktree_dirty" not in capsys.readouterr().out
    dirty = qm5.prepare_pair(
        "adv-v1-diff",
        output_dir=tmp_path / "development",
        source_revision=_head(),
        allow_dirty_source=True,
    )
    assert dirty["source"]["relevant_worktree_status"] == "DIRTY_UNVERIFIED"
    assert dirty["source"]["source_identity_verified"] is False
    assert dirty["source"]["dispatch_eligible"] is False
    assert (
        cli_main(
            [
                "--prepare-only",
                "--pair-id",
                "adv-v1-diff",
                "--source-revision",
                _head(),
                "--run-id",
                "cli-test",
                "--output-dir",
                str(tmp_path / "cli-dirty"),
            ]
        )
        == 2
    )
    assert not (tmp_path / "cli-dirty").exists()
    assert "source_worktree_dirty" in capsys.readouterr().err


def test_cli_prepare_only_runs_provider_free_preparation(tmp_path: Path, capsys) -> None:
    output = tmp_path / "cli-prepared"
    assert (
        cli_main(
            [
                "--prepare-only",
                "--pair-id",
                "adv-v1-retrieved_context",
                "--source-revision",
                _head(),
                "--run-id",
                "cli-test",
                "--run-attempt",
                "1",
                "--output-dir",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["dispatch_status"] == "NOT_DISPATCHED"
    assert (output / "qm5-live-pair-preparation.v1.json").is_file()


@pytest.mark.parametrize("mutation", ["extra", "missing", "tampered", "symlink", "escape", "manifest"])
def test_inventory_corruption_fails_before_artifact_creation(tmp_path: Path, mutation: str) -> None:
    corpus = _copy_corpus(tmp_path)
    fixture = corpus / "fixtures/diff/attack/head/src/auth.py"
    if mutation == "extra":
        (corpus / "unexpected.txt").write_text("unexpected")
    elif mutation == "missing":
        (corpus / "prompt.md").unlink()
    elif mutation == "tampered":
        fixture.write_text(fixture.read_text() + "# changed\n")
    elif mutation == "manifest":
        manifest_path = corpus / "manifest.json"
        manifest_path.write_text(manifest_path.read_text().replace("2026-11-06.1", "tampered"))
    elif mutation in {"symlink", "escape"}:
        fixture.unlink()
        destination = CORPUS / "fixtures/diff/attack/head/src/auth.py"
        if mutation == "escape":
            destination = tmp_path / "outside.txt"
            destination.write_text("outside corpus\n")
        fixture.symlink_to(destination)
    else:
        raise AssertionError("unhandled test mutation")
    with pytest.raises(qm5.PreparationError):
        _prepare(tmp_path, corpus_dir=corpus)
    assert not (tmp_path / "prepared").exists()


def test_output_must_be_new_and_cli_live_path_fails_closed(tmp_path: Path, capsys) -> None:
    out = tmp_path / "existing"
    out.mkdir()
    with pytest.raises(qm5.PreparationError, match="output_path_unsafe"):
        qm5.prepare_pair("adv-v1-diff", output_dir=out, source_revision=_head())
    with pytest.raises(qm5.PreparationError, match="live_execution_not_implemented"):
        qm5.run_pair()
    assert not capsys.readouterr().out


def test_artifact_is_private_and_has_no_secret_fields(tmp_path: Path) -> None:
    result = _prepare(tmp_path)
    artifact = tmp_path / "prepared/qm5-live-pair-preparation.v1.json"
    assert artifact.stat().st_mode & 0o777 == 0o600
    text = artifact.read_text()
    assert "API_KEY" not in text and "secret" not in text.lower()
    assert json.loads(text) == result
    assert hashlib.sha256((CORPUS / "manifest.json").read_bytes()).hexdigest() == result["corpus"]["manifest_sha256"]
