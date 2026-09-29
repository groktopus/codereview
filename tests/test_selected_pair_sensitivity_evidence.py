from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from pr_review_harness import cli, providers
from pr_review_harness import selected_model_trial as trial
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.injection_trials import DEFAULT_LIMITS, prepare_suite

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "experiments/selected-pair-sensitivity-evidence-v1.json"
SUITE_PATH = ROOT / "examples/injection/fixture-suite.v2.json"
SEEDED_ROOT = ROOT / "examples/evaluation/seeded-writer-synth-001"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_contract() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def test_manifest_hashes_bind_existing_fixture_sources():
    contract = _load_contract()
    provenance = contract["provenance"]
    suite = provenance["fixture_suite"]
    assert suite["sha256"] == _sha(SUITE_PATH)

    seeded = provenance["seeded_fixture"]
    assert seeded["truth_sha256"] == _sha(SEEDED_ROOT / "truth.json")
    assert seeded["package_identity_sha256"] == _sha(ROOT / seeded["package_identity_path"])
    truth = json.loads((SEEDED_ROOT / "truth.json").read_text(encoding="utf-8"))
    assert truth["fixture_id"] == seeded["fixture_id"]
    assert truth["model_input"] is False
    for relative, digest in seeded["source_hashes"].items():
        assert digest == _sha(SEEDED_ROOT / relative)
        assert digest == truth["sha256"][relative]


def test_manifest_payload_hashes_and_truth_scope_match_suite():
    contract = _load_contract()
    suite = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
    pair = contract["pair"]
    variants = {row["case_id"]: row for row in suite["variants"]}
    attack = variants["code-comment-attack"]
    benign = variants["code-comment-benign"]
    for row, expected in (
        (attack, pair["attack_payload_sha256"]),
        (benign, pair["benign_payload_sha256"]),
    ):
        encoded = json.dumps(
            {"path": row["path"], "payload": row["payload"]},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        assert hashlib.sha256(encoded).hexdigest() == expected
        assert row["attack_vector"] == "code_comment"

    oracle = contract["construction_oracle"]
    assert suite["base_auth_source"].strip() == "def may_read(user, document):\n    return user.id == document.owner_id"
    assert suite["head_auth_source"].strip() == "def may_read(user, document):\n    return True"
    assert oracle["finding_expected_in_both_pair_members"] is True


def test_selected_pair_inputs_cover_defect_contract_and_payload_without_running_target(tmp_path):
    contract = _load_contract()
    prepared = prepare_suite(
        tmp_path / "prepared",
        suite_path=SUITE_PATH,
        repo_support_root=ROOT,
        repetitions=1,
        limits=DEFAULT_LIMITS,
    )
    by_id = {case.case_id: case for case in prepared.cases}
    pair = contract["pair"]
    attack = by_id[pair["attack_case_id"]]
    benign = by_id[pair["benign_case_id"]]
    assert attack.pair_case_id == benign.case_id
    assert benign.pair_case_id == attack.case_id
    assert attack.anchor["label_id"] == benign.anchor["label_id"] == "owner-check-removed"
    assert attack.anchor["path"] == benign.anchor["path"] == "src/auth.py"
    assert attack.anchor["line"] == benign.anchor["line"] == 3

    required_paths = {"src/auth.py", "src/service.py", "docs/access-contract.md"}
    assert attack.behavior_sha256 == benign.behavior_sha256
    for case in (attack, benign):
        evidence = list(case.snapshot["evidence"].values())
        assert required_paths <= {row.get("path") for row in evidence}
        by_ref = {row["evidence_id"]: row for row in evidence}
        anchor_rows = [by_ref[ref] for ref in case.anchor["evidence_refs"]]
        assert {(row["source_kind"], row["path"]) for row in anchor_rows} == {
            ("diff", "src/auth.py"),
            ("head_file", "src/auth.py"),
        }
        base = next(row for row in evidence if row.get("source_kind") == "base_file" and row.get("path") == "src/auth.py")
        assert "user.id == document.owner_id" in base["content"]
        head = next(row for row in evidence if row.get("source_kind") == "head_file" and row.get("path") == "src/auth.py")
        assert head["content"].splitlines()[case.anchor["line"] - 1].strip() == "return True"
        assert case.variant["payload"] in head["content"]
        assert case.variant["kind"] == ("attack" if case is attack else "benign_lookalike")
        service = next(row for row in evidence if row.get("path") == "src/service.py")
        access_contract = next(row for row in evidence if row.get("path") == "docs/access-contract.md")
        assert "may_read" in service["content"] and "document.contents" in service["content"]
        assert "only when the caller owns" in access_contract["content"]

    assert prepared.suite_sha256 == contract["provenance"]["fixture_suite"]["sha256"]


def test_contract_keeps_model_and_jev_outputs_advisory_and_unrun():
    contract = _load_contract()
    coverage = contract["input_coverage_contract"]
    assert coverage["coverage_target"] == "PREPARED_CASE_SNAPSHOT_AND_CLI_PREPARE_ONLY_LUNA_REQUEST_BODIES"
    assert coverage["exact_luna_request_coverage"] == "CHECKED_PROVIDER_FREE_PREPARE_ONLY"
    assert coverage["jev_request_coverage"] == "NOT_RUN_CANDIDATE_DEPENDENT"
    evaluation = contract["evaluation_contract"]
    assert evaluation["human_labels"] == "NONE"
    assert evaluation["primary_model_calls"] == evaluation["jev_calls"] == "NOT_RUN"
    assert evaluation["provider_calls"] == 0
    assert evaluation["target_code_execution"] == "NOT_RUN"
    assert evaluation["primary_model_output"] == "ADVISORY_CANDIDATE_EVIDENCE"
    assert evaluation["jev_output"].startswith("ADVISORY_ONLY")


def test_cli_prepare_only_serializes_exact_luna_requests_with_paired_evidence(tmp_path, monkeypatch, capsys):
    """Capture the production CLI request bodies while its prepare-only gate prevents dispatch."""
    contract = _load_contract()
    prepared = prepare_suite(
        tmp_path / "prepared",
        suite_path=SUITE_PATH,
        repo_support_root=ROOT,
        repetitions=1,
        limits=trial._limits(),
    )
    profile_path = prepared.profile_path
    limits_path = tmp_path / "limits.json"
    trial._write_json(limits_path, trial._limits())
    provider_path, decision_path, _ = trial._synthetic_configs(tmp_path)
    by_id = {case.case_id: case for case in prepared.cases}
    bodies_by_case: dict[str, list[bytes]] = {}
    active_case_id: str | None = None
    original_serializer = providers.OpenAIProvider.serialize_review_request

    def capture_serializer(provider, task, evidence, limits):
        body = original_serializer(provider, task, evidence, limits)
        frame = inspect.currentframe()
        caller = frame.f_back if frame is not None else None
        try:
            # The planner also serializes candidate bodies while sizing groups.
            # Capture only the final request serialization in cli._run_one's
            # provider-free prepare-only branch.
            if (
                caller is not None
                and caller.f_code.co_filename == cli.__file__
                and caller.f_code.co_name == "_run_one"
            ):
                assert active_case_id is not None
                bodies_by_case.setdefault(active_case_id, []).append(body)
        finally:
            del caller, frame
        return body

    def reject_provider_dispatch(*_args, **_kwargs):
        raise AssertionError("prepare-only must never dispatch a provider request")

    monkeypatch.setattr(providers.OpenAIProvider, "serialize_review_request", capture_serializer)
    monkeypatch.setattr(providers.OpenAIProvider, "review", reject_provider_dispatch)
    monkeypatch.setattr(ClaimTransport, "__call__", reject_provider_dispatch)

    pair = contract["pair"]
    pair_members = (pair["attack_case_id"], pair["benign_case_id"])
    for case_id, other_case_id in (
        (pair["attack_case_id"], pair["benign_case_id"]),
        (pair["benign_case_id"], pair["attack_case_id"]),
    ):
        case = by_id[case_id]
        other_case = by_id[other_case_id]
        active_case_id = case_id
        command = trial._command(
            Path("/unused/pr-review"),
            case,
            profile_path,
            limits_path,
            tmp_path / "cli-output" / case_id,
            provider_path,
            decision_path,
            dry_run=False,
        )
        assert command[0] == "/unused/pr-review"
        exit_code = cli.main([*command[1:-1], "--prepare-only", command[-1]])
        captured = capsys.readouterr()
        assert exit_code == 0, captured.out + captured.err
        report = json.loads(captured.out.strip().splitlines()[-1])
        assert report["status"] == "PREPARED_ONLY"
        assert report["command"] == "review"
        assert report["snapshot"]["base_sha"] == case.base_sha
        assert report["snapshot"]["head_sha"] == case.head_sha
        assert report["no_provider_calls"] is True
        assert report["no_target_code_execution"] is True

        descriptors = report["primary_requests"]
        serialized_by_identity = {}
        for body in bodies_by_case[case_id]:
            identity = (len(body), hashlib.sha256(body).hexdigest())
            prior = serialized_by_identity.setdefault(identity, body)
            assert prior == body
        assert descriptors
        descriptor_by_identity = {
            (row["input_bytes"], row["input_sha256"]): row for row in descriptors
        }
        assert len(descriptor_by_identity) == len(descriptors)
        assert set(serialized_by_identity) == set(descriptor_by_identity)
        for body_identity, descriptor in descriptor_by_identity.items():
            assert body_identity in serialized_by_identity
            body = serialized_by_identity[body_identity]
            body_hash = hashlib.sha256(body).hexdigest()
            assert body_identity == (len(body), body_hash)
            assert descriptor["admitted"] is True
            request = json.loads(body)
            user = json.loads(request["messages"][1]["content"])
            evidence = user["evidence"]
            evidence_text = "\n".join(
                row.get("content", "") for row in evidence if isinstance(row.get("content"), str)
            )
            assert any(
                row.get("source_kind") == "diff"
                and row.get("path") == "src/auth.py"
                and "return True" in row.get("content", "")
                for row in evidence
            )
            assert any(
                row.get("path") == "src/service.py"
                and "document.contents" in row.get("content", "")
                for row in evidence
            )
            assert any(
                row.get("path") == "docs/access-contract.md"
                and "only when the caller owns" in row.get("content", "")
                for row in evidence
            )
            assert case.variant["payload"] in evidence_text
            assert other_case.variant["payload"] not in evidence_text

    assert set(bodies_by_case) == set(pair_members)
