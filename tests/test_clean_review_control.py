from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

from pr_review_harness import cli, providers
from pr_review_harness import selected_model_trial as trial
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.injection_trials import prepare_suite

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "examples/evaluation/clean-review-control-v1"
MANIFEST_PATH = FIXTURE_ROOT / "fixture.json"
SUITE_PATH = ROOT / "examples/injection/fixture-suite.v2.json"
CLEAN_FIXTURE_SHA256 = "b0e5c4117026659f0c5045db117fb54ffdbdcc9c1eff9c89f58ae59087b12d91"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(repo: Path, *args: str, env: dict[str, str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=10,
    )
    return result.stdout.strip()


def _load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _assert_fixture_identity(manifest: dict) -> tuple[dict, dict[str, bytes]]:
    assert _sha(MANIFEST_PATH.read_bytes()) == CLEAN_FIXTURE_SHA256
    suite_raw = SUITE_PATH.read_bytes()
    assert _sha(suite_raw) == manifest["context_provenance"]["fixture_suite_sha256"]
    suite = json.loads(suite_raw)
    files = {
        name: (FIXTURE_ROOT / name).read_bytes()
        for name in manifest["file_hashes"]
    }
    assert {name: _sha(raw) for name, raw in files.items()} == manifest["file_hashes"]

    base = files["auth.base.py"]
    head = files["auth.clean-head.py"]
    allowed_comment = manifest["construction_oracle"]["allowed_head_only_line"].encode("utf-8")
    assert head.count(allowed_comment) == 1
    assert head.replace(allowed_comment, b"", 1) == base
    assert base == suite["base_auth_source"].encode("utf-8")
    for suite_path, fixture_name in manifest["context_provenance"]["context_mapping"].items():
        expected = suite["context_files"][suite_path].encode("utf-8")
        assert files[fixture_name] == expected
    return suite, files


def _materialize_clean_case(repo: Path, suite: dict, files: dict[str, bytes]) -> tuple[str, str]:
    repo.mkdir(parents=True)
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "Clean review fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Clean review fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }
    _git(repo, "init", "--quiet", env=env)
    _git(repo, "config", "core.hooksPath", os.devnull, env=env)
    path_map = {
        "auth.base.py": "src/auth.py",
        "caller.source.txt": "src/service.py",
        "access-contract.md": "docs/access-contract.md",
        "test-contract.md": "tests/test_access_contract.md",
    }
    for name, relative in path_map.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[name])
    (repo / "README.md").write_text("Synthetic authorization review fixture. Target code is never run.\n")
    (repo / "tests/test_auth.py").write_text("# Auth regression test fixture; intentionally not executed.\n")
    _git(repo, "add", "--all", env=env)
    _git(repo, "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "synthetic base", env=env)
    base_sha = _git(repo, "rev-parse", "HEAD", env=env)

    (repo / "src/auth.py").write_bytes(files["auth.clean-head.py"])
    env["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:01+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:01+00:00"
    _git(repo, "add", "--", "src/auth.py", env=env)
    _git(repo, "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "comment-only change", env=env)
    head_sha = _git(repo, "rev-parse", "HEAD", env=env)
    assert _git(repo, "diff", "--name-only", base_sha, head_sha, env=env).splitlines() == ["src/auth.py"]
    return base_sha, head_sha


def test_clean_control_manifest_proves_comment_only_behavior_preservation():
    manifest = _load_manifest()
    assert manifest["schema"] == "clean-review-control-fixture.v1"
    assert manifest["kind"] == "behavior_preserving_code_change"
    assert manifest["case_id"] == "r1-code-clean-control"
    assert manifest["construction_oracle"]["expected_material_candidate"] is False
    assert manifest["construction_oracle"]["expected_coverage"] == "COMPLETE"
    assert "code-clean negative" in manifest["relationship_to_injection_suite"]
    suite, files = _assert_fixture_identity(manifest)
    assert b"return user.id == document.owner_id" in files["auth.clean-head.py"]
    assert b"return True" not in files["auth.clean-head.py"]
    assert suite["head_auth_source"].strip().endswith("return True")


def test_clean_control_prepare_only_binds_exact_primary_requests(tmp_path, monkeypatch, capsys):
    """Exercise exact request preparation only; no provider or target code runs."""
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    manifest = _load_manifest()
    _suite, files = _assert_fixture_identity(manifest)
    repo = tmp_path / "clean-repo"
    base_sha, head_sha = _materialize_clean_case(repo, _suite, files)

    reference = prepare_suite(
        tmp_path / "reference-fixture",
        suite_path=SUITE_PATH,
        repo_support_root=ROOT,
        repetitions=1,
        limits=trial._limits(),
    )
    profile_path = reference.profile_path
    limits_path = tmp_path / "limits.json"
    trial._write_json(limits_path, trial._limits())
    provider_path, decision_path, _ = trial._synthetic_configs(tmp_path)
    case = SimpleNamespace(
        case_id=manifest["case_id"],
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    bodies: list[bytes] = []
    original_serializer = providers.OpenAIProvider.serialize_review_request

    def capture_serializer(provider, task, evidence, limits):
        body = original_serializer(provider, task, evidence, limits)
        frame = inspect.currentframe()
        caller = frame.f_back if frame is not None else None
        try:
            if (
                caller is not None
                and caller.f_code.co_filename == cli.__file__
                and caller.f_code.co_name == "_run_one"
            ):
                bodies.append(body)
        finally:
            del caller, frame
        return body

    def reject_dispatch(*_args, **_kwargs):
        raise AssertionError("prepare-only must not dispatch a provider or decision request")

    monkeypatch.setattr(providers.OpenAIProvider, "serialize_review_request", capture_serializer)
    monkeypatch.setattr(providers.OpenAIProvider, "_call", reject_dispatch)
    monkeypatch.setattr(ClaimTransport, "__call__", reject_dispatch)
    command = trial._command(
        Path("/unused/pr-review"),
        case,
        profile_path,
        limits_path,
        tmp_path / "cli-output",
        provider_path,
        decision_path,
        dry_run=False,
    )
    exit_code = cli.main([*command[1:-1], "--prepare-only", command[-1]])
    captured = capsys.readouterr()
    assert exit_code == 0, captured.out + captured.err
    report = json.loads(captured.out.strip().splitlines()[-1])
    assert report["status"] == "PREPARED_ONLY"
    assert report["snapshot"]["base_sha"] == base_sha
    assert report["snapshot"]["head_sha"] == head_sha
    assert report["no_provider_calls"] is True
    assert report["no_target_code_execution"] is True

    descriptors = report["primary_requests"]
    serialized_by_identity = {
        (len(body), _sha(body)): body
        for body in bodies
    }
    descriptor_by_identity = {
        (row["input_bytes"], row["input_sha256"]): row
        for row in descriptors
    }
    assert len(descriptor_by_identity) == len(descriptors)
    assert descriptors and len(serialized_by_identity) == len(bodies)
    assert set(serialized_by_identity) == set(descriptor_by_identity)
    for identity, descriptor in descriptor_by_identity.items():
        body = serialized_by_identity[identity]
        assert identity == (len(body), _sha(body))
        assert descriptor["admitted"] is True
        request = json.loads(body)
        user = json.loads(request["messages"][1]["content"])
        evidence = user["evidence"]
        auth_diff = next(
            row for row in evidence
            if row.get("source_kind") == "diff" and row.get("path") == "src/auth.py"
        )
        assert "Ordinary maintenance note" in auth_diff["content"]
        assert "return True" not in auth_diff["content"]
        head_auth = next(
            row for row in evidence
            if row.get("source_kind") == "head_file" and row.get("path") == "src/auth.py"
        )
        assert "return user.id == document.owner_id" in head_auth["content"]
        for path, expected in (
            ("src/service.py", files["caller.source.txt"].decode("utf-8")),
            ("docs/access-contract.md", files["access-contract.md"].decode("utf-8")),
            ("tests/test_access_contract.md", files["test-contract.md"].decode("utf-8")),
        ):
            context = next(row for row in evidence if row.get("path") == path)
            assert context["content"] == expected
        evidence_text = "\n".join(row.get("content", "") for row in evidence)
        suite = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
        for variant in suite["variants"]:
            if variant["payload"]:
                assert variant["payload"] not in evidence_text
