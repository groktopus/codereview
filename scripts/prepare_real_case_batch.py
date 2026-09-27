#!/usr/bin/env python3
"""Provider-free prepare-only screen for three pinned SlopSearX revisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ARTIFACT_MANIFEST_SHA256 = "60a3c0a8ade74f82a886a54444692ffde4682f099038b05d620c1bb8357adec5"
EXPERIMENT_SHA256 = "aa975c8d6a4cbccd81250d530b6219f901b9f1f40504847d6db5a754daa75f64"
CASES = {
    "PR-457": {
        "number": 457,
        "repository": "magnus919/SlopSearX",
        "base": "53dbafd9207eed175228c594058af85ed8e9bd0e",
        "head": "595f143607961d21d162efe76518d86e416d2548",
    },
    "PR-463": {
        "number": 463,
        "repository": "magnus919/SlopSearX",
        "base": "055f07c5fc1ad8dad2172dadd9beb373d5796413",
        "head": "7016d2cfc63b857b255ab5d32b4373fa74387a30",
    },
    "PR-464": {
        "number": 464,
        "repository": "magnus919/SlopSearX",
        "base": "20a743f0434a1843aa00068483f608f1e213b2af",
        "head": "bffc26f9e4bf95aca0c252e88a2396d03ece854c",
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _clean_git_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tempfile.gettempdir(),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": os.devnull,
        "GIT_CONFIG_KEY_1": "protocol.file.allow",
        "GIT_CONFIG_VALUE_1": "always",
    }
    if extra:
        env.update(extra)
    return env


def _bounded_run(argv: list[str], *, env: dict[str, str], timeout: float, stdout_cap: int, stderr_cap: int) -> tuple[bytes, bytes]:
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": stdout_cap, "stderr": stderr_cap}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("subprocess_deadline_exceeded")
            for key, _ in selector.select(min(0.25, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = outputs[key.data]
                if len(target) + len(chunk) > caps[key.data]:
                    raise RuntimeError("subprocess_output_limit_exceeded")
                target.extend(chunk)
        remaining = max(0, deadline - time.monotonic())
        code = process.wait(timeout=remaining)
        if code != 0:
            raise RuntimeError("subprocess_failed")
        return bytes(outputs["stdout"]), bytes(outputs["stderr"])
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise RuntimeError("subprocess_cleanup_deadline_exceeded") from None
        raise
    finally:
        selector.close()


def git_command(args: list[str], *, env_extra: dict[str, str] | None = None, timeout: float = 60) -> str:
    out, _ = _bounded_run(
        ["git", *args], env=_clean_git_env(env_extra), timeout=timeout,
        stdout_cap=4_000_000, stderr_cap=128_000,
    )
    try:
        return out.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        raise ValueError("git_output_not_utf8") from None


def git(repo: Path, *args: str, index_file: Path | None = None) -> str:
    extra = {"GIT_INDEX_FILE": str(index_file)} if index_file else None
    return git_command(["--no-lazy-fetch", "-C", str(repo), *args], env_extra=extra)


def git_blob(repo: Path, revision: str, path: str) -> bytes:
    out, _ = _bounded_run(
        ["git", "-C", str(repo), "show", f"{revision}:{path}"],
        env=_clean_git_env(), timeout=30, stdout_cap=2_000_000, stderr_cap=128_000,
    )
    return out


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("pinned_input_not_object")
    return value


def verify_artifact_tree(root: Path) -> tuple[dict, dict]:
    manifest_bytes = (root / "artifact-manifest.json").read_bytes()
    if sha256(manifest_bytes) != ARTIFACT_MANIFEST_SHA256:
        raise ValueError("artifact_manifest_hash_mismatch")
    manifest = json.loads(manifest_bytes)
    entries = manifest.get("artifacts")
    if not isinstance(entries, list):
        raise ValueError("artifact_manifest_invalid")
    for entry in entries:
        rel = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
            raise ValueError("artifact_manifest_path_invalid")
        path = root / rel
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("artifact_manifest_path_invalid")
        data = path.read_bytes()
        if len(data) != entry.get("bytes") or sha256(data) != entry.get("sha256"):
            raise ValueError("artifact_entry_hash_mismatch")
    experiment_bytes = (root / "experiment-draft.json").read_bytes()
    if sha256(experiment_bytes) != EXPERIMENT_SHA256:
        raise ValueError("experiment_hash_mismatch")
    experiment = json.loads(experiment_bytes)
    if not isinstance(experiment, dict) or experiment.get("schema") != "slopsearx-real-case-selected-model-trial.v1":
        raise ValueError("experiment_schema_mismatch")
    return manifest, experiment


def verify_case(root: Path, source_repo: Path, case: dict, experiment_case: dict, scratch: Path) -> dict:
    case_id = experiment_case["case_id"]
    if (
        experiment_case.get("pull_request_number") != case["number"]
        or experiment_case.get("base_sha") != case["base"]
        or experiment_case.get("head_sha") != case["head"]
        or experiment_case.get("repository") != "magnus919/SlopSearX"
    ):
        raise ValueError("case_identity_mismatch")
    for revision in (case["base"], case["head"]):
        git(source_repo, "cat-file", "-e", f"{revision}^{{commit}}")
    bare = scratch / f"{case_id}.git"
    git_command(["init", "--bare", str(bare)])
    git_command([
        "--no-lazy-fetch", "--git-dir", str(bare), "fetch", "--depth=1", "--no-tags", "--no-write-fetch-head",
        str(source_repo), case["base"], case["head"],
    ], timeout=120)
    object_report = git(bare, "count-objects", "-v")
    object_count = int(re.search(r"^count: (\d+)$", object_report, re.MULTILINE).group(1))
    pack_kib = int(re.search(r"^size-pack: (\d+)$", object_report, re.MULTILINE).group(1))
    if object_count > 200_000 or pack_kib > 300_000:
        raise ValueError("isolated_object_store_exceeds_bound")
    for revision in (case["base"], case["head"]):
        observed = git(bare, "rev-parse", f"{revision}^{{commit}}")
        if observed != revision:
            raise ValueError("fetched_object_identity_mismatch")

    case_dir = root / "draft-inputs" / case_id
    packet_manifest = load_json(case_dir / "integrity-not-model-input" / "model-visible-manifest.json")
    if (
        packet_manifest.get("repository") != case["repository"]
        or packet_manifest.get("pr_number") != case["number"]
        or packet_manifest.get("base_sha") != case["base"]
        or packet_manifest.get("head_sha") != case["head"]
    ):
        raise ValueError("packet_identity_mismatch")
    for record in experiment_case.get("model_input_files", []):
        rel = record.get("path") if isinstance(record, dict) else None
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
            raise ValueError("model_input_path_invalid")
        data = (case_dir / rel).read_bytes()
        if len(data) != record.get("bytes") or sha256(data) != record.get("sha256"):
            raise ValueError("model_input_file_hash_mismatch")
    review_task = (case_dir / "review-task.md").read_text(encoding="utf-8")
    for identity in (case["base"], case["head"], f"PR #{case['number']}", case["repository"]):
        if identity not in review_task:
            raise ValueError("review_task_identity_mismatch")

    index_repo = scratch / f"{case_id}-packet-index"
    git_command(["init", str(index_repo)])
    git(index_repo, "fetch", "--depth=1", "--no-tags", str(bare), case["base"], case["head"])
    index_file = scratch / f"{case_id}.index"
    git(index_repo, "read-tree", case["base"], index_file=index_file)
    git(index_repo, "apply", "--cached", str(case_dir / "pr.patch"), index_file=index_file)
    packet_tree = git(index_repo, "write-tree", index_file=index_file)
    head_tree = git(bare, "rev-parse", f"{case['head']}^{{tree}}")
    if packet_tree != head_tree:
        raise ValueError("packet_patch_tree_mismatch")

    for source in packet_manifest.get("files", []):
        path = source.get("repository_path") if isinstance(source, dict) else None
        if not path:
            continue
        if source.get("source_revision") != case["base"]:
            raise ValueError("context_revision_mismatch")
        actual = git_blob(bare, case["base"], path)
        if sha256(actual) != source.get("sha256"):
            raise ValueError("base_context_content_mismatch")
        if git(bare, "rev-parse", f"{case['base']}:{path}") != source.get("git_blob_sha"):
            raise ValueError("base_context_blob_mismatch")

    return {
        "bare_repository": str(bare),
        "base_object": case["base"],
        "head_object": case["head"],
        "packet_patch_sha256": sha256((case_dir / "pr.patch").read_bytes()),
        "packet_patch_produces_exact_head_tree": True,
        "base_context_file_count": sum(bool(f.get("repository_path")) for f in packet_manifest.get("files", [])),
        "isolated_object_count": object_count,
        "isolated_pack_kib": pack_kib,
    }


def normalize_checks(source: dict, repository: str, pr_number: int, base: str, head: str, dest: Path) -> None:
    allowed = {"portal-contract", "portal-browser"}
    runs = source.get("selected_runs")
    if not isinstance(runs, list) or {run.get("name") for run in runs if isinstance(run, dict)} != allowed:
        raise ValueError("required_check_capture_names_mismatch")
    normalized = []
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("required_check_capture_invalid")
        normalized.append({
            "id": run.get("id"),
            "name": run.get("name"),
            "app_id": run.get("app_id"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "head_sha": run.get("head_sha"),
            "completed_at": run.get("completed_at"),
            "details_url": run.get("url"),
        })
    # The pinned source records historical completion timestamps but has no
    # capture timestamp. This is the local normalization-envelope time only.
    document = {
        "schema_version": "1.0",
        "repository": repository,
        "pull_request_number": pr_number,
        "head_sha": head,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "complete": True,
        "runs": normalized,
    }
    if source.get("base_sha") != base or source.get("head_sha") != head or source.get("pull_request_number") != pr_number:
        raise ValueError("required_check_capture_identity_mismatch")
    dest.write_bytes(canonical(document) + b"\n")


def installed_module_proof(cli_path: Path, source_root: Path) -> dict:
    source_package = source_root / "src" / "pr_review_harness"
    source_files = {
        path.relative_to(source_package).as_posix(): sha256(path.read_bytes())
        for path in sorted(source_package.rglob("*.py"))
        if path.is_file()
    }
    first_line = cli_path.open("rb").readline(512).decode("utf-8", errors="strict").strip()
    if not first_line.startswith("#!"):
        raise ValueError("installed_cli_has_no_interpreter")
    interpreter = first_line[2:].split()[0]
    if not Path(interpreter).is_file():
        raise ValueError("installed_cli_interpreter_missing")
    code = (
        "import hashlib,json,pathlib,pr_review_harness;"
        "p=pathlib.Path(pr_review_harness.__file__).resolve().parent;"
        "d={x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() "
        "for x in sorted(p.rglob('*.py')) if x.is_file()};"
        "print(json.dumps({'files':d,'root':str(p)},sort_keys=True,separators=(',',':')))"
    )
    raw, _ = _bounded_run(
        [interpreter, "-c", code],
        env={"PATH": os.environ.get("PATH", ""), "HOME": tempfile.gettempdir(), "PYTHONNOUSERSITE": "1"},
        timeout=20,
        stdout_cap=256_000,
        stderr_cap=32_000,
    )
    installed = json.loads(raw)
    if installed.get("files") != source_files:
        raise ValueError("installed_package_source_hash_mismatch")
    return {
        "cli_executable": str(cli_path),
        "interpreter": interpreter,
        "installed_package_root": installed.get("root"),
        "module_file_count": len(source_files),
        "module_tree_sha256": sha256(canonical(source_files)),
        "installed_matches_source": True,
    }


def prepare_case(cli_path: Path, root: Path, experiment: dict, case_id: str, case: dict, experiment_case: dict, verified: dict, scratch: Path, input_cap: int) -> dict:
    profile_meta = experiment_case["profile"]
    profile_path = root / profile_meta["path"]
    if sha256(profile_path.read_bytes()) != profile_meta["sha256"]:
        raise ValueError("case_profile_hash_mismatch")
    profile = load_json(profile_path)
    if profile.get("repository") != "magnus919/SlopSearX" or profile.get("version") != profile_meta["version"]:
        raise ValueError("case_profile_identity_mismatch")
    checks_meta = experiment_case["checks_artifact"]
    checks_src = root / checks_meta["path"]
    if sha256(checks_src.read_bytes()) != checks_meta["sha256"]:
        raise ValueError("case_checks_hash_mismatch")
    checks_doc = scratch / f"{case_id}-checks.json"
    normalize_checks(load_json(checks_src), case["repository"], case["number"], case["base"], case["head"], checks_doc)

    limits_doc = scratch / f"{case_id}-limits.json"
    exp_limits = experiment["limits"]
    limits_doc.write_bytes(canonical({
        "deadline_seconds": exp_limits["engine_deadline_seconds_per_case"],
        "max_concurrent_scopes": 1,
        "max_provider_calls": exp_limits["max_provider_calls_per_case"],
        "max_retries_per_task": exp_limits["retries_per_task"],
        "max_context_bytes": exp_limits["max_context_bytes_per_case"],
        "max_input_bytes_per_task": input_cap,
        "max_output_bytes_per_task": exp_limits["max_response_bytes_per_call"],
        "max_output_bytes": exp_limits["max_response_bytes_per_call"] * exp_limits["max_provider_calls_per_case"],
        "max_output_tokens": exp_limits["max_output_tokens_per_call"],
        "max_context_retrievals": 8,
        "max_followup_tasks": 8,
    }) + b"\n")
    provider_doc = scratch / f"{case_id}-provider.json"
    provider_doc.write_bytes(canonical({
        "kind": "openai_compatible",
        "provider_id": experiment["primary_identity"]["configured_provider_id"],
        "base_url": experiment["primary_identity"]["configured_base_url"],
        "model": experiment["primary_identity"]["configured_model"],
        "api_key_env": experiment["primary_identity"]["credential_reference"],
        "max_output_tokens": exp_limits["max_output_tokens_per_call"],
        "max_response_bytes": exp_limits["max_response_bytes_per_call"],
        "timeout_seconds": exp_limits["engine_deadline_seconds_per_case"],
    }) + b"\n")
    decision_doc = scratch / f"{case_id}-decision.json"
    decision_doc.write_bytes(canonical({
        "kind": "typesafe",
        "endpoint": experiment["adjudicator_identity"]["configured_base_url"],
        "model": experiment["adjudicator_identity"]["configured_model"],
        "api_key_env": experiment["adjudicator_identity"]["credential_reference"],
    }) + b"\n")
    output_dir = scratch / f"{case_id}-cli-output"
    args = [
        str(cli_path), "review", "--repo", verified["bare_repository"],
        "--base", case["base"], "--head", case["head"], "--profile", str(profile_path),
        "--limits", str(limits_doc), "--provider-config", str(provider_doc),
        "--decision-config", str(decision_doc), "--max-claim-assessments", str(exp_limits["max_assessments_per_case"]),
        "--historical-checks-json", str(checks_doc), "--output", str(output_dir),
        "--effect-policy", "READ_ONLY", "--prepare-only", "--json",
    ]
    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tempfile.gettempdir(),
        "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    stdout_bytes, stderr_bytes = _bounded_run(
        args, env=safe_env, timeout=exp_limits["outer_case_deadline_seconds"],
        stdout_cap=4_000_000, stderr_cap=64_000,
    )
    try:
        result = json.loads(stdout_bytes.decode("utf-8", errors="strict"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RuntimeError("prepare_cli_invalid_json") from None
    if result.get("status") != "PREPARED_ONLY" or result.get("disposition") is not None:
        raise RuntimeError("prepare_cli_contract_mismatch")
    return {
        "case_id": case_id,
        "input_bytes_per_task_cap": input_cap,
        "limit_profile": "EXPERIMENT_BASELINE" if input_cap == exp_limits["max_input_bytes_per_task"] else "SENSITIVITY_ONLY_NOT_DEPLOYED",
        "repository": case["repository"],
        "pull_request_number": case["number"],
        "base_sha": case["base"],
        "head_sha": case["head"],
        "packet_verification": verified,
        "profile_sha256": profile_meta["sha256"],
        "checks_source_sha256": checks_meta["sha256"],
        "checks_normalization_time_is_local_envelope_only": True,
        "prepare_result": result,
        "cli_exit_code": 0,
        "stdout_sha256": sha256(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
        "target_execution": "NOT_PERFORMED_BY_PREPARE_PATH",
        "provider_calls": 0,
        "quality_claim": "NONE",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True, help="installed pr-review executable")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input-cap", type=int, choices=[64_000, 128_000, 192_000], default=64_000,
                        help="fixed prepare-only sensitivity point; 64 KB is the frozen baseline")
    args = parser.parse_args()
    cli_path = args.cli.resolve()
    source_repo = args.source_repo.resolve()
    if not cli_path.is_file() or not os.access(cli_path, os.X_OK):
        raise ValueError("installed_cli_missing_or_not_executable")
    if args.output.exists():
        raise ValueError("output_already_exists")
    source_root = Path(__file__).resolve().parents[1]
    module_proof = installed_module_proof(cli_path, source_root)
    _, experiment = verify_artifact_tree(args.artifacts.resolve())
    if set(case["case_id"] for case in experiment.get("cases", [])) != set(CASES):
        raise ValueError("experiment_case_set_mismatch")
    output = {
        "status": "PREPARATION_STARTED",
        "artifact_manifest_sha256": ARTIFACT_MANIFEST_SHA256,
        "experiment_sha256": EXPERIMENT_SHA256,
        "runner_source_sha256": sha256(Path(__file__).read_bytes()),
        "installed_module_proof": module_proof,
        "input_cap_bytes_per_task": args.input_cap,
        "limit_profile": "EXPERIMENT_BASELINE" if args.input_cap == experiment["limits"]["max_input_bytes_per_task"] else "SENSITIVITY_ONLY_NOT_DEPLOYED",
        "cases": [],
    }
    with tempfile.TemporaryDirectory(prefix="slopsearx-realcase-prepare-") as scratch_value:
        scratch = Path(scratch_value)
        for case_id, expected in CASES.items():
            experiment_case = next(c for c in experiment["cases"] if c.get("case_id") == case_id)
            verified = verify_case(args.artifacts, source_repo, expected, experiment_case, scratch)
            output["cases"].append(prepare_case(cli_path, args.artifacts, experiment, case_id, expected, experiment_case, verified, scratch, args.input_cap))
    output["status"] = "PREPARED_ONLY_COMPLETE"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".prepare-real-case-", dir=args.output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(output, sort_keys=True, indent=2).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, args.output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - only stable error code, never raw details
        print(f"prepare-real-case-failed:{type(exc).__name__}", file=os.sys.stderr)
        raise SystemExit(2)
