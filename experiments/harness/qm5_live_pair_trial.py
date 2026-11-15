"""Provider-free preparation of one immutable QM5 reciprocal pair."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .selected_model_trial import _limits, trial_contract

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "examples/evaluation/adversarial-pairs-v1"
PAIR_IDS = (
    "adv-v1-diff",
    "adv-v1-code_comment",
    "adv-v1-string_literal",
    "adv-v1-documentation",
    "adv-v1-retrieved_context",
)
SCHEMA = "qm5-live-pair-preparation.v1"
_HEX = re.compile(r"^[0-9a-f]{40,64}$")


class PreparationError(ValueError):
    """A frozen input or preparation boundary was invalid."""


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise PreparationError("inventory_shape_invalid")
    return value, raw


def _controlled_env(**extra: str) -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/dev/null",
            "GIT_CONFIG_KEY_1": "commit.gpgsign",
            "GIT_CONFIG_VALUE_1": "false",
            "GIT_TEMPLATE_DIR": "/dev/null",
            "GIT_AUTHOR_NAME": "QM5 synthetic fixture",
            "GIT_AUTHOR_EMAIL": "qm5-fixture@invalid",
            "GIT_COMMITTER_NAME": "QM5 synthetic fixture",
            "GIT_COMMITTER_EMAIL": "qm5-fixture@invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
            "LC_ALL": "C",
            **extra,
        }
    )
    return env


def _source_git(*args: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, check=False, env=_controlled_env())
    if result.returncode:
        raise PreparationError("trusted_source_lookup_failed")
    return result.stdout if binary else result.stdout.decode("utf-8", "strict").strip()


def _inventory(root: Path, source_revision: str) -> tuple[dict[str, Any], dict[str, str], str, dict[str, str]]:
    """Compare every corpus byte to the tracked tree at the exact source revision."""
    root = root.resolve(strict=True)
    prefix = "examples/evaluation/adversarial-pairs-v1/"
    listing = _source_git("ls-tree", "-rz", "--full-tree", source_revision, "--", prefix, binary=True)
    trusted: dict[str, tuple[str, str]] = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", "strict")
        if mode != "100644" or kind != "blob" or not path.startswith(prefix):
            raise PreparationError("trusted_inventory_entry_invalid")
        trusted[path[len(prefix) :]] = (oid, mode)
    if not trusted:
        raise PreparationError("trusted_inventory_missing")
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PreparationError("inventory_symlink_rejected")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != set(trusted):
        raise PreparationError("inventory_membership_mismatch")
    hashes: dict[str, str] = {}
    for relative, (oid, _) in trusted.items():
        safe = PurePosixPath(relative)
        if safe.is_absolute() or ".." in safe.parts or "\\" in relative:
            raise PreparationError("inventory_path_rejected")
        candidate = root.joinpath(*safe.parts)
        if candidate.resolve(strict=True) != candidate.absolute():
            raise PreparationError("inventory_escape_rejected")
        content = _source_git("cat-file", "blob", oid, binary=True)
        local = candidate.read_bytes()
        if content != local:
            raise PreparationError("trusted_inventory_content_mismatch")
        hashes[relative] = _digest(content)
    manifest, manifest_bytes = _json(root / "manifest.json")
    files = manifest.get("files")
    fixtures = manifest.get("fixture_files")
    if not isinstance(files, dict) or not isinstance(fixtures, list):
        raise PreparationError("inventory_shape_invalid")
    if any(not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in fixtures):
        raise PreparationError("inventory_shape_invalid")
    fixture_paths = [item["path"] for item in fixtures]
    if len(fixture_paths) != len(set(fixture_paths)):
        raise PreparationError("inventory_duplicate_path")
    expected = {"manifest.json", *files, *(item["path"] for item in fixtures), "README.md", "scorecard.json"}
    if set(trusted) != expected:
        raise PreparationError("inventory_membership_mismatch")
    if _digest(manifest_bytes) != hashes["manifest.json"]:
        raise PreparationError("manifest_revision_mismatch")
    for relative, expected_hash in files.items():
        if hashes.get(relative) != expected_hash:
            raise PreparationError("inventory_hash_mismatch")
    for item in fixtures:
        if hashes.get(item["path"]) != item.get("sha256"):
            raise PreparationError("fixture_hash_mismatch")
    digest = _digest(manifest_bytes)
    return manifest, hashes, digest, {path: item[0] for path, item in trusted.items()}


def _git(git_dir: Path, *args: str, input_bytes: bytes | None = None) -> str:
    env = _controlled_env()
    result = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args], input=input_bytes, capture_output=True, check=False, env=env
    )
    if result.returncode:
        raise PreparationError("synthetic_git_operation_failed")
    return result.stdout.decode("utf-8", "strict").strip()


def _commit(git_dir: Path, files: dict[str, bytes], parent: str | None) -> tuple[str, str]:
    _git(git_dir, "read-tree", "--empty")
    for relative, content in sorted(files.items()):
        blob = _git(git_dir, "hash-object", "-w", "--stdin", input_bytes=content)
        _git(git_dir, "update-index", "--add", "--cacheinfo", f"100644,{blob},{relative}")
    tree = _git(git_dir, "write-tree")
    args = ["commit-tree", tree]
    if parent:
        args.extend(["-p", parent])
    commit = _git(git_dir, *args, input_bytes=b"QM5 deterministic synthetic snapshot\n")
    if _git(git_dir, "rev-parse", f"{commit}^{{tree}}") != tree:
        raise PreparationError("synthetic_tree_verification_failed")
    if parent and _git(git_dir, "rev-parse", f"{commit}^") != parent:
        raise PreparationError("synthetic_parent_verification_failed")
    return commit, tree


def _snapshot(
    repo: Path,
    fixture_root: Path,
    case: dict[str, Any],
    case_id: str,
    blob_ids: dict[str, str],
    corpus_hashes: dict[str, str],
) -> dict[str, Any]:
    vector = case["attack_vector"]
    kind = "attack" if case_id == case["attack_case_id"] else "benign"
    source = fixture_root / "fixtures" / vector / kind
    if source.is_symlink() or not source.is_dir():
        raise PreparationError("fixture_snapshot_missing")
    git_dir = repo / f"{case_id.replace(':', '-')}.git"
    git_dir.mkdir(mode=0o700)
    subprocess.run(
        ["git", "init", "--bare", "--template=", "--object-format=sha1", str(git_dir)],
        capture_output=True,
        check=True,
        env=_controlled_env(),
    )
    source_prefix = source.relative_to(fixture_root).as_posix()
    side_files: dict[str, dict[str, bytes]] = {}
    file_hashes: dict[str, dict[str, str]] = {}
    for side in ("base", "head"):
        prefix = f"{source_prefix}/{side}/"
        expected = {path[len(prefix) :]: oid for path, oid in blob_ids.items() if path.startswith(prefix)}
        if not expected:
            raise PreparationError("fixture_snapshot_empty")
        side_files[side] = {
            relative: _source_git("cat-file", "blob", oid, binary=True) for relative, oid in expected.items()
        }
        file_hashes[side] = {relative: _digest(side_files[side][relative]) for relative in sorted(side_files[side])}
        if any(corpus_hashes.get(f"{prefix}{relative}") != file_hashes[side][relative] for relative in expected):
            raise PreparationError("fixture_snapshot_hash_mismatch")
    base, base_tree = _commit(git_dir, side_files["base"], None)
    head, head_tree = _commit(git_dir, side_files["head"], base)
    diff = _git(git_dir, "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", base, head)
    anchors: list[dict[str, Any]] = []
    current_path = ""
    for line in diff.splitlines():
        file_match = re.match(r"^diff --git a/(\S+) b/(\S+)$", line)
        if file_match:
            current_path = file_match.group(2)
        hunk = re.match(r"^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@", line)
        if hunk:
            anchors.append(
                {
                    "path": current_path,
                    "base_start": int(hunk.group(1)),
                    "base_count": int(hunk.group(2) or 1),
                    "head_start": int(hunk.group(3)),
                    "head_count": int(hunk.group(4) or 1),
                }
            )
    return {
        "git_dir": git_dir.name,
        "base_sha": base,
        "base_tree_sha": base_tree,
        "head_sha": head,
        "head_tree_sha": head_tree,
        "file_hashes": file_hashes,
        "changed_hunks": len(anchors),
        "line_anchors": anchors,
    }


def _source_revision(expected: str, allow_dirty_source: bool) -> tuple[str, bool]:
    if not isinstance(expected, str) or not _HEX.fullmatch(expected):
        raise PreparationError("source_revision_mismatch")
    revision = _source_git("rev-parse", "HEAD")
    if revision != expected:
        raise PreparationError("source_revision_mismatch")
    paths = [
        "experiments/harness/selected_model_trial.py",
        "experiments/harness/qm5_live_pair_trial.py",
        "scripts/run_qm5_live_pair_trial.py",
        "tests/test_qm5_live_pair_trial.py",
        "docs/evidence/qm5-live-pair-preparation.md",
        "examples/evaluation/adversarial-pairs-v1",
    ]
    clean = not _source_git("status", "--porcelain", "--untracked-files=all", "--", *paths)
    if not clean and not allow_dirty_source:
        raise PreparationError("source_worktree_dirty")
    return revision, clean


def _source_file_identities(revision: str) -> dict[str, dict[str, Any]]:
    paths = (
        "experiments/harness/selected_model_trial.py",
        "experiments/harness/qm5_live_pair_trial.py",
        "scripts/run_qm5_live_pair_trial.py",
    )
    identities = {}
    for relative in paths:
        current = ROOT / relative
        committed = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{revision}:{relative}"],
            capture_output=True,
            check=False,
            env=_controlled_env(),
        )
        working_hash = _digest(current.read_bytes())
        committed_hash = _digest(committed.stdout) if committed.returncode == 0 else None
        identities[relative] = {
            "working_sha256": working_hash,
            "committed_sha256": committed_hash,
            "matches_commit": committed_hash == working_hash,
        }
    return identities


def prepare_pair(
    pair_id: str,
    *,
    output_dir: Path,
    source_revision: str,
    corpus_dir: Path = CORPUS,
    run_id: str = "local",
    run_attempt: int = 1,
    allow_dirty_source: bool = False,
) -> dict[str, Any]:
    """Prepare exactly one frozen reciprocal pair without provider or target execution."""
    if (
        pair_id not in PAIR_IDS
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id)
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt < 1
    ):
        raise PreparationError("pair_selection_invalid")
    source, source_clean = _source_revision(source_revision, allow_dirty_source)
    source_files = _source_file_identities(source)
    source_exact = source_clean and all(item["matches_commit"] for item in source_files.values())
    if corpus_dir.is_symlink() or corpus_dir.resolve(strict=True) != corpus_dir.absolute():
        raise PreparationError("corpus_root_unsafe")
    corpus = corpus_dir.resolve(strict=True)
    target = output_dir.absolute()
    if target.exists() or target.is_symlink() or not target.parent.is_dir() or target.parent.resolve() != target.parent:
        raise PreparationError("output_path_unsafe")
    manifest, hashes, manifest_digest, blob_ids = _inventory(corpus, source)
    pairs, pair_bytes = _json(corpus / "pairs.json")
    matches = [pair for pair in pairs.get("pairs", []) if pair.get("pair_id") == pair_id]
    if len(matches) != 1 or manifest.get("corpus_id") != pairs.get("corpus_id"):
        raise PreparationError("pair_not_in_frozen_inventory")
    pair = matches[0]
    if pair.get("split") != "challenge":
        raise PreparationError("pair_split_invalid")
    contract = trial_contract("v2")
    caps = {
        "max_provider_calls": contract.max_provider_calls,
        "max_primary_requests": contract.max_primary_requests,
        "max_claim_assessments": contract.max_claim_assessments,
        "max_retries_per_task": 0,
        "pair_max_provider_calls": contract.max_provider_calls * 2,
        "pair_max_primary_requests": contract.max_primary_requests * 2,
        "pair_max_claim_assessments": contract.max_claim_assessments * 2,
        "engine_limits": _limits(contract),
    }
    prep_id = f"qm5prep-v1:{source[:12]}:{pair_id}:{run_id}:{run_attempt}"
    with tempfile.TemporaryDirectory(prefix=".qm5-pair-", dir=target.parent) as temp:
        stage = Path(temp) / "result"
        snapshots = stage / "snapshots"
        snapshots.mkdir(parents=True, mode=0o700)
        case_rows = []
        for kind in ("attack", "benign"):
            case_id = pair[f"{kind}_case_id"]
            source_data = _snapshot(snapshots, corpus, pair, case_id, blob_ids, hashes)
            case_rows.append(
                {
                    "case_id": f"qm5live-v1:{pair_id}:{kind}",
                    "authored_case_id": case_id,
                    "authored_run_id": pair["runs"]["harness"][f"{kind}_run_id"],
                    "run_id": f"{prep_id}:{kind}",
                    "arm": "harness",
                    "source": source_data,
                }
            )
        result = {
            "schema": SCHEMA,
            "preparation_id": prep_id,
            "source": {
                "repository_revision": source,
                "relevant_worktree_status": "CLEAN" if source_clean else "DIRTY_UNVERIFIED",
                "source_files": source_files,
                "source_identity_verified": source_exact,
                "dispatch_eligible": False,
            },
            "corpus": {
                "corpus_id": manifest["corpus_id"],
                "dataset_version": manifest["dataset_version"],
                "manifest_sha256": manifest_digest,
                "pairs_sha256": _digest(pair_bytes),
                "verified_file_count": len(hashes),
                "verified_file_sha256": dict(sorted(hashes.items())),
            },
            "pair": {
                "live_pair_id": f"qm5live-v1:{pair_id}",
                "authored_pair_id": pair_id,
                "provenance": {"known_defect": pair["known_defect"], "family_id": pair["family_id"]},
            },
            "cases": case_rows,
            "contract": {"version": contract.version, "trial_id": contract.trial_id, "caps": caps},
            "mode": "READ_ONLY",
            "dispatch_status": "NOT_DISPATCHED",
            "effect_observation": "UNKNOWN",
        }
        data = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        artifact = stage / "qm5-live-pair-preparation.v1.json"
        descriptor = os.open(artifact, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        artifact.chmod(stat.S_IRUSR | stat.S_IWUSR)
        os.rename(stage, target)
    return result


def run_pair(*args: Any, **kwargs: Any) -> None:
    """Live execution belongs to a later reviewed slice and is deliberately unavailable."""
    raise PreparationError("live_execution_not_implemented")
