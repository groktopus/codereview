from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import audit_compatibility_pin_literals as pin_inventory  # noqa: E402

POSIX_DIRFD = pytest.mark.skipif(
    not pin_inventory.SECURE_DIRFD_SUPPORTED,
    reason="requires secure POSIX dirfd/no-follow support",
)


def _make_root(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name in ("src", "scripts", "tests", "experiments", "docs", "examples", ".github"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "docs" / "evidence").mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")
    return root


@POSIX_DIRFD
def test_inventory_classifies_candidates_and_preserves_unknowns(tmp_path: Path):
    root = _make_root(tmp_path / "repo")
    revision = "0123456789abcdef" * 2 + "01234567"
    (root / "src" / "runtime.py").write_text(
        f'SOURCE_REVISION = "{revision}"\nresponse_sha256 = "' + "a" * 64 + '"\nopaque = "' + "b" * 64 + '"\n',
        encoding="utf-8",
    )
    (root / ".github" / "action.yml").write_text(f"steps:\n  - uses: owner/action@{revision}\n", encoding="utf-8")
    report = pin_inventory.audit(root, source_revision="c8331390c148d4b1958827b31bce65c6a7a3e858")
    categories = [row["category"] for row in report["occurrences"]]
    assert categories.count("git_revision_candidate") == 1
    assert categories.count("content_digest_candidate") == 1
    assert categories.count("unknown") == 1
    assert categories.count("action_commit_pin") == 1
    assert report["occurrence_count"] == 4
    assert all(len(row["context_sha256"]) == 64 for row in report["occurrences"])
    assert "do not prove a compatibility pin" in report["classification_note"]


@POSIX_DIRFD
def test_inventory_is_deterministic_and_excludes_generated_census_reports(tmp_path: Path):
    root = _make_root(tmp_path / "repo")
    (root / "tests" / "sample.py").write_text('value = "' + "c" * 64 + '"\n', encoding="utf-8")
    (root / "tests" / ".git").mkdir()
    (root / "tests" / ".git" / "ignored.py").write_text('value = "' + "d" * 64 + '"\n', encoding="utf-8")
    output_rel = "docs/evidence/vd3-pin-census-main-aaaaaaaa.json"
    (root / output_rel).write_text('value = "' + "e" * 64 + '"\n', encoding="utf-8")
    from pytest import raises

    with raises(ValueError, match="obsolete"):
        pin_inventory.audit(root, source_revision="a" * 40, output_relative_path=output_rel)
    # The scanner's own implementation and test are excluded even when fixture data
    # contains matching digest-shaped strings in those files.
    report = pin_inventory.audit(root, source_revision="a" * 40)
    again = pin_inventory.audit(root, source_revision="a" * 40)
    assert json.dumps(report, sort_keys=True) == json.dumps(again, sort_keys=True)
    assert report["excluded_paths"] == sorted([*pin_inventory.SELF_AUDIT_PATHS, pin_inventory.GENERATED_CENSUS_PATH])
    assert report["occurrence_count"] == 1
    assert any(row["path"] == "tests/sample.py" for row in report["occurrences"])
    assert all(row["path"] != output_rel for row in report["occurrences"])
    stdout_report = io.StringIO()
    with contextlib.redirect_stdout(stdout_report):
        assert pin_inventory.main(["--root", str(root), "--source-revision", "a" * 40]) == 0
    assert json.loads(stdout_report.getvalue()) == report


@POSIX_DIRFD
def test_inventory_skips_external_file_and_directory_symlinks(tmp_path: Path):
    root = _make_root(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "external.md"
    external.write_text('token = "' + "f" * 64 + '"\n', encoding="utf-8")
    (root / "src" / "linked.md").symlink_to(external)
    (root / "src" / "linked_dir").symlink_to(outside, target_is_directory=True)
    report = pin_inventory.audit(root)
    assert report["occurrence_count"] == 0
    assert report["skipped_symlink_paths"] == ["src/linked.md", "src/linked_dir"]


@POSIX_DIRFD
def test_inventory_rejects_symlinked_declared_root(tmp_path: Path):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    examples = root / "examples"
    examples.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    examples.symlink_to(outside, target_is_directory=True)
    with raises(pin_inventory.ScanRootError, match="declared scan root is a symlink"):
        pin_inventory.audit(root)


@POSIX_DIRFD
def test_inventory_rejects_relative_root_and_scan_root_symlinks(tmp_path: Path):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    linked_root = tmp_path / "repo-link"
    linked_root.symlink_to(root, target_is_directory=True)
    with raises(ValueError):
        pin_inventory.audit(Path("relative"))
    with raises(pin_inventory.ScanRootError):
        pin_inventory.audit(linked_root)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    with raises(pin_inventory.ScanRootError):
        pin_inventory.audit(linked_parent / root.name)


@POSIX_DIRFD
def test_cli_output_is_exclusive_and_anchored_under_selected_root(tmp_path: Path):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    revision = "c8331390c148d4b1958827b31bce65c6a7a3e858"
    destination = root / "docs" / "evidence" / f"vd3-pin-census-main-{revision[:8]}.json"
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        assert pin_inventory.main(["--root", str(root), "--source-revision", revision]) == 0
    assert not destination.exists()
    stdout_report = json.loads(stdout.getvalue())
    assert pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"]) == 0
    saved = destination.read_bytes()
    with raises(SystemExit):
        pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"])
    assert destination.read_bytes() == saved
    assert json.loads(saved) == stdout_report
    assert stdout_report["source_revision"] == revision


@POSIX_DIRFD
def test_cli_rejects_evidence_symlink_and_does_not_touch_target(tmp_path: Path):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / f"vd3-pin-census-main-{revision[:8]}.json"
    target.write_text("preserve", encoding="utf-8")
    evidence = root / "docs" / "evidence"
    evidence.rmdir()
    evidence.symlink_to(outside, target_is_directory=True)
    with raises(SystemExit):
        pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"])
    assert target.read_text(encoding="utf-8") == "preserve"


def test_cli_requires_valid_source_revision_for_stdout_and_output(tmp_path: Path, capsys):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    for args in (
        ["--root", str(root), "--source-revision", "invalid"],
        ["--root", str(root), "--output"],
    ):
        with raises(SystemExit):
            pin_inventory.main(args)
    assert capsys.readouterr().out == ""
    assert not list((root / "docs" / "evidence").iterdir())


def test_inventory_fails_closed_when_secure_dirfd_features_are_unavailable(tmp_path: Path, monkeypatch):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    monkeypatch.setattr(pin_inventory, "SECURE_DIRFD_SUPPORTED", False)
    with raises(pin_inventory.ScanRootError, match="lacks dirfd"):
        pin_inventory.audit(root)


@POSIX_DIRFD
def test_inventory_rejects_missing_declared_scan_root(tmp_path: Path):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    (root / "examples").rmdir()
    with raises(pin_inventory.ScanRootError, match="declared scan root is missing"):
        pin_inventory.audit(root)


@POSIX_DIRFD
def test_directory_entry_budget_stops_incremental_enumeration(tmp_path: Path, monkeypatch):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    directory_fd = pin_inventory._open_root(root)
    consumed = 0

    class Entry:
        def __init__(self, name: str):
            self.name = name

    class DirectoryEntries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def __iter__(self):
            nonlocal consumed
            for index in range(pin_inventory.MAX_DIRECTORY_ENTRIES + 100):
                consumed += 1
                yield Entry(f"entry-{index}")

    monkeypatch.setattr(pin_inventory.os, "scandir", lambda _fd: DirectoryEntries())
    real_dup = pin_inventory.os.dup
    real_close = pin_inventory.os.close
    duplicates = set()

    def tracked_dup(descriptor):
        duplicate = real_dup(descriptor)
        duplicates.add(duplicate)
        return duplicate

    def tracked_close(descriptor):
        duplicates.discard(descriptor)
        return real_close(descriptor)

    monkeypatch.setattr(pin_inventory.os, "dup", tracked_dup)
    monkeypatch.setattr(pin_inventory.os, "close", tracked_close)
    try:
        with raises(OSError, match="directory-entry limit"):
            list(pin_inventory._walk(directory_fd, "src", [], {"directory_entries": 0}, set()))
    finally:
        pin_inventory.os.close(directory_fd)
    assert consumed == pin_inventory.MAX_DIRECTORY_ENTRIES + 1
    assert duplicates == set()


@POSIX_DIRFD
def test_inventory_enforces_directory_depth_limit(tmp_path: Path, monkeypatch):
    from pytest import raises

    monkeypatch.setattr(pin_inventory, "MAX_SCAN_DEPTH", 3)
    root = _make_root(tmp_path / "repo")
    nested = root / "src"
    for index in range(pin_inventory.MAX_SCAN_DEPTH + 1):
        nested = nested / f"d{index}"
        nested.mkdir()
    with raises(OSError, match="directory depth"):
        pin_inventory.audit(root)


@POSIX_DIRFD
def test_cli_cleans_temporary_output_after_write_failure(tmp_path: Path, monkeypatch):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    revision = "b" * 40

    def fail_write(_fd, _data):
        raise OSError("simulated output failure")

    monkeypatch.setattr(pin_inventory.os, "write", fail_write)
    with raises(SystemExit):
        pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"])
    evidence = root / "docs" / "evidence"
    assert not (evidence / f"vd3-pin-census-main-{revision[:8]}.json").exists()
    assert list(evidence.iterdir()) == []


@POSIX_DIRFD
def test_atomic_output_succeeds_with_no_clobber_link_promotion(tmp_path: Path):
    root = _make_root(tmp_path / "repo")
    revision = "d" * 40
    destination = root / "docs" / "evidence" / f"vd3-pin-census-main-{revision[:8]}.json"
    assert pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"]) == 0
    report = json.loads(destination.read_bytes())
    assert report["source_revision"] == revision
    assert list((root / "docs" / "evidence").iterdir()) == [destination]


@POSIX_DIRFD
def test_atomic_output_fsyncs_and_preserves_collision(tmp_path: Path, monkeypatch):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    revision = "c" * 40
    destination = root / "docs" / "evidence" / f"vd3-pin-census-main-{revision[:8]}.json"
    destination.write_text("preserve", encoding="utf-8")
    real_fsync = pin_inventory.os.fsync
    fsync_calls = []

    def tracked_fsync(descriptor):
        fsync_calls.append(descriptor)
        return real_fsync(descriptor)

    monkeypatch.setattr(pin_inventory.os, "fsync", tracked_fsync)
    with raises(SystemExit):
        pin_inventory.main(["--root", str(root), "--source-revision", revision, "--output"])
    assert destination.read_text(encoding="utf-8") == "preserve"
    assert fsync_calls
    assert list((root / "docs" / "evidence").iterdir()) == [destination]


@POSIX_DIRFD
def test_inventory_closes_file_descriptors_after_decode_failure(tmp_path: Path, monkeypatch):
    from pytest import raises

    root = _make_root(tmp_path / "repo")
    (root / "src" / "bad.md").write_bytes(b"\xff")
    opened: set[int] = set()
    real_open = pin_inventory.os.open
    real_close = pin_inventory.os.close

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.add(descriptor)
        return descriptor

    def tracked_close(descriptor):
        opened.discard(descriptor)
        return real_close(descriptor)

    monkeypatch.setattr(pin_inventory.os, "open", tracked_open)
    monkeypatch.setattr(pin_inventory.os, "close", tracked_close)
    with raises(OSError, match="not UTF-8"):
        pin_inventory.audit(root)
    assert opened == set()
