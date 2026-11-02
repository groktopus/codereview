"""RS-3: SBOM, unsigned provenance, release verification, and reproducible builds."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_reproducible_build as reproducibility  # noqa: E402
import generate_provenance as provenance  # noqa: E402
import generate_sbom as sbom  # noqa: E402
import verify_release_artifacts as verifier  # noqa: E402

PACKAGE = "pr-review-harness"
VERSION = "1.2.3"
WHEEL = "pr_review_harness-1.2.3-py3-none-any.whl"
SDIST = "pr_review_harness-1.2.3.tar.gz"
CREATED = "2025-11-02T09:00:00Z"


def _metadata(
    *, license_expression: str = "MIT", requires: tuple[str, ...] = (), requires_python: str = ">=3.11"
) -> str:
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {PACKAGE}",
        f"Version: {VERSION}",
        f"License-Expression: {license_expression}",
        f"Requires-Python: {requires_python}",
        "Summary: fixture",
        "Provides-Extra: dev",
        'Requires-Dist: pytest>=8; extra == "dev"',
        *(f"Requires-Dist: {item}" for item in requires),
    ]
    return "\n".join(lines) + "\n"


def _wheel(path: Path, *, metadata: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pr_review_harness/__init__.py", "VALUE = 1\n")
        archive.writestr(f"pr_review_harness-{VERSION}.dist-info/METADATA", metadata or _metadata())
        archive.writestr(f"pr_review_harness-{VERSION}.dist-info/RECORD", "")
    return path


def _tar_bytes(*, content: bytes = b"payload\n", mtime: int = 1000) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data, is_dir in (
            (f"{PACKAGE.replace('-', '_')}-{VERSION}", b"", True),
            (f"{PACKAGE.replace('-', '_')}-{VERSION}/PKG-INFO", _metadata().encode(), False),
            (f"{PACKAGE.replace('-', '_')}-{VERSION}/payload.txt", content, False),
        ):
            info = tarfile.TarInfo(name)
            info.mtime = mtime
            info.mode = 0o644
            if is_dir:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _sdist(path: Path, *, content: bytes = b"payload\n", gzip_mtime: int = 1000, tar_mtime: int = 1000) -> Path:
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=gzip_mtime) as handle:
        handle.write(_tar_bytes(content=content, mtime=tar_mtime))
    return path


def _dist(tmp_path: Path, name: str = "dist", **kwargs: object) -> Path:
    directory = tmp_path / name
    directory.mkdir()
    _wheel(directory / WHEEL, **{key: value for key, value in kwargs.items() if key == "metadata"})  # type: ignore[arg-type]
    _sdist(
        directory / SDIST,
        content=kwargs.get("content", b"payload\n"),  # type: ignore[arg-type]
        gzip_mtime=kwargs.get("gzip_mtime", 1000),  # type: ignore[arg-type]
        tar_mtime=kwargs.get("tar_mtime", 1000),  # type: ignore[arg-type]
    )
    return directory


def _checksums(dist: Path, *extra: Path) -> Path:
    targets = sorted(dist.glob("*")) + list(extra)
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in targets if path.is_file()]
    path = dist / "SHA256SUMS"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _provenance(dist: Path) -> dict[str, object]:
    return provenance.build_provenance(
        dist,
        repository="groktopus/codereview",
        source_revision="a" * 40,
        source_ref="refs/tags/v1.2.3",
        workflow_ref="groktopus/codereview/.github/workflows/release.yml@refs/tags/v1.2.3",
        workflow_sha="b" * 40,
        builder_id="https://github.com/groktopus/codereview/.github/workflows/release.yml@refs/tags/v1.2.3",
        builder_image="GitHub Actions ubuntu-latest",
        invocation_id="12345",
        python_version="3.13.7",
        build_command="python -m build --wheel --sdist --outdir dist",
        created=CREATED,
        source_date_epoch=1762074000,
    )


def _evidence(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    dist = _dist(tmp_path)
    document = sbom.build_document(dist, created=CREATED)
    sbom_path = dist / "pr-review-harness-1.2.3.cdx.json"
    sbom.write_document(document, sbom_path)
    provenance_path = dist / "provenance.json"
    provenance.write_document(_provenance(dist), provenance_path)
    checksums = _checksums(dist)
    return dist, sbom_path, provenance_path, checksums


# --- SBOM -----------------------------------------------------------------


def test_sbom_describes_the_actual_artifacts_with_hashes(tmp_path: Path) -> None:
    dist = _dist(tmp_path)
    document = sbom.build_document(dist, created=CREATED)

    component = document["metadata"]["component"]  # type: ignore[index]
    assert component["name"] == PACKAGE
    assert component["version"] == VERSION
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    properties = {item["name"]: item["value"] for item in component["properties"]}
    assert properties["pr-review-harness:requires-python"] == ">=3.11"
    assert properties["pr-review-harness:runtime-dependencies"] == "0"

    components = {item["name"]: item for item in document["components"]}
    assert set(components) == {WHEEL, SDIST}
    for name, path in ((WHEEL, dist / WHEEL), (SDIST, dist / SDIST)):
        assert components[name]["hashes"] == [{"alg": "SHA-256", "content": sbom.sha256_file(path)}]
        assert components[name]["type"] == "file"


def test_sbom_is_deterministic_and_omits_an_undeclared_timestamp(tmp_path: Path) -> None:
    dist = _dist(tmp_path)
    first = sbom.build_document(dist, created=CREATED)
    second = sbom.build_document(dist, created=CREATED)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["metadata"]["timestamp"] == CREATED  # type: ignore[index]

    without_timestamp = sbom.build_document(dist)
    assert "timestamp" not in without_timestamp["metadata"]  # type: ignore[operator]
    assert without_timestamp["serialNumber"] == first["serialNumber"]


def test_sbom_rejects_runtime_dependencies(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _wheel(dist / WHEEL, metadata=_metadata(requires=("requests>=2",)))
    _sdist(dist / SDIST)
    with pytest.raises(sbom.SupplyChainError, match="runtime dependency"):
        sbom.build_document(dist)


def test_sbom_rejects_a_non_mit_license(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _wheel(dist / WHEEL, metadata=_metadata(license_expression="Apache-2.0"))
    _sdist(dist / SDIST)
    with pytest.raises(sbom.SupplyChainError, match="license"):
        sbom.build_document(dist)


def test_sbom_cli_fails_cleanly_without_artifacts(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert sbom.main(["--dist", str(empty), "--output", str(tmp_path / "sbom.json")]) == 1


# --- provenance -----------------------------------------------------------


def test_provenance_records_subjects_and_is_explicitly_unsigned(tmp_path: Path) -> None:
    dist = _dist(tmp_path)
    document = _provenance(dist)

    subjects = {item["name"]: item["digest"]["sha256"] for item in document["subject"]}
    assert subjects == {
        WHEEL: sbom.sha256_file(dist / WHEEL),
        SDIST: sbom.sha256_file(dist / SDIST),
    }
    assert document["_type"] == "https://in-toto.io/Statement/v1"
    assert document["predicateType"] == "https://slsa.dev/provenance/v1"
    assert document["signing"]["status"] == "unsigned"
    assert document["signing"]["signature"] is None
    assert any("Unsigned" in limitation for limitation in document["limitations"])
    external = document["predicate"]["buildDefinition"]["externalParameters"]
    assert external["source"]["revision"] == "a" * 40
    assert external["workflow"]["ref"].endswith("refs/tags/v1.2.3")
    assert external["build"]["sourceDateEpoch"] == "1762074000"
    assert document["predicate"]["runDetails"]["builder"]["id"].endswith("refs/tags/v1.2.3")


def test_provenance_is_deterministic(tmp_path: Path) -> None:
    dist = _dist(tmp_path)
    first = _provenance(dist)
    second = _provenance(dist)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_provenance_cli_derives_builder_identity_from_the_workflow_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dist = _dist(tmp_path)
    for name in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_WORKFLOW_REF", "GITHUB_RUN_ID"):
        monkeypatch.delenv(name, raising=False)
    output = tmp_path / "provenance.json"
    status = provenance.main(
        [
            "--dist",
            str(dist),
            "--output",
            str(output),
            "--repository",
            "groktopus/codereview",
            "--source-revision",
            "a" * 40,
            "--source-ref",
            "refs/tags/v1.2.3",
            "--workflow-ref",
            "groktopus/codereview/.github/workflows/release.yml@refs/tags/v1.2.3",
            "--workflow-sha",
            "b" * 40,
            "--build-command",
            "python -m build",
            "--created",
            CREATED,
            "--quiet",
        ]
    )
    assert status == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["predicate"]["runDetails"]["builder"]["id"] == (
        "https://github.com/groktopus/codereview/.github/workflows/release.yml@refs/tags/v1.2.3"
    )
    assert document["signing"]["status"] == "unsigned"


def test_provenance_does_not_invent_a_signature_or_signed_status(tmp_path: Path) -> None:
    document = _provenance(_dist(tmp_path))
    signing = document["signing"]
    assert signing["tool"] is None
    assert signing["certificate"] is None
    assert "signature" not in document
    assert signing["status"] == "unsigned"


# --- verification ---------------------------------------------------------


def test_verifier_accepts_consistent_unsigned_release_evidence(tmp_path: Path) -> None:
    dist, sbom_path, provenance_path, checksums = _evidence(tmp_path)
    result = verifier.verify(
        dist,
        sbom=sbom_path,
        provenance=provenance_path,
        checksums=checksums,
        source_revision="a" * 40,
        workflow_ref="groktopus/codereview/.github/workflows/release.yml@refs/tags/v1.2.3",
    )
    assert result["status"] == "PASS"
    assert result["signed"] is False
    assert result["failures"] == []
    assert any("unsigned" in note for note in result["notes"])


def test_verifier_rejects_tampered_artifacts_and_checksums(tmp_path: Path) -> None:
    dist, sbom_path, provenance_path, checksums = _evidence(tmp_path)
    with (dist / WHEEL).open("ab") as handle:
        handle.write(b"tampered")
    result = verifier.verify(dist, sbom=sbom_path, provenance=provenance_path, checksums=checksums)
    assert result["status"] == "FAIL"
    assert any("checksum mismatch" in failure for failure in result["failures"])
    assert any("SBOM" in failure or "provenance" in failure for failure in result["failures"])


def test_verifier_require_signed_fails_for_unsigned_provenance(tmp_path: Path) -> None:
    dist, sbom_path, provenance_path, checksums = _evidence(tmp_path)
    result = verifier.verify(
        dist,
        sbom=sbom_path,
        provenance=provenance_path,
        checksums=checksums,
        require_signed=True,
    )
    assert result["status"] == "FAIL"
    assert any("signature verification is not implemented" in failure for failure in result["failures"])


def test_verifier_does_not_accept_a_forged_signed_claim(tmp_path: Path) -> None:
    import json

    dist, sbom_path, provenance_path, checksums = _evidence(tmp_path)
    document = json.loads(provenance_path.read_text(encoding="utf-8"))
    document["signing"] = {"status": "signed", "signature": "deadbeef", "certificate": None, "tool": None}
    provenance_path.write_text(json.dumps(document), encoding="utf-8")
    checksums = _checksums(dist)
    result = verifier.verify(dist, sbom=sbom_path, provenance=provenance_path, checksums=checksums, require_signed=True)
    assert result["status"] == "FAIL"
    assert any("signature verification is not implemented" in failure for failure in result["failures"])


def test_verifier_rejects_a_source_revision_mismatch(tmp_path: Path) -> None:
    dist, sbom_path, provenance_path, checksums = _evidence(tmp_path)
    result = verifier.verify(
        dist,
        sbom=sbom_path,
        provenance=provenance_path,
        checksums=checksums,
        source_revision="c" * 40,
    )
    assert result["status"] == "FAIL"
    assert any("source revision" in failure for failure in result["failures"])


# --- reproducibility ------------------------------------------------------


def test_reproducibility_reports_byte_identical_artifacts(tmp_path: Path) -> None:
    first = _dist(tmp_path, "first")
    second = _dist(tmp_path, "second")
    report = reproducibility.compare_build_dirs(first, second)
    assert report["status"] == "REPRODUCIBLE"
    assert report["artifact_hashes_match"] is True
    assert report["content_matches"] is True
    assert report["non_determinism"] == []


def test_reproducibility_names_gzip_metadata_as_the_sdist_non_determinism(tmp_path: Path) -> None:
    first = _dist(tmp_path, "first", gzip_mtime=1000)
    second = _dist(tmp_path, "second", gzip_mtime=2000)
    report = reproducibility.compare_build_dirs(first, second)
    assert report["status"] == "CONTENT_REPRODUCIBLE"
    assert report["artifact_hashes_match"] is False
    assert report["content_matches"] is True
    assert any("gzip header mtime differs" in reason for reason in report["non_determinism"])
    assert reproducibility.main(["--compare", str(first), str(second)]) == 0
    assert reproducibility.main(["--compare", str(first), str(second), "--require-identical-artifacts"]) == 1


def test_reproducibility_rejects_different_artifact_content(tmp_path: Path) -> None:
    first = _dist(tmp_path, "first", content=b"one\n")
    second = _dist(tmp_path, "second", content=b"two\n")
    report = reproducibility.compare_build_dirs(first, second)
    assert report["status"] == "NOT_REPRODUCIBLE"
    assert report["content_matches"] is False
    assert reproducibility.main(["--compare", str(first), str(second)]) == 1


def test_reproducibility_build_mode_uses_two_source_copies_and_keeps_the_first_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = _dist(tmp_path, "template")
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(
        "#!/usr/bin/env python3\n"
        "import os, pathlib, shutil, sys\n"
        "if sys.argv[1] == '-c':\n"
        "    print('1.0.0')\n"
        "    print('80.0.0')\n"
        "    print('3.13.0')\n"
        "    raise SystemExit(0)\n"
        "outdir = pathlib.Path(sys.argv[sys.argv.index('--outdir') + 1])\n"
        "outdir.mkdir(parents=True, exist_ok=True)\n"
        "for item in pathlib.Path(os.environ['FAKE_DIST']).iterdir():\n"
        "    shutil.copy2(item, outdir / item.name)\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    monkeypatch.setenv("FAKE_DIST", str(template))
    source = tmp_path / "source"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    dist_out = tmp_path / "release-dist"
    report = reproducibility.run(
        source,
        python=str(fake_python),
        epoch=1762074000,
        work_dir=tmp_path / "work",
        dist_out=dist_out,
        created=CREATED,
    )
    assert report["status"] == "REPRODUCIBLE"
    assert report["python_version"] == "3.13.0"
    assert sorted(path.name for path in dist_out.iterdir()) == sorted([SDIST, WHEEL])
    assert reproducibility.summary_markdown(report).startswith("# Reproducibility report")
