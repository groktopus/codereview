"""RS-2/RS-3: the release workflow stays tag-gated, pinned, and least-privilege."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
PINNED_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
ATTESTATION_ACTION = "actions/attest-build-provenance"
ATTESTATION_PIN = f"{ATTESTATION_ACTION}@e8998f949152b193b063cb0ec769d69d929409be"


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_is_triggered_by_a_tag_or_an_existing_tag_dispatch() -> None:
    text = _workflow()
    triggers = text.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
    assert "tags:" in triggers
    assert "v*.*.*" in triggers
    assert "workflow_dispatch:" in triggers
    assert "inputs:" in triggers
    assert "existing release tag" in triggers.lower()
    assert "branches:" not in triggers


def _job_permission_lines(job: str) -> set[str]:
    block = job.split("permissions:\n", 1)[1].split("steps:", 1)[0]
    return {
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def test_release_workflow_permissions_are_least_privilege() -> None:
    text = _workflow()
    top_permissions = text.split("\npermissions:\n", 1)[1].split("\njobs:", 1)[0]
    assert "contents: read" in top_permissions
    assert "write" not in top_permissions

    build_job = text.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
    # The only write scopes in the build job are the two required by keyless
    # GitHub OIDC attestation; it never receives contents: write.
    assert _job_permission_lines(build_job) == {
        "contents: read",
        "id-token: write",
        "attestations: write",
    }
    assert "contents: write" not in build_job
    assert "contents: write" not in _job_permission_lines(build_job)

    publish_job = text.split("  publish:\n", 1)[1]
    assert _job_permission_lines(publish_job) == {"contents: write"}


def test_release_workflow_uses_no_external_credentials_or_secrets() -> None:
    text = _workflow()
    assert "secrets." not in text
    assert "${{ secrets" not in text
    assert "GH_TOKEN: ${{ github.token }}" in text
    assert "password" not in text.lower()


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    text = _workflow()
    uses = [line.split("uses:", 1)[1].strip().split()[0] for line in text.splitlines() if "uses:" in line]
    assert uses
    for action in uses:
        assert PINNED_ACTION.match(action), action


def test_release_workflow_never_creates_a_tag_and_refuses_missing_or_existing_releases() -> None:
    text = _workflow()
    assert "git tag " not in text
    assert "gh release create" in text
    assert "--verify-tag" in text
    assert "refs/tags/${RELEASE_TAG}^{commit}" in text
    assert "release already exists" in text
    assert "gh api \"repos/${GH_REPO}/git/ref/tags/${RELEASE_TAG}\"" in text
    assert "pull_request_target:" not in text
    assert "compare/${RELEASE_TAG}...${DEFAULT_BRANCH}" in text


def test_release_workflow_builds_checksums_and_attaches_artifacts_and_notes() -> None:
    text = _workflow()
    for token in (
        "scripts/check_reproducible_build.py",
        "sha256sum ./*.whl ./*.tar.gz > SHA256SUMS",
        "sha256sum -c SHA256SUMS",
        "dist/*.whl",
        "dist/*.tar.gz",
        "dist/SHA256SUMS",
        "--notes-file dist/RELEASE-NOTES.md",
        "--verify-tag",
        "scripts/check_version_policy.py",
    ):
        assert token in text
    import re
    asset = re.search(r"^\s+dist/RELEASE-NOTES\.md \\$", text, re.MULTILINE)
    assert asset is not None, "RELEASE-NOTES.md must be a positional release asset"
    assert asset.start() < text.index("--notes-file dist/RELEASE-NOTES.md")


def test_release_workflow_generates_and_publishes_supply_chain_evidence() -> None:
    text = _workflow()
    for token in (
        'SOURCE_DATE_EPOCH=${epoch}',
        "--source-date-epoch \"$SOURCE_DATE_EPOCH\"",
        "scripts/generate_sbom.py",
        "scripts/generate_provenance.py",
        "scripts/verify_release_artifacts.py",
        "dist/REPRODUCIBILITY.json",
        "dist/REPRODUCIBILITY.md",
        "dist/provenance.json",
        "*.cdx.json",
        "--build-command",
    ):
        assert token in text
    # The unsigned provenance/SBOM layer is retained; the attestation is an
    # additional signed layer, not a replacement.
    assert "Record unsigned build provenance" in text
    assert "signing" not in text.lower() or "unsigned" in text.lower()
    # The publish step attaches the evidence as release assets, not only as a
    # workflow artifact.
    release_step = text.split("Create the GitHub Release", 1)[1]
    assert '"${EVIDENCE[@]}"' in release_step
    assert "provenance.json" in release_step
    assert "*.cdx.json" in release_step


def test_release_workflow_attests_verified_wheel_and_sdist_with_pinned_action() -> None:
    text = _workflow()
    build_job = text.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
    assert ATTESTATION_PIN in build_job
    assert "# v2.4.0" in build_job.split(ATTESTATION_PIN, 1)[1].splitlines()[0]

    attest_step = build_job.split("Attest the verified wheel and sdist", 1)[1].split("- name:", 1)[0]
    assert "subject-path: |" in attest_step
    assert "dist/*.whl" in attest_step
    assert "dist/*.tar.gz" in attest_step

    # Attestation happens after the wheel/sdist and their evidence are verified,
    # and before the verified release set is retained for the publish job.
    verify = build_job.index("Verify SBOM, provenance, and checksums agree")
    attest = build_job.index(ATTESTATION_PIN)
    retain = build_job.index("Retain the verified release evidence")
    assert verify < attest < retain
    assert "Verify SBOM, provenance, and checksums agree" not in build_job[attest:retain]


def test_release_workflow_verifies_evidence_in_both_build_and_publish() -> None:
    text = _workflow()
    build_job = text.split("  build:\n", 1)[1].split("  publish:\n", 1)[0]
    publish_job = text.split("  publish:\n", 1)[1]
    assert "verify_release_artifacts.py" in build_job
    assert "verify_release_artifacts.py" in publish_job
    assert "--source-revision \"$SOURCE_REVISION\"" in build_job


def test_verification_workflow_runs_the_reproducibility_and_supply_chain_checks() -> None:
    text = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    job = text.split("  supply-chain:\n", 1)[1].split("\n  installed-wheel:", 1)[0]
    assert "scripts/check_reproducible_build.py" in job
    assert "--source-date-epoch" in job
    assert "scripts/generate_sbom.py" in job
    assert "scripts/generate_provenance.py" in job
    assert "scripts/verify_release_artifacts.py" in job
    assert "tests/test_supply_chain.py" in job
    assert "actions/upload-artifact@" in job


def test_release_workflow_documents_keyless_attestation_and_v010_limit() -> None:
    supply_chain = (ROOT / "docs/SUPPLY-CHAIN.md").read_text(encoding="utf-8")
    releasing = (ROOT / "docs/RELEASING.md").read_text(encoding="utf-8")
    notes = (ROOT / "docs/releases/0.1.1.md").read_text(encoding="utf-8")
    for name, text in (
        ("docs/SUPPLY-CHAIN.md", supply_chain),
        ("docs/RELEASING.md", releasing),
        ("docs/releases/0.1.1.md", notes),
    ):
        lowered = text.lower()
        assert "keyless" in lowered, name
        assert "oidc" in lowered, name
        assert "gh attestation verify" in text, name
        assert "--repo groktopus/codereview" in text, name
        assert "unsigned" in lowered, name
        assert "v0.1.0" in text, name
        assert "remains unsigned" in lowered, name
    assert "provenance.json" in supply_chain
    assert "GitHub artifact attestation is not used" not in supply_chain
    assert "No release asset carries a signature" not in supply_chain


def test_release_actions_reuse_the_same_pins_as_the_verification_workflow() -> None:
    def pins(text: str) -> set[str]:
        found = set()
        for line in text.splitlines():
            if "uses:" in line:
                found.add(line.split("uses:", 1)[1].strip().split()[0])
        return found

    release_pins = pins(_workflow())
    verification_pins = pins((ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"))
    # The attestation action is release-only; every other release pin must be
    # shared with the verification workflow.
    assert release_pins - {ATTESTATION_PIN} <= verification_pins
    assert ATTESTATION_PIN not in verification_pins
