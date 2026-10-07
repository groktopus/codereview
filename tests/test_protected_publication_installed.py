"""Installed-wheel smoke for the protected publication runtime's safe defaults.

Set ``PR_REVIEW_PROTECTED_PUBLICATION_WHEEL`` to the final candidate wheel to
run these subprocess checks. They are skipped in source-only unit runs so the
test suite does not build a wheel repeatedly or race the concurrent source
work. The subprocess imports and executes ``python -m`` from the installed
wheel, outside this checkout.
"""

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


def _policy(*, enabled: bool) -> dict[str, object]:
    repository = "owner/repo"
    source_path = ".github/workflows/review.yml"
    return {
        "schema": "pr-review-protected-publication-policy.v1",
        "enabled": enabled,
        "repository": {"name": repository, "id": 8123},
        "default_branch": "main",
        "publisher_workflow": {
            "id": 801,
            "path": ".github/workflows/pr-publish.yml",
            "ref": f"{repository}/.github/workflows/pr-publish.yml@refs/heads/main",
        },
        "source_workflow": {
            "id": 802,
            "path": source_path,
            "ref": f"{repository}/{source_path}@refs/heads/main",
        },
        "called_harness": {
            "repository": "owner/codereview",
            "path": ".github/workflows/pr-analysis.yml",
            "sha": "a" * 40,
        },
        "app": {
            "id": 333,
            "installation_id": 444,
            "slug": "review-agent",
            "actor_login": "review-agent[bot]",
        },
        "profile": {
            "version": "profile-v1",
            "sha256": "b" * 64,
            "provider_configuration_identity": "provider-identity-sha256:" + "c" * 64,
        },
        "publication": {
            "allowed_dispositions": ["COMMENT"],
            "max_review_body_bytes": 60_000,
            "effect_policy": "PUBLISH_REVIEW",
        },
        "limits": {"max_runs": 10, "max_pages": 2, "max_reviews": 100, "deadline_seconds": 30},
        "artifact_trust_mode": "API_BOUND_SHA256",
        "artifact_redirect_hosts": ["results-receiver.actions.githubusercontent.com"],
    }


def _git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _workspace(path: Path, *, with_policy: bool) -> str:
    path.mkdir()
    _git("init", "-q", cwd=path)
    _git("config", "user.name", "Installed runtime test", cwd=path)
    _git("config", "user.email", "installed-runtime-test@example.invalid", cwd=path)
    (path / "README.md").write_text("protected runtime test workspace\n", encoding="utf-8")
    if with_policy:
        policy_path = path / ".github" / "pr-review-publisher-policy.json"
        policy_path.parent.mkdir(parents=True)
        policy_path.write_text(json.dumps(_policy(enabled=False), sort_keys=True) + "\n", encoding="utf-8")
    _git("add", "-A", cwd=path)
    _git("commit", "-qm", "fixture", cwd=path)
    return _git("rev-parse", "HEAD", cwd=path)


@pytest.fixture(scope="module")
def installed_runtime(tmp_path_factory):
    wheel_value = os.environ.get("PR_REVIEW_PROTECTED_PUBLICATION_WHEEL")
    if not wheel_value:
        pytest.skip("set PR_REVIEW_PROTECTED_PUBLICATION_WHEEL to the final candidate wheel")
    wheel = Path(wheel_value).resolve(strict=True)
    assert wheel.is_file() and wheel.suffix == ".whl"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    assert "pr_review_harness/protected_publication_runtime.py" in names
    assert "pr_review_harness/github_app_canary.py" in names

    root = tmp_path_factory.mktemp("protected-publication-installed")
    target = root / "site"
    target.mkdir()
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--no-compile", "--target", str(target), str(wheel)],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]

    audit = root / "audit"
    audit.mkdir()
    (audit / "sitecustomize.py").write_text(
        """import os, socket
secret_names = {
    'GITHUB_TOKEN', 'PR_REVIEW_GITHUB_APP_PRIVATE_KEY',
    'LLM_BASE_URL', 'LLM_MODEL', 'LLM_API_KEY',
    'JEV_BASE_URL', 'JEV_MODEL', 'JEV_API_KEY', 'TYPESAFE_API_KEY'
}
original = dict(os.environ)
secret_marker = original['SECRET_ACCESS_MARKER']
network_marker = original['NETWORK_ACCESS_MARKER']
class GuardedEnvironment(dict):
    def get(self, key, default=None):
        if key in secret_names:
            with open(secret_marker, 'a', encoding='utf-8') as f:
                f.write(key + '\\n')
        return super().get(key, default)
os.environ = GuardedEnvironment(original)
def deny_network(*args, **kwargs):
    with open(network_marker, 'a', encoding='utf-8') as f:
        f.write('network\\n')
    raise OSError('network disabled in installed-runtime test')
socket.socket.connect = deny_network
socket.create_connection = deny_network
""",
        encoding="utf-8",
    )
    return root, target, audit


def _run_installed(installed_runtime, tmp_path: Path, *, with_policy: bool) -> tuple[dict, Path, Path]:
    root, target, audit = installed_runtime
    workspace = tmp_path / ("protected" if with_policy else "missing-policy")
    source_sha = _workspace(workspace, with_policy=with_policy)
    secret_marker = tmp_path / "secret-access.log"
    network_marker = tmp_path / "network-access.log"
    env = {
        "PATH": os.defpath,
        "HOME": str(tmp_path),
        "PYTHONPATH": os.pathsep.join((str(audit), str(target))),
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_SHA": source_sha,
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/pr-publish.yml@refs/heads/main",
        "GITHUB_RUN_ID": "700",
        "GITHUB_RUN_ATTEMPT": "1",
        "SECRET_ACCESS_MARKER": str(secret_marker),
        "NETWORK_ACCESS_MARKER": str(network_marker),
        "GITHUB_TOKEN": "test-only-secret-canary",
        "PR_REVIEW_GITHUB_APP_PRIVATE_KEY": "test-only-secret-canary",
        "LLM_BASE_URL": "test-only-secret-canary",
        "LLM_MODEL": "test-only-secret-canary",
        "LLM_API_KEY": "test-only-secret-canary",
        "JEV_BASE_URL": "test-only-secret-canary",
        "JEV_MODEL": "test-only-secret-canary",
        "JEV_API_KEY": "test-only-secret-canary",
        "TYPESAFE_API_KEY": "test-only-secret-canary",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "pr_review_harness.protected_publication_runtime"],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    outcome = json.loads(completed.stdout)
    assert not secret_marker.exists(), secret_marker.read_text(encoding="utf-8") if secret_marker.exists() else ""
    assert not network_marker.exists(), network_marker.read_text(encoding="utf-8") if network_marker.exists() else ""
    return outcome, secret_marker, network_marker


def test_installed_module_is_importable_and_valid_disabled_policy_uses_no_secrets_or_network(
    installed_runtime, tmp_path
):
    outcome, secret_marker, network_marker = _run_installed(installed_runtime, tmp_path, with_policy=True)

    assert outcome == {
        "schema": "pr-review-protected-publication.v1",
        "status": "DISABLED",
        "reason": "publication_disabled",
    }
    assert not secret_marker.exists()
    assert not network_marker.exists()


def test_missing_protected_policy_fails_closed_without_secrets_or_network(installed_runtime, tmp_path):
    outcome, secret_marker, network_marker = _run_installed(installed_runtime, tmp_path, with_policy=False)

    assert outcome == {
        "schema": "pr-review-protected-publication.v1",
        "status": "UNKNOWN",
        "reason": "protected_policy_path_untrusted",
    }
    assert not secret_marker.exists()
    assert not network_marker.exists()
