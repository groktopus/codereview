import json
from pathlib import Path

import yaml

from pr_review_harness.protected_publication_runtime import ProtectedPublicationPolicy

ROOT = Path(__file__).resolve().parents[1]


def test_actions_token_templates_are_bounded_inert_and_match_policy():
    policy = json.loads((ROOT / "templates/protected-publisher-policy-v2.json").read_text(encoding="utf-8"))
    assert policy["schema"] == "pr-review-protected-publication-policy.v2"
    assert policy["authorization_mode"] == "STANDING_BOUNDED"
    assert policy["enabled"] is False
    assert policy["credential"] == {"kind": "ACTIONS_TOKEN", "actor_login": "github-actions[bot]"}
    assert policy["publisher_workflow"]["sha256"] == "REPLACE_WITH_REVIEWED_PUBLISHER_WORKFLOW_SHA256"

    # A complete local test policy is accepted while the shipped template
    # deliberately keeps unresolved target identities and remains disabled.
    policy.update(
        repository={"name": "owner/repo", "id": 8123},
        default_branch="main",
        publisher_workflow={
            "id": 1,
            "path": ".github/workflows/pr-publish.yml",
            "ref": "owner/repo/.github/workflows/pr-publish.yml@refs/heads/main",
            "sha256": "d" * 64,
        },
        source_workflow={
            "id": 2,
            "path": ".github/workflows/pr-analysis.yml",
            "ref": "owner/repo/.github/workflows/pr-analysis.yml@refs/heads/main",
        },
        called_harness={"repository": "harness/repo", "path": ".github/workflows/pr-analysis.yml", "sha": "a" * 40},
        profile={"version": "v1", "sha256": "b" * 64, "provider_configuration_identity": "provider-identity-sha256:" + "c" * 64},
        artifact_redirect_hosts=["downloads.example.test"],
    )
    assert not ProtectedPublicationPolicy.parse(policy).enabled

    workflow = yaml.load(
        (ROOT / "templates/protected-pr-review-publisher-github-token.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert workflow["jobs"]["publisher-disabled"]["if"] == "${{ false }}"
    assert workflow["permissions"] == {"actions": "read", "contents": "read", "pull-requests": "read"}
    assert workflow["jobs"]["publisher-disabled"]["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "write",
    }
    steps = workflow["jobs"]["publisher-disabled"]["steps"]
    assert steps[0]["with"]["ref"] == "${{ github.sha }}"
    assert steps[0]["with"]["persist-credentials"] == "false"
    runtime_step = next(step for step in steps if step.get("name") == "Run the protected publication runtime")
    assert runtime_step["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    assert "PR_REVIEW_GITHUB_APP_PRIVATE_KEY" not in runtime_step["env"]
