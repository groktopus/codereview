# Versioning policy

**Status:** authoritative for package and contract versions. **Owner:** groktopus/codereview maintainers. **Issue:** #260 (RS-2).

This repository versions two different things independently:

| Surface | Version source | Current value |
|---|---|---|
| Python package and CLI | `pyproject.toml` `project.version` | `0.1.0` |
| Contract identities | [`contract_registry.json`](../src/pr_review_harness/contract_registry.json) | `contract-registry.v1` |

A package version is a statement about the installed distribution. A contract
version is a statement about one review, claim, canary, or artifact interface.
They move independently: a package patch can fix a bug without changing any
contract, and a new contract identity can ship in a package minor release.
Consumers pin the contract identities they need in addition to the package
version. See the [contract registry](CONTRACT-REGISTRY.md) for the authoritative
supported, deprecated, archived, and experimental matrix.

## Package semantic versioning

### Format

The package uses `MAJOR.MINOR.PATCH` (optionally with a pre-release or build
suffix, for example `0.2.0-rc1`). Release tags are `v` followed by exactly that
version: `v0.1.0`, `v0.2.0-rc1`. The release workflow rejects any other tag shape
or any tag that does not equal `project.version`.

* `MAJOR` changes for an incompatible change to a promised surface.
* `MINOR` changes for backward-compatible functionality or any contract
  addition/deprecation.
* `PATCH` changes for backward-compatible corrections that do not change a
  promised surface.

### What a package version promises

A version promises the following, and nothing more:

| Surface | Promise |
|---|---|
| CLI | The documented command names (`review`, `publish`, `stats`), documented option names and their meaning, and process exit-code meanings. Removing or renaming a command or option, or changing what an exit code means, is breaking. |
| Installed entry point | The `pr-review` console script resolves to the documented CLI. The only advertised review entry point remains `pr_review_harness.engine.run_review`; other modules are internal unless a document names them. |
| Artifact schemas | The installed package emits only registered artifact identities. A package version never silently changes the meaning of an already-registered artifact version; incompatible artifact changes require a new artifact identity and a package release that declares it. |
| Contract compatibility | The registry shipped in the wheel is authoritative. A target's pinned default is not silently upgraded. Deprecated identities remain selectable during their compatibility window; archived identities are rejected by default. |
| Packaging | The distribution remains a wheel plus source archive, installs on the documented Python range, and declares the same runtime dependency properties. |

A version does **not** promise review quality, model accuracy, provider or
GitHub availability, target-repository behavior, exact prose output, latency,
or that an experimental or deprecated contract keeps working after its window.
Those are separate evidence questions, not version guarantees.

### Pre-1.0 releases

`0.y.z` is pre-1.0. A `0.y` minor release may include a breaking change, but it
must still be documented under a `Breaking` changelog heading, carry a migration
note, and follow the deprecation window for any contract removal. `0.y.z` patch
releases are limited to backward-compatible fixes. At `1.0.0` the strict
SemVer rule applies: breaking changes require a major release. The project does
not claim post-1.0 stability before these rules are exercised by a real release.

### Change classification

| Change | Release |
|---|---|
| Remove or rename a documented CLI command or option; change an exit-code meaning | major (pre-1.0: minor) + `Breaking` |
| Remove or rename a field in an artifact schema; change a field type or meaning; add a required field to a closed schema | major (pre-1.0: minor) + new artifact identity + `Breaking` |
| Add an optional CLI flag, output field, or a new registered contract identity | minor |
| Deprecate a contract identity without removing it | minor |
| Bug fix, documentation correction, or internal refactor with no promised-surface change | patch |
| Security fix | patch, or minor if it changes a promised surface |
| Any release that adds, deprecates, or removes a registered contract | at least minor (removal: major after the compatibility window) |
| Editorial clarification with no schema or behavior change | patch; no contract version bump |

Every merge that changes behavior or a promised surface updates the
`Unreleased` section of [`CHANGELOG.md`](../CHANGELOG.md) in the same pull
request. Breaking entries appear under `### Breaking` and use the
`BREAKING CHANGE:` convention when the change originates in a commit message.

### Tags and releases

* A release tag is immutable once the GitHub Release exists. Never move or
  delete a published tag; publish a follow-up patch instead.
* A tag may be created only from a commit on `main` whose required checks
  passed at that exact revision.
* The tag is the trigger. The release workflow does not create tags and does
  not create a GitHub Release unless the tag already exists and matches the
  package version.
* The first release has no special version semantics; `v0.1.0` uses the same
  gate as later releases.

### Deprecation window

Deprecated package surfaces and contract identities follow the registry
compatibility window: at least one minor release **and** 90 days after the
replacement is designated. A deprecated identity is never the default for new
selection, but an existing target's pinned default is frozen until its owner
migrates. Every binding records the deprecated status and replacement.

## Contract versioning policy

Contract versions are explicit, independent identities. The registry is the
authority for which identities exist, their status, replacement path, source
path, and removal evidence. A contract is not versioned by the package version,
and a package release never changes a contract's meaning in place.

### Identity rules

* An identity string is immutable. It is never reused for different semantics.
* An incompatible change creates a new identity (a new major or a new name) and
  registers it before it is used.
* Existing artifact files and profile files are not rewritten to make a new
  package pass. Archived identities retain their source and provenance.
* The registry itself has an identity, `contract-registry.v1`, and a matching
  schema. A breaking registry-shape change requires a new registry identity and
  schema file.
* Every identity is registered with `kind`, `name`, `version`, `status`,
  `owner`, and its source path or symbol. Review contracts additionally record
  the exact combination and checks enforced by preflight.
* Deprecation requires a replacement path or an explicit terminal marker; the
  compatibility window and removal evidence requirements are defined in
  [`CONTRACT-REGISTRY.md`](CONTRACT-REGISTRY.md).

### Contract families

| Family | Examples | Version form |
|---|---|---|
| Review contracts, profiles, limits | `codereview-native-v1`, `legacy-v14`, `ordinary-review-limits-v3` | Identity name; the trailing `vN` is the contract generation |
| Claim assessment | `claim-assessment.2`, `claim-assessment.3` | Integer contract version after the family name |
| Canary/publication receipt | `actions-receipt-v1`, `actions-receipt-v2`, `actions-receipt-v3` | Identity name with a generation suffix |
| Artifacts, model output, context, policy | `review-result.v0.1`, `review-run-summary.v1`, `specialist-findings.v4`, `context-selection.v3` | `<family>.v<MAJOR>` or `<family>.v<MAJOR>.<MINOR>` |

### What a contract version promises

| Contract family | Promise |
|---|---|
| Review contract | The exact target/profile/limits/claim-cap combination and the invariant checks recorded in the registry. Preflight rejects a combination that does not resolve to the registered entry, and the effective contract set is recorded in every result. |
| Claim assessment | The output record shape and the stable `contract_version` identity. A consumer that pins `claim-assessment.2` can read the fields that identity documents; a shape change requires `claim-assessment.3` or a new major. |
| Canary/publication receipt | The receipt fields and protocol semantics used to validate a publication observation. A receiver never guesses an unregistered receipt generation. |
| Artifact schema | The JSON Schema file published under `schemas/`. Field names, types, and required/closed-object behavior are stable for that identity; consumers may pin the schema file and validate emitted artifacts. |

### Breaking-change rules

A contract change is breaking when it removes or renames a field or command,
changes a field type or meaning, adds a required field, narrows an accepted
enum, changes a default that can alter a disposition, changes receipt or
publication semantics, or changes the combination/invariants that a review
contract claims.

Breaking contract changes require a new identity (new major or new registered
name) **and** a package release that adds the identity through the registry.
They also require a `Breaking` changelog entry and a migration note; existing
consumers of the old identity keep their pinned behavior during the deprecation
window. When a schema uses `additionalProperties: false`, adding a field is
breaking for strict validators and therefore requires a new major rather than a
minor.

Additive changes are allowed in a new minor identity when existing consumers can
ignore the addition. Adding an optional field to an open schema, adding a new
registered identity, and deprecating an identity without removing it are minor.
Editorial clarifications that do not change a schema or behavior do not require
a contract version bump.

### Package and contract interaction

* A package release declares the registry it ships; results record the registry
  digest and the effective contract set.
* Any release that adds, deprecates, or removes a registered identity is at
  least a package minor. Removing or archiving an identity is a package major
  after `1.0.0`, subject to the compatibility window.
* A package release never silently changes a target's pinned default contract.
  Selection changes are separate owner decisions recorded in the registry.
* Contract identities do not need to match the package version. A wheel version
  such as `0.4.1` may carry `review-result.v0.1` and `claim-assessment.3`.

## Changelog policy

`CHANGELOG.md` uses `Keep a Changelog` sections: `Added`, `Changed`,
`Deprecated`, `Removed`, `Fixed`, `Security`, plus `Breaking` for incompatible
changes. `Unreleased` is always present and is the merge target for every
classified change. Released headings carry a date and are ordered newest first.
A released version must have at least one classified entry.

Classify a conventional commit before opening the pull request:

```sh
python3 scripts/check_changelog.py --classify "feat(cli): add --json to stats"
python3 scripts/check_changelog.py --classify "fix!: reject an unknown receipt version"
```

`feat` maps to `Added`, `fix` to `Fixed`, most maintenance types to `Changed`,
and `!` or a `BREAKING CHANGE:` footer to `Breaking`. Unknown commit types
return `unclassified` and require a human decision rather than a guess.

## Enforcement

`scripts/check_version_policy.py` and its tests enforce the following on every
change:

* `pyproject.toml` version, changelog headings, and the newest released section
  agree;
* the changelog has `Unreleased`, valid categories, dates, and no empty or
  duplicate releases;
* the registry version matches its schema filename and `const`, every required
  contract kind exists, and every artifact schema and artifact identity is
  declared in `scripts/release-policy.v1.json`;
* every `v*` tag is a semantic version with a changelog entry and is not newer
  than the package;
* an explicit release tag exists, equals the package version, and has release
  notes (used by the release workflow).

```sh
python3 scripts/check_changelog.py
python3 scripts/check_version_policy.py
python3 scripts/check_version_policy.py --tag v0.1.0 --notes-out /tmp/release-notes.md
python3 -m pytest -q tests/test_version_policy.py tests/test_changelog.py tests/test_release_workflow.py
```

The release workflow repeats the tag check before it builds and again before it
creates the GitHub Release. See [RELEASING.md](RELEASING.md).
