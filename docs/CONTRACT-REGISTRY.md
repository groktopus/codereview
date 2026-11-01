# Contract and version registry

**Status:** authoritative for contract selection. **Owner:** groktopus/codereview maintainers. **Issue:** #249 (CA-3).

The harness carries several generations of review profiles, limits revisions, model
contracts, claim-assessment versions, and publication receipts. This document and the
machine-readable registry it describes are the single place that states which versions
exist, which are selectable, what replaced what, and what evidence must survive before
anything is removed.

## Registry file

| Item | Value |
|---|---|
| Registry | [`src/pr_review_harness/contract_registry.json`](../src/pr_review_harness/contract_registry.json) |
| JSON Schema | [`schemas/contract-registry.v1.schema.json`](../schemas/contract-registry.v1.schema.json) |
| Loader / validator | [`src/pr_review_harness/contract_registry.py`](../src/pr_review_harness/contract_registry.py) |
| Registry version | `contract-registry.v1` |

The registry ships inside the installed package, so engine preflight never depends on a
working-directory guess. It is the only source for the resolver's contract matrix; the
resolver no longer hardcodes profile paths or digests.

Every contract entry records:

- `kind`, `name`, and `version`;
- `status` (`supported`, `deprecated`, or `archived`);
- `owner`;
- `replaced_by` (a same-kind registry name, or `null` for a supported contract or a
  terminal deprecated contract);
- `invariants` (machine-readable facts that must remain true);
- `source_path` and, for immutable JSON evidence, `source_sha256`; or a
  `source_symbol` when the contract lives in code;
- `deprecation` for deprecated entries and `archived` for archived entries.

Review-contract entries additionally carry the exact `combination` (target repository,
profile, limits, claim-assessment cap) and `checks`, the data-driven invariants the
resolver enforces before it emits a binding.

## Supported matrix

Exactly **one** review contract, **one** review profile, and **one** limits set are
supported:

| Component | Supported value |
|---|---|
| Review contract | `codereview-native-v1` |
| Review profile | `profiles/codereview-native-v1-candidate.json` (`codereview-native-v1-candidate`) |
| Limits | `profiles/ordinary-review-limits-v3.json` (`ordinary-review-limits-v3`) |
| Target repository | `groktopus/codereview` |
| Claim-assessment cap | 4 |
| Claim-assessment contracts | `claim-assessment.2` (default), `claim-assessment.3` (`PR_MERGE_BASE`) |

The registry validator fails if a second supported review contract, profile, or limits
entry appears, or if the supported combination does not resolve to them.

Selection defaults:

- An empty `REVIEW_CONTRACT`, `default`, or an omitted contract resolves to the
  registry's default for the target repository.
- `REVIEW_CONTRACT=supported` resolves to the single supported combination and is
  rejected for any other target repository.
- Explicit deprecated names remain resolvable during their compatibility window and
  record their status in the binding; archived names are rejected with
  `review_contract_archived` and never reach file reads.

### Deprecated contracts

| Kind | Name | Replaced by | Window |
|---|---|---|---|
| review contract | `legacy-v14` | `bounded-production-v16` | 2026-11-01 → 2027-02-01 |
| review contract | `bounded-production-v16` | `bounded-production-v17` | 2026-11-01 → 2027-02-01 |
| review contract | `bounded-production-v17` | terminal (owner retires the SlopSearX target binding) | 2026-11-01 → 2027-02-01 |
| profile | `slopsearx-v14-jev-reconciliation-candidate` | `slopsearx-v16-bounded-production-candidate` | 2026-11-01 → 2027-02-01 |
| profile | `slopsearx-v16-bounded-production-candidate` | `slopsearx-v17-context-target-manifest-candidate` | 2026-11-01 → 2027-02-01 |
| profile | `slopsearx-v17-context-target-manifest-candidate` | terminal | 2026-11-01 → 2027-02-01 |
| profile | `slopsearx-v8-static-review-boundaries` (`profiles/slopsearx.json`) | `slopsearx-v14-jev-reconciliation-candidate` | 2026-11-01 → 2027-02-01 |
| limits | `ordinary-review-limits-v2` | `ordinary-review-limits-v3` | 2026-11-01 → 2027-02-01 |
| claim assessment | `claim-assessment.1` | `claim-assessment.2` | 2026-11-01 → 2027-02-01 |
| canary receipt | `actions-receipt-v1` | `actions-receipt-v2` | 2026-11-01 → 2027-02-01 |
| model output | `specialist-findings.v1`–`.v3` | `specialist-findings.v4` | 2026-11-01 → 2027-02-01 |
| model output | `semantic-adjudication.v1`–`.v2` | `semantic-adjudication.v3` | 2026-11-01 → 2027-02-01 |
| context | `context-selection.v1`–`.v2` | `context-selection.v3` | 2026-11-01 → 2027-02-01 |

A deprecated contract is never the registry default. The SlopSearX caller keeps its
explicit historical default (`legacy-v14`) so the existing read-only pilot does not
change behavior mid-window; that caller default is tracked as an owner migration item,
not as a supported default.

### Archived contracts

| Kind | Name | Evidence |
|---|---|---|
| profile | `slopsearx-v9-context-candidate` | `docs/CONTEXT-SELECTION.md`, PR466 v1 manifest |
| profile | `slopsearx-v10-bounded-head-context-trial` | PR466 v2 manifest |
| profile | `slopsearx-v11-related-implementation-context-candidate` | PR466 v3 manifest |
| profile | `slopsearx-v12-dependency-context-candidate` | PR466 v4 manifest |
| profile | `slopsearx-v13-static-assessment-candidate` | PR466 v5 manifest |
| limits | `ordinary-review-limits-v1` | `docs/DEPLOYMENT-CONFIGURATION.md` |

Archived entries are immutable evidence. Their files are **not** rewritten, because
trial manifests bind their SHA-256. See [`profiles/ARCHIVE.md`](../profiles/ARCHIVE.md).
No production surface may reference an archived contract; this is enforced by
`tests/test_contract_registry.py`.

## Deprecation policy

1. **Announcement.** A dated entry in this document and in the registry names the
   contract, its replacement, the compatibility window, and the evidence required for
   removal. The registry entry is the authoritative record.
2. **Replacement path.** `replaced_by` must name an existing entry of the same kind
   that is not archived. A contract with no same-target successor is explicitly marked
   `terminal` with the owner decision it depends on. A deprecation without a replacement
   path or a terminal marker fails validation.
3. **Compatibility window.** A deprecated contract stays selectable and executable for
   at least one minor release and 90 days after the replacement is designated. It is
   never a default. Every binding and run artifact records `status=deprecated` and the
   replacement, so an operator can migrate without reading code. The window is
   enforcement metadata; the engine records the status and does not silently upgrade.
4. **Removal evidence.** Before a contract becomes `archived` or is deleted, the
   registry must record: a successful run artifact that names the replacement; no
   production reference; the retained, unchanged source file and its provenance; and
   the owner decision that authorizes removal. Archiving requires `archived_on`,
   `archival_note`, and `evidence_paths`. Deletion is not authorized by this policy.

## Preflight validation

`review_stages.preflight_review` calls
`contract_registry.effective_contract_set()` before any provider dispatch or result
write. For a registered profile it enforces:

- the profile's repository/version resolves to exactly one registered review contract;
- the supplied limits match the registered limits values (keys other than
  `schema_version`, which the CLI strips);
- no component of the combination is `archived`;
- the claim-assessment, claim-reconciliation, context-selection, and
  context-target-manifest versions named by the profile or snapshot are registered and
  not archived.

Failures are `EnginePreflightError("invalid_review_request", detail)` with stable
details: `archived contract combination rejected`,
`contract limits do not match the registered combination`,
`contract version is not registered`, `contract registry is invalid`, and related
codes. Nothing is dispatched and no result file is created.

A profile that is not registered at all (for example a synthetic test fixture or a
library caller's inline profile) is recorded as `unregistered` rather than rejected.
The resolver is the production admission gate; preflight enforces every profile that
can be identified as registered. This keeps the engine usable as a library without
weakening hosted selection.

## Run artifact contract identity

Every result written by `build_and_persist_result` contains `effective_contracts`, and
the ledger identity records the same object. An auditor can read the contract set
without knowing the code:

```json
"effective_contracts": {
  "registration": "registered",
  "registry": {"version": "contract-registry.v1", "status": "supported", "sha256": "…"},
  "review_contract": {"name": "codereview-native-v1", "version": "codereview-native-v1", "status": "supported", "owner": "…", "replaced_by": null, "source_path": "scripts/resolve_review_contract.py", "source_sha256": null},
  "profile": {"name": "codereview-native-v1-candidate", "version": "codereview-native-v1-candidate", "status": "supported", "source_path": "profiles/codereview-native-v1-candidate.json", "source_sha256": "32d4…"},
  "limits": {"name": "ordinary-review-limits-v3", "version": "ordinary-review-limits-v3", "status": "supported", "source_path": "profiles/ordinary-review-limits-v3.json", "source_sha256": "ec19…"},
  "claim_assessment": {"name": "claim-assessment.2", "status": "supported"},
  "claim_reconciliation": {"name": "claim-reconciliation.v1", "status": "supported"},
  "specialist_findings": {"name": "specialist-findings.v4", "status": "supported"},
  "adjudication": {"name": "semantic-adjudication.v3", "status": "supported"},
  "specialist_input": {"name": "specialist-input.v2", "status": "supported"},
  "context_selection": {"name": "context-selection.v3", "status": "supported"},
  "context_target_manifest": null,
  "context_followup": {"name": "context-followup.v1", "status": "supported"},
  "target_profile_bindings": {"name": "target-profile-bindings.v1", "status": "supported"},
  "run_artifact": {"name": "review-result.v0.1", "status": "supported"}
}
```

Deprecated components carry their `deprecation` block; unregistered fixtures carry
`registration: "unregistered"`. Publication/canary receipts can obtain the same
authoritative receipt identity through `contract_registry.receipt_contract_set()`;
the publication runtime itself is outside this issue's edit scope.

## Changing the registry

1. Add or update the entry and its `source_path`/`source_sha256` (or `source_symbol`).
2. Run `python -m pytest tests/test_contract_registry.py -q`.
3. If the change alters the supported combination, update this document, the resolver
   defaults, and the artifact example in the same change.
4. Never rewrite a profile or limits file owned by an archived/deprecated entry; add a
   new versioned file instead.

## Owner decisions assumed for this change

These are recorded because the issue did not name the replacement target or the
deprecation dates. They are reversible via the registry:

- The single supported combination is the harness's own production target,
  `groktopus/codereview` + `codereview-native-v1` + limits v3. The SlopSearX contracts
  remain deprecated (not archived) during the window so the existing pilot keeps
  working.
- Deprecation announcements use the issue/assessment date 2026-11-01 and a 90-day
  minimum window ending 2027-02-01. The owner may ratify different dates.
- `bounded-production-v17` and its profile are terminal: retiring the SlopSearX target
  binding is an owner decision, not an automatic replacement.
