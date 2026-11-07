# Independent read-only scoped verification

Verifier: child agent `87cfe6b1-a2b1-4bda-b9e9-aa272abcb6e9` (separate context),
2026-11-07. Read-only review; no edits, providers, target execution or network.

**Verdict: CLEAR for scoped new reconcile tests; no blocking issue.** This is not
full VD-2 acceptance. The verifier read the complete production module, existing
tests, and new tests, and independently ran the 119-case focused selection with
bytecode/cache writes disabled: **119 passed in 0.06s**.

The independently checked source/test hashes match the
[expanded manifest](expanded-manifest.json). Tests use public APIs, meaningful
fixed stable-ID and inventory-boundary oracles, not a copied implementation.
Consolidation overlaps some existing assertions but adds all six permutations,
purity, original-input replay and complete usage/provenance records. Replay is
accurately distinguished from re-consolidating output or persisted-ledger replay.
Location validity does not prove file-anchor evidence authentication; the caller
performs that separately.

The verifier parsed both complete native metadata files and found exact equality
of all 656 `exit_code_by_key` entries: **573 killed /83 survived /no other codes**.
Per-function counts (killed/survived): `_norm`10/1, `stable_candidate_id`80/0,
`validate_location`231/27, `consolidate_findings`252/55. Function-hash maps match;
type-check-error maps are empty. Raw file hashes differ because timing metadata
is not identical; no raw-file identity claim is made.

Status-map SHA-256 depends on JSON serialization:

- Sorted keys with default `json.dumps` spacing (report summary convention):
  `f8cf65bc98a1fa11615373d00549010d6abbb865d51fa64a6a68d2280d31b386`.
- Sorted keys, compact `separators=(",", ":")` (independent verifier convention):
  `43fd5cc6fe62b5cb3e7c6b3dc3c042313d2ffaf14c7035af59557737c56502fa`.

Both fingerprints refer to the same equal status maps, not raw metadata files.
Historical 668-mutant evidence is a separate retained universe; no silent
same-universe substitution or survivor-equivalence claim is accepted.
