# Acquisition verification

Verified2026-11-07 at source HEAD `8e477420c5752537129963a402b1ba91b6956151`, branch `evidence/qm4-incumbent-capture`. Only this new evidence directory is untracked; no existing source/runtime file was changed. No commits/pushes were performed.

Executed standard-library, offline assertions against the retained package:

- PASS: exactly41 unique IDs, set-equal to the frozen incumbent manifest.
- PASS: every complete identity equals the corresponding frozen identity (not PR-number-only matching).
- PASS:41 case-file exact hashes/byte sizes and4 supporting-file exact hashes/byte sizes match index references; no unindexed supporting JSON.
- PASS: all capture timestamps parse timezone-aware; source endpoint URLs use `https://api.github.com/`.
- PASS:87 inventoried collection surfaces:86 captured,1 explicitly over-cap; every captured collection has<100 records and captured record count matches index count.
- PASS: each case JSON plus attributable support remains below262,144 bytes; largest aggregate case44,865 bytes (per-case budget includes its shared attribution bytes); shared attribution evidence is2,789 bytes. Entire package exceeds a single-case budget because it covers41 separate cases; it does not pool those caps.
- PASS: harness checker and regression suite pass offline; the checker computes the same largest aggregate (`44865`) while checking each case against the 262,144-byte bound.
- PASS: model identity is explicit null on all41 cases; all41 final exact-snapshot output statuses remain missing, with nonempty specific reasons. No predictions or adjudications invented.
- PASS: manually reconciled PR289 original/current commit identities; PR745 stale linked head; PR759 exact base/head checkout, early receipt timestamp and hidden final output; PR746 exact review head but wrong observed base.
- PASS: `git diff --check` exit0; final HEAD unchanged.

Reason distribution:28 no attributable Droid records on inspected surfaces;8 original-head-mismatched Droid reviews;1 stale issue-comment receipt;1 original-head-matched review with base mismatch;1 identity-bound security receipt with final output unavailable;1 CodeQL-only non-Droid case;1 comment-surface over-cap gap.

The package CLI plus `tests/test_qm4_observations.py` and `tests/test_incumbent_comparison.py` are offline harness checks; they execute no target code or provider requests. They verify local integrity and conservative inventory classification, not complete GitHub history, underlying review correctness, or authenticated provider execution. SHA256 values and source URLs are retained-data claims, not upstream signatures.
