# Installed stateless CLI verification

Source: `0fa1344`. Python: 3.13.6. Wheel SHA-256: `8c5396ea93a690b8ffefbd83fe23dae51a256f1ee9b3f745ddd34f6663206d0d`.

The wheel was built without dependency downloads, checked byte-for-byte against all 19 reviewed Python modules, and installed noneditably into a fresh environment. The process ran outside the checkout with no PYTHONPATH source fallback. The standard package smoke passed, including a provider-free terminal INCOMPLETE report and the read-only effect gate.

A controlled sealed test fixture then exercised the installed `publish` command with no effect-store argument or configuration. It returned PREVIEW_ONLY, semantic disposition INCOMPLETE, proposed GitHub event COMMENT, and effect_store_accessed=false. Explicit --authorize-publish returned exit 2. No GitHub access, provider calls, or external writes occurred.

The earlier live injection fixture was also attempted and rejected during preflight: it has a local filesystem repository identity, no PR number, and unknown freshness. It is not a publishable PR artifact. The validation was preserved; the successful preview used an explicitly controlled test fixture instead. Two fixture-generation attempts failed before CLI execution while preparing that controlled input; these were helper invocation errors, not successful publication tests.

This evidence establishes the installed CLI path only. It does not establish hosted Actions identity, receipt upload, publication behavior, review quality or Droid replacement readiness.

Broader integrated regression check on committed `8961b39`: 232 tests and four subtests passed in 62.73 seconds using Python 3.13 with plugin autoload disabled, excluding `tests/test_providers.py` (localhost tests separately exercised previously). Ruff check passed across src, tests and scripts. The new quality-regression and adapter work was not part of this committed tree.
