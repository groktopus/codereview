#!/usr/bin/env python3
"""Gate a stored review result on its canonical completeness summary.

This is the provider-free CI entry point.  It reads only local JSON, emits the
machine-readable summary, and exits non-zero when a required obligation
regresses against the stored baseline.

Usage:
    python scripts/check_completeness.py --result artifacts/run.json --summary-only --json
    python scripts/check_completeness.py --baseline tests/fixtures/completeness/baseline.v1.json \
        --result tests/fixtures/completeness/good-result.json
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pr_review_harness.completeness import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
