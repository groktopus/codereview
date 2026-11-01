"""Make the repository-only ``experiments`` package importable for archive tests.

The installed package (``src/pr_review_harness``) is the production surface.
Archived experiment harnesses live in ``experiments/`` outside the wheel, so the
test process needs the repository root on ``sys.path`` to import them and to
exercise historical evidence without reinstalling anything.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
