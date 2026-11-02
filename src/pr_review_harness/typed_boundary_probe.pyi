"""Positive CI fixture binding real boundary functions to protocols."""

from __future__ import annotations

from .planner import plan_review
from .reconcile import consolidate_findings
from .report import render_report
from .review_stages import finish_attempt_stage, start_attempt_stage
from .typed_contracts import (
    AttemptFinishBoundary,
    AttemptStartBoundary,
    PlannerBoundary,
    ReconcileBoundary,
    ReportBoundary,
)

planner_boundary: PlannerBoundary = plan_review
reconcile_boundary: ReconcileBoundary = consolidate_findings
report_boundary: ReportBoundary = render_report
attempt_start_boundary: AttemptStartBoundary = start_attempt_stage
attempt_finish_boundary: AttemptFinishBoundary = finish_attempt_stage
