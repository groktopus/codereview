"""Negative mypy fixture; CI requires this stub to fail type checking."""

from __future__ import annotations

from .typed_contracts import TaskRecord

INVALID_TASK: TaskRecord = {"task_id": "task-1", "unit_ids": "not-a-list"}
