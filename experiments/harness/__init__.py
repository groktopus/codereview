"""Archived and reusable experiment harnesses for the review harness.

Nothing in this package is installed with ``pr-review-harness``.  The modules are
kept here, outside ``src``, so historical trial code and its evidence stay
runnable while the installed package exposes a single review path.  Experiment
modules import the production core from ``pr_review_harness``; they do not
re-implement budgets, settlement, retries, or disposition.
"""
