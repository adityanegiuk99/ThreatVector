"""Unit tests for the Day 4 retraining promotion gate."""
from __future__ import annotations

import pytest

from app.services.ml.retrain import incumbent_baseline, should_activate


class _FakeRow:
    def __init__(self, version, auc):
        self._t = (version, auc)

    def __iter__(self):
        return iter(self._t)

    def __getitem__(self, i):
        return self._t[i]


class _FakeDB:
    def __init__(self, row):
        self._row = row

    def execute(self, *a, **k):
        return self

    def first(self):
        return self._row


def test_gate_activates_without_incumbent():
    activated, reason = should_activate(None, 0.5, 0.01)
    assert activated is True
    assert "no incumbent" in reason


def test_gate_activates_on_clear_improvement():
    activated, _ = should_activate(0.80, 0.83, 0.01)
    assert activated is True


def test_gate_activates_at_exact_margin():
    # 0.8100 vs 0.8000 with margin 0.01 -> exactly meets threshold
    activated, _ = should_activate(0.80, 0.81, 0.01)
    assert activated is True


def test_gate_blocks_on_tiny_improvement():
    activated, reason = should_activate(0.80, 0.805, 0.01)
    assert activated is False
    assert "did not beat" in reason


def test_gate_blocks_on_regression():
    activated, _ = should_activate(0.90, 0.10, 0.01)
    assert activated is False


def test_gate_margin_zero_requires_strict_or_equal_better():
    activated, _ = should_activate(0.80, 0.80, 0.0)
    assert activated is True


def test_incumbent_baseline_handles_no_active_model():
    """incumbent_baseline must return (None, None) when nothing is active.
    Uses a fake db so this runs without Postgres."""
    from app.services.ml.retrain import incumbent_baseline as read_baseline

    fake = _FakeDB(_FakeRow(None, None))
    version, auc = read_baseline(fake, "kev90d")
    assert version is None
    assert auc is None
