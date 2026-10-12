"""Unit tests for the Day 3 scheduler interval / coalescing logic."""
from __future__ import annotations

from types import SimpleNamespace

from app.services.scheduler import (
    DEFAULT_Schedules,
    Schedule,
    env_overrides,
    run_due_source,
    run_once,
)


class FakeLockDB:
    """Minimal db double: the advisory-lock path succeeds on a real session; in unit
    tests we patch _SourceLock instead, so run_due_source only needs a doc-able object."""

    def __setattr__(self, name, value):
        object.__setattr__(self, name, value)


def test_schedule_due_first_run():
    s = Schedule(name="kev", interval_seconds=3600)
    assert s.due(now=1000.0, last_run=None) is True


def test_schedule_not_due_within_interval():
    s = Schedule(name="nvd", interval_seconds=3600)
    assert s.due(now=1000.0, last_run=900.0) is False  # only 100s elapsed


def test_schedule_due_after_interval():
    s = Schedule(name="attack", interval_seconds=600)
    assert s.due(now=1000.0, last_run=300.0) is True


def test_run_due_source_skips_when_not_due(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "app.services.scheduler._ingest",
        lambda db, sched: called.__setitem__("n", called["n"] + 1),
    )
    s = Schedule(name="kev", interval_seconds=3600)
    result = run_due_source(db=SimpleNamespace(), sched=s, now=1000.0, last_run=900.0)
    assert result == 900.0
    assert called["n"] == 0


def test_run_due_source_skips_when_lock_held(monkeypatch):
    """Lock already held by another worker: no ingest, timestamp unchanged."""
    called = {"n": 0}
    monkeypatch.setattr(
        "app.services.scheduler._ingest",
        lambda db, sched: called.__setitem__("n", called["n"] + 1),
    )
    monkeypatch.setattr("app.services.scheduler._SourceLock", _FakeLockAlwaysHeld)
    s = Schedule(name="kev", interval_seconds=60)
    result = run_due_source(db=SimpleNamespace(), sched=s, now=1000.0, last_run=900.0)
    assert result == 900.0
    assert called["n"] == 0


class _FakeLockAlwaysHeld:
    def __init__(self, db, name):
        pass

    def __enter__(self):
        return False

    def __exit__(self, *exc):
        return False


class _FakeLockAcquired:
    def __init__(self, db, name):
        pass

    def __enter__(self):
        return True

    def __exit__(self, *exc):
        return False


def test_run_due_source_runs_when_due(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(
        "app.services.scheduler._ingest",
        lambda db, sched: called.__setitem__("n", called["n"] + 1),
    )
    monkeypatch.setattr("app.services.scheduler._SourceLock", _FakeLockAcquired)
    s = Schedule(name="kev", interval_seconds=60)
    result = run_due_source(db=SimpleNamespace(), sched=s, now=1000.0, last_run=900.0)
    assert result == 1000.0
    assert called["n"] == 1


def test_run_once_executes_all_initially_due_sources(monkeypatch):
    called = []
    monkeypatch.setattr(
        "app.services.scheduler._ingest",
        lambda db, sched: called.append(sched.name),
    )
    monkeypatch.setattr("app.services.scheduler._SourceLock", _FakeLockAcquired)
    scheds = {
        "kev": Schedule(name="kev", interval_seconds=1),
        "nvd": Schedule(name="nvd", interval_seconds=1),
        "attack": Schedule(name="attack", interval_seconds=1),
    }
    last = run_once(db=SimpleNamespace(), schedules=scheds, last_runs=None)
    # All three had no last_run -> all due on the first pass.
    assert sorted(called) == ["attack", "kev", "nvd"]
    assert all(v == last[k] for k, v in last.items() if v is not None)


def test_run_once_second_pass_skips_fresh_runs(monkeypatch):
    called = []
    monkeypatch.setattr(
        "app.services.scheduler._ingest",
        lambda db, sched: called.append(sched.name),
    )
    monkeypatch.setattr("app.services.scheduler._SourceLock", _FakeLockAcquired)
    scheds = {
        "kev": Schedule(name="kev", interval_seconds=3600),
        "nvd": Schedule(name="nvd", interval_seconds=3600),
    }
    import time as _time
    now = _time.time()
    result = run_once(db=SimpleNamespace(), schedules=scheds, last_runs={k: now for k in scheds})
    assert called == []  # everything fresh
    # timestamps unchanged
    assert result == {k: now for k in scheds}


def test_env_overrides_valid():
    import os

    old = os.environ.get("VEYLIX_KEV_INTERVAL_MIN")
    try:
        os.environ["VEYLIX_KEV_INTERVAL_MIN"] = "15"
        override = env_overrides()
        assert "kev" in override
        assert override["kev"].interval_seconds == 15 * 60
    finally:
        if old is None:
            os.environ.pop("VEYLIX_KEV_INTERVAL_MIN", None)
        else:
            os.environ["VEYLIX_KEV_INTERVAL_MIN"] = old


def test_env_overrides_invalid_falls_back():
    import os

    old = os.environ.get("VEYLIX_NVD_INTERVAL_MIN")
    try:
        os.environ["VEYLIX_NVD_INTERVAL_MIN"] = "not-a-number"
        override = env_overrides()
        # invalid value must not crash: falls back to defaults for that source
        assert override["nvd"].interval_seconds == DEFAULT_Schedules["nvd"].interval_seconds
    finally:
        if old is None:
            os.environ.pop("VEYLIX_NVD_INTERVAL_MIN", None)
        else:
            os.environ["VEYLIX_NVD_INTERVAL_MIN"] = old


def test_env_overrides_clamps_tiny_intervals():
    import os

    old = os.environ.get("VEYLIX_ATTACK_INTERVAL_MIN")
    try:
        os.environ["VEYLIX_ATTACK_INTERVAL_MIN"] = "1"  # below the 5-minute floor
        override = env_overrides()
        assert override["attack"].interval_seconds == 5 * 60
    finally:
        if old is None:
            os.environ.pop("VEYLIX_ATTACK_INTERVAL_MIN", None)
        else:
            os.environ["VEYLIX_ATTACK_INTERVAL_MIN"] = old
