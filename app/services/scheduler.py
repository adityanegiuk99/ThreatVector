"""Day 3: Pipeline scheduler for incremental ingestion.

Runs the three public-source ingestion flows (CISA KEV, NVD, MITRE ATT&CK)
on independent intervals, with per-source coalescing (skips a run if the
previous one is still active via a DB advisory lock) and structured logging
of every attempt into ingestion_runs. Designed to be driven by:
  - cron / GitHub Actions scheduled workflow (recommended for production)
  - a long-running loop via `python -m app.services.scheduler` (dev only)

No third-party scheduler dependency: interval logic is injectable and
unit-testable.
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.logging_conf import configure_logging

logger = logging.getLogger("veylix.scheduler")

# Advisory-lock keys, stable per source.
_LOCK_KEYS = {"kev": 7001, "nvd": 7002, "attack": 7003}


@dataclass
class Schedule:
    """Interval configuration for one source."""

    name: str
    interval_seconds: int
    lookback_days: int = 3

    def due(self, now: float, last_run: float | None) -> bool:
        if last_run is None:
            return True
        return (now - last_run) >= self.interval_seconds


DEFAULT_Schedules: dict[str, Schedule] = {
    "kev": Schedule(name="kev", interval_seconds=3 * 3600),
    "nvd": Schedule(name="nvd", interval_seconds=6 * 3600, lookback_days=3),
    "attack": Schedule(name="attack", interval_seconds=24 * 3600),
}


def env_overrides() -> dict[str, Schedule]:
    """Allow runtime tuning without code changes.

    VEYLIX_KEV_INTERVAL_MIN, VEYLIX_NVD_INTERVAL_MIN, VEYLIX_ATTACK_INTERVAL_MIN
    (minutes). Falls back to defaults when unset/invalid.
    """
    override = {}
    for name, sched in DEFAULT_Schedules.items():
        raw = os.getenv(f"VEYLIX_{name.upper()}_INTERVAL_MIN")
        if raw:
            try:
                minutes = max(5, int(raw))
                override[name] = Schedule(
                    name=sched.name, interval_seconds=minutes * 60, lookback_days=sched.lookback_days
                )
            except ValueError:
                logger.warning("Ignoring invalid %s interval %r", name, raw)
    return override or dict(DEFAULT_Schedules)


class _SourceLock:
    """Postgres advisory-lock wrapper to coalesce concurrent runs."""

    def __init__(self, db, name: str):
        self.db = db
        self.key = _LOCK_KEYS[name]
        self._acquired = False

    def __enter__(self) -> bool:
        row = self.db.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": self.key}).scalar()
        self._acquired = bool(row)
        return self._acquired

    def __exit__(self, *exc) -> None:
        if self._acquired:
            self.db.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": self.key})


def run_due_source(db, sched: Schedule, now: float, last_run: float | None) -> float | None:
    """Run a single source if due. Returns the new last-run timestamp (or None on skip)."""
    if not sched.due(now, last_run):
        return last_run
    with _SourceLock(db, sched.name) as acquired:
        if not acquired:
            logger.info("source %s skipped: another run holds the advisory lock", sched.name)
            return last_run
        _ingest(db, sched)
        return now


def _ingest(db, sched: Schedule) -> None:
    started = datetime.now(timezone.utc)
    try:
        from app.services.ingestion.cisa_kev import ingest_kev
        from app.services.ingestion.nvd import ingest_nvd
        from app.services.ingestion.attack import ingest_attck

        if sched.name == "kev":
            ingest_kev(db, incremental=True)
        elif sched.name == "nvd":
            ingest_nvd(db, incremental=True, lookback_days=sched.lookback_days)
        elif sched.name == "attack":
            ingest_attck(db, incremental=True)
        else:
            raise ValueError(f"unknown schedule: {sched.name}")
        logger.info(
            "source %s ok in %.1fs",
            sched.name,
            (datetime.now(timezone.utc) - started).total_seconds(),
        )
    except Exception:
        logger.exception("source %s failed", sched.name)
        # Do not re-raise: a failing source must not break the scheduler loop.


def run_once(db, schedules: dict[str, Schedule] | None = None, last_runs: dict[str, float] | None = None):
    """Execute every due source exactly once. Returns the updated last-run map.

    Pure enough for integration testing (single invocation, no sleep loop).
    """
    schedules = schedules or env_overrides()
    last_runs = dict(last_runs or {})
    now = time.time()
    for name in sorted(schedules):
        sched = schedules[name]
        new_ts = run_due_source(db, sched, now, last_runs.get(name))
        last_runs[name] = new_ts
    return last_runs


def run_loop(poll_seconds: int = 60) -> None:  # pragma: no cover - long-running process
    """Dev-mode loop: never exits; use cron in production instead."""
    from app.db.session import SessionLocal

    schedules = env_overrides()
    last_runs: dict[str, float] = {}
    logger.info("scheduler loop started: %s", {n: s.interval_seconds for n, s in schedules.items()})
    while True:
        db = SessionLocal()
        try:
            last_runs = run_once(db, schedules, last_runs)
        finally:
            db.close()
        time.sleep(poll_seconds)


def main() -> None:  # pragma: no cover - CLI
    parser = argparse.ArgumentParser(description="Scheduled incremental ingestion")
    parser.add_argument("--loop", action="store_true", help="Run continuously (dev only)")
    args = parser.parse_args()
    configure_logging()
    if args.loop:
        run_loop()
    else:
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            last = run_once(db)
            logger.info("run_once complete: %s", last)
        finally:
            db.close()


if __name__ == "__main__":
    main()
