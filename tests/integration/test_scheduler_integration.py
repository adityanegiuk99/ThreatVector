"""Integration test for the Day 3 scheduler against the live Postgres.

Requires DATABASE_URL / docker Postgres (veylix-db). Skips cleanly when the
database is unreachable so the suite still runs offline.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text

from app.services.scheduler import _LOCK_KEYS, _SourceLock


def _db_available() -> bool:
    try:
        from app.db.session import engine

        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _db_available(), reason="live Postgres not reachable"
)


def test_advisory_lock_roundtrip():
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        with _SourceLock(db, "kev") as acquired:
            assert acquired is True
            # Same lock key from a second session must NOT acquire.
            db2 = SessionLocal()
            try:
                with _SourceLock(db2, "kev") as second:
                    assert second is False
            finally:
                db2.close()
        # After release, a new session can acquire again.
        db3 = SessionLocal()
        try:
            with _SourceLock(db3, "kev") as again:
                assert again is True
        finally:
            db3.close()
    finally:
        db.close()


def test_lock_keys_stable():
    assert _LOCK_KEYS == {"kev": 7001, "nvd": 7002, "attack": 7003}
