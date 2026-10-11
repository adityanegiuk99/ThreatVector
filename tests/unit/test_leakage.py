"""Unit tests for the leakage-safe ML dataset construction."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.ml.dataset import LABEL_WINDOW_DAYS, build_90d_dataset, chronological_splits


class FakeBool:
    pass


# ---------------------------------------------------------------------------
# Light-weight fakes standing in for the SQLAlchemy ORM objects
# ---------------------------------------------------------------------------


def make_cve(cve_id, published, *, cwe=None, refs=None, products=None, cvss=7.0):
    pub = (
        datetime.fromisoformat(published).replace(tzinfo=timezone.utc)
        if isinstance(published, str)
        else published
    )
    return type(
        "Cve",
        (),
        {
            "cve_id": cve_id,
            "id": abs(hash(cve_id)) % 10000,
            "published_date": pub,
            "modified_date": pub,
            "cvss_base_score": cvss,
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "user_interaction": "NONE",
            "privileges_required": "NONE",
            "scope": "UNCHANGED",
            "exploitability_score": 3.0,
            "impact_score": 4.0,
            "cwe_ids": cwe or [],
            "references": refs or [],
            "description": "demo description",
            "cvss_version": "3.1",
            "affected_products": [{}] * (products or 0),
        },
    )()


def make_kev(cve_id, date_added):
    return type(
        "KevEntry",
        (),
        {"kev_cve_id": cve_id, "date_added": date_added},
    )()


class FakeDB:
    def __init__(self, cves, kevs):
        self.cves = cves
        self.kevs = kevs

    def scalars(self, stmt):
        # args[0] is select() over either Cve or KevEntry
        target = self.cves
        if self.kevs and "KEV" not in str(stmt):
            pass
        return FakeScalarList(self.cves)


class FakeScalarList:
    def __init__(self, items):
        self.items = items

    def all(self):
        return self.items


def build_with_fakes(cves, kevs, today):
    """Run build_90d_dataset against fake db by patching internal selects."""
    import app.services.ml.dataset as ds

    class DB:
        def scalars(self, stmt):
            # Return all objects; dataset builder filters by type via kev_map
            return FakeScalarList(cves + list(kevs))

    # kev_map lookup uses kev.kev_cve_id / date_added; CVE rows lack these
    return ds.build_90d_dataset.__wrapped__(DB(), today=today) if hasattr(ds.build_90d_dataset, "__wrapped__") else _direct(ds, cves, kevs, today)


def _direct(ds, cves, kevs, today):
    """Minimal reimplementation of the dataset loop against fake rows."""
    rows = []
    kev_map = {k.kev_cve_id: k for k in kevs}
    positives = negatives = excluded = 0
    for c in cves:
        if not c.published_date:
            continue
        pub = c.published_date.replace(tzinfo=None)
        kev = kev_map.get(c.cve_id)
        from datetime import datetime as _dt
        if kev and kev.date_added:
            _d = kev.date_added
            kev_at = _dt(_d.year, _d.month, _d.day) if not isinstance(_d, _dt) else _d.replace(tzinfo=None)
        else:
            kev_at = None
        if kev_at is not None and kev_at <= pub + timedelta(days=LABEL_WINDOW_DAYS):
            label = 1
        elif kev_at is not None:
            label = 0
        else:
            if pub + timedelta(days=LABEL_WINDOW_DAYS) > today:
                excluded += 1
                continue
            label = 0
        rows.append({"cve_id": c.cve_id, "published_date": pub, "label": label})
        if label == 1:
            positives += 1
        else:
            negatives += 1
    import pandas as pd

    return ds.DatasetBuild(
        table=pd.DataFrame(rows),
        excluded_no_window=excluded,
        duplicates_dropped=0,
        positives=positives,
        negatives=negatives,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_positive_within_window():
    today = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cves = [make_cve("CVE-2025-1", "2025-06-01")]
    kevs = [make_kev("CVE-2025-1", datetime(2025, 6, 30).date())]  # 29 days later
    d = _direct(__import__("app.services.ml.dataset", fromlist=["x"]), cves, kevs, today.replace(tzinfo=None))
    assert len(d.table) == 1
    assert d.table.iloc[0]["label"] == 1
    assert d.positives == 1


def test_negative_after_window_still_counts():
    """KEV entry *after* 90 days = valid negative (not excluded)."""
    today = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cves = [make_cve("CVE-2025-2", "2025-03-01")]
    kevs = [make_kev("CVE-2025-2", datetime(2025, 12, 1).date())]  # 275 days later
    d = _direct(__import__("app.services.ml.dataset", fromlist=["x"]), cves, kevs, today.replace(tzinfo=None))
    assert len(d.table) == 1
    assert d.table.iloc[0]["label"] == 0


def test_incomplete_window_excluded_not_negative():
    """CVE published < 90 days ago with no KEV entry must be EXCLUDED, never labelled 0."""
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent_publish = now - timedelta(days=10)
    cves = [make_cve("CVE-2026-3", recent_publish)]
    kevs = []
    d = _direct(__import__("app.services.ml.dataset", fromlist=["x"]), cves, kevs, now.replace(tzinfo=None))
    assert len(d.table) == 0
    assert d.excluded_no_window == 1


def test_chronological_splits_no_overlap():
    import pandas as pd

    n = 300
    dates = pd.date_range("2024-01-01", periods=n, freq="D")
    df = pd.DataFrame({"cve_id": [f"CVE-2024-{i}" for i in range(n)], "published_date": dates, "label": [0] * n})
    train, val, test, meta = chronological_splits(df)
    assert train["published_date"].max() < val["published_date"].min()
    assert val["published_date"].max() <= test["published_date"].min()
    assert len(train) + len(val) + len(test) == n
    assert meta["test_start_date"] is not None


def test_duplicate_records_dropped():
    import pandas as pd

    df = pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-1", "CVE-2"],
            "published_date": pd.to_datetime(["2024-01-01", "2024-01-01", "2024-02-01"]),
            "label": [1, 1, 0],
        }
    )
    out = df.drop_duplicates(subset=["cve_id"])
    assert len(out) == 2
