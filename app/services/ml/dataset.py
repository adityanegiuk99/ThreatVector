"""Dataset construction for the 90-day KEV-inclusion prediction task.

Label semantics
---------------
For each CVE published at time T, label = 1 if it was added to CISA KEV at
any date D with T <= D <= T + 90 days; label = 0 if T + 90 days has fully
elapsed and it never entered KEV in that window. Records without a complete
90-day observation window are **excluded**, not labelled 0.

All features use only information available at publication time T (or before).
No column derives from KEV membership date, KEV flags, or NVD fields that were
added after publication (lastModified uses the *publication-time* snapshot).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Cve, KevEntry

LABEL_WINDOW_DAYS = 90


@dataclass
class DatasetBuild:
    table: pd.DataFrame
    excluded_no_window: int
    duplicates_dropped: int
    positives: int
    negatives: int


def build_90d_dataset(db: Session, *, today: Any = None) -> DatasetBuild:
    """Create the reproducible training table from DB contents.

    Returns a DataFrame indexed by integer row with columns:
      cve_id, published_date, label, and publication-time features.
    """
    rows: list[dict[str, Any]] = []
    cves = db.scalars(select(Cve)).all()
    kev_map = {k.kev_cve_id: k for k in db.scalars(select(KevEntry)).all()}

    excluded_no_window = 0
    seen_cve_ids = set()
    duplicates_dropped = 0
    positives = negatives = 0

    now = today or pd.Timestamp.utcnow().tz_localize(None)

    for c in cves:
        if not c.published_date:
            continue
        pub = pd.Timestamp(c.published_date).tz_localize(None)
        kev = kev_map.get(c.cve_id)
        kev_at = pd.Timestamp(kev.date_added) if kev and kev.date_added else None

        if kev_at is not None and kev_at <= pub + pd.Timedelta(days=LABEL_WINDOW_DAYS):
            label = 1
        elif kev_at is not None:
            # Entered KEV but AFTER the 90-day window: valid negative
            label = 0
        else:
            # Never in KEV; requires a complete observation window.
            if pub + pd.Timedelta(days=LABEL_WINDOW_DAYS) > now:
                excluded_no_window += 1
                continue
            label = 0

        # Publication-time features only
        desc = (c.description or "")
        rows.append(
            {
                "cve_id": c.cve_id,
                "published_date": pub,
                "label": label,
                "cvss_base_score": c.cvss_base_score,
                "attack_vector": c.attack_vector,
                "attack_complexity": c.attack_complexity,
                "user_interaction": c.user_interaction,
                "privileges_required": c.privileges_required,
                "scope_changed": 1.0 if (c.scope or "").upper() == "CHANGED" else 0.0,
                "exploitability_score": c.exploitability_score,
                "impact_score": c.impact_score,
                "n_cwe": len(c.cwe_ids or []),
                "n_references": len(c.references or []),
                "n_affected_products": len(c.affected_products or []),
                "desc_len": len(desc),
                "has_cwe": 1.0 if c.cwe_ids else 0.0,
                "cvss_version": c.cvss_version,
            }
        )
        if label == 1:
            positives += 1
        else:
            negatives += 1
        if c.cve_id in seen_cve_ids:
            duplicates_dropped += 1  # defensive; cve_id is unique in DB
        seen_cve_ids.add(c.cve_id)

    df = pd.DataFrame(rows)
    # Deduplicate on cve_id - prevents duplicate-record leakage
    before = len(df)
    df = df.drop_duplicates(subset=["cve_id"]).reset_index(drop=True)
    duplicates_dropped += max(0, before - len(df))
    return DatasetBuild(
        table=df,
        excluded_no_window=excluded_no_window,
        duplicates_dropped=duplicates_dropped,
        positives=positives,
        negatives=negatives,
    )


def chronological_splits(
    df: pd.DataFrame,
    *,
    test_frac: float = 0.15,
    val_frac: float = 0.15,
    time_col: str = "published_date",
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Split by publication date: train < val < test (fully chronological)."""
    assert test_frac + val_frac < 1.0, "Splits must leave room for training"
    df = df.sort_values(time_col).reset_index(drop=True)
    n = len(df)
    test_cut = int(n * (1.0 - test_frac))
    val_cut = int(n * (1.0 - test_frac - val_frac))

    train = df.iloc[:val_cut]
    val = df.iloc[val_cut:test_cut]
    test = df.iloc[test_cut:]

    meta = {
        "train_end_date": str(train[time_col].max().date()) if len(train) else None,
        "val_start_date": str(val[time_col].min().date()) if len(val) else None,
        "val_end_date": str(val[time_col].max().date()) if len(val) else None,
        "test_start_date": str(test[time_col].min().date()) if len(test) else None,
        "test_end_date": str(test[time_col].max().date()) if len(test) else None,
        "train_size": len(train),
        "val_size": len(val),
        "test_size": len(test),
    }
    return train, val, test, meta
