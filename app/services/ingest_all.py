"""CLI wrappers for ingesting a single source.

Usage:
    python -m app.services.ingest_all --source kev
    python -m app.services.ingest_all --source nvd [--lookback-days 30]
    python -m app.services.ingest_all --source attack
    python -m app.services.ingest_all --source all
"""
from __future__ import annotations

import argparse
import logging

from app.core.config import settings
from app.db.session import SessionLocal

logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run_source(source: str, lookback_days: int, full: bool) -> None:
    from app.services.ingestion.cisa_kev import ingest_kev
    from app.services.ingestion.nvd import ingest_nvd
    from app.services.ingestion.attack import ingest_attck

    db = SessionLocal()
    try:
        if source in ("kev", "all"):
            ingest_kev(db, incremental=not full)
        if source in ("nvd", "all"):
            ingest_nvd(db, incremental=not full, lookback_days=lookback_days)
        if source in ("attack", "all"):
            ingest_attck(db, incremental=not full)
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest public vulnerability intelligence")
    parser.add_argument("--source", choices=["kev", "nvd", "attack", "all"], required=True)
    parser.add_argument("--lookback-days", type=int, default=30, help="NVD incremental lookback in days")
    parser.add_argument("--full", action="store_true", help="Force a full refresh, bypassing caches")
    args = parser.parse_args()
    run_source(args.source, args.lookback_days, args.full)


if __name__ == "__main__":
    main()
