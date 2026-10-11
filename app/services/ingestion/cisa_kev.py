"""CISA Known Exploited Vulnerabilities (KEV) catalog ingestion.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Adapters keep only normalized, observed facts from the feed; nothing is fabricated.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.db.models import Cve, KevEntry, IngestionRun
from app.db.models.base import utcnow
from app.services.http import fetch_json

logger = logging.getLogger("veylix.ingest.kev")

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def ingest_kev(db: Session, *, incremental: bool = True) -> dict[str, Any]:
    """Fetch and upsert the full KEV catalog. Entrypoems are deduplicated on kev_cve_id."""
    run = IngestionRun(source="cisa_kev", status="running", started_at=utcnow())
    db.add(run)
    db.commit()

    fetched = upserted = skipped = 0
    try:
        payload = fetch_json(KEV_FEED_URL, cache_ttl=900 if incremental else None)
        entries = payload.get("vulnerabilities", [])
        fetched = len(entries)
        catalog_meta = {
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "count": payload.get("count"),
        }

        cve_id_map: dict[str, int] = dict(db.execute(select(Cve.cve_id, Cve.id)).all())

        for entry in entries:
            kev_cve = (entry.get("cveID") or "").strip()
            if not kev_cve:
                skipped += 1
                continue
            date_added = parse_date(entry.get("dateAdded"))
            if date_added:
                date_added = date_added.date()

            vals = dict(
                kev_cve_id=kev_cve,
                vendor_project=entry.get("vendorProject"),
                product=entry.get("product"),
                vulnerability_name=entry.get("vulnerabilityName"),
                date_added=date_added,
                due_date=parse_date(entry.get("dueDate")),
                known_ransomware_use=(entry.get("knownRansomwareCampaignUse") == "Known"),
                required_action=entry.get("requiredAction"),
                notes=entry.get("notes"),
                cwes=entry.get("cwes") or [],
            )

            # Ensure a Cve row exists FIRST so the KevEntry FK can link to it.
            if kev_cve not in cve_id_map:
                cve = db.scalar(select(Cve).where(Cve.cve_id == kev_cve))
                if cve is None:
                    cve = Cve(
                        cve_id=kev_cve,
                        title=entry.get("vulnerabilityName"),
                        source="cisa_kev",
                        published_date=datetime.combine(date_added, datetime.min.time(), tzinfo=timezone.utc)
                        if date_added
                        else None,
                    )
                    db.add(cve)
                    db.flush()
                cve_id_map[kev_cve] = cve.id

            stmt = (
                pg_insert(KevEntry)
                .values(cve_id=cve_id_map[kev_cve], **vals)
                .on_conflict_do_update(
                    index_elements=["kev_cve_id"],
                    set_={
                        "cve_id": cve_id_map[kev_cve],
                        "vendor_project": vals["vendor_project"],
                        "product": vals["product"],
                        "vulnerability_name": vals["vulnerability_name"],
                        "date_added": vals["date_added"],
                        "due_date": vals["due_date"],
                        "known_ransomware_use": vals["known_ransomware_use"],
                        "required_action": vals["required_action"],
                        "notes": vals["notes"],
                        "cwes": vals["cwes"],
                        "updated_at": utcnow(),
                    },
                )
            )
            db.execute(stmt)
            upserted += 1

        db.commit()
        run.status = "success"
        run.records_fetched = fetched
        run.records_upserted = upserted
        run.records_skipped = skipped
        run.detail = catalog_meta
        run.finished_at = utcnow()
        db.commit()
        logger.info("KEV ingest complete: fetched=%d upserted=%d skipped=%d", fetched, upserted, skipped)
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = utcnow()
        db.commit()
        logger.exception("KEV ingest failed")
        raise
    return {"fetched": fetched, "upserted": upserted, "skipped": skipped}
