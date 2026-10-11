"""MITRE ATT&CK Enterprise techniques ingestion via STIX bundles.

Source: https://github.com/mitre-attack/attack-stix-data (stix bundle enterprise-attack.json)
Data is used as retrieval *grounding* material for the analyst assistant; no scoring depends on it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.db.models import IntelDocument, IngestionRun
from app.db.models.base import utcnow
from app.services.http import fetch_json

logger = logging.getLogger("veylix.ingest.attck")

ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)


def _iso_to_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def ingest_attck(db: Session, *, incremental: bool = True, only: str = "attack-pattern") -> dict[str, Any]:
    """Ingest MITRE ATT&CK techniques into intel_documents (source='attack').
    Chunks are handled separately by the embedding indexer.
    """
    run = IngestionRun(source="mitre_attack", status="running", started_at=utcnow())
    db.add(run)
    db.commit()

    fetched = upserted = skipped = 0
    try:
        payload = fetch_json(ATTACK_BUNDLE_URL, cache_ttl=86400 if incremental else None)
        objects = payload.get("objects", [])
        if only:
            objects = [o for o in objects if o.get("type") == only]
        fetched = len(objects)
        seen = set()
        for obj in objects:
            ext_id = obj.get("id")
            if not ext_id or ext_id in seen:
                skipped += 1
                continue
            seen.add(ext_id)
            name = obj.get("name")
            if not name:
                skipped += 1
                continue
            description = obj.get("description") or ""
            refs = obj.get("external_references") or []
            url = next((r.get("url") for r in refs if r.get("url")), None)
            # Extract the MITRE technique id (e.g. T1059)
            mitre_id = next(
                (r.get("external_id") for r in refs if r.get("external_id") and r.get("source_name") == "mitre"),
                None,
            )
            created = _iso_to_dt(obj.get("created"))
            modified = _iso_to_dt(obj.get("modified"))

            doc = db.scalar(
                select(IntelDocument).where(
                    IntelDocument.source == "attck",
                    IntelDocument.external_id == ext_id,
                )
            )
            if doc is None:
                doc = IntelDocument(
                    source="attck",
                    external_id=ext_id,
                    tenant_id="default",
                )
                db.add(doc)
            title = f"{name}" + (f" ({mitre_id})" if mitre_id else "")
            content = f"{title}\n\n{description}".strip()
            import hashlib

            doc.title = title
            doc.content = content
            doc.url = url
            doc.published_at = modified or created
            doc.content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            upserted += 1

        db.commit()
        run.status = "success"
        run.records_fetched = fetched
        run.records_upserted = upserted
        run.records_skipped = skipped
        run.detail = {"only": only}
        run.finished_at = utcnow()
        db.commit()
        logger.info("ATT&CK ingest: fetched=%d upserted=%d skipped=%d", fetched, upserted, skipped)
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = utcnow()
        db.commit()
        logger.exception("ATT&CK ingest failed")
        raise
    return {"fetched": fetched, "upserted": upserted, "skipped": skipped}
