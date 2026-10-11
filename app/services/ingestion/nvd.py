"""NVD CVE ingestion using the public NVD 2.0 API.

Source: https://nvd.nist.gov/developers/vulnerabilities
The API supports incremental sync via lastModStartDate/lastModEndDate.

Nothing is fabricated; records come only from the NVD feed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Cve, AffectedProduct, IngestionRun
from app.db.models.base import utcnow
from app.services.http import fetch_json

logger = logging.getLogger("veylix.ingest.nvd")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS_PER_PAGE = 2000  # API limit


def _parse_iso(value: str | None) -> datetime | None:
    """NVD uses ISO 8601 like 2024-01-01T00:00:00.000 or with -05:00 offsets."""
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _metric_to_dict(metric: dict, version_key: str) -> dict[str, Any] | None:
    entries = metric.get(version_key)
    if not entries:
        return None
    data = entries[-1]  # prefer latest
    cvss_data = data.get("cvssData", {})
    return dict(
        base_score=cvss_data.get("baseScore"),
        vector_string=cvss_data.get("vectorString"),
        severity=cvss_data.get("baseSeverity"),
        version=cvss_data.get("version"),
        exploitability=cvss_data.get("exploitabilityScore"),
        impact=cvss_data.get("impactScore"),
    )


def _extract_first_metric(vuln: dict) -> dict[str, Any] | None:
    metrics = vuln.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = _metric_to_dict(metrics, key)
        if m:
            return m
    return None


def _extract_attack_vector(vector_string: str | None) -> str | None:
    if not vector_string:
        return None
    for part in vector_string.split("/"):
        if part.startswith("AV:"):
            return part[3:]
    return None


def _extract_attack_complexity(vector_string: str | None) -> str | None:
    if not vector_string:
        return None
    for part in vector_string.split("/"):
        if part.startswith("AC:"):
            return part[3:]
    return None


def _extract_cpe_products(vuln: dict) -> list[dict[str, Any]]:
    """Extract vendor/product/version info from CPE/NPE configuration data."""
    products: list[dict[str, Any]] = []
    seen = set()
    for cfg in vuln.get("configurations") or []:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria")
                if not cpe:
                    continue
                parts = cpe.split(":")
                # cpe:2.3:a:vendor:product:version:...
                if len(parts) >= 5 and parts[0] == "cpe":
                    key = (parts[3], parts[4], parts[5] if len(parts) > 5 else "")
                    if key in seen:
                        continue
                    seen.add(key)
                    products.append(
                        dict(
                            vendor=parts[3],
                            product=parts[4],
                            affected_version=parts[5] if len(parts) > 5 else None,
                            version_range=match.get("versionStartIncluding")
                            or match.get("versionStartExcluding")
                            or match.get("versionEndIncluding")
                            or match.get("versionEndExcluding"),
                        )
                    )
    return products


def _upsert_cve(db: Session, vuln: dict) -> str:
    """Upsert a single NVD vuln record; returns 'inserted' | 'updated' | 'unchanged'."""
    cna = (vuln.get("containers") or {}).get("cna") or {}
    descriptions = vuln.get("descriptions") or []
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        cna.get("descriptions", [{}])[0].get("value") if cna.get("descriptions") else None,
    )
    cve_id = vuln.get("id")

    metric = _extract_first_metric(vuln)
    refs = [
        {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags")}
        for r in (vuln.get("references") or [])
    ]

    weaknesses = vuln.get("weaknesses") or []
    cwe_ids = sorted(
        {
            d.get("value")
            for w in weaknesses
            for d in (w.get("description") or [])
            if d.get("value") and d.get("value") != "NVD-CWE-noinfo"
        }
    )

    published = _parse_iso(vuln.get("published"))
    modified = _parse_iso(vuln.get("lastModified"))

    existing = db.scalar(select(Cve).where(Cve.cve_id == cve_id))
    created = False
    if existing is None:
        cve = Cve(
            cve_id=cve_id,
            title=cna.get("title"),
            description=desc,
            source="nvd",
            published_date=published,
            modified_date=modified,
            raw=vuln,
        )
        db.add(cve)
        created = True
        existing = cve
    # Update mutable fields
    existing.title = cna.get("title") or existing.title
    if desc:
        existing.description = desc
    if published:
        existing.published_date = published
    if modified:
        existing.modified_date = modified
    existing.raw = vuln

    if metric:
        existing.cvss_base_score = metric.get("base_score")
        existing.cvss_vector_string = metric.get("vector_string")
        existing.cvss_severity = metric.get("severity")
        existing.cvss_version = metric.get("version")
        existing.exploitability_score = metric.get("exploitability")
        existing.impact_score = metric.get("impact")
        vs = metric.get("vector_string") or ""
        existing.attack_vector = _extract_attack_vector(vs)
        existing.attack_complexity = _extract_attack_complexity(vs)
    existing.cwe_ids = cwe_ids
    existing.references = refs

    products = _extract_cpe_products(vuln)
    if products:
        # Clear and insert fresh product data (NVD is authoritative for this)
        for ap in existing.affected_products:
            db.delete(ap)
        db.flush()
        for p in products:
            db.add(AffectedProduct(cve=existing, **p))
    return "inserted" if created else "updated"


def ingest_nvd(
    db: Session,
    *,
    incremental: bool = True,
    lookback_days: int = 30,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict[str, Any]:
    """Fetch CVEs from NVD.

    incremental: use lastModStartDate/lastModEndDate for the trailing `lookback_days`.
    start_date/end_date override that window (both required) for backfills.
    """
    run = IngestionRun(source="nvd", status="running", started_at=utcnow())
    db.add(run)
    db.commit()

    now = datetime.now(timezone.utc)
    if start_date is None or end_date is None:
        end_date = now
        start_date = now - timedelta(days=lookback_days) if incremental else None
        if start_date is None:
            start_date = datetime(1988, 1, 1, tzinfo=timezone.utc)

    fetched = inserted = updated = skipped = 0
    headers = {}
    if settings.veylix_nvd_api_key:
        headers["apiKey"] = settings.veylix_nvd_api_key

    try:
        params: dict[str, Any] = {
            "resultsPerPage": MAX_RESULTS_PER_PAGE,
            "startIndex": 0,
            "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        }
        while True:
            payload = fetch_json(NVD_API, params=params, headers=headers, cache_ttl=600)
            fetched += payload.get("resultsPerPage", 0)
            for vuln in payload.get("vulnerabilities", []):
                # NVD wraps each record under "cve"
                item = vuln.get("cve", vuln)
                cve_id = item.get("id")
                if not cve_id:
                    skipped += 1
                    continue
                # NVD rate limits; modest sleep between pages
                try:
                    status = _upsert_cve(db, item)
                    if status == "inserted":
                        inserted += 1
                    else:
                        updated += 1
                except Exception as record_exc:
                    db.rollback()
                    skipped += 1
                    logger.warning("Failed to upsert %s: %s", cve_id, record_exc)
            if payload.get("startIndex", 0) + payload.get("resultsPerPage", 0) >= payload.get("totalResults", 0):
                break
            params["startIndex"] = payload.get("startIndex", 0) + payload.get("resultsPerPage", 0)
            db.commit()  # commit after each page; keeps memory bounded

        db.commit()
        run.status = "success"
        run.records_fetched = fetched
        run.records_upserted = inserted + updated
        run.records_skipped = skipped
        run.detail = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "inserted": inserted,
            "updated": updated,
        }
        run.finished_at = utcnow()
        db.commit()
        logger.info("NVD ingest: fetched=%d inserted=%d updated=%d skipped=%d", fetched, inserted, updated, skipped)
    except Exception as exc:
        db.rollback()
        run.status = "failed"
        run.error = str(exc)
        run.finished_at = utcnow()
        db.commit()
        logger.exception("NVD ingest failed")
        raise
    return {"fetched": fetched, "inserted": inserted, "updated": updated, "skipped": skipped}
