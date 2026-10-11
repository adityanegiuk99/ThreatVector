"""CVE endpoints: search, details."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.security import get_current_user
from app.db.models import Cve, KevEntry, AffectedProduct
from app.db.session import get_db
from app.schemas.common import CveDetail, CveOut, Page

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _sort_columns(sort: str):
    return {
        "published_desc": Cve.published_date.desc(),
        "published_asc": Cve.published_date.asc(),
        "cvss_desc": Cve.cvss_base_score.desc(),
        "cvss_asc": Cve.cvss_base_score.asc(),
    }.get(sort, Cve.published_date.desc())


@router.get("", response_model=Page[CveOut])
def search_cves(
    q: str | None = Query(None, description="Search in CVE id, title, description"),
    cwe: str | None = Query(None),
    severity: str | None = Query(None, description="LOW|MEDIUM|HIGH|CRITICAL"),
    in_kev: bool | None = Query(None),
    published_after: str | None = Query(None, description="YYYY-MM-DD"),
    published_before: str | None = Query(None, description="YYYY-MM-DD"),
    min_cvss: float | None = Query(None, ge=0, le=10),
    max_cvss: float | None = Query(None, ge=0, le=10),
    sort: str = Query("published_desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(Cve.id)
    if q:
        like = f"%{q.strip().upper()}%"
        stmt = stmt.where(
            or_(
                func.upper(Cve.cve_id) == q.strip().upper() if q.strip().upper().startswith("CVE") else False,
                Cve.description.ilike(f"%{q}%"),
                Cve.title.ilike(f"%{q}%"),
            )
        )
    if severity:
        stmt = stmt.where(Cve.cvss_severity == severity.upper())
    if min_cvss is not None:
        stmt = stmt.where(Cve.cvss_base_score >= min_cvss)
    if max_cvss is not None:
        stmt = stmt.where(Cve.cvss_base_score <= max_cvss)
    if cwe:
        stmt = stmt.where(Cve.cwe_ids.cast(func.text("text[]")).contains([cwe.upper()]))
    if published_after:
        stmt = stmt.where(Cve.published_date >= published_after)
    if published_before:
        stmt = stmt.where(Cve.published_date < published_before)
    if in_kev is not None:
        stmt = stmt.join(Cve.kev, isouter=False if in_kev else None).filter(
            KevEntry.id.is_not(None) if in_kev else KevEntry.id.is_(None)
        )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(
        select(Cve)
        .where(Cve.id.in_(stmt))
        .order_by(_sort_columns(sort))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).scalars().all()
    items = [CveOut.model_validate(r).model_dump() for r in rows]
    return Page.make(items, total, page, page_size)


@router.get("/{cve_id}", response_model=CveDetail)
def cve_detail(cve_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    cve = db.execute(
        select(Cve)
        .options(joinedload(Cve.kev), joinedload(Cve.affected_products))
        .where(Cve.cve_id == cve_id.upper())
    ).unique().scalar_one_or_none()
    if cve is None:
        raise HTTPException(404, "CVE not found")
    data = CveDetail.model_validate(cve).model_dump(exclude={"affected_products", "kev"})
    data["affected_products"] = [
        {
            "vendor": p.vendor,
            "product": p.product,
            "affected_version": p.affected_version,
            "version_range": p.version_range,
        }
        for p in cve.affected_products
    ]
    data["kev"] = (
        {
            "kev_cve_id": cve.kev.kev_cve_id,
            "vendor_project": cve.kev.vendor_project,
            "product": cve.kev.product,
            "vulnerability_name": cve.kev.vulnerability_name,
            "date_added": cve.kev.date_added,
            "due_date": cve.kev.due_date,
            "known_ransomware_use": cve.kev.known_ransomware_use,
            "required_action": cve.kev.required_action,
            "notes": cve.kev.notes,
        }
        if cve.kev
        else None
    )
    return data
