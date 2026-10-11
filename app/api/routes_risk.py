"""Risk / remediation queue endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import get_current_user
from app.db.models import Asset, Cve, KevEntry, Prediction, ModelVersion
from app.db.session import get_db
from app.services.risk.engine import compute_risk

router = APIRouter(prefix="/api/risk", tags=["risk"])


@router.get("/queue")
def remediation_queue(
    asset_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Risk-ranked CVE×Asset pairs. Uses active model's predictions when available."""
    active_model = db.scalar(select(ModelVersion).where(ModelVersion.is_active.is_(True)))

    assets = db.scalars(select(Asset).where(Asset.is_active.is_(True))).all()
    if asset_id:
        assets = [a for a in assets if a.id == asset_id]

    cves = (
        db.execute(
            select(Cve, KevEntry)
            .outerjoin(KevEntry, KevEntry.cve_id == Cve.id)
            .options(selectinload(Cve.affected_products))
            .order_by(Cve.published_date.desc())
            .limit(500)
        )
        .all()
    )

    predictions: dict[int, float] = {}
    if active_model:
        rows = db.execute(
            select(Prediction.cve_id, Prediction.score).where(Prediction.model_version_id == active_model.id)
        ).all()
        predictions = dict(rows)

    entries: list[dict[str, Any]] = []
    for cve, kev in cves:
        for asset in assets:
            expl = compute_risk(cve, kev, asset, predictions.get(cve.id))
            entries.append(
                {
                    "cve_id": cve.cve_id,
                    "asset_id": asset.id,
                    "hostname": asset.hostname,
                    "exposure": asset.exposure,
                    "criticality": asset.criticality,
                    "cvss": cve.cvss_base_score,
                    "in_kev": bool(kev),
                    "ml_score": expl.ml_score,
                    "score": expl.final_score,
                    "confidence": expl.confidence,
                    "explanation": expl.to_dict(),
                }
            )
    entries.sort(key=lambda e: e["score"], reverse=True)
    total = len(entries)
    page_items = entries[(page - 1) * page_size : page * page_size]
    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "model": {"name": active_model.name if active_model else None, "version": active_model.version if active_model else None},
    }


@router.get("/{cve_id}")
def risk_for_cve(
    cve_id: str,
    asset_id: int | None = None,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    cve = db.scalar(
        select(Cve).options(selectinload(Cve.affected_products)).where(Cve.cve_id == cve_id.upper())
    )
    if cve is None:
        return {"error": "not_found", "detail": f"{cve_id} not found"}
    kev = db.scalar(select(KevEntry).where(KevEntry.cve_id == cve.id))
    active_model = db.scalar(select(ModelVersion).where(ModelVersion.is_active.is_(True)))
    ml_score = None
    if active_model:
        ml_score = db.scalar(
            select(Prediction.score).where(
                Prediction.cve_id == cve.id and Prediction.model_version_id == active_model.id
            )
        )
    assets = [a for a in db.scalars(select(Asset)).all() if asset_id is None or a.id == asset_id]
    results = []
    for asset in assets:
        expl = compute_risk(cve, kev, asset, ml_score)
        results.append(expl.to_dict())
    no_asset = compute_risk(cve, kev, None, ml_score)
    return {"cve_id": cve.cve_id, "asset_free": no_asset.to_dict(), "per_asset": results}
