"""Asset CRUD with tenant scoping."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.security import get_current_user
from app.db.models import Asset, AssetSoftware, AuditEvent
from app.db.session import get_db
from app.schemas.common import AssetCreate, AssetOut, AssetUpdate, Page

router = APIRouter(prefix="/api/assets", tags=["assets"])


def _audit(db: Session, user, action: str, object_id: str | None, detail: dict | None = None):
    db.add(
        AuditEvent(
            user_id=getattr(user, "id", None),
            action=action,
            object_type="asset",
            object_id=str(object_id) if object_id else None,
            detail=detail,
        )
    )


def _replace_software(db: Session, asset: Asset, software: list[dict] | None):
    if software is None:
        return
    for sw in list(asset.software):
        db.delete(sw)
    db.flush()
    for item in software:
        asset.software.append(
            AssetSoftware(
                vendor=(item.get("vendor") or "").strip(),
                product=(item.get("product") or "").strip(),
                version=item.get("version"),
                match_confidence=item.get("match_confidence", "manual"),
            )
        )


@router.get("", response_model=Page[AssetOut])
def list_assets(
    q: str | None = Query(None),
    asset_type: str | None = None,
    exposure: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(Asset)
    if q:
        stmt = stmt.where(Asset.hostname.ilike(f"%{q}%"))
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if exposure:
        stmt = stmt.where(Asset.exposure == exposure)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Asset.hostname).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page.make([AssetOut.model_validate(r).model_dump() for r in rows], total, page, page_size)


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    existing = db.scalar(
        select(func.count()).where(Asset.hostname == payload.hostname)
    )
    if (existing or 0) > 0:
        raise HTTPException(409, "Asset with that hostname already exists")
    asset = Asset(**payload.model_dump(exclude={"software"}))
    db.add(asset)
    db.flush()
    _replace_software(db, asset, payload.software)
    _audit(db, user, "asset.create", asset.hostname, {"criticality": asset.criticality})
    db.commit()
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    asset = db.scalar(select(Asset).options(joinedload(Asset.software)).where(Asset.id == asset_id))
    if asset is None:
        raise HTTPException(404, "Asset not found")
    data = AssetOut.model_validate(asset).model_dump()
    data["software"] = [
        {"vendor": s.vendor, "product": s.product, "version": s.version, "match_confidence": s.match_confidence}
        for s in asset.software
    ]
    return data


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db), user=Depends(get_current_user)
):
    asset = db.scalar(select(Asset).options(joinedload(Asset.software)).where(Asset.id == asset_id))
    if asset is None:
        raise HTTPException(404, "Asset not found")
    data = payload.model_dump(exclude_unset=True)
    _replace_software(db, asset, data.pop("software", None))
    for key, val in data.items():
        setattr(asset, key, val)
    _audit(db, user, "asset.update", asset.hostname, {"fields": list(data.keys())})
    db.commit()
    out = AssetOut.model_validate(asset).model_dump()
    out["software"] = [
        {"vendor": s.vendor, "product": s.product, "version": s.version, "match_confidence": s.match_confidence}
        for s in asset.software
    ]
    return out


@router.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    _audit(db, user, "asset.delete", asset.hostname)
    db.delete(asset)
    db.commit()
