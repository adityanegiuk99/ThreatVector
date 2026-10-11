"""Auth, notes, ingestion status, evaluation metrics, predictions."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.db.models import (
    AnalystNote,
    AuditEvent,
    Cve,
    EvaluationMetric,
    IngestionRun,
    ModelVersion,
    Prediction,
    User,
)
from app.db.session import get_db
from app.schemas.common import NoteCreate, NoteOut, Page, TokenOut

router = APIRouter(prefix="/api", tags=["platform"])


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/auth/register", response_model=TokenOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    exists = db.scalar(select(User).where(User.username == payload.username))
    if exists:
        raise HTTPException(409, "Username already taken")
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role="analyst",
    )
    db.add(user)
    db.commit()
    return TokenOut(access_token=create_access_token(user.username, user.role))


@router.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    return TokenOut(access_token=create_access_token(user.username, user.role))


@router.get("/ingestion/status")
def ingestion_status(
    source: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Latest ingestion runs, per source, plus overall data freshness."""
    stmt = select(IngestionRun).order_by(desc(IngestionRun.started_at)).limit(limit)
    if source:
        stmt = stmt.where(IngestionRun.source == source)
    runs = db.scalars(stmt).all()
    latest_by_source: dict[str, Any] = {}
    for r in runs:
        latest_by_source.setdefault(
            r.source,
            {
                "source": r.source,
                "status": r.status,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "records_fetched": r.records_fetched,
                "records_upserted": r.records_upserted,
                "error": r.error,
            },
        )
    return {"runs": [r.id and None for r in runs], "latest_by_source": latest_by_source}


@router.get("/models/evaluation")
def model_evaluation(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Compare all registered model versions by metric."""
    versions = db.scalars(select(ModelVersion).order_by(ModelVersion.created_at)).all()
    out = []
    for v in versions:
        metrics = {}
        for m in db.scalars(select(EvaluationMetric).where(EvaluationMetric.model_version_id == v.id)).all():
            metrics.setdefault(m.dataset_tag or "test", {})[m.metric_name] = m.metric_value
        out.append(
            dict(
                model_version_id=v.id,
                name=v.name,
                version=v.version,
                algorithm=v.algorithm,
                is_active=v.is_active,
                trained_on=v.trained_on,
                metrics=metrics,
            )
        )
    return out


@router.post("/models/{version_id}/activate")
def activate_model(version_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    v = db.get(ModelVersion, version_id)
    if v is None:
        raise HTTPException(404, "Model version not found")
    db.query(ModelVersion).filter(ModelVersion.name == v.name).update({"is_active": False})
    v.is_active = True
    db.add(AuditEvent(user_id=user.id, action="model.activate", object_type="model_version", object_id=str(v.id)))
    db.commit()
    return {"status": "ok", "active_version": v.version}


@router.post("/models/{version_id}/predict")
def batch_predict(version_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Score all CVEs without a prediction from this model version (bounded)."""
    import joblib
    import numpy as np
    import pandas as pd
    from pathlib import Path

    from app.services.ml.features import build_features, FeatureSchema

    mv = db.get(ModelVersion, version_id)
    if mv is None:
        raise HTTPException(404, "Model version not found")
    if mv.algorithm == "rules_baseline":
        raise HTTPException(400, "The rules baseline has no fitted artifact to run inference with")

    art = Path(mv.artifact_path or "")
    if not (art / "model.joblib").exists() or not (art / "schema.joblib").exists():
        raise HTTPException(503, "Model artifacts missing on disk; run training first")

    model = joblib.load(art / "model.joblib")
    schema: FeatureSchema = joblib.load(art / "schema.joblib")

    cves = db.scalars(select(Cve).where(~Cve.id.in_(select(Prediction.cve_id).where(Prediction.model_version_id == mv.id))).limit(2000)).all()
    preds_inserted = 0
    batch_rows = []
    for cve in cves:
        if not cve.published_date:
            continue
        pub = cve.published_date
        batch_rows.append(
            {
                "cve_id": cve.cve_id,
                "cvss_base_score": cve.cvss_base_score,
                "attack_vector": cve.attack_vector,
                "attack_complexity": cve.attack_complexity,
                "user_interaction": cve.user_interaction,
                "privileges_required": cve.privileges_required,
                "scope_changed": 1.0 if (cve.scope or "").upper() == "CHANGED" else 0.0,
                "exploitability_score": cve.exploitability_score,
                "impact_score": cve.impact_score,
                "n_cwe": len(cve.cwe_ids or []),
                "n_references": len(cve.references or []),
                "n_affected_products": len(cve.affected_products),
                "desc_len": len(cve.description or ""),
                "has_cwe": 1.0 if cve.cwe_ids else 0.0,
                "cvss_version": cve.cvss_version,
            }
        )
    if batch_rows:
        import pandas as pd

        df_new = pd.DataFrame(batch_rows)
        X_new, _ = build_features(df_new, schema)
        scores = model.predict_proba(X_new)[:, 1]
        now = func.now()  # placeholder; real timestamp below
        from app.db.models.base import utcnow

        for row, score in zip(batch_rows, scores):
            cve_row = next(c for c in cves if c.cve_id == row["cve_id"])
            db.add(
                Prediction(
                    cve_id=cve_row.id,
                    model_version_id=mv.id,
                    score=float(score),
                    prediction=bool(score >= 0.4),
                    features={
                        k: (float(v) if isinstance(v, (int, float)) else str(v) if v is not None else None)
                        for k, v in row.items()
                        if k != "cve_id"
                    },
                    predicted_at=utcnow(),
                )
            )
            preds_inserted += 1
    db.commit()
    return {"status": "ok", "predictions_inserted": preds_inserted, "model_version": mv.version}


@router.get("/notes", response_model=Page[NoteOut])
def list_notes(
    cve_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(AnalystNote).order_by(desc(AnalystNote.created_at))
    if cve_id:
        stmt = stmt.where(
            AnalystNote.cve_id == db.scalar(select(Cve.id).where(Cve.cve_id == cve_id.upper()))
        )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return Page.make([NoteOut.model_validate(r).model_dump() for r in rows], total, page, page_size)


@router.post("/notes", response_model=NoteOut, status_code=201)
def create_note(payload: NoteCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    if payload.cve_id:
        cve = db.scalar(select(Cve).where(Cve.cve_id == payload.cve_id.upper()))
        if cve is None:
            raise HTTPException(404, f"CVE {payload.cve_id} not found")
        payload = payload.model_copy(update={"cve_id": str(cve.id)})
    note = AnalystNote(
        cve_id=int(payload.cve_id) if payload.cve_id else None,
        asset_id=payload.asset_id,
        author_name=user.username,
        status=payload.status,
        body=payload.body,
    )
    db.add(note)
    db.add(
        AuditEvent(
            user_id=user.id,
            action="note.create",
            object_type="analyst_note",
            object_id=payload.cve_id,
        )
    )
    db.commit()
    return NoteOut.model_validate(note)


@router.patch("/notes/{note_id}", response_model=NoteOut)
def update_note(note_id: int, payload: NoteCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    note = db.get(AnalystNote, note_id)
    if note is None:
        raise HTTPException(404, "Note not found")
    for field in ("status", "body"):
        val = getattr(payload, field, None)
        if val is not None:
            setattr(note, field, val)
    db.add(AuditEvent(user_id=user.id, action="note.update", object_type="analyst_note", object_id=str(note_id)))
    db.commit()
    return NoteOut.model_validate(note)


@router.get("/audit", response_model=Page[dict])
def audit_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    stmt = select(AuditEvent).order_by(desc(AuditEvent.created_at))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    items = [
        {
            "id": r.id,
            "user_id": r.user_id,
            "action": r.action,
            "object_type": r.object_type,
            "object_id": r.object_id,
            "detail": r.detail,
            "created_at": r.created_at,
        }
        for r in rows
    ]
    return Page.make(items, total, page, page_size)
