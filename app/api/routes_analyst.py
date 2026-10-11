"""Analyst assistant and intel search endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.models import AuditEvent
from app.db.session import get_db
from app.schemas.common import AnalystQuery, AnalystResponse, IntelChunkOut
from app.services.analyst.service import analyst_query
from app.services.retrieval.search import semantic_search, keyword_search

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/analyst", response_model=AnalystResponse)
def ask_analyst(payload: AnalystQuery, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        out = analyst_query(db, payload.question)
    except Exception as exc:
        raise HTTPException(503, f"Analyst service unavailable: {exc}") from exc
    db.add(AuditEvent(user_id=user.id, action="analyst.query", object_type="analyst", detail={"q_len": len(payload.question)}))
    db.commit()
    return out


@router.get("/intel/search", response_model=list[IntelChunkOut])
def intel_search(
    q: str = Query(min_length=2, max_length=500),
    mode: str = Query("semantic", pattern="^(semantic|keyword)$"),
    source: str | None = None,
    top_k: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    sources = source.split(",") if source else None
    if mode == "keyword":
        rows = keyword_search(db, q, top_k=top_k, sources=sources)
    else:
        try:
            rows = semantic_search(db, q, top_k=top_k, sources=sources)
        except Exception:
            rows = keyword_search(db, q, top_k=top_k, sources=sources)
    return rows
