"""Retrieval: hybrid keyword (pg_trgm) + vector similarity over intel chunks."""
from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models.intel import EMBEDDING_DIM
from app.services.retrieval.embed import embed_texts


def semantic_search(
    db: Session,
    query: str,
    *,
    top_k: int = 5,
    sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Cosine-similarity retrieval over intel_chunks using pgvector."""
    qvec = embed_texts([query])[0].tolist()
    sql = """
        SELECT d.id, d.source, d.external_id, d.title, d.url, d.published_at,
               c.chunk_index, c.content,
               1 - (c.embedding <=> :qvec) AS score
        FROM intel_chunks c
        JOIN intel_documents d ON d.id = c.document_id
        WHERE c.embedding IS NOT NULL
        """
    params: dict[str, Any] = {"top_k": top_k, "qvec": str(qvec)}
    if sources:
        sql += " AND d.source IN :sources"
        params["sources"] = tuple(sources)
    sql += " ORDER BY c.embedding <=> :qvec LIMIT :top_k"
    rows = db.execute(text(sql), params).all()
    out = []
    for r in rows:
        out.append(
            dict(
                document_id=r.id,
                source=r.source,
                external_id=r.external_id,
                title=r.title,
                url=r.url,
                published_at=r.published_at,
                chunk_index=r.chunk_index,
                content=r.content,
                score=float(r.score),
            )
        )
    return out


def keyword_search(
    db: Session,
    query: str,
    *,
    top_k: int = 5,
    sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Trigram keyword fallback (still DB-backed, still real retrieval)."""
    sql = """
        SELECT d.id, d.source, d.external_id, d.title, d.url, d.published_at,
               c.chunk_index, c.content, 0.5::float AS score
        FROM intel_chunks c
        JOIN intel_documents d ON d.id = c.document_id
        WHERE c.content ILIKE :pat
          {extra}
        LIMIT :top_k
    """
    extra = ""
    params: dict[str, Any] = {"pat": f"%{query}%", "top_k": top_k}
    if sources:
        extra = " AND d.source IN :sources"
        params["sources"] = tuple(sources)
    sql = sql.format(extra=extra)
    rows = db.execute(text(sql), params).all()
    return [dict(r._asdict()) for r in rows]
