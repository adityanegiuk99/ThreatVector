"""Semantic indexing: chunk intel documents and upsert embeddings in pgvector."""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import numpy as np
from sqlalchemy import delete, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import IntelChunk, IntelDocument
from app.db.models.intel import EMBEDDING_DIM

logger = logging.getLogger("veylix.retrieval.index")

_MODEL_CACHE: Any = None


def get_model():
    """Lazy-load the sentence-transformers model; cached in-module."""
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        from sentence_transformers import SentenceTransformer

        _MODEL_CACHE = SentenceTransformer(settings.embedding_model)
    return _MODEL_CACHE


def embed_texts(texts: list[str]) -> np.ndarray:
    model = get_model()
    return model.encode(texts, normalize_embeddings=True, show_progress_bar=False)


def chunk_text(content: str, max_chars: int = 1500, overlap_chars: int = 150) -> list[str]:
    """Word-aware sliding-window chunking."""
    content = content.strip()
    if not content:
        return []
    if len(content) <= max_chars:
        return [content]
    chunks = []
    start = 0
    while start < len(content):
        end = min(start + max_chars, len(content))
        # Prefer breaking on newline or sentence boundary
        window = content[start:end]
        if end < len(content):
            break_at = max(window.rfind("\n\n"), window.rfind(". "))
            if break_at > max_chars // 2:
                end = start + break_at + 1
        chunks.append(content[start:end].strip())
        start = end - overlap_chars if end < len(content) else end
    return [c for c in chunks if c]


def index_documents(db: Session, *, batch_size: int = 32) -> dict[str, int]:
    """Index all intel documents that have no chunks yet (or whose content_hash changed)."""
    docs = db.scalars(select(IntelDocument)).all()
    todo = []
    for doc in docs:
        if not doc.content:
            continue
        chunks = chunk_text(doc.content)
        want_hashes = [hashlib.sha256(c.encode()).hexdigest() for c in chunks]
        have = {c.chunk_index: c for c in doc.chunks}
        if have and all(h.content_hash == want_hashes[i] for i, h in have.items() if i < len(want_hashes)) and len(have) == len(chunks):
            continue
        todo.append((doc, chunks))

    indexed = 0
    for i in range(0, len(todo), batch_size):
        batch = todo[i : i + batch_size]
        flat_texts = []
        for doc, chunks in batch:
            flat_texts.extend(chunks)
        if not flat_texts:
            continue
        embeddings = embed_texts(flat_texts)
        ptr = 0
        for doc, chunks in batch:
            db.execute(delete(IntelChunk).where(IntelChunk.document_id == doc.id))
            for j, chunk in enumerate(chunks):
                vec = embeddings[ptr]
                db.add(
                    IntelChunk(
                        document_id=doc.id,
                        chunk_index=j,
                        content=chunk,
                        content_hash=hashlib.sha256(chunk.encode()).hexdigest(),
                        embedding=vec,
                    )
                )
                ptr += 1
        indexed += len(flat_texts)
    db.commit()
    logger.info("Indexed %d chunks from %d documents", indexed, len(todo))
    return {"documents_indexed": len(todo), "chunks_indexed": indexed}
