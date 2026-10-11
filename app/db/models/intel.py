"""Intelligence documents, embeddings, ingestion runs."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Index, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin
from pgvector.sqlalchemy import Vector

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2


class IntelDocument(Base, TimestampMixin):
    __tablename__ = "intel_documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # nvd|cisa_kev|attck|vendor
    external_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(String(512))
    content: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(1024))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str | None] = mapped_column(String(128))
    chunks: Mapped[list["IntelChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("uq_intel_doc", "source", "external_id", unique=True),
    )


class IntelChunk(Base, TimestampMixin):
    __tablename__ = "intel_chunks"

    id: Mapped[int] = mapped_column(primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("intel_documents.id", ondelete="CASCADE"), index=True)
    chunk_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    embedding = mapped_column(Vector(EMBEDDING_DIM))
    content_hash: Mapped[str | None] = mapped_column(String(128))

    document: Mapped[IntelDocument] = relationship(back_populates="chunks")

    __table_args__ = (
        Index("uq_chunk", "document_id", "chunk_index", unique=True),
    )


class IngestionRun(Base, TimestampMixin):
    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)  # running|success|failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    records_fetched: Mapped[int | None] = mapped_column(Integer)
    records_upserted: Mapped[int | None] = mapped_column(Integer)
    records_skipped: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict | None] = mapped_column(JSONB)
