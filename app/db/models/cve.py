"""Vulnerability (CVE), KEV, affected products, risk."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Date,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, utcnow

# NOTE: JSONB is only valid on Postgres; the rest of the project targets Postgres.


class Cve(Base, TimestampMixin):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector_string: Mapped[str | None] = mapped_column(String(512))
    cvss_severity: Mapped[str | None] = mapped_column(String(32))
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    exploitability_score: Mapped[float | None] = mapped_column(Float)
    impact_score: Mapped[float | None] = mapped_column(Float)
    cwe_ids: Mapped[list | None] = mapped_column(JSONB, default=list)
    references: Mapped[list | None] = mapped_column(JSONB, default=list)
    attack_vector: Mapped[str | None] = mapped_column(String(32))
    attack_complexity: Mapped[str | None] = mapped_column(String(32))
    privileges_required: Mapped[str | None] = mapped_column(String(32))
    user_interaction: Mapped[str | None] = mapped_column(String(32))
    scope: Mapped[str | None] = mapped_column(String(32))
    integrity_impact: Mapped[str | None] = mapped_column(String(32))
    availability_impact: Mapped[str | None] = mapped_column(String(32))
    confidentiality_impact: Mapped[str | None] = mapped_column(String(32))
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    modified_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64), default="nvd", nullable=False)
    raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    affected_products: Mapped[list["AffectedProduct"]] = relationship(
        back_populates="cve", cascade="all, delete-orphan", lazy="selectin"
    )
    kev: Mapped["KevEntry | None"] = relationship(
        back_populates="cve", uselist=False, cascade="all, delete-orphan"
    )


class AffectedProduct(Base, TimestampMixin):
    __tablename__ = "affected_products"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    vendor: Mapped[str | None] = mapped_column(String(128), index=True)
    product: Mapped[str | None] = mapped_column(String(128), index=True)
    affected_version: Mapped[str | None] = mapped_column(String(128))
    version_range: Mapped[str | None] = mapped_column(String(256))
    platform: Mapped[str | None] = mapped_column(String(64))

    cve: Mapped[Cve] = relationship(back_populates="affected_products")

    __table_args__ = (
        Index("ix_ap_cve_vendor_product", "cve_id", "vendor", "product"),
    )


class KevEntry(Base, TimestampMixin):
    """CISA Known Exploited Vulnerability catalog entry."""
    __tablename__ = "kev_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), unique=True, index=False)
    kev_cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    vendor_project: Mapped[str | None] = mapped_column(String(255))
    product: Mapped[str | None] = mapped_column(String(255))
    vulnerability_name: Mapped[str | None] = mapped_column(String(512))
    date_added: Mapped[date | None] = mapped_column(Date, index=True)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)
    required_action: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list | None] = mapped_column(JSONB, default=list)

    cve: Mapped[Cve] = relationship(back_populates="kev")


class RiskAssessment(Base, TimestampMixin):
    __tablename__ = "risk_assessments"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True)
    base_score: Mapped[float | None] = mapped_column(Float)
    ml_score: Mapped[float | None] = mapped_column(Float)
    rule_score: Mapped[float | None] = mapped_column(Float)
    final_score: Mapped[float | None] = mapped_column(Float, index=True)
    explanation: Mapped[dict | None] = mapped_column(JSONB)
    method_version: Mapped[str] = mapped_column(String(32), default="v1")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_ra_cve_asset", "cve_id", "asset_id"),
    )
