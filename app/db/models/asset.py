"""Assets and software inventory."""
from __future__ import annotations

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(64), default="server", nullable=False)
    criticality: Mapped[int] = mapped_column(Integer, default=3, nullable=False)  # 1..5 (5 = most critical)
    exposure: Mapped[str] = mapped_column(String(32), default="internal", nullable=False)  # internal|dmz|external
    network_zone: Mapped[str | None] = mapped_column(String(64))
    owner: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Version/asset criticality weight used in risk scoring
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    software: Mapped[list["AssetSoftware"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (UniqueConstraint("tenant_id", "hostname", name="uq_asset_tenant_hostname"),)


class AssetSoftware(Base, TimestampMixin):
    __tablename__ = "asset_software"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=False)
    vendor: Mapped[str] = mapped_column(String(128), index=True)
    product: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    match_confidence: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="software")
