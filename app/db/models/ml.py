"""ML model versions, evaluation metrics, predictions."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin


class ModelVersion(Base, TimestampMixin):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_schema: Mapped[str | None] = mapped_column(String(64))
    trained_on: Mapped[str | None] = mapped_column(Text)  # dataset fingerprint: CSV hash
    trained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    artifact_path: Mapped[str | None] = mapped_column(String(512))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    params: Mapped[dict | None] = mapped_column(JSONB)
    notes: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (UniqueConstraint("name", "version", name="uq_model_name_version"),)


class EvaluationMetric(Base, TimestampMixin):
    __tablename__ = "evaluation_metrics"

    id: Mapped[int] = mapped_column(primary_key=True)
    model_version_id: Mapped[int] = mapped_column(
        ForeignKey("model_versions.id", ondelete="CASCADE"), index=True
    )
    dataset_tag: Mapped[str | None] = mapped_column(String(32), default="test")
    metric_name: Mapped[str] = mapped_column(String(64), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    split: Mapped[str | None] = mapped_column(String(32))
    detail: Mapped[dict | None] = mapped_column(JSONB)

    __table_args__ = (
        UniqueConstraint("model_version_id", "dataset_tag", "metric_name", name="uq_eval_metric"),
    )


class Prediction(Base, TimestampMixin):
    __tablename__ = "predictions"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True, nullable=False)
    cve_id: Mapped[int] = mapped_column(ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    model_version_id: Mapped[int] = mapped_column(
        ForeignKey("model_versions.id", ondelete="CASCADE"), index=True
    )
    score: Mapped[float | None] = mapped_column(Float)
    prediction: Mapped[bool | None] = mapped_column(Boolean)
    features: Mapped[dict | None] = mapped_column(JSONB)
    shap_values: Mapped[dict | None] = mapped_column(JSONB)
    predicted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("uq_pred", "cve_id", "model_version_id", unique=True),
    )
