"""Initial schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-11

"""
import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

EMBED_DIM = 384


def _ts_cols():
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(32), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        *_ts_cols(),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("asset_type", sa.String(64), nullable=False, server_default="server"),
        sa.Column("criticality", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("exposure", sa.String(32), nullable=False, server_default="internal"),
        sa.Column("network_zone", sa.String(64), nullable=True),
        sa.Column("owner", sa.String(128), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1.0"),
        *_ts_cols(),
        sa.UniqueConstraint("tenant_id", "hostname", name="uq_asset_tenant_hostname"),
    )

    op.create_table(
        "asset_software",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor", sa.String(128), nullable=False, index=True),
        sa.Column("product", sa.String(128), nullable=False, index=True),
        sa.Column("version", sa.String(64), nullable=True),
        sa.Column("match_confidence", sa.String(32), nullable=False, server_default="manual"),
        *_ts_cols(),
    )
    op.create_index("ix_asset_software_asset_id", "asset_software", ["asset_id"])

    op.create_table(
        "cves",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(32), nullable=False, unique=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_base_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector_string", sa.String(512), nullable=True),
        sa.Column("cvss_severity", sa.String(32), nullable=True),
        sa.Column("cvss_version", sa.String(16), nullable=True),
        sa.Column("exploitability_score", sa.Float(), nullable=True),
        sa.Column("impact_score", sa.Float(), nullable=True),
        sa.Column("cwe_ids", postgresql.JSONB(), nullable=True),
        sa.Column("references", postgresql.JSONB(), nullable=True),
        sa.Column("attack_vector", sa.String(32), nullable=True),
        sa.Column("attack_complexity", sa.String(32), nullable=True),
        sa.Column("privileges_required", sa.String(32), nullable=True),
        sa.Column("user_interaction", sa.String(32), nullable=True),
        sa.Column("scope", sa.String(32), nullable=True),
        sa.Column("integrity_impact", sa.String(32), nullable=True),
        sa.Column("availability_impact", sa.String(32), nullable=True),
        sa.Column("confidentiality_impact", sa.String(32), nullable=True),
        sa.Column("published_date", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("modified_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(64), nullable=False, server_default="nvd"),
        sa.Column("raw", postgresql.JSONB(), nullable=True),
        *_ts_cols(),
    )

    op.create_table(
        "affected_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("vendor", sa.String(128), nullable=True, index=True),
        sa.Column("product", sa.String(128), nullable=True, index=True),
        sa.Column("affected_version", sa.String(128), nullable=True),
        sa.Column("version_range", sa.String(256), nullable=True),
        sa.Column("platform", sa.String(64), nullable=True),
        *_ts_cols(),
    )
    op.create_index("ix_ap_cve_vendor_product", "affected_products", ["cve_id", "vendor", "product"])

    op.create_table(
        "kev_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("kev_cve_id", sa.String(32), nullable=False, unique=True),
        sa.Column("vendor_project", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("vulnerability_name", sa.String(512), nullable=True),
        sa.Column("date_added", sa.Date(), nullable=True, index=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("known_ransomware_use", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("cwes", postgresql.JSONB(), nullable=True),
        *_ts_cols(),
    )

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("base_score", sa.Float(), nullable=True),
        sa.Column("ml_score", sa.Float(), nullable=True),
        sa.Column("rule_score", sa.Float(), nullable=True),
        sa.Column("final_score", sa.Float(), nullable=True, index=True),
        sa.Column("explanation", postgresql.JSONB(), nullable=True),
        sa.Column("method_version", sa.String(32), nullable=False, server_default="v1"),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        *_ts_cols(),
    )
    op.create_index("ix_ra_cve_asset", "risk_assessments", ["cve_id", "asset_id"])

    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("author_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("author_name", sa.String(255), nullable=True),
        sa.Column("status", sa.String(64), nullable=False, server_default="triaged"),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        *_ts_cols(),
    )
    op.create_index("ix_note_cve_asset", "analyst_notes", ["cve_id", "asset_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=True),
        sa.Column("object_id", sa.String(64), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", sa.String(64), nullable=True),
        *_ts_cols(),
    )

    op.create_table(
        "intel_documents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("source", sa.String(64), nullable=False, index=True),
        sa.Column("external_id", sa.String(255), nullable=False, index=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("url", sa.String(1024), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("content_hash", sa.String(128), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("source", "external_id", name="uq_intel_doc"),
    )

    op.create_table(
        "intel_chunks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("intel_documents.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("chunk_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("embedding", Vector(EMBED_DIM), nullable=True),
        sa.Column("content_hash", sa.String(128), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("document_id", "chunk_index", name="uq_chunk"),
    )

    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_fetched", sa.Integer(), nullable=True),
        sa.Column("records_upserted", sa.Integer(), nullable=True),
        sa.Column("records_skipped", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        *_ts_cols(),
    )

    op.create_table(
        "model_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("feature_schema", sa.String(64), nullable=True),
        sa.Column("trained_on", sa.Text(), nullable=True),
        sa.Column("trained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("artifact_path", sa.String(512), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("params", postgresql.JSONB(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("name", "version", name="uq_model_name_version"),
    )

    op.create_table(
        "evaluation_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_version_id", sa.Integer(), sa.ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("dataset_tag", sa.String(32), nullable=True, server_default="test"),
        sa.Column("metric_name", sa.String(64), nullable=False),
        sa.Column("metric_value", sa.Float(), nullable=False),
        sa.Column("split", sa.String(32), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("model_version_id", "dataset_tag", "metric_name", name="uq_eval_metric"),
    )

    op.create_table(
        "predictions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, server_default="default", index=True),
        sa.Column("cve_id", sa.Integer(), sa.ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("model_version_id", sa.Integer(), sa.ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("prediction", sa.Boolean(), nullable=True),
        sa.Column("features", postgresql.JSONB(), nullable=True),
        sa.Column("shap_values", postgresql.JSONB(), nullable=True),
        sa.Column("predicted_at", sa.DateTime(timezone=True), nullable=True),
        *_ts_cols(),
        sa.UniqueConstraint("cve_id", "model_version_id", name="uq_pred"),
    )


def downgrade() -> None:
    op.drop_table("predictions")
    op.drop_table("evaluation_metrics")
    op.drop_table("model_versions")
    op.drop_table("ingestion_runs")
    op.drop_table("intel_chunks")
    op.drop_table("intel_documents")
    op.drop_table("audit_events")
    op.drop_table("analyst_notes")
    op.drop_table("risk_assessments")
    op.drop_table("kev_entries")
    op.drop_table("affected_products")
    op.drop_table("cves")
    op.drop_table("asset_software")
    op.drop_table("assets")
    op.drop_table("users")
