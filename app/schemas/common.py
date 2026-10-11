"""Pydantic schemas: common envelope + domain objects."""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Paginated response envelope."""
    items: list[T]
    total: int
    page: int
    page_size: int

    @classmethod
    def make(cls, items: list[T], total: int, page: int, page_size: int) -> "Page[T]":
        return cls(items=items, total=total, page=page, page_size=page_size)


class CveOut(BaseModel):
    model_config = {"from_attributes": True}

    cve_id: str
    title: str | None = None
    description: str | None = None
    cvss_base_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector_string: str | None = None
    cvss_version: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    cwe_ids: list[Any] | None = None
    published_date: Any | None = None
    modified_date: Any | None = None
    source: str | None = None


class CveDetail(CveOut):
    exploitability_score: float | None = None
    impact_score: float | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    confidentiality_impact: str | None = None
    references: list[Any] | None = None
    affected_products: Any = []
    kev: Any = None


class AssetOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    tenant_id: str | None = None
    hostname: str | None = None
    asset_type: str | None = None
    criticality: int | None = None
    exposure: str | None = None
    network_zone: str | None = None
    owner: str | None = None
    notes: str | None = None
    is_active: bool | None = None
    weight: float | None = None


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str = "server"
    criticality: int = Field(default=3, ge=1, le=5)
    exposure: str = "internal"
    network_zone: str | None = None
    owner: str | None = None
    notes: str | None = None
    software: list[dict[str, Any]] = []


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    exposure: str | None = None
    network_zone: str | None = None
    owner: str | None = None
    notes: str | None = None
    software: list[dict[str, Any]] | None = None


class RiskOut(BaseModel):
    cve_id: str
    observed_facts: dict[str, Any]
    score_terms: list[dict[str, Any]]
    rule_score: float
    ml_score: float | None = None
    ml_label: str | None = None
    final_score: float
    asset_context: dict[str, Any] | None = None
    confidence: str
    caveats: list[str] = []


class IntelDocOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    source: str
    external_id: str
    title: str | None = None
    url: str | None = None
    published_at: Any | None = None


class IntelChunkOut(IntelDocOut):
    content: str | None = None
    score: float | None = None


class AnalystQuery(BaseModel):
    question: str = Field(min_length=3, max_length=2000)


class AnalystResponse(BaseModel):
    answer: str
    citations: list[dict[str, Any]]
    mode: str  # llm | fallback
    uncertainty: list[str] = []


class ModelEvalOut(BaseModel):
    model_version_id: int
    name: str
    version: str
    algorithm: str
    is_active: bool
    trained_on: str | None = None
    metrics: dict[str, dict[str, float]]  # split -> {metric: value}


class NoteOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    cve_id: int | None = None
    asset_id: int | None = None
    author_name: str | None = None
    status: str | None = None
    body: str | None = None
    created_at: Any | None = None


class NoteCreate(BaseModel):
    cve_id: str | None = None
    asset_id: int | None = None
    status: str = "triaged"
    body: str = Field(min_length=1)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
