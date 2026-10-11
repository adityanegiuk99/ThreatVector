"""Veylix FastAPI application."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_assets import router as assets_router
from app.api.routes_cves import router as cves_router
from app.api.routes_risk import router as risk_router
from app.api.routes_analyst import router as analyst_router
from app.api.routes_misc import router as misc_router
from app.core.config import settings
from app.core.logging_conf import configure_logging

configure_logging()

app = FastAPI(
    title="Veylix API",
    description="AI cybersecurity threat-intelligence platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://frontend:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cves_router)
app.include_router(assets_router)
app.include_router(risk_router)
app.include_router(analyst_router)
app.include_router(misc_router)


@app.get("/api/health")
def health():
    """Health check for container orchestration."""
    return {"status": "ok", "app": "veylix", "env": settings.env}
