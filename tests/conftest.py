"""Shared pytest fixtures: FastAPI TestClient with a real test DB and token."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Point at a disposable test DB (must exist before tests run; see run_tests script)
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5433")
os.environ.setdefault("POSTGRES_DB", "veylix")
os.environ.setdefault("POSTGRES_USER", "veylix")
os.environ.setdefault("POSTGRES_PASSWORD", "veylix_dev_password")
os.environ.setdefault("VEYLIX_SECRET_KEY", "test-secret-key-not-for-prod")

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import SessionLocal  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(fastapi_app) as c:
        yield c


@pytest.fixture(scope="session")
def auth_headers(client):
    """Create+login a test user; return auth headers."""
    username = "pytest_user"
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing is None:
            db.add(
                User(
                    username=username,
                    email="pytest@veylix.local",
                    hashed_password=hash_password("pytest_pw_123"),
                    role="admin",
                )
            )
            db.commit()
    finally:
        db.close()
    token = create_access_token(username, "admin")
    return {"Authorization": f"Bearer {token}"}
