"""Integration tests against the real DB and API (requires test Postgres up)."""
from __future__ import annotations

import pytest


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_vulnerability_search_pagination(client, auth_headers):
    r = client.get("/api/vulnerabilities", headers=auth_headers, params={"page_size": 5, "page": 1})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"items", "total", "page", "page_size"}
    assert len(body["items"]) <= 5


def test_vulnerability_search_requires_auth(client):
    r = client.get("/api/vulnerabilities")
    assert r.status_code == 401


def test_cve_detail_not_found(client, auth_headers):
    r = client.get("/api/vulnerabilities/CVE-9999-999999", headers=auth_headers)
    assert r.status_code == 404


def test_asset_crud_roundtrip(client, auth_headers):
    payload = {
        "hostname": "pytest-asset-1",
        "criticality": 4,
        "exposure": "dmz",
        "asset_type": "server",
        "software": [{"vendor": "nginx", "product": "nginx", "version": None}],
    }
    r = client.post("/api/assets", headers=auth_headers, json=payload)
    assert r.status_code == 201, r.text
    asset = r.json()
    assert asset["hostname"] == "pytest-asset-1"
    aid = asset["id"]

    # duplicate hostname rejected
    r2 = client.post("/api/assets", headers=auth_headers, json=payload)
    assert r2.status_code == 409

    # patch
    r3 = client.patch(f"/api/assets/{aid}", headers=auth_headers, json={"criticality": 5})
    assert r3.status_code == 200
    assert r3.json()["criticality"] == 5

    # list contains it
    r4 = client.get("/api/assets", headers=auth_headers, params={"q": "pytest-asset-1"})
    assert r4.status_code == 200
    assert any(a["hostname"] == "pytest-asset-1" for a in r4.json()["items"])

    # delete
    r5 = client.delete(f"/api/assets/{aid}", headers=auth_headers)
    assert r5.status_code == 204
    r6 = client.get(f"/api/assets/{aid}", headers=auth_headers)
    assert r6.status_code == 404


def test_asset_validation_bounds(client, auth_headers):
    r = client.post(
        "/api/assets",
        headers=auth_headers,
        json={"hostname": "", "criticality": 99, "exposure": "internal"},
    )
    assert r.status_code == 422  # validation rejects empty hostname and criticality 99


def test_intel_search_returns_list(client, auth_headers):
    r = client.get(
        "/api/intel/search",
        headers=auth_headers,
        params={"q": "escalate privileges", "mode": "keyword", "top_k": 3},
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_analyst_returns_citations(client, auth_headers):
    r = client.post(
        "/api/analyst",
        headers=auth_headers,
        json={"question": "What techniques relate to credential dumping?"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] in ("fallback", "llm")
    assert isinstance(body["citations"], list)
    for c in body["citations"]:
        assert "source" in c and "external_id" in c


def test_ingestion_status_requires_auth(client):
    r = client.get("/api/ingestion/status")
    assert r.status_code == 401


def test_audit_requires_auth(client):
    r = client.get("/api/audit")
    assert r.status_code == 401
