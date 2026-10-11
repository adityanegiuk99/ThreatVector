"""End-to-end tests on the real ingested dataset (requires ingestion to have run):

- models/evaluation lists registered versions with metrics
- ingestion/status shows sources as success
- analyst returns cited results grounded in intel documents
- risk queue returns explainable entries
"""
from __future__ import annotations

import pytest


def test_e2e_ml_evaluator_lists_models(client, auth_headers):
    r = client.get("/api/models/evaluation", headers=auth_headers)
    assert r.status_code == 200
    models = r.json()
    assert len(models) >= 1, "training must have run before e2e tests"
    for m in models:
        assert set(m) >= {"model_version_id", "name", "version", "algorithm", "is_active", "metrics"}
        assert m["metrics"], "every registered version must carry metrics"


def test_e2e_ingestion_status_success(client, auth_headers):
    r = client.get("/api/ingestion/status", headers=auth_headers)
    assert r.status_code == 200
    latest = r.json()["latest_by_source"]
    assert "cisa_kev" in latest, "KEV must be ingested"
    assert latest["cisa_kev"]["status"] == "success"
    assert (latest["cisa_kev"].get("records_fetched") or 0) > 500, "eccentric KEV size sanity"


def test_e2e_kev_cve_detail(client, auth_headers):
    """Pick a KEV-tagged CVE from search and pull its detail with linked KEV info."""
    r = client.get(
        "/api/vulnerabilities", headers=auth_headers, params={"in_kev": "true", "page_size": 1}
    )
    items = r.json()["items"]
    assert items, "dataset must contain KEV entries"
    cve_id0 = items[0]["cve_id"]
    detail = client.get(f"/api/vulnerabilities/{cve_id0}", headers=auth_headers).json()
    assert detail["cve_id"] == cve_id0
    # KEV linkage may or may not be complete for every record, but search marked it
    assert detail["kev"] is not None


def test_e2e_analyst_has_real_citations(client, auth_headers):
    r = client.post(
        "/api/analyst",
        headers=auth_headers,
        json={"question": "Which ATT&CK techniques involve command and scripting interpreter?"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] in ("fallback", "llm")
    assert len(body["citations"]) > 0, "must cite retrieved sources"
    for c in body["citations"]:
        assert c["source"] == "attck"
        assert c["external_id"].startswith("attack-pattern--")


def test_e2e_risk_queue_explainable(client, auth_headers):
    """Risk queue must return final score terms with recorded observed facts."""
    r = client.get("/api/risk/queue", headers=auth_headers, params={"page_size": 5})
    assert r.status_code == 200
    body = r.json()
    items = body["items"]
    assert len(items) > 0, "risk engine should score available CVEs×assets"
    entry = items[0]
    assert 0.0 <= entry["score"] <= 10.0
    assert entry["explanation"]["observed_facts"], "explanation needs observed facts"
    terms = entry["explanation"]["score_terms"]
    assert terms, "must have score terms"
    for t in terms:
        assert set(t) >= {"name", "contribution", "reason"}
