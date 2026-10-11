"""Unit tests for ingestion adapters' parse/normalize logic (no network)."""
from __future__ import annotations

from datetime import datetime

from app.services.ingestion.cisa_kev import parse_date
from app.services.ingestion.nvd import _extract_attack_complexity, _extract_attack_vector, _extract_cpe_products, _parse_iso
from app.services.ingestion.attack import _iso_to_dt


def test_kev_date_parse_valid():
    assert parse_date("2024-05-01") == datetime(2024, 5, 1, tzinfo=__import__("datetime").timezone.utc)


def test_kev_date_parse_invalid_returns_none():
    assert parse_date("not-a-date") is None
    assert parse_date(None) is None
    assert parse_date("") is None


def test_nvd_iso_parse():
    assert _parse_iso("2024-05-01T12:00:00.000").year == 2024
    assert _parse_iso("2024-05-01T12:00:00Z") is not None
    assert _parse_iso("garbage") is None


def test_attack_vector_extraction():
    assert _extract_attack_vector("CVSS:3.1/AV:N/AC:L/PR:N") == "N"
    assert _extract_attack_vector("CVSS:2.0/AV:N/AC:L") == "N"
    assert _extract_attack_vector(None) is None


def test_attack_complexity_extraction():
    assert _extract_attack_complexity("CVSS:3.1/AV:N/AC:L") == "L"
    assert _extract_attack_complexity("CVSS:3.1/AV:N/AC:H") == "H"


def test_cpe_products_dedupe():
    vuln = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:*"},
                            {"criteria": "cpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:*"},  # dup
                            {"criteria": "cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*"},
                        ]
                    }
                ]
            }
        ]
    }
    products = _extract_cpe_products(vuln)
    assert len(products) == 2
    pairs = {(p["vendor"], p["product"]) for p in products}
    assert ("nginx", "nginx") in pairs
    assert ("apache", "httpd") in pairs


def test_attck_iso():
    assert _iso_to_dt("2024-05-01T00:00:00.000Z") is not None
    assert _iso_to_dt(None) is None
