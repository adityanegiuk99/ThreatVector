"""Unit tests for the deterministic risk engine."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.risk.engine import compute_risk


def make_cve(**kw):
    defaults = dict(
        cve_id="CVE-TEST-1",
        cvss_base_score=9.0,
        cvss_vector_string="AV:N/AC:L",
        attack_vector="N",
        attack_complexity="L",
        cwe_ids=["CWE-79"],
        published_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
        description="A serious test vulnerability",
        references=[{"url": "https://example.com"}],
        affected_products=[
            type("AP", (), {"vendor": "nginx", "product": "nginx", "affected_version": "1.18"})()
        ],
    )
    defaults.update(kw)
    return type("Cve", (), defaults)()


def make_kev(ransomware=False):
    return type(
        "KevEntry",
        (),
        {
            "kev_cve_id": "CVE-TEST-1",
            "date_added": datetime(2025, 2, 1).date(),
            "known_ransomware_use": ransomware,
        },
    )()


def make_asset(hostname="srv-1", exposure="internal", criticality=3, software=None):
    software = software or []
    return type(
        "Asset",
        (),
        {
            "hostname": hostname,
            "asset_type": "server",
            "exposure": exposure,
            "criticality": criticality,
            "software": [
                type(
                    "SW",
                    (),
                    {"vendor": v, "product": p, "version": ver},
                )
                for v, p, ver in software
            ],
        },
    )()


def test_kev_dominates_score():
    expl_kev = compute_risk(make_cve(), make_kev(), None)
    expl_no_kev = compute_risk(make_cve(), None, None)
    assert expl_kev.final_score > expl_no_kev.final_score
    kev_term = next(t for t in expl_kev.score_terms if t.name == "kev")
    assert kev_term.contribution > 0


def test_known_ransomware_adds_bonus():
    expl_r = compute_risk(make_cve(), make_kev(ransomware=True), None)
    expl_p = compute_risk(make_cve(), make_kev(ransomware=False), None)
    assert expl_r.final_score > expl_p.final_score + 0.3


def test_external_exposure_raises_score():
    ext = compute_risk(make_cve(), None, make_asset(exposure="external"))
    internal = compute_risk(make_cve(), None, make_asset(exposure="internal"))
    assert ext.final_score > internal.final_score


def test_software_match_with_version_is_likely():
    cve = make_cve()
    asset = make_asset(software=[("nginx", "nginx", "1.18")])
    expl = compute_risk(cve, None, asset)
    match_term = next(t for t in expl.score_terms if t.name == "match")
    assert match_term.contribution > 0
    assert expl.asset_context["match_confidence"] == "likely"


def test_software_match_without_version_flags_ambiguous():
    """Missing installed version => ambiguous => manual review caveat."""
    cve = make_cve()
    asset = make_asset(software=[("nginx", "nginx", None)])
    expl = compute_risk(cve, None, asset)
    assert expl.asset_context["match_confidence"] == "ambiguous"
    assert any("manual" in c.lower() or "ambiguous" in c.lower() for c in expl.caveats)


def test_null_cvss_scores_lower():
    expl_null = compute_risk(make_cve(cvss_base_score=None), None, None)
    expl_9 = compute_risk(make_cve(), None, None)
    assert expl_null.final_score < expl_9.final_score


def test_scores_within_bounds():
    expl = compute_risk(make_cve(cvss_base_score=10.0), make_kev(ransomware=True), make_asset(exposure="external", criticality=5, software=[("nginx", "nginx", "1.18")]), ml_score=0.95)
    assert 0.0 <= expl.final_score <= 10.0


def test_ml_score_labeled_not_attack_probability():
    expl = compute_risk(make_cve(), None, None, ml_score=0.5)
    assert "KEV" in expl.ml_label  # states estimate of future KEV inclusion


def test_explanation_separates_fact_and_prediction():
    """Observed facts contain no ML or LLM-derived values."""
    expl = compute_risk(make_cve(), make_kev(), None, ml_score=0.7)
    assert "ml" not in expl.observed_facts and "llm" not in expl.observed_facts
    assert "cvss_base_score" in expl.observed_facts
