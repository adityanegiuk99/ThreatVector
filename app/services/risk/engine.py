"""Deterministic, explainable risk engine.

Produces a transparent, rules-based baseline score (0-10) from each CVE's observed
facts, asset context, ML prediction (treated as an *estimate of future KEV inclusion*),
and evidence completeness. Scoring is intentionally auditable: every term contributes
a visible, bounded delta.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

from app.db.models import Asset, AssetSoftware, Cve


@dataclass
class ScoreTerm:
    """A single score contribution with its inputs and rationale."""
    name: str
    contribution: float
    reason: str


@dataclass
class RiskExplanation:
    cve_id: str
    observed_facts: dict[str, Any] = field(default_factory=dict)
    score_terms: list[ScoreTerm] = field(default_factory=list)
    rule_score: float = 0.0
    ml_score: float | None = None
    ml_label: str = "not available"
    final_score: float = 0.0
    asset_context: dict[str, Any] | None = None
    confidence: str = "low"
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _dedup_key(k: str) -> str:
    return (k or "").strip().lower()


def _asset_software_matches(cve: Cve, asset: Asset) -> tuple[bool, str]:
    """Return (matched, confidence). Confidence in {exact, likely, ambiguous, none}.

    Version is flagged "ambiguous" when the CVE's affected version range string
    is missing, or when the installed version does not parse as comparable.
    """
    aff = {( _dedup_key(p.vendor or ""), _dedup_key(p.product or "")) for p in cve.affected_products}
    for sw in asset.software:
        key = (_dedup_key(sw.vendor), _dedup_key(sw.product))
        if key in aff:
            if not sw.version or not any(p.affected_version for p in cve.affected_products):
                return True, "ambiguous"
            return True, "likely"
    return False, "none"


def compute_risk(
    cve: Cve,
    kev_entry: Any | None,
    asset: Asset | None = None,
    ml_score: float | None = None,
    *,
    weights: dict[str, float] | None = None,
) -> RiskExplanation:
    """Score a CVE (optionally in the context of one asset) on a 0-10 scale."""
    weights = weights or {}
    w = {
        "cvss": 0.25,
        "kev": 0.30,
        "exposure": 0.10,
        "criticality": 0.10,
        "match": 0.15,
        "evidence": 0.05,
        "ml": 0.05,
        **{k: v for k, v in weights.items()},
    }
    # Normalize weights to sum to 1
    total = sum(w.values())
    w = {k: v / total for k, v in w.items()}

    explanation = RiskExplanation(cve_id=cve.cve_id)
    explanation.observed_facts = {
        "cvss_base_score": cve.cvss_base_score,
        "cvss_vector": cve.cvss_vector_string,
        "attack_vector": cve.attack_vector,
        "attack_complexity": cve.attack_complexity,
        "cwe_ids": cve.cwe_ids,
        "published_date": cve.published_date.isoformat() if cve.published_date else None,
        "date_added_to_kev": kev_entry.date_added.isoformat() if kev_entry and kev_entry.date_added else None,
        "known_ransomware_use": kev_entry.known_ransomware_use if kev_entry else False,
        "affected_product_count": len(cve.affected_products),
    }

    terms = []
    # 1. CVSS severity
    cs = cve.cvss_base_score
    cvss_norm = (cs or 0.0) / 10.0
    terms.append(ScoreTerm("cvss", cvss_norm * w["cvss"] * 10.0,
                           f"CVSS {cs if cs is not None else 'missing'} normalized to {cvss_norm:.2f}"
                           ))

    # 2. KEV membership (observed fact, highest weight)
    kev_norm = 1.0 if kev_entry else 0.0
    ransomware_bonus = 0.15 if (kev_entry and kev_entry.known_ransomware_use) else 0.0
    terms.append(ScoreTerm("kev", (kev_norm + ransomware_bonus) * w["kev"] * 10.0,
                           "In KEV catalog" if kev_entry else "Not in KEV catalog"))

    # 3. Exposure of the asset (asset-level only)
    if asset is not None:
        exposure_map = {"external": 1.0, "dmz": 0.6, "internal": 0.2}
        exp_norm = exposure_map.get(asset.exposure, 0.2)
        terms.append(ScoreTerm("exposure", exp_norm * w["exposure"] * 10.0,
                               f"Asset exposure={asset.exposure}"))

        crit_norm = (asset.criticality or 3) / 5.0
        terms.append(ScoreTerm("criticality", crit_norm * w["criticality"] * 10.0,
                               f"Asset criticality={asset.criticality}/5"))
        matched, match_conf = _asset_software_matches(cve, asset)
        match_norm = 1.0 if match_conf in ("exact", "likely") else (0.5 if match_conf == "ambiguous" else 0.0)
        terms.append(ScoreTerm("match", match_norm * w["match"] * 10.0,
                               f"Installed software match confidence={match_conf}"))
        explanation.asset_context = {
            "hostname": asset.hostname,
            "asset_type": asset.asset_type,
            "criticality": asset.criticality,
            "exposure": asset.exposure,
            "match_confidence": match_conf,
        }
        if match_conf == "ambiguous":
            explanation.caveats.append(
                "Version match is ambiguous - flag for manual analyst review before acting."
            )
    else:
        terms.append(ScoreTerm("exposure", 0.0, "No asset context provided"))
        terms.append(ScoreTerm("criticality", 0.0, "No asset context provided"))
        terms.append(ScoreTerm("match", 0.0, "No asset context provided"))

    # 4. Evidence completeness
    completeness = 0.0
    completeness += 1.0 if cve.description else 0.0
    completeness += 1.0 if cve.cvss_base_score is not None else 0.0
    completeness += 1.0 if cve.cwe_ids else 0.0
    completeness += 1.0 if cve.references else 0.0
    completeness /= 4.0
    terms.append(ScoreTerm("evidence", completeness * w["evidence"] * 10.0,
                           f"Evidence completeness {completeness:.0%}"))

    # 5. ML KEV prediction (this is not a per-organization attack probability)
    if ml_score is not None:
        ml_norm = max(0.0, min(1.0, ml_score))
        terms.append(ScoreTerm("ml_kev_likelihood", ml_norm * w["ml"] * 10.0,
                               "ML estimate of future KEV inclusion"))
        explanation.ml_score = ml_score
        explanation.ml_label = "estimate of future KEV inclusion within 90 days of publication"
    else:
        explanation.ml_label = "not available"
        explanation.caveats.append(
            "ML prediction unavailable; relying on deterministic scoring only."
        )

    explanation.score_terms = terms
    explanation.rule_score = _combine_dict(
        cvss_norm=cvss_norm,
        kev_norm=kev_norm + ransomware_bonus,
        exposure=exposure_map.get(asset.exposure, 0.2) if asset else 0.2,
        criticality=(asset.criticality or 3) / 5.0 if asset else 0.6,
        match=1.0 if (asset and _asset_software_matches(cve, asset)[1] in ("exact", "likely")) else 0.0,
        evidence=completeness,
        ml=ml_score if ml_score is not None else None,
        weights=w,
    )
    explanation.final_score = explanation.rule_score
    explanation.confidence = "high" if completeness == 1.0 else "medium" if completeness >= 0.5 else "low"
    return explanation


def _combine_dict(
    *,
    cvss_norm: float,
    kev_norm: float,
    exposure: float,
    criticality: float,
    match: float,
    evidence: float,
    ml: float | None,
    weights: dict[str, float],
) -> float:
    """Combine normalized terms into a 0-10 score."""
    ml_val = ml if ml is not None else 0.0
    total = (
        cvss_norm * weights["cvss"]
        + kev_norm * weights["kev"]
        + exposure * weights["exposure"]
        + criticality * weights["criticality"]
        + match * weights["match"]
        + evidence * weights["evidence"]
        + ml_val * weights["ml"]
    )
    return round(min(10.0, max(0.0, total * 10.0)), 2)


def iso_to_json(dt: datetime | None) -> str | None:  # pragma: no cover - helper
    return dt.isoformat() if dt else None
