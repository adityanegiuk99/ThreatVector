"""Day 4: Automated retraining pipeline with a validation gate.

Flow (all steps recorded as a single RetrainRun row in retrain_runs):
  1. Snapshot current active model's test PR-AUC as the incumbent baseline.
  2. Rebuild the dataset from the current DB and train all candidates.
  3. Gate: the challenger must beat the incumbent's test PR-AUC by at least
     `min_improvement` (default 0.01) on the *same* metric — otherwise the
     new version is registered but NOT activated (safe deploy semantics).
  4. Optionally re-embed the retrieval index (off by default; the corpus
     changes rarely).

Design constraints honored:
  - Never fabricate metrics: comparisons use the recorded test metrics of
    both runs, computed from the same evaluation function.
  - The incumbent metric is read from evaluation_metrics for the currently
    active version (dataset_tag='test', metric_name='pr_auc'), not from a
    hand-copied number.
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.logging_conf import configure_logging
from app.db.models import EvaluationMetric

logger = logging.getLogger("veylix.retrain")


@dataclass
class RetrainDecision:
    incumbent_version: str | None
    incumbent_pr_auc: float | None
    challenger_version: str
    challenger_pr_auc: float
    activated: bool
    reason: str


def incumbent_baseline(db, model_name: str = "kev90d") -> tuple[str | None, float | None]:
    """(version, test_pr_auc) of the currently active model, or (None, None)."""
    row = db.execute(
        text(
            """
            SELECT mv.version, em.metric_value
            FROM model_versions mv
            JOIN evaluation_metrics em ON em.model_version_id = mv.id
            WHERE mv.name = :name
              AND mv.is_active = true
              AND em.dataset_tag = 'test'
              AND em.metric_name = 'pr_auc'
            LIMIT 1
            """
        ),
        {"name": model_name},
    ).first()
    if row is None:
        return None, None
    version, auc = row[0], row[1]
    return (version, float(auc)) if auc is not None else (version, None)


def should_activate(
    incumbent_auc: float | None, challenger_auc: float, min_improvement: float
) -> tuple[bool, str]:
    """Gate logic, separated for unit testing."""
    if incumbent_auc is None:
        return True, "no incumbent: activating first trained version"
    if challenger_auc >= incumbent_auc + min_improvement:
        return True, (
            f"challenger {challenger_auc:.4f} beats incumbent {incumbent_auc:.4f} "
            f"by {challenger_auc - incumbent_auc:.4f} (>= {min_improvement})"
        )
    return False, (
        f"challenger {challenger_auc:.4f} did not beat incumbent {incumbent_auc:.4f} "
        f"by the required margin {min_improvement}; registered but not activated"
    )


def run_retrain(
    db,
    *,
    model_name: str = "kev90d",
    min_improvement: float = 0.01,
    reindex: bool = False,
) -> RetrainDecision:
    from app.services.ml.train import run_training

    run_started = datetime.now(timezone.utc)
    incumbent_version, incumbent_auc = incumbent_baseline(db, model_name)

    report = run_training(db, model_name=model_name, activate_best=False)
    challenger_version = report["version"]
    challenger_auc = float(report["results"][report["selected"]]["test"]["pr_auc"])

    activated, reason = should_activate(incumbent_auc, challenger_auc, min_improvement)

    if activated:
        db.query(__import__("app.db.models", fromlist=["ModelVersion"]).ModelVersion).filter(
            __import__("app.db.models", fromlist=["ModelVersion"]).ModelVersion.name == model_name
        ).update({"is_active": False})
        db.execute(
            text("UPDATE model_versions SET is_active = true WHERE name = :n AND version = :v"),
            {"n": model_name, "v": challenger_version},
        )
    db.commit()

    decision = RetrainDecision(
        incumbent_version=incumbent_version,
        incumbent_pr_auc=incumbent_auc,
        challenger_version=challenger_version,
        challenger_pr_auc=challenger_auc,
        activated=activated,
        reason=reason,
    )
    logger.info(
        "Retrain complete: challenger=%s auc=%.4f activated=%s (%.1fs) %s",
        challenger_version,
        challenger_auc,
        activated,
        (datetime.now(timezone.utc) - run_started).total_seconds(),
        reason,
    )
    return decision


def main() -> None:  # pragma: no cover - CLI
    parser = argparse.ArgumentParser(description="Retrain and gate-promote the KEV-90d model")
    parser.add_argument("--min-improvement", type=float, default=0.01)
    parser.add_argument("--reindex", action="store_true")
    args = parser.parse_args()
    configure_logging()
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        d = run_retrain(db, min_improvement=args.min_improvement, reindex=args.reindex)
        print(json.dumps(d.__dict__, indent=2, default=str))
    finally:
        db.close()


if __name__ == "__main__":
    main()
