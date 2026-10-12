"""Day 4: Automated retraining pipeline with a validation gate.

Flow:
  1. Read the current active model's test PR-AUC from evaluation_metrics
     as the incumbent baseline (never a hand-copied number).
  2. Rebuild the dataset from the current DB and train all candidates via
     the existing leakage-safe pipeline (train.run_training).
  3. Gate: the challenger must beat the incumbent's test PR-AUC by at least
     `min_improvement` — otherwise the new versions are registered but NOT
     activated (safe deploy semantics).
  4. Optionally re-embed the retrieval index (--reindex).

IDs and version strings are taken from run_training's own report
(model_version_ids / selected), so this module can never drift from what
train.py actually wrote.
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.logging_conf import configure_logging

logger = logging.getLogger("veylix.retrain")


@dataclass
class RetrainDecision:
    incumbent_version: str | None
    incumbent_pr_auc: float | None
    challenger_version: str
    challenger_pr_auc: float
    challenger_model_version_id: int | None
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
    from sqlalchemy.orm import Session as _Session  # noqa: F401  (typing aid only)

    from app.db.models import ModelVersion
    from app.services.ml.train import run_training

    run_started = datetime.now(timezone.utc)
    incumbent_version, incumbent_auc = incumbent_baseline(db, model_name)

    report = run_training(db, model_name=model_name, activate_best=False)
    challenger_version = report["version"]
    challenger_auc = float(report["results"][report["selected"]]["test"]["pr_auc"])
    mv_id = (report.get("model_version_ids") or {}).get(report["selected"])

    activated, reason = should_activate(incumbent_auc, challenger_auc, min_improvement)

    if activated:
        if mv_id is None:
            # Belt-and-braces: locate the exact candidate row by (name, version-alias).
            row = db.execute(
                text(
                    "SELECT id FROM model_versions "
                    "WHERE name = :n AND version = :v "
                    "ORDER BY trained_at DESC LIMIT 1"
                ),
                {"n": model_name, "v": f"{challenger_version}-{report['selected']}"},
            ).first()
            mv_id = row[0] if row else None
        if mv_id is None:
            activated = False
            reason = "could not locate challenger model_version row; nothing activated"
        else:
            # Deactivate only the same-name family, in one statement, then
            # activate exactly the challenger row chosen above.
            with db.begin_nested() as sp:
                db.execute(
                    text("UPDATE model_versions SET is_active = false WHERE name = :n"),
                    {"n": model_name},
                )
                db.execute(
                    text("UPDATE model_versions SET is_active = true WHERE id = :id"),
                    {"id": mv_id},
                )
                sp.commit()

    db.commit()

    if reindex:
        from app.services.retrieval.embed import index_documents

        counts = index_documents(db)
        logger.info("reindex complete: %s", counts)

    decision = RetrainDecision(
        incumbent_version=incumbent_version,
        incumbent_pr_auc=incumbent_auc,
        challenger_version=challenger_version,
        challenger_pr_auc=challenger_auc,
        challenger_model_version_id=mv_id,
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
