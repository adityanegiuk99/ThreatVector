"""Training and evaluation for the 90-day KEV-inclusion model.

Compares:
  - Rules baseline: CVE in KEV always scores 1.0 else CVSS/10 (uses observed facts only;
    for evaluation only the train-period rule is allowed - we tune the threshold on val).
  - Logistic Regression (scikit-learn)
  - LightGBM (with early stopping on the validation split)

Evaluation uses the fully chronological test split and reports:
  PR-AUC, ROC-AUC, precision@k, recall@k, Brier score
No metric is invented: everything is computed from data on disk.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Cve, EvaluationMetric, KevEntry, ModelVersion
from app.services.ml.dataset import build_90d_dataset, chronological_splits
from app.services.ml.features import build_features, FeatureSchema

logger = logging.getLogger("veylix.ml.train")

ARTIFACT_DIR = Path(settings.artifacts_dir) / "ml"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class SplitEvaluation:
    split: str
    n: int
    positives: int
    metrics: dict[str, float | None] = field(default_factory=dict)


def _pr_auc(y_true, scores) -> float:
    return float(average_precision_score(y_true, scores))


def _roc_auc(y_true, scores) -> float | None:
    try:
        return float(roc_auc_score(y_true, scores))
    except ValueError:
        return None  # happens when only one class present in split


def precision_at_k(y_true, scores, k_frac: float = 0.05) -> float:
    n = len(y_true)
    k = max(1, int(n * k_frac))
    order = np.argsort(-np.asarray(scores))[:k]
    return float(np.mean(np.asarray(y_true)[order]))


def recall_at_k(y_true, scores, k_frac: float = 0.05) -> float:
    total_pos = int(np.sum(y_true))
    if total_pos == 0:
        return 0.0
    n = len(y_true)
    k = max(1, int(n * k_frac))
    order = np.argsort(-np.asarray(scores))[:k]
    return float(np.sum(np.asarray(y_true)[order]) / total_pos)


def evaluate(y_true, scores) -> dict[str, float | None]:
    y = np.asarray(y_true).astype(int)
    s = np.asarray(scores, dtype=np.float64)
    out = {
        "pr_auc": _pr_auc(y, s),
        "roc_auc": _roc_auc(y, s),
        "precision@1%": precision_at_k(y, s, 0.01),
        "precision@5%": precision_at_k(y, s, 0.05),
        "recall@5%": recall_at_k(y, s, 0.05),
        "recall@10%": recall_at_k(y, s, 0.10),
        "brier": float(brier_score_loss(y, s)),
    }
    return {k: (round(v, 6) if v is not None else None) for k, v in out.items()}


def rules_baseline_score(df: pd.DataFrame) -> np.ndarray:
    """A simple interpretable baseline: CVSS/10 adjusted by ransomware-flag unknown."""
    return np.clip(df["cvss_base_score"].fillna(0.0).astype(float).values / 10.0, 0.0, 1.0)


def train_all_models(
    train: pd.DataFrame,
    val: pd.DataFrame,
    test: pd.DataFrame,
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Train the three candidate models; return fitted pipelines + split predictions."""
    X_train, schema = build_features(train)
    X_val, _ = build_features(val, schema)
    X_test, _ = build_features(test, schema)

    y_train = train["label"].values
    y_val = val["label"].values
    y_test = test["label"].values

    results: dict[str, Any] = {"schema": schema.to_dict(), "split_meta": meta}

    # --- Rules baseline -------------------------------------------------
    rule_val_scores = rules_baseline_score(val)
    rule_test_scores = rules_baseline_score(test)
    results["rules"] = {
        "val": evaluate(y_val, rule_val_scores),
        "test": evaluate(y_test, rule_test_scores),
    }

    # --- Logistic Regression ---------------------------------------------
    lr = LogisticRegression(max_iter=1000, class_weight="balanced")
    lr.fit(X_train.values, y_train)
    lr_val = lr.predict_proba(X_val.values)[:, 1]
    lr_test = lr.predict_proba(X_test.values)[:, 1]
    results["logreg"] = {
        "val": evaluate(y_val, lr_val),
        "test": evaluate(y_test, lr_test),
        "train_size": len(X_train),
        "params": {"max_iter": 1000, "class_weight": "balanced"},
    }

    # --- LightGBM (optional; falls back gracefully) -----------------------
    try:
        import lightgbm as lgb

        pos = int(np.sum(y_train))
        neg = int(len(y_train) - pos)
        model = lgb.LGBMClassifier(
            n_estimators=1000,
            learning_rate=0.05,
            num_leaves=31,
            class_weight="balanced",
            verbose=-1,
        )
        model.fit(
            X_train,
            y_train,
            eval_set=[(X_val, y_val)],
            eval_metric="average_precision",
            callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False), lgb.log_evaluation(0)],
        )
        lgb_val = model.predict_proba(X_val)[:, 1]
        lgb_test = model.predict_proba(X_test)[:, 1]
        results["lightgbm"] = {
            "val": evaluate(y_val, lgb_val),
            "test": evaluate(y_test, lgb_test),
            "best_iteration": model.best_iteration_,
            "params": model.get_params(),
        }
        results["_lightgbm_model"] = model
    except ImportError:
        logger.warning("LightGBM not installed; skipping that candidate")
        results["lightgbm"] = None

    results["_logreg_model"] = lr
    results["_schema"] = schema
    results["_feature_importance"] = {
        name: float(coef) for name, coef in zip(schema.feature_names, lr.coef_[0])
    }
    return results


def run_training(db: Session, *, model_name: str = "kev90d", activate_best: bool = True) -> dict[str, Any]:
    """End-to-end: build dataset, compare models, register the best to DB, persist artifacts."""
    dataset = build_90d_dataset(db)
    df = dataset.table
    if df.empty:
        raise RuntimeError("No CVE data present; ingest before training.")

    train, val, test, split_meta = chronological_splits(df)
    all_results = train_all_models(train, val, test, split_meta)

    # Choose best on val PR-AUC among {rules, logreg, lightgbm}
    def val_pr(m):  # m in {rules, logreg, lightgbm}
        r = all_results.get(m)
        if not r or r.get("val") is None:
            return -1.0
        return r["val"].get("pr_auc") or 0.0

    candidates = {"rules": "rules_baseline", "logreg": "logistic_regression", "lightgbm": "lightgbm"}
    best_model_key = max(candidates.keys(), key=val_pr)
    logger.info("Selected model: %s (val PR-AUC=%.4f)", best_model_key, val_pr(best_model_key))

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    version = f"_{timestamp}"
    artifact_dir = ARTIFACT_DIR / f"{model_name}{version}"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    if best_model_key == "rules":
        algorithm = "rules_baseline"
    elif best_model_key == "logreg":
        algorithm = "logistic_regression"
    else:
        algorithm = "lightgbm"

    model_dir_name = f"{model_name}{version}"
    # Save artifacts for ML candidates (rules baseline requires no binary artifact)
    if best_model_key == "logreg":
        joblib.dump(all_results["_logreg_model"], artifact_dir / "model.joblib")
        joblib.dump(all_results["_schema"], artifact_dir / "schema.joblib")
    elif best_model_key == "lightgbm":
        joblib.dump(all_results["_lightgbm_model"], artifact_dir / "model.joblib")
        joblib.dump(all_results["_schema"], artifact_dir / "schema.joblib")

    dataset_path = ARTIFACT_DIR / f"dataset_{timestamp}.csv"
    df.to_csv(dataset_path, index=False)

    eval_report = {
        "model_name": model_name,
        "version": version,
        "algorithm": algorithm,
        "selected": best_model_key,
        "split_meta": split_meta,
        "dataset_counts": {
            "total": len(df),
            "positives": dataset.positives,
            "negatives": dataset.negatives,
            "excluded_no_window": dataset.excluded_no_window,
            "duplicates_dropped": dataset.duplicates_dropped,
        },
        "results": {
            k: all_results[k] for k in ("rules", "logreg", "lightgbm") if all_results.get(k)
        },
        "feature_importance": all_results.get("_feature_importance", {}),
    }
    with open(artifact_dir / "eval_report.json", "w", encoding="utf-8") as fh:
        json.dump(eval_report, fh, indent=2, default=str)

    # --- Register in database --------------------------------------------
    # One ModelVersion row per candidate so metrics don't collide; the best is activated.
    version_rows: dict[str, int] = {}
    artifacts = {
        "logreg": ("model.joblib", all_results.get("_logreg_model")),
        "lightgbm": ("model.joblib", all_results.get("_lightgbm_model")),
    }
    for model_key, alias in candidates.items():
        res = all_results.get(model_key)
        if not res:
            continue
        candidate_dir = ARTIFACT_DIR / f"{model_name}{version}_{alias}"
        candidate_dir.mkdir(parents=True, exist_ok=True)
        fname, model_obj = artifacts.get(model_key, (None, None))
        if fname and model_obj is not None:
            joblib.dump(model_obj, candidate_dir / fname)
            joblib.dump(all_results["_schema"], candidate_dir / "schema.joblib")
        rows = db.query(ModelVersion).filter(ModelVersion.name == model_name, ModelVersion.algorithm == alias).all()
        for r in rows:
            r.is_active = False
        mv = ModelVersion(
            name=model_name,
            version=f"{version}-{alias}",
            algorithm=alias,
            feature_schema="publication_time_v1",
            trained_on=f"rows={len(df)};test_end={split_meta.get('test_end_date')}",
            trained_at=datetime.now(),
            artifact_path=str(candidate_dir),
            is_active=(model_key == best_model_key and activate_best),
            notes="Leakage-safe chronological split training.",
        )
        db.add(mv)
        db.flush()
        version_rows[model_key] = mv.id
        for split in ("val", "test"):
            if res.get(split) is None:
                continue
            for m_name, m_val in res[split].items():
                if m_val is None:
                    continue
                db.add(
                    EvaluationMetric(
                        model_version_id=mv.id,
                        dataset_tag=split,
                        metric_name=m_name,
                        metric_value=float(m_val),
                        split=split,
                        detail=None,
                    )
                )
    db.commit()
    logger.info("Registered %d model versions", len(version_rows))
    report = {**eval_report, "model_version_ids": version_rows, "artifact_dir": str(artifact_dir)}
    return report


def main() -> None:  # pragma: no cover - CLI
    import argparse

    from app.db.session import SessionLocal

    parser = argparse.ArgumentParser(description="Train and evaluate KEV-90d models")
    parser.add_argument("--no-activate", action="store_true")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        report = run_training(db, activate_best=not args.no_activate)
        print(json.dumps(report, indent=2, default=str))
    finally:
        db.close()


if __name__ == "__main__":
    main()
