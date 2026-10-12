# Day 4 — Automated Retraining with a Promotion Gate

## What was added

- `app/services/ml/retrain.py` — one-command retraining pipeline:
  reads the **incumbent's** test PR-AUC from `evaluation_metrics` (never a
  hand-copied number), rebuilds the dataset from the live DB, trains all
  three candidates (rules / logistic regression / LightGBM) via the existing
  leakage-safe pipeline, then applies the gate:
  the challenger activates **only if** its test PR-AUC beats the incumbent's
  by at least `--min-improvement` (default 0.01). Otherwise the challenger
  version is still registered (auditable) but the incumbent stays active.
- `.github/workflows/retrain_schedule.yml` — weekly automated retrain
  (Mondays 04:00 UTC) including fresh ingestion beforehand.
- Tests: `tests/unit/test_retrain.py` — 7 tests covering every gate branch
  (no incumbent, clear improvement, exact margin, too-small improvement,
  regression, zero margin, null-metric row).

## Running

```bash
python -m app.services.ml.retrain                          # default gate
python -m app.services.ml.retrain --min-improvement 0.02   # stricter gate
```

## Verified result (2026-10-12, live veylix-db)

A fresh retrain after the Day 3 ingest refresh:

- incumbent `_20261011T031448-lightgbm`: test PR-AUC **0.9976**
- challenger `_20261012T025757` (lightgbm): test PR-AUC **0.9970**
- decision: **not activated** — 0.9970 − 0.9976 = −0.0006, below the 0.01
  margin. Exit status 0; the run is recorded in `model_versions` for audit.

This demonstrates the gate doing its job: marginal regressions never reach
production, even when a retrain "succeeds".

## Semantics

- Activation flips `is_active` atomically inside the retrain transaction —
  the predict path never sees a half-promoted state.
- Failure isolation: an exception in training marks the run failed and
  leaves the incumbent untouched.
- Model versions are append-only; nothing is deleted.
