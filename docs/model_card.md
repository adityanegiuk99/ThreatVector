# Model Card — Veylix KEV-90D Predictor (v0.1)

## Task
Estimate the probability that a CVE, given its publication-time observable features, will be added
to the CISA Known Exploited Vulnerabilities (KEV) catalog within 90 days of its publication.

**This is an estimate of future KEV catalog inclusion, not a probability that any specific
organization will be attacked.**

## Data
- Source: `cves` (NVD data: publication-time fields) and `kev_entries` (CISA KEV) in the platform DB.
- Labels:
  - **Positive (1)** when the KEV `date_added` falls in `[published, published + 90 days]`.
  - **Negative (0)** when the KEV entry came strictly later than 90 days, or when no entry
    exists **and** a full 90-day observation window has elapsed since publication.
  - Records are **excluded** if the window is not complete (no invalid negatives).
- Features (all available at publication time): `cvss_base_score`, `exploitability_score`,
  `impact_score`, `n_cwe`, `n_references`, `n_affected_products`, `desc_len`, `has_cwe`,
  `scope_changed`, one-hot categories (`attack_vector`, `attack_complexity`,
  `user_interaction`, `privileges_required`, `cvss_version`).
- **No KEV-derived feature** is used at inference time (date_added, ransomware flag, etc.).

## Splits
Strictly chronological by `published_date`: train < validation < test, with no overlap and
deduplication on `cve_id` to prevent duplicate-record leakage.

## Candidates compared
1. **Rules baseline**: `cvss_base_score / 10` (interpretable floor).
2. **LogisticRegression** (`class_weight=balanced`).
3. **LightGBM** (`num_leaves=31`, `learning_rate=0.05`, up to 1000 trees, early stopping on val PR-AUC).

Selection: highest validation PR-AUC. The current champion is LightGBM for the dataset ingested on
2026-10-11; the logistic model is registered simultaneously so stakeholders can see the delta.

## Metrics
Reported on both validation and test splits: PR-AUC, ROC-AUC, precision@1%, precision@5%,
recall@5%, recall@10%, and Brier score. All values are produced by
`app/services/ml/train.py::evaluate()` from the actual test data and stored in the
`evaluation_metrics` table; they are never hard-coded. The exact values for each run are in
`artifacts/ml/<version>/eval_report.json` and in the Models page of the UI.

## Interpretability
- Logistic regression: feature coefficients stored per version in the eval report.
- LightGBM: model-visible feature importances can be dumped from the artifact; SHAP is optional.
- The risk engine surfaces only the publication-time feature names, not post-publication facts.

## Limitations
- KEV inclusion is a slow-moving, occasionally political process; PR-AUC measured on historical
  data may not persist.
- Class balance is highly skewed and driven by catalog policy changes over the years.
- Features are NVD-centric; broader threat-intel signals (e.g. vendor advisories, exploit PoCs)
  are not yet incorporated.
- 90 days is an operational choice; models for other horizons need retraining.
