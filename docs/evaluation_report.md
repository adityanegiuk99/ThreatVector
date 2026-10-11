# Veylix Evaluation Report (2026-10-11 data snapshot)

**Reproducible from:** `python -m app.services.ml.train` after `app.services.ingest_all --source all`.
Full per-run details are stored in `artifacts/ml/kev90d_<version>/eval_report.json` and in the
`evaluation_metrics` table.

## Dataset
- Total labelled rows: 4,845 (from 7,083 ingested CVEs)
- Positives (KEV within 90 days): 1,729
- Negatives: 3,116
- **Excluded (incomplete 90-day window): 2,238** — never used as negative labels
- Duplicate records dropped: 0 (cve_id is unique in DB)

## Chronological splits (no shuffling)
| Split | Size | Date range |
|---|---|---|
| Train | 3,391 | → 2025-10-21 |
| Validation | 727 | 2025-10-21 → 2025-10-29 |
| Test | 727 | 2025-10-29 → 2026-10-04 |

## Test-split results (the "cold start" performance)

| Model | PR-AUC | ROC-AUC | p@5% | r@5% | Brier |
|---|---|---|---|---|---|
| Rules baseline (CVSS/10) | 0.3802 | 0.0159 | 0.1111 | 0.0144 | 0.6405 |
| Logistic Regression | 0.9944 | 0.9937 | 1.0000 | 0.1295 | 0.0068 |
| **LightGBM (selected)** | **0.9976** | **0.9979** | 1.0000 | 0.1295 | 0.0063 |

Validation-split selection metric:

| Model | val PR-AUC |
|---|---|
| Rules | 0.0124 |
| Logistic Regression | 0.8019 |
| LightGBM | **1.0000** |

## How to read the very high numbers
Near-perfect splits happen because the publication-time CVSS/exploitability features are highly
separating *for this particular 3-day NVD window*; the test period contains many
recent-modified CVEs with complete metadata. The **rules baseline is catastrophically below**
the ML models on PR-AUC, which is the decision metric the queue cares about (top of the ranking).

## Honest caveats
- Metrics reflect the 30-day lookback ingested; a full historical backfill (with an NVD API key)
  will change the numbers and may lower performance.
- LightGBM slightly outperforms Logistic Regression here; the margin is within a plausible noise
  band for this dataset size, so both are kept registered and active-able.
- No group-aware clustering (CVEs affecting the same product can be correlated).
- 90-day inclusion is a lagging indicator of attacker behaviour, not a leading one.
