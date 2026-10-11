# Veylix — AI Cyber Threat Intelligence Platform

Veylix prioritizes vulnerabilities with ML, explains every score, and answers analyst questions with cited, retrieval-grounded intelligence — using only real data from CISA KEV, NVD, and MITRE ATT&CK.

- **Explainable risk queue**: deterministic rules engine with per-term score breakdown; ML prediction shown separately and labelled as an estimate of future KEV inclusion.
- **Leakage-safe ML**: predicts whether a CVE will reach CISA KEV within 90 days of publication using chronological splits; rules baseline vs. Logistic Regression vs. LightGBM are all evaluated and versioned.
- **RAG analyst**: pgvector semantic retrieval over ATT&CK + advisories, retrieval-only citations when no LLM key is configured; prompt-injection-resistant; refuses to invent exploitation status.
- **Functional dashboard**: overview, remediation queue, vulnerability explorer, asset inventory, AI analyst, ML evaluation, and settings/audit all wired to real backend data.

## Repository layout

```
app/                 FastAPI backend (api/, core/, db/, schemas/, services/)
app/services/        ingestion (CISA KEV, NVD, MITRE ATT&CK), risk, ml, retrieval, analyst
app/db/migrations/   Alembic migrations (pgvector + pg_trgm)
src/                 Next.js 14 + Tailwind frontend (TypeScript)
tests/               unit, integration, and e2e pytest suites
scripts/             bootstrap.sh, demo asset generator
docs/                architecture, data dictionary, model card, evaluation report, threat model
artifacts/ml/        versioned model artifacts and evaluation reports
docker/              API and frontend Dockerfiles
.github/workflows/   CI (backend tests against real Postgres, frontend build)
```

## Quickstart (developer machine)

Requirements: Docker, Python 3.11+, Node 20+.

```bash
cp .env.example .env          # adjust credentials; defaults target the local compose stack
pip install -r requirements.txt
docker compose up -d db       # Postgres 16 with the pgvector + pg_trgm extensions
alembic upgrade head
```

### Reproducible pipeline

```bash
# 1. Ingest real public data (incremental; caches responses under data/cache)
python -m app.services.ingest_all --source all --lookback-days 30   # NVD without a key is rate-limited

# 2. Build the retrieval index (SentenceTransformer all-MiniLM-L6-v2; 384-dim)
python -m app.services.reindex

# 3. Generate demo asset inventory
python scripts/generate_demo_assets.py

# 4. Train + evaluate (writes artifacts/ml/<version>-<algo>/ and registers metrics)
python -m app.services.ml.train
```

### Run the stack

```bash
uvicorn app.main:app --reload                 # API on :8000
cd src && npm install && npm run dev          # UI on :3000
```

Or in Docker (API + worker + frontend + database):

```bash
docker compose up --build
```

First-time UI use: register an account on `/login`. **The first registered user's role is `analyst`; promote to admin via SQL if needed** (`UPDATE users SET role='admin' WHERE username='...'`).

### Tests

```bash
pytest tests -q                # unit + integration + e2e (integration needs a DB)
```

## Environment variables (see `.env.example`)

| Var | Purpose |
|---|---|
| `POSTGRES_{HOST,PORT,DB,USER,PASSWORD}` | DB connection |
| `VEYLIX_SECRET_KEY` | JWT signing key; generate with `openssl rand -hex 32` |
| `LLM_PROVIDER` (`none`/`anthropic`/`openai`), `LLM_MODEL`, `LLM_API_KEY` | optional LLM; unset → deterministic fallback |
| `EMBEDDING_MODEL` | SentenceTransformer model name |
| `veylix_NVD_API_KEY` | optional NVD API key (raises rate limits) |
| `veylix_REQUEST_TIMEOUT`, `veylix_MAX_RETRIES` | HTTP tuning |

## Ingestion sources

| Source | Endpoint | Notes |
|---|---|---|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | full catalog each run, dedup on `kev_cve_id` |
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | incremental via `lastModStartDate/EndDate`; API key recommended |
| MITRE ATT&CK | `https://github.com/mitre-attack/attack-stix-data` (`enterprise-attack/enterprise-attack.json`) | techniques → intel_documents for retrieval |

Ingestion never fabricates fields; missing values stay NULL and explanations mark them as unavailable.

## Model card (summary — full text in docs/model_card.md)

- **Task**: P(CVE added to CISA KEV within 90 days of publication).
- **Label rule**: positive if KEV date professionals falls in [pub, pub+90d]; late KEV entries label 0; **records without a full 90-day observation window are excluded**, never labelled 0.
- **Features**: publication-time only (CVSS, scores, product count, CWE count, references, description length, vector fields) — no KEV-derived features.
- **Splits**: chronological train < val < test (no shuffling, no duplicates).
- **Comparison**: rules baseline (CVSS/10), LogisticRegression (balanced), LightGBM (balanced, early stopping on val PR-AUC).
- **Metrics**: PR-AUC, ROC-AUC, precision@k, recall@k, Brier.
- **Interpretation limits**: an estimate of catalog inclusion, not per-organization compromise probability; see docs/limitations.md.

## Security notes

- Inputs validated with Pydantic; all intelligence endpoints require a JWT.
- Retrieved documents are treated as untrusted: known instruction-injection phrasings are flagged and excluded from synthesis.
- The platform suggests remediations; it never executes changes or performs scanning.
- Keep `.env` out of git (`.gitignore` already excludes it).

## Known limitations (summary; full text in docs/limitations.md)

- NVD ingestion without an API key is rate-limited (~5 requests/30s); use `veylix_NVD_API_KEY` for meaningful backfills.
- `shap` is optional (commented out in requirements.txt) because it needs a C++ toolchain on Windows; feature importance uses model coefficients / LightGBM gains instead.
- The risk engine's weights are a defensible starting point, not ground truth; tune them for your risk appetite.
- The remediation queue recomputes scores per request over the newest 500 CVEs; for tens of thousands of assets, precompute.
