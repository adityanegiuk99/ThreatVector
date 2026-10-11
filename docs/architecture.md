# Veylix Architecture

## Overview

Veylix is a modular monolith: one FastAPI process for API + services, one ingestion worker
(the same image re-run as a worker), one Postgres with pgvector, one Next.js frontend.

```
+-------------------+        HTTPS         +----------------------+       TLS        +----------------+
|  Public sources   |<---------------------|  Ingestion worker    |<---------------->|   Postgres     |
|  CISA KEV (JSON)  |   retries + cache    |  app/services/       |   SQLAlchemy     |   + pgvector   |
|  NVD 2.0 REST     |                      |    ingestion/        |                  |                |
|  MITRE ATT&CK STIX|                      +----------------------+                  |                |
+-------------------+                                 |                         |                |
                                                      | upsert                  |                |
                                                      v                         |                |
                                            +----------------------------------------------------+
                                            |                     database                       |
                                            |  cves, kev_entries, affected_products,             |
                                            |  assets + asset_software, risk_assessments,        |
                                            |  intel_documents + intel_chunks (vectors),         |
                                            |  model_versions, evaluation_metrics, predictions,  |
                                            |  analyst_notes, audit_events, ingestion_runs       |
                                            +----------------------------------------------------+
                                                      ^
      +-----------------+     JSON/JWT       +--------+----------+        proxies /api      +----------------+
      |    Analyst      |<-------------------|    FastAPI         |<------------------------>|   Next.js UI   |
      |   (browser)     |                    |    app/main.py     |      CORS allow-list     |   (Vercel/Dkr) |
      +-----------------+                    +--------------------+                          +----------------+
                                                          |
                                                          v
                                              +-------------------------+
                                              |  Risk engine (pure fn)  |
                                              |  + ML artifact (LGBM)   |
                                              |  + Analyst (RAG)        |
                                              +-------------------------+
```

## Data flow

1. **Ingestion**: worker fetches public JSON/STIX, normalizes, deduplicates on natural keys
   (`cve_id`, `kev_cve_id`, `(source, external_id)`), caches raw responses to disk, retries with
   backoff, and records an `ingestion_runs` row with counts and (on failure) the error.
2. **ML training**: `app/services/ml/` builds a publication-time feature table with explicit
   label-window handling, chronological splits, trains 3 candidates, evaluates, dumps versioned
   artifacts, and registers `model_versions` + `evaluation_metrics`.
3. **Prediction serving**: `/api/models/{id}/predict` loads the versioned artifact and scores
   Cves missing a prediction (up to 2000 at a time).
4. **Risk queue**: per CVE×asset pair the deterministic engine combines observed facts with
   asset exposure/criticality/match confidence + the active model's score into a 0-10 vector of
   contributions, each with a plain-language reason string.
5. **Analyst**: the query is embedded, semantic search runs over `intel_chunks` (pgvector),
   injection-flagged content is excluded, and either an LLM (optional) or a deterministic
   summarizer produces the answer bound to specific source citations.

## Key invariants

- No feature derivation from post-publication data at inference time.
- No fabricated fields anywhere: absent data is NULL, and surfaced as "not available".
- Every user-visible factual claim in the analyst flow either cites a source or is omitted.
- The ML label is a *catalog-inclusion* estimate, never an attack probability.
