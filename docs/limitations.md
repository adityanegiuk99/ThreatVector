# Veylix Limitations

## Data
- **Fast-moving sources**: NVD adds/edits continuously; KEV policy changes over years. Metrics in
  the model card reflect the exact ingested window and will change as more history is ingested.
- **NVD without an API key** is ~5 requests / 30 s: full backfills take hours. Set `veylix_NVD_API_KEY`.
- **CPE-parsing approximation**: product extraction relies on CPE strings; non-CPE advisories
  (A-shot / NoMa) contribute no affected products yet.
- **KEV linkage depth**: CVEs may exist in KEV that NVD has not (yet) published; these are still
  stored but with minimal publication-time metadata (title/date_added only), which limits what
  the model can say about them.

## ML
- **Single horizon**: only the 90-day KEV task is trained; other horizons are not modelled.
- **No grouping awareness**: CVEs about the same product/family share correlated outcomes;
  grouped or time-series cross-validation may be more conservative than the chronological split.
- **Brier + PR tradeoff**: heavily imbalanced labels; LR and LGB both use class_weight=balanced
  which changes the calibration scale.
- **SHAP optional**: without the `shap` package, explanation relies on coefficients / gains.
- **No drift monitor**: metric recomputation is on-demand (manual retrain).

## Risk engine
- **Weights are a starting point**, not security-policy ground truth; overrides exist
  (`weights` parameter) but are not persisted per-tenant yet.
- **Remediation availability** term is currently a coarse signal from evidence completeness, not
  a vendor-patch-existence lookup.
- **Ambiguous version matching**: when the asset inventory lacks a version string, the engine
  flags it for manual review rather than guessing; this may understate risk for those rows.

## Retrieval / analyst
- **English-only input**, sentence-transformer `all-MiniLM-L6-v2`.
- **Injection guard is heuristic**: regex-based; a determined adversary can craft phrasings it
  misses. Reading the original citation is always possible from the UI.
- **No multi-hop reasoning without an LLM key**: the fallback lists retrieved evidence and
  publication-time facts, it does not synthesize a full analyst narrative.
- **Citations are retrieval-only**: no generated "facts" beyond the summaries; abuse of the LLM
  path could still produce incorrect synthesis from true sources (mitigated by requiring
  citations on every claim in the prompt).

## Operations
- **Single-node**: Docker Compose is one Postgres, one API, one worker; horizontal scale is
  out of scope.
- **Tenant isolation is structural not enforced today**: all data is tenant 'default'; production
  needs row-level security or a tenant filter in every query.
- **Frontend rewrites proxy** `/api/*` at dev time; in production configure CORS/origin
  allow-list properly.
