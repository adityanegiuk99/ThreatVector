# Data Dictionary

All timestamps are timezone-aware UTC (`DateTime(timezone=True)`).

## users
| Column | Type | Notes |
|---|---|---|
| id | int PK | |
| username | varchar(64) unique | login id |
| email | varchar(255) unique | |
| hashed_password | varchar(255) | bcrypt |
| role | varchar(32) | analyst/admin/viewer |
| is_active | bool | soft delete |

## assets
| Column | Type | Notes |
|---|---|---|
| id | int PK | |
| tenant_id | varchar(64) | default 'default' |
| hostname | varchar(255) | unique per tenant |
| asset_type | varchar(64) | server/workstation/network/cloud |
| criticality | int 1..5 | 5 = most critical |
| exposure | varchar(32) | internal/dmz/external |
| network_zone, owner, notes | text | descriptive |
| weight | float | reserved scoring multiplier |

## asset_software
| Column | Type | Notes |
|---|---|---|
| asset_id | FK->assets.id CASCADE | |
| vendor, product | varchar(128) | normalized via CPE |
| version | varchar(64) | NULL => ambiguous match |
| match_confidence | varchar(32) | manual / likely / ambiguous |

## cves
| Column | Type | Notes |
|---|---|---|
| cve_id | varchar(32) unique | CVE-YYYY-NNNN |
| description | text | observed facts only |
| cvss_base_score | float | from NVD metrics (V2/V30/V31/V40) |
| cvss_vector_string | varchar(512) | supports CVSSv4 |
| cvss_severity | varchar(32) | LOW/MEDIUM/HIGH/CRITICAL |
| attack_vector / attack_complexity / privileges_required / user_interaction / scope / impacts | varchar(32) | parsed from vector |
| cwe_ids | JSONB list | |
| references | JSONB list | url/source/tags |
| published_date / modified_date | tz datetime | from NVD |
| source | varchar(64) | nvd / cisa_kev |
| raw | JSONB | last NVD payload for audit |

## affected_products
| Column | Type | Notes |
|---|---|---|
| cve_id | FK->cves.id CASCADE | |
| vendor, product | varchar(128) | from CPE |
| affected_version | varchar(128) | raw CPE version field, when present |
| version_range | varchar(256) | startIncluding/Excluding etc |

## kev_entries
| Column | Type | Notes |
|---|---|---|
| kev_cve_id | varchar(32) unique | cveID from CISA feed |
| cve_id | FK->cves.id | resolved linkage |
| vendor_project, product, vulnerability_name | text | feed observed facts |
| date_added, due_date | date | catalog dates |
| known_ransomware_use | bool | 'Known' from feed |
| required_action, notes | text | |
| cwes | JSONB | |

## risk_assessments
Durable record of a computed risk (cve_id, asset_id, tenant_id, base_score, ml_score, rule_score,
final_score, explanation JSONB, method_version, computed_at).

## analyst_notes
Analyst commentary and remediation status (`triaged` / `in_progress` / `mitigated` / `deferred`);
author_name is denormalized for display.

## audit_events
Action log: user, action, object_type, object_id, detail JSONB, ip (nullable).

## intel_documents / intel_chunks
`intel_documents` is the retrieval knowledge base keyed by `(source, external_id)`; `intel_chunks`
holds the word-aware sliding-window chunks with a 384-dim pgvector `embedding` (all-MiniLM-L6-v2,
cosine-normalized).

## ingestion_runs
Per-run record: source, status (running/success/failed), counts fetched/upserted/skipped, error,
detail JSONB (catalog version, date range).

## model_versions
Name+version unique; algorithm, feature_schema, trained_on (rows + test end date), artifact_path,
is_active flag, params JSONB.

## evaluation_metrics
(model_version_id, dataset_tag, metric_name) unique — actual numeric evaluations only.

## predictions
One per (cve_id, model_version_id): score, prediction, features JSONB, shap_values JSONB (nullable),
predicted_at.
