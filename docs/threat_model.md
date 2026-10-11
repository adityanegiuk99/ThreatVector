# Veylix Threat Model (STRIDE-lite)

## Scope
Veylix backend (FastAPI), database (Postgres+pgvector), frontend (Next.js), ingestion workers.
Excludes: the CISA/NVD/MITRE infrastructure itself, the hosting provider, analysts' browsers.

## Trust boundaries
1. Browser ↔ API (public internet → JWT-authenticated FastAPI)
2. Ingestion workers ↔ external sources (public feeds over HTTPS)
3. Analyst assistant ↔ retrieved documents (untrusted third-party text)
4. Users ↔ each other (tenant isolation)

## Threats and controls

| # | Threat | Control |
|---|---|---|
| T1 | Unauthorized data access (spoofing) | JWT bearer auth on every intelligence endpoint; `get_current_user` dependency; 401 without token (tested) |
| T2 | Privilege escalation to admin | Role check on admin endpoints (`require_admin`); new users default `analyst` |
| T3 | Cross-tenant reading | All user-facing queries scope by `tenant_id` (currently one tenant); safe extension point documented |
| T4 | SQL injection | SQLAlchemy parameterized queries only; no string interpolation into SQL (intel search uses bound parameters) |
| T5 | Mass assignment / invalid input | Pydantic models with explicit fields and bounds; 422 on bad payloads (tested) |
| T6 | Prompt injection via retrieved documents | `INJECTION_PATTERNS` regexes flag suspicious instructions; flagged content excluded from the synthesis and surfaced as uncertainty (tested) |
| T7 | Poisoned external feed | Ingestion treats feeds as data: records are parsed defensively, failures logged and never propagated to scoring; feed URLs pinned |
| T8 | Model/explanation tampering | Model artifacts versioned by directory name; selection and metrics recorded in DB with timestamps; UI shows trained_on fingerprint |
| T9 |credential leak through logs | No LLM/api keys logged; secrets only via environment variables |
| T10 | DoS via expensive endpoints | Pagination (max 100), bounded prediction batches, and the risk queue's 500-CVE scan is per-request; rate-limit at proxy level recommended |
| T11 | Replay of analyst notes/sessions | JWT expiry (`access_token_expire_minutes`); HTTPS recommended (terminate at reverse proxy) |
| T12 | Supply-chain risk | Pinned dependency versions in requirements.txt; CI updates only via explicit PR |

## Residual risks
- Default admin is not provisioned: analysts can elevate only by direct SQL, which is intentional
  in the single-tenant MVP; production deployments should wire an IdP.
- Ingestion caching writes attacker-influenced content to `data/cache/` — stored as JSON, never
  executed; periodically purge.
- No per-user rate limiting yet (username login attempts not throttled) — recommended to add
  fail2ban or application-level counters for internet-exposed deployments.

## Explicitly out of scope
- Automatically applying remediation, scanning networks, or auto-updating asset inventories.
- Cryptographic audit of external feed signatures (CISA publishes SHA-256 alongside the feed;
  ingestion does not enforce it).
