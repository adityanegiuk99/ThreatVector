# Day 3 — Scheduled Incremental Ingestion

## What was added

- `app/services/scheduler.py` — interval scheduler for the three public
  sources, driven by `Schedule.due()` (pure, unit-testable), with
  **Postgres advisory-lock coalescing** so concurrent cron/loop invocations
  never double-ingest, and failure isolation (one source erroring never
  blocks the others).
- `.github/workflows/ingest_schedule.yml` — production scheduler: GitHub
  Actions cron running the same code paths (KEV every 3 h, NVD every 6 h
  with 3-day lookback, ATT&CK daily at 03:00 UTC), plus manual
  `workflow_dispatch`.
- Tests: `tests/unit/test_scheduler.py` (11 tests) and
  `tests/integration/test_scheduler_integration.py` (advisory lock
  round-trip on live Postgres; skips cleanly offline).

## Configuration

Interval overrides (minutes, floor 5):

```bash
export VEYLIX_KEV_INTERVAL_MIN=180     # default 180
export VEYLIX_NVD_INTERVAL_MIN=360     # default 360
export VEYLIX_ATTACK_INTERVAL_MIN=1440 # default 1440
```

## Running

Dev loop (never exits):

```bash
python -m app.services.scheduler --loop
```

One-shot (what cron calls):

```bash
python -m app.services.scheduler
```

Each run writes a row to `ingestion_runs` and logs timing per source.

## Verified results (2026-10-12, live veylix-db)

| source       | status  | fetched | upserted |
|--------------|---------|---------|----------|
| mitre_attack | success |     858 |      858 |
| cisa_kev     | success |    1739 |     1739 |
| nvd          | success |    2318 |     2318 |

`run_once` completed in ~40 s wall clock, exit status 0.
