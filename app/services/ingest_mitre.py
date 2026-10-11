"""Runnable alias: python -m app.services.ingest_mitre"""
from app.services.ingest_all import run_source

if __name__ == "__main__":
    run_source("attack", lookback_days=30, full=False)
