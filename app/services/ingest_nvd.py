"""Runnable alias: python -m app.services.ingest_nvd"""
from app.services.ingest_all import run_source

if __name__ == "__main__":
    run_source("nvd", lookback_days=30, full=False)
