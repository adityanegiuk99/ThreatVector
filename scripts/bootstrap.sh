#!/usr/bin/env bash
# Veylix bootstrap script — from clean checkout to running stack.
# Requirements: python 3.11+, node 20+, docker; Postgres reachable at the
# coordinates in .env (docker-compose makes this automatic).

set -euo pipefail

# 1. Python deps (a venv is recommended)
python -m venv .venv 2>/dev/null || true
if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
pip install --quiet -r requirements.txt

# 2. Environment
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example - update credentials before production."
fi

# 3. Database: start Postgres (+pgvector) alone if no full stack is wanted
if command -v docker >/dev/null 2>&1; then
  docker compose up -d db
  echo "Waiting for Postgres..."
  until docker compose exec -T db pg_isready -U "${POSTGRES_USER:-veylix}" >/dev/null 2>&1; do
    sleep 2
  done
fi

# 4. Migrations
alembic upgrade head

# 5. Ingest public sources (small sample by default; remove --lookback for full)
python -m app.services.ingest_all --source all --lookback-days 30

# 6. Embeddings for retrieval
python -m app.services.reindex || python -c "
from app.db.session import SessionLocal
from app.services.retrieval.embed import index_documents
db = SessionLocal(); index_documents(db); db.close()"

# 7. Train + evaluate ML model (registers artifact + metrics; activates best)
python -m app.services.ml.train

# 8. Done. Start the API:
echo ""
echo "Next: uvicorn app.main:app --reload        (API at http://localhost:8000)"
echo "      cd src && npm install && npm run dev (UI at http://localhost:3000)"
