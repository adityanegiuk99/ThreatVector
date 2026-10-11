-- Veylix database bootstrap (runs automatically in the official postgres container).
-- Alembic migrations are the source of truth for schema changes after this.

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
