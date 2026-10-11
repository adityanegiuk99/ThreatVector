"""Runnable alias: python -m app.services.reindex"""
from __future__ import annotations

from app.core.logging_conf import configure_logging

configure_logging()


def main() -> None:
    from app.db.session import SessionLocal
    from app.services.retrieval.embed import index_documents

    db = SessionLocal()
    try:
        result = index_documents(db)
        print(result)
    finally:
        db.close()


if __name__ == "__main__":
    main()
