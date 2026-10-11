"""Veylix application settings."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"

    # Database
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "veylix"
    postgres_user: str = "veylix"
    postgres_password: str = "veylix_dev_password"

    # Security
    veylix_secret_key: str = "change-me-in-prod"
    veylix_signing_key: str = "change-me-in-prod"
    access_token_expire_minutes: int = 60 * 24

    # LLM
    llm_provider: str = "none"  # anthropic | openai | none
    llm_model: str = ""
    llm_api_key: str = ""

    # Retrieval
    embedding_model: str = "all-MiniLM-L6-v2"

    # Ingestion
    veylix_nvd_api_key: str = ""
    veylix_request_timeout: int = 30
    veylix_max_retries: int = 3
    veylix_rate_limit_sleep: float = 1.0

    # Data dirs
    data_dir: str = "data"
    artifacts_dir: str = "artifacts"

    @property
    def sqlalchemy_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_url(self) -> str:
        return self.sqlalchemy_url


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
