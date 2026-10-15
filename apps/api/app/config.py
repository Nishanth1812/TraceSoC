from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    app_env: str = "development"
    app_name: str = "TraceSOC API"
    database_url: str = "postgresql+psycopg://tracesoc:tracesoc@localhost:5432/tracesoc"
    schema_revision: str = "bootstrap"
    ai_provider: str = "mock"
    ai_api_key: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
