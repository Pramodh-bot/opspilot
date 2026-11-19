"""Application settings, loaded from environment variables (12-factor)."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "OpsPilot"
    environment: str = "development"  # development | production
    log_level: str = "INFO"
    # False in production compose: the app DB role has no DDL rights; `python -m app.migrate` creates the schema.
    auto_create_schema: bool = True

    database_url: str = "postgresql+psycopg://opspilot_app:opspilot_app@localhost:5432/opspilot"

    # --- auth ---
    jwt_secret: str = Field(default="dev-only-change-me-dev-only-change-me", min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    bcrypt_rounds: int = Field(default=12, ge=4, le=16)

    # first-run bootstrap admin (only created if the users table is empty)
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    # token required by the Alertmanager webhook (X-Webhook-Token header)
    webhook_token: str | None = None

    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    # --- agent / LLM ---
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 20.0
    llm_failure_threshold: int = 3
    llm_recovery_seconds: float = 30.0
    rag_top_k: int = 3
    executor_mode: str = "simulate"  # simulate | disabled

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.is_production and settings.jwt_secret.startswith("dev-only"):
        raise RuntimeError("JWT_SECRET must be set to a strong random value in production")
    return settings
