"""Application configuration using pydantic-settings."""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_name: str = "Aegis Sentinel AI"
    app_env: str = "development"
    debug: bool = False
    secret_key: str = Field(..., min_length=32)
    access_token_expire_minutes: int = 60
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/aegis.db"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"

    # Scanner safety
    scanner_max_concurrent_requests: int = 5
    scanner_request_timeout: int = 15
    scanner_max_response_size_kb: int = 512
    scanner_rate_limit_per_domain: int = 10
    scanner_user_agent: str = (
        "Aegis-Sentinel-AI/1.0 (Authorized Security Assessment)"
    )

    # Domain verification
    domain_verification_token_prefix: str = "aegis-verify-"
    domain_verification_file_path: str = "/.well-known/aegis-sentinel-verification.txt"

    # Auth bootstrap
    first_superuser_email: str = "admin@example.com"
    first_superuser_password: str = "ChangeMeImmediately123!"

    # Notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: str = "noreply@example.com"
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # CORS
    cors_origins: List[str] = ["http://localhost:8000", "http://127.0.0.1:8000"]

    # Logging
    log_level: str = "INFO"
    log_json: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            import json
            try:
                return json.loads(v)
            except Exception:
                return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
