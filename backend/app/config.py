"""Application configuration loaded from environment variables."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Aegis Sandbox AI"
    api_version: str = "v1"
    environment: str = "development"

    # Database — defaults to a local SQLite file so the prototype runs with
    # zero external services. Point at PostgreSQL in production.
    database_url: str = "sqlite:///./aegis.db"

    # Infrastructure (optional in prototype)
    redis_url: str = "redis://localhost:6379/0"

    # AI providers — leave blank to use the built-in deterministic simulator.
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    ai_model: str = "aegis-analyst-v2"
    use_real_llm: bool = False

    # Threat-intel API keys (optional — mock data is used when absent)
    virustotal_api_key: str = ""
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""

    # CORS
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
