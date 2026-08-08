"""Application configuration loaded from environment variables."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root = backend/ (parent of the app package).
BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AI-Powered Intelligent Sandbox"
    api_version: str = "v1"
    environment: str = "development"

    # Database — SQLite by default so the prototype runs with zero external
    # services. Point at PostgreSQL in production.
    database_url: str = f"sqlite:///{BACKEND_DIR / 'aegis.db'}"

    # Infrastructure (optional in prototype)
    redis_url: str = "redis://localhost:6379/0"

    # AI (Phase 4) — Ollama, provider-configurable. Defaults are safe when
    # Ollama is not installed: analysis must never depend on the AI.
    ollama_url: str = "http://localhost:11434"
    ai_model: str = "qwen3"

    # File handling
    max_upload_size: int = 100 * 1024 * 1024  # 100 MiB
    upload_dir: str = str(BACKEND_DIR.parent / "uploads")
    report_dir: str = str(BACKEND_DIR.parent / "reports")

    # CORS
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def upload_dir_path(self) -> Path:
        return Path(self.upload_dir)

    @property
    def report_dir_path(self) -> Path:
        return Path(self.report_dir)

    @property
    def ai_provider_label(self) -> str:
        return f"ollama/{self.ai_model} (not configured)"


@lru_cache
def get_settings() -> Settings:
    return Settings()
