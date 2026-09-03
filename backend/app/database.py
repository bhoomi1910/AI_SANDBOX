"""Database engine, session and declarative base.

SQLite by default (see Settings.database_url). Tables are created on startup
via init_db(); a small in-app migration step can be layered on later if the
schema evolves.
"""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    """Create tables and directories needed at startup."""
    from app import models  # noqa: F401  (register models on Base)

    Base.metadata.create_all(bind=engine)
    settings.upload_dir_path.mkdir(parents=True, exist_ok=True)
    settings.quarantine_dir_path.mkdir(parents=True, exist_ok=True)
    settings.report_dir_path.mkdir(parents=True, exist_ok=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
