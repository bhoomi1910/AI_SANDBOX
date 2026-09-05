"""Structured logging with per-request request IDs.

Design (kept deliberately small):

- ``request_id_var`` is a ``contextvars.ContextVar`` populated by the request
  middleware in ``main.py``. Any logger call inside a request handler picks up
  the active request ID automatically via :class:`RequestIdFilter`.
- :class:`SafeFormatter` emits a stable ``key=value`` line and tolerates log
  records that do not carry the optional fields (request_id, investigation_id,
  analyzer) — it substitutes ``-`` so a plain ``logger.info(...)`` never breaks.
- :func:`setup_logging` is idempotent and safe to call from the app lifespan.

No secrets, query strings or file contents are ever logged.
"""
from __future__ import annotations

import contextvars
import logging
import sys

# Active request ID for the current request (set by the middleware).
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_SANITIZED_REQUEST_ID = "-"  # used when logging occurs outside a request scope

LOG_FORMAT = (
    "%(asctime)s level=%(levelname)s logger=%(name)s "
    "request_id=%(request_id)s investigation_id=%(investigation_id)s "
    "analyzer=%(analyzer)s event=%(message)s"
)

_OPTIONAL_FIELDS = {
    "request_id": "-",
    "investigation_id": "-",
    "analyzer": "-",
}


class SafeFormatter(logging.Formatter):
    """Formats structured ``key=value`` log lines, defaulting missing fields."""

    def format(self, record: logging.LogRecord) -> str:
        for field, default in _OPTIONAL_FIELDS.items():
            if not hasattr(record, field):
                setattr(record, field, default)
        return super().format(record)


class RequestIdFilter(logging.Filter):
    """Attaches the current request ID to every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_var.get() or _SANITIZED_REQUEST_ID
        return True


def setup_logging(level: str = "INFO") -> None:
    """Configure the root logger with the structured formatter.

    Idempotent: repeated calls (e.g. reloads) replace the handlers instead of
    stacking duplicates.
    """
    configured_level = (level or "INFO").upper()
    root = logging.getLogger()
    root.setLevel(configured_level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeFormatter(LOG_FORMAT))
    handler.addFilter(RequestIdFilter())

    root.handlers = [handler]

    # Let libraries keep their default levels while still using our format.
    logging.getLogger("uvicorn").setLevel("WARNING")
    logging.getLogger("sqlalchemy.engine").setLevel("WARNING")


def generate_request_id(request_headers: dict | None = None) -> str:
    """Return a request ID: a validated client-provided value or a new UUID."""
    import uuid as _uuid

    if request_headers:
        provided = request_headers.get("x-request-id") or request_headers.get("X-Request-ID")
        if provided:
            cleaned = str(provided).strip()
            if cleaned and len(cleaned) <= 64 and all(
                c.isalnum() or c in "-._" for c in cleaned
            ):
                return cleaned
    return _uuid.uuid4().hex