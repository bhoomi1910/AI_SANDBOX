"""Structured logging + request-ID propagation.

Unit tests cover the formatter/filter/generator directly; integration tests
assert that a real request carries a stable X-Request-ID from response headers
into error bodies and access logs.
"""
import logging

from app.logging_config import (
    LOG_FORMAT,
    RequestIdFilter,
    SafeFormatter,
    generate_request_id,
    request_id_var,
)


# --- unit: formatter / filter / generator --------------------------------

def _format(record: logging.LogRecord) -> str:
    return SafeFormatter(LOG_FORMAT).format(record)


def test_safe_formatter_defaults_missing_fields():
    record = logging.LogRecord("my.logger", logging.INFO, "x.py", 1, "sample stored", None, None)
    line = _format(record)
    assert "level=INFO" in line
    assert "logger=my.logger" in line
    assert "request_id=-" in line
    assert "investigation_id=-" in line
    assert "analyzer=-" in line
    assert "event=sample stored" in line


def test_safe_formatter_preserves_extra_fields():
    record = logging.LogRecord("my.logger", logging.INFO, "x.py", 1, "analysis done", None, None)
    record.investigation_id = "INV-2026-1234"
    record.analyzer = "static"
    line = _format(record)
    assert "investigation_id=INV-2026-1234" in line
    assert "analyzer=static" in line


def test_request_id_filter_reads_contextvar():
    token = request_id_var.set("req-abc-123")
    try:
        record = logging.LogRecord("my.logger", logging.ERROR, "x.py", 1, "boom", None, None)
        assert RequestIdFilter().filter(record) is True
        assert record.request_id == "req-abc-123"
    finally:
        request_id_var.reset(token)


def test_request_id_filter_defaults_outside_request():
    record = logging.LogRecord("my.logger", logging.INFO, "x.py", 1, "startup", None, None)
    RequestIdFilter().filter(record)
    assert record.request_id == "-"


def test_generate_request_id_honors_safe_value():
    assert generate_request_id({"X-Request-ID": "abc-123.def_GHI"}) == "abc-123.def_GHI"


def test_generate_request_id_rejects_unsafe_values():
    bad = [
        {"X-Request-ID": "abc def"},          # whitespace
        {"X-Request-ID": "a;b"},              # punctuation not in -._
        {"X-Request-ID": "x" * 65},           # over 64 chars
        {"X-Request-ID": "../../etc/passwd"},  # path traversal chars
        {"X-Request-ID": "\n"},
    ]
    for headers in bad:
        assert generate_request_id(headers) != headers["X-Request-ID"]


def test_generate_request_id_returns_uuid_hex():
    rid = generate_request_id()
    assert len(rid) == 32 and all(c in "0123456789abcdef" for c in rid)


# --- integration: request-level propagation --------------------------------

def test_response_carries_generated_request_id(client):
    resp = client.get("/api/health")
    rid = resp.headers.get("X-Request-ID")
    assert rid and len(rid) == 32 and all(c in "0123456789abcdef" for c in rid)


def test_client_provided_request_id_is_honored(client):
    resp = client.get("/api/health", headers={"X-Request-ID": "client-trace-42"})
    assert resp.headers["X-Request-ID"] == "client-trace-42"


def test_unsafe_client_request_id_is_replaced(client):
    resp = client.get("/api/health", headers={"X-Request-ID": "bad id ; drop"})
    rid = resp.headers["X-Request-ID"]
    assert rid != "bad id ; drop"
    assert len(rid) == 32


def test_error_response_includes_matching_request_id(client):
    resp = client.get("/api/investigations/nope-12345")
    assert resp.status_code == 404
    assert resp.json()["request_id"] == resp.headers["X-Request-ID"]


def test_validation_error_includes_request_id(client):
    resp = client.post("/api/samples/upload")
    assert resp.status_code == 422
    assert resp.json()["request_id"] == resp.headers["X-Request-ID"]


def test_request_logged_with_request_id(client, caplog):
    with caplog.at_level(logging.INFO):
        resp = client.get("/api/health")
    rid = resp.headers["X-Request-ID"]
    assert rid
    hits = [r for r in caplog.records if r.getMessage().startswith("request GET /api/health")]
    assert hits, "access-log line missing from caplog"