"""Unit tests for the report context builder (service.py).

The context builder must consume persisted results without recomputing them,
must never call the AI, and must label AI vs deterministic content clearly.
"""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="report-unit-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 't.db'}"
os.environ["UPLOAD_DIR"] = str(_TMP / "uploads")
os.environ["REPORT_DIR"] = str(_TMP / "reports")

import pytest  # noqa: E402

from app.database import init_db, SessionLocal  # noqa: E402
from app.models import Investigation, new_id, utcnow  # noqa: E402
from app.services.reports import AnalysisIncompleteError, generate_report_pdf  # noqa: E402
from app.services.reports.service import build_context  # noqa: E402


@pytest.fixture(scope="module")
def db():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


def _inv(db, **overrides):
    fields = dict(
        id=new_id(), case_id="INV-2099-0001", filename="sample.ps1", file_type="script",
        mime_type="text/plain", size_bytes=10, sha256="1" * 64, md5="2" * 32,
        sha1="3" * 40, storage_path="x", status="completed", severity="high",
        risk_score=40, classification="Suspicious - downloader", verdict="suspicious",
        uploaded_at=utcnow(),
    )
    fields.update(overrides)
    return Investigation(**fields)


def _payload():
    return {
        "fileType": "script", "family": "script", "modules": {"script": "ok"},
        "static": {"entropy": 5.0, "strings": [], "yara": []},
        "findings": [
            {"severity": "high", "category": "downloader", "title": "Downloads",
             "detail": "dl", "confidence": 0.8, "mitre": "T1105", "module": "script"},
        ],
        "score": {"total": 40, "severity": "high", "verdict": "suspicious",
                  "breakdown": [], "method": "w"},
        "evidence": [], "iocs": [], "mitre": [],
        "classification": "Suspicious - downloader",
    }


def test_context_never_recomputes_analysis(db):
    inv = _inv(db)
    payload = _payload()
    payload["score"] = {"total": 42, "severity": "critical", "verdict": "malicious",
                        "breakdown": [], "method": "w"}
    ctx = build_context(inv, payload)
    # values must come from the persisted payload/row, not recalculated
    assert ctx["score_total"] == 42
    assert ctx["severity"] == inv.severity
    assert ctx["verdict"] == inv.verdict
    assert ctx["sha256"] == inv.sha256
    assert ctx["md5"] == inv.md5


def test_deterministic_summary_when_ai_absent(db):
    inv = _inv(db)
    ctx = build_context(inv, _payload())
    assert ctx["executive_label"] == "deterministic"
    assert "AI-assisted" in ctx["executive_summary"]  # clearly labelled
    assert "unavailable" in ctx["executive_summary"]
    assert ctx["ai"] is None
    assert ctx["ai_label"] is None


def test_ai_content_consumed_when_cached_completed(db):
    inv = _inv(db)
    payload = _payload()
    payload["ai"] = {
        "status": "completed", "provider": "ollama/qwen3:4b", "model": "qwen3:4b",
        "executive_summary": "Validated AI summary text.",
        "recommendations": [{"priority": "high", "action": "Quarantine host"}],
        "confidence": 90,
    }
    ctx = build_context(inv, payload)
    assert ctx["executive_label"] == "ai"
    assert ctx["executive_summary"] == "Validated AI summary text."
    assert ctx["ai_label"] == "ollama/qwen3:4b / qwen3:4b"
    assert any(r["source"] == "ai" for r in ctx["recommendations"])


def test_recommendations_derived_from_findings(db):
    inv = _inv(db)
    ctx = build_context(inv, _payload())
    recs = [r for r in ctx["recommendations"] if r["source"] == "deterministic"]
    assert recs, "downloader finding must yield a deterministic recommendation"
    assert any("download" in r["action"].lower() for r in recs)


def test_generate_raises_incomplete_when_no_payload(db):
    inv = _inv(db)
    db.add(inv)
    db.commit()
    with pytest.raises(AnalysisIncompleteError):
        generate_report_pdf(inv.id, db)


def test_generate_raises_not_found_for_missing(db):
    with pytest.raises(Exception) as exc:
        generate_report_pdf("missing-id", db)
    assert type(exc.value).__name__ == "ReportNotFoundError"
