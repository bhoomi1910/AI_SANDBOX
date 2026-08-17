"""Comprehensive dashboard endpoint tests.

Tests create Investigation records directly in the DB (bypassing the upload
endpoint which triggers background analysis threads) for deterministic control.
"""
import json
import hashlib
from datetime import timedelta

import pytest
from sqlalchemy.orm import sessionmaker

from app.models import AnalysisResult, Investigation, Base
from app.models import new_id, utcnow


def _get_session():
    from app.database import engine
    return sessionmaker(bind=engine)


_inv_counter = 9000

def _create_inv(db, **overrides):
    """Create an Investigation record directly."""
    global _inv_counter
    _inv_counter += 1
    inv = Investigation(
        id=new_id(),
        case_id=overrides.get("case_id", f"INV-2026-{_inv_counter:04d}"),
        filename=overrides.get("filename", "test.exe"),
        file_type=overrides.get("file_type", "exe"),
        mime_type=overrides.get("mime_type", ""),
        size_bytes=overrides.get("size_bytes", 1024),
        sha256=overrides.get("sha256", hashlib.sha256(new_id().encode()).hexdigest()),
        md5=overrides.get("md5", "d41d8cd98f00b204"),
        sha1=overrides.get("sha1", "da39a3ee5e6b4b0d"),
        storage_path=overrides.get("storage_path", "/tmp/test"),
        status=overrides.get("status", "queued"),
        progress=overrides.get("progress", 0),
        current_stage=overrides.get("current_stage", "Waiting"),
        severity=overrides.get("severity", "info"),
        risk_score=overrides.get("risk_score", 0),
        malware_family=overrides.get("malware_family", "Pending"),
        classification=overrides.get("classification", "Pending analysis"),
        verdict=overrides.get("verdict", "suspicious"),
        ai_confidence=overrides.get("ai_confidence", 0),
        detections=overrides.get("detections", 0),
        total_engines=overrides.get("total_engines", 0),
        tags=overrides.get("tags_json", "[]"),
        mitre_techniques=overrides.get("mitre_techniques_json", "[]"),
        assigned_to=overrides.get("assigned_to", "Unassigned"),
        submitted_by=overrides.get("submitted_by", "analyst"),
        uploaded_at=overrides.get("uploaded_at", utcnow()),
        completed_at=overrides.get("completed_at", None),
    )
    db.add(inv)
    db.flush()
    return inv


def _store_analysis_result(db, inv_id, payload):
    ar = AnalysisResult(
        id=new_id(),
        investigation_id=inv_id,
        file_sha256=hashlib.sha256(b"test").hexdigest(),
        data=json.dumps(payload),
        created_at=utcnow(),
    )
    db.add(ar)
    db.flush()


def _populate(client):
    """Create 5 test investigations with analysis results. Returns (before, after)."""
    Session = _get_session()

    before = client.get("/api/dashboard/stats").json()["summary"]

    with Session() as db:
        # 1. Completed critical malicious exe
        inv1 = _create_inv(db,
            filename="malware.exe", file_type="exe", status="completed",
            severity="critical", verdict="malicious", risk_score=95,
            malware_family="Emotet", detections=60, total_engines=72,
            mitre_techniques_json=json.dumps(["T1055", "T1071", "T1547"]),
            completed_at=utcnow(),
        )
        _store_analysis_result(db, inv1.id, {
            "fileType": "exe", "family": "pe",
            "static": {"yara": [
                {"rule": "Emotet_Loader", "description": "Emotet", "severity": "high", "tags": [], "author": "test"},
                {"rule": "Packed_PE", "description": "Packed", "severity": "medium", "tags": [], "author": "test"},
                {"rule": "Emotet_Loader", "description": "Emotet", "severity": "high", "tags": [], "author": "test"},
            ]},
            "iocs": [
                {"id": "ioc-0001", "type": "ip", "value": "192.168.1.100", "severity": "medium", "confidence": 0.8, "sources": [], "count": 1, "mitre_techniques": []},
                {"id": "ioc-0002", "type": "url", "value": "http://evil.com/payload", "severity": "medium", "confidence": 0.9, "sources": [], "count": 1, "mitre_techniques": ["T1071"]},
                {"id": "ioc-0003", "type": "domain", "value": "c2.evil.com", "severity": "low", "confidence": 0.75, "sources": [], "count": 1, "mitre_techniques": []},
                {"id": "ioc-0004", "type": "hash", "value": "abc123", "severity": "medium", "confidence": 0.85, "sources": [], "count": 1, "mitre_techniques": []},
            ],
            "mitre": [
                {"technique_id": "T1055", "technique": "Process Injection", "tactic": "Defense Evasion", "confidence": 0.9, "severity": "high", "source_modules": [], "findings": [], "evidence": []},
                {"technique_id": "T1071", "technique": "Application Layer Protocol", "tactic": "Command and Control", "confidence": 0.8, "severity": "medium", "source_modules": [], "findings": [], "evidence": []},
            ],
        })

        # 2. Completed high suspicious pdf
        inv2 = _create_inv(db,
            filename="phish.pdf", file_type="pdf", status="completed",
            severity="high", verdict="suspicious", risk_score=75,
            malware_family="Unknown", mitre_techniques_json=json.dumps(["T1566", "T1204"]),
            completed_at=utcnow(),
        )
        _store_analysis_result(db, inv2.id, {
            "fileType": "pdf", "family": "pdf",
            "static": {"yara": [
                {"rule": "PDF_Phishing", "description": "Phishing PDF", "severity": "high", "tags": [], "author": "test"},
            ]},
            "iocs": [
                {"id": "ioc-0005", "type": "url", "value": "http://phish.com/login", "severity": "medium", "confidence": 0.8, "sources": [], "count": 1, "mitre_techniques": []},
                {"id": "ioc-0006", "type": "domain", "value": "phish.com", "severity": "low", "confidence": 0.7, "sources": [], "count": 1, "mitre_techniques": []},
            ],
            "mitre": [
                {"technique_id": "T1566", "technique": "Phishing", "tactic": "Initial Access", "confidence": 0.85, "severity": "high", "source_modules": [], "findings": [], "evidence": []},
            ],
        })

        # 3. Completed low clean docx
        _create_inv(db,
            filename="resume.docx", file_type="docx", status="completed",
            severity="low", verdict="clean", risk_score=5,
            malware_family="None", detections=0, total_engines=68,
            mitre_techniques_json=json.dumps([]),
            completed_at=utcnow(),
        )

        # 4. Queued exe
        _create_inv(db,
            filename="pending.exe", file_type="exe", status="queued",
            severity="info",
        )

        # 5. Failed dll
        _create_inv(db,
            filename="broken.dll", file_type="dll", status="failed",
            severity="info",
        )

        db.commit()

    after = client.get("/api/dashboard/stats").json()
    return before, after


# ─── Structural tests (always valid) ────────────────────────────

def test_response_has_all_keys(client):
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    stats = resp.json()
    for key in ("summary", "statusDistribution", "severityBreakdown",
                "verdictDistribution", "fileTypeDistribution", "malwareFamilies",
                "timeline", "recentInvestigations", "highRiskInvestigations",
                "iocStatistics", "yaraStatistics", "mitreStatistics",
                "systemHealth", "note"):
        assert key in stats, f"Missing key: {key}"


def test_summary_structure(client):
    resp = client.get("/api/dashboard/stats")
    summary = resp.json()["summary"]
    for field in ("total", "active", "completed", "failed", "pending", "today"):
        assert field in summary
        assert isinstance(summary[field], int)
        assert summary[field] >= 0


def test_timeline_always_30_days(client):
    resp = client.get("/api/dashboard/stats")
    timeline = resp.json()["timeline"]
    assert len(timeline) == 30
    for day in timeline:
        assert "date" in day
        assert isinstance(day["count"], int)


def test_ioc_statistics_structure(client):
    resp = client.get("/api/dashboard/stats")
    iocs = resp.json()["iocStatistics"]
    assert isinstance(iocs["total"], int)
    assert isinstance(iocs["by_type"], list)


def test_yara_statistics_structure(client):
    resp = client.get("/api/dashboard/stats")
    yara = resp.json()["yaraStatistics"]
    for field in ("total_matches", "investigations_with_matches", "top_rules"):
        assert field in yara


def test_mitre_statistics_structure(client):
    resp = client.get("/api/dashboard/stats")
    mitre = resp.json()["mitreStatistics"]
    for field in ("total_techniques", "unique_techniques", "investigations_with_mitre", "top_techniques", "top_tactics"):
        assert field in mitre


def test_system_health_structure(client):
    resp = client.get("/api/dashboard/stats")
    health = resp.json()["systemHealth"]
    assert isinstance(health, list)
    assert len(health) > 0
    for h in health:
        assert "name" in h
        assert "status" in h


# ─── Relative tests (check delta from before population) ────────

def test_populated_summary(client):
    before, after = _populate(client)
    s = after["summary"]
    assert s["total"] == before["total"] + 5
    assert s["completed"] == before["completed"] + 3
    assert s["active"] == before["active"] + 1  # queued
    assert s["failed"] == before["failed"] + 1


def test_status_distribution(client):
    _, after = _populate(client)
    dist = after["statusDistribution"]
    assert dist.get("completed", 0) >= 3
    assert dist.get("queued", 0) >= 1
    assert dist.get("failed", 0) >= 1


def test_severity_distribution(client):
    _, after = _populate(client)
    sev = after["severityBreakdown"]
    names = {s["name"] for s in sev}
    assert "Critical" in names
    assert "High" in names
    assert "Low" in names
    critical = next(s for s in sev if s["name"] == "Critical")
    assert critical["value"] >= 1


def test_verdict_distribution(client):
    _, after = _populate(client)
    vd = after["verdictDistribution"]
    names = {v["name"] for v in vd}
    assert "Malicious" in names
    assert "Suspicious" in names
    assert "Clean" in names


def test_file_type_distribution(client):
    _, after = _populate(client)
    ft = after["fileTypeDistribution"]
    names = {f["name"] for f in ft}
    assert "exe" in names
    assert "pdf" in names
    assert "docx" in names
    assert "dll" in names


def test_malware_families(client):
    _, after = _populate(client)
    fams = after["malwareFamilies"]
    names = {f["name"] for f in fams}
    assert "Emotet" in names
    assert "Unknown" not in names
    assert "None" not in names
    assert "Pending" not in names


def test_ioc_statistics(client):
    _, after = _populate(client)
    iocs = after["iocStatistics"]
    assert iocs["total"] >= 6
    types = {t["type"] for t in iocs["by_type"]}
    assert "ip" in types
    assert "url" in types
    assert "domain" in types
    assert "hash" in types


def test_yara_statistics(client):
    _, after = _populate(client)
    yara = after["yaraStatistics"]
    assert yara["total_matches"] >= 4
    assert yara["investigations_with_matches"] >= 2
    rules = {r["rule"] for r in yara["top_rules"]}
    assert "Emotet_Loader" in rules


def test_mitre_statistics(client):
    _, after = _populate(client)
    mitre = after["mitreStatistics"]
    assert mitre["total_techniques"] >= 5
    assert mitre["unique_techniques"] >= 4
    assert mitre["investigations_with_mitre"] >= 2
    techs = {t["technique"] for t in mitre["top_techniques"]}
    assert "T1055" in techs
    assert "T1566" in techs


def test_high_risk_investigations(client):
    _, after = _populate(client)
    hr = after["highRiskInvestigations"]
    assert len(hr) >= 2
    severities = {inv["severity"] for inv in hr}
    assert severities <= {"critical", "high"}


def test_timeline_has_data(client):
    _, after = _populate(client)
    timeline = after["timeline"]
    assert any(t["count"] > 0 for t in timeline)


def test_no_exceptions_with_corrupt_json(client):
    Session = _get_session()
    with Session() as db:
        inv = _create_inv(db, filename="corrupt.exe", status="completed")
        ar = AnalysisResult(
            id=new_id(),
            investigation_id=inv.id,
            file_sha256="deadbeef",
            data="NOT VALID JSON{{{",
            created_at=utcnow(),
        )
        db.add(ar)
        db.commit()

    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    assert "summary" in resp.json()


def test_no_storage_path_exposed(client):
    resp = client.get("/api/dashboard/stats")
    text = json.dumps(resp.json())
    assert "storage_path" not in text.lower()
