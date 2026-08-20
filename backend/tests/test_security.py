"""Adversarial test fixtures — safe test data that simulates malicious characteristics.

These tests verify that the analysis pipeline handles edge cases gracefully
without creating or executing real malware.
"""
import pytest


# ── Empty / malformed file uploads ──────────────────────────────────────

class TestEmptyAndMalformedUploads:
    def test_empty_file_rejected(self, client):
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("empty.exe", b"", "application/octet-stream")},
        )
        assert resp.status_code == 422

    def test_oversized_file_rejected(self, client):
        huge = b"MZ" + b"\x00" * (1024 * 1024 + 1)
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("huge.exe", huge, "application/octet-stream")},
        )
        assert resp.status_code == 413

    def test_null_byte_in_filename(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("malware\x00.exe", content, "application/octet-stream")},
        )
        if resp.status_code == 201:
            inv = resp.json()["investigation"]
            assert "\x00" not in inv["sample"]["filename"]

    def test_path_traversal_filename(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("../../etc/passwd", content, "application/octet-stream")},
        )
        if resp.status_code == 201:
            inv = resp.json()["investigation"]
            assert "/" not in inv["sample"]["filename"]
            assert ".." not in inv["sample"]["filename"]


# ── Filename edge cases ────────────────────────────────────────────────

class TestFilenameSanitization:
    def test_long_filename_truncated(self, client):
        long_name = "a" * 500 + ".exe"
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp = client.post(
            "/api/samples/upload",
            files={"file": (long_name, content, "application/octet-stream")},
        )
        if resp.status_code == 201:
            inv = resp.json()["investigation"]
            assert len(inv["sample"]["filename"]) <= 120

    def test_unicode_filename_sanitized(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("Привет.exe", content, "application/octet-stream")},
        )
        if resp.status_code == 201:
            inv = resp.json()["investigation"]
            assert inv["sample"]["filename"]

    def test_only_dots_filename(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp = client.post(
            "/api/samples/upload",
            files={"file": ("............", content, "application/octet-stream")},
        )
        if resp.status_code == 201:
            inv = resp.json()["investigation"]
            assert inv["sample"]["filename"]


# ── API endpoint security ──────────────────────────────────────────────

class TestAPISecurity:
    def test_health_no_database_url(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "database" not in data
        assert "components" in data

    def test_health_components_present(self, client):
        resp = client.get("/api/health")
        data = resp.json()
        assert "api" in data["components"]
        assert "static_analysis" in data["components"]
        assert "ai_engine" in data["components"]

    def test_invalid_investigation_id_returns_404(self, client):
        resp = client.get("/api/investigations/nonexistent-id-12345")
        assert resp.status_code == 404

    def test_invalid_patch_verdict_returns_400(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        upload_resp = client.post(
            "/api/samples/upload",
            files={"file": ("test_sec1.exe", content, "application/octet-stream")},
        )
        if upload_resp.status_code == 201:
            inv_id = upload_resp.json()["investigation"]["id"]
            resp = client.patch(
                f"/api/investigations/{inv_id}",
                json={"verdict": "definitely-malicious"},
            )
            assert resp.status_code == 400

    def test_invalid_severity_returns_400(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        upload_resp = client.post(
            "/api/samples/upload",
            files={"file": ("test_sec2.exe", content, "application/octet-stream")},
        )
        if upload_resp.status_code == 201:
            inv_id = upload_resp.json()["investigation"]["id"]
            resp = client.patch(
                f"/api/investigations/{inv_id}",
                json={"severity": "extreme"},
            )
            assert resp.status_code == 400

    def test_security_headers_present(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "Referrer-Policy" in resp.headers

    def test_closure_notes_length_limited(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        upload_resp = client.post(
            "/api/samples/upload",
            files={"file": ("test_sec3.exe", content, "application/octet-stream")},
        )
        if upload_resp.status_code == 201:
            inv_id = upload_resp.json()["investigation"]["id"]
            long_notes = "A" * 5000
            resp = client.patch(
                f"/api/investigations/{inv_id}",
                json={"closureNotes": long_notes, "resolution": "true-positive"},
            )
            if resp.status_code == 200:
                assert len(resp.json()["closureNotes"]) <= 2000


# ── Duplicate SHA handling ─────────────────────────────────────────────

class TestDuplicateSHA:
    def test_duplicate_upload_creates_separate_investigation(self, client):
        content = b"MZ\x90\x00" + b"\x00" * 100
        resp1 = client.post(
            "/api/samples/upload",
            files={"file": ("dup1.exe", content, "application/octet-stream")},
        )
        resp2 = client.post(
            "/api/samples/upload",
            files={"file": ("dup2.exe", content, "application/octet-stream")},
        )
        if resp1.status_code == 201 and resp2.status_code == 201:
            inv1 = resp1.json()["investigation"]
            inv2 = resp2.json()["investigation"]
            assert inv1["id"] != inv2["id"]
            assert inv1["sample"]["sha256"] == inv2["sample"]["sha256"]


# ── JSON payload handling ──────────────────────────────────────────────

class TestCorruptPayload:
    def test_corrupt_analysis_result_handled(self, client):
        from app.database import get_db
        from app.models import AnalysisResult, Investigation, new_id, utcnow

        db = next(get_db())
        try:
            inv = Investigation(
                id=new_id(),
                case_id=f"SEC-{new_id()[:8]}",
                filename="corrupt_test.exe",
                file_type="exe",
                size_bytes=100,
                sha256="a" * 64,
                md5="b" * 32,
                sha1="c" * 40,
                storage_path="/tmp/corrupt",
                status="completed",
                verdict="suspicious",
                uploaded_at=utcnow(),
            )
            db.add(inv)
            db.flush()
            result = AnalysisResult(
                investigation_id=inv.id,
                file_sha256="a" * 64,
                data="NOT VALID JSON{{{",
            )
            db.add(result)
            db.commit()

            resp = client.get(f"/api/investigations/{inv.id}/static")
            assert resp.status_code == 200
        finally:
            db.close()
