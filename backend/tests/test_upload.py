import hashlib

SAMPLE = b"MZ\x90\x00" + b"FAKE-SAMPLE-CONTENT" * 64


def test_valid_upload_creates_investigation(client):
    resp = client.post(
        "/api/samples/upload",
        files={"file": ("invoice_scan.exe", SAMPLE, "application/octet-stream")},
    )
    assert resp.status_code == 201
    body = resp.json()
    inv = body["investigation"]

    assert body["message"] == "Sample received and queued for analysis"
    assert inv["caseId"].startswith("INV-")
    assert inv["status"] == "queued"
    assert inv["progress"] == 0
    assert inv["sample"]["filename"] == "invoice_scan.exe"
    assert inv["sample"]["fileType"] == "exe"
    assert inv["sample"]["size"] == len(SAMPLE)
    assert inv["sample"]["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    assert inv["sample"]["md5"] == hashlib.md5(SAMPLE).hexdigest()
    assert inv["sample"]["sha1"] == hashlib.sha1(SAMPLE).hexdigest()


def test_upload_roundtrip_investigation_list_and_get(client):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("sample.pdf", b"%PDF-1.4 test", "application/pdf")},
    ).json()["investigation"]

    listed = client.get("/api/investigations").json()
    assert any(i["id"] == created["id"] for i in listed)

    detail = client.get(f"/api/investigations/{created['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == created["id"]
    assert detail.json()["sample"]["filename"] == "sample.pdf"


def test_upload_empty_file_rejected(client):
    resp = client.post(
        "/api/samples/upload",
        files={"file": ("empty.bin", b"", "application/octet-stream")},
    )
    assert resp.status_code == 422


def test_upload_oversize_file_rejected(client):
    big = b"A" * (2 * 1024 * 1024)
    resp = client.post(
        "/api/samples/upload",
        files={"file": ("big.bin", big, "application/octet-stream")},
    )
    assert resp.status_code == 413


def test_upload_path_traversal_sanitised(client):
    resp = client.post(
        "/api/samples/upload",
        files={"file": ("..\\..\\evil.exe", SAMPLE, "application/octet-stream")},
    )
    assert resp.status_code == 201
    assert resp.json()["investigation"]["sample"]["filename"] == "evil.exe"


def test_status_filter(client):
    resp = client.get("/api/investigations?status=completed")
    assert resp.status_code == 200
    assert all(i["status"] == "completed" for i in resp.json())


def test_deepdive_endpoints_return_pending(client):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("x.dll", SAMPLE, "application/octet-stream")},
    ).json()["investigation"]
    inv_id = created["id"]

    assert client.get(f"/api/investigations/{inv_id}/static").status_code == 200
    assert client.get(f"/api/investigations/{inv_id}/threat-intel").status_code == 200
    assert client.get(f"/api/investigations/{inv_id}/mitre").status_code == 200
    assert client.get(f"/api/investigations/{inv_id}/ai").status_code == 200
