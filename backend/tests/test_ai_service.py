"""AI service: completed / unavailable / error outcomes, provenance attached."""
from app.services.ai import AIProvider, AIUnavailable, AIValidationError
from app.services.ai.service import run_ai_analysis


class FakeProvider(AIProvider):
    name = "fake"

    def __init__(self, raw=None, mode="ok"):
        self.raw = raw
        self.mode = mode

    def label(self):
        return "ollama/fake"

    def select_model(self):
        if self.mode == "down":
            raise AIUnavailable("cannot reach Ollama")
        return "fake-model"

    def generate(self, prompt, model):
        if self.mode == "down":
            raise AIUnavailable("cannot reach Ollama")
        if self.mode == "garbage":
            raise AIValidationError("not a JSON object")
        return self.raw or ('{"executive_summary": "s", "technical_summary": "t", '
                            '"threat_explanation": "e", "key_findings": ["a"], '
                            '"risk_factors": ["b"], "mitre_explanation": '
                            '[{"technique_id": "T1071", "explanation": "ok"}], '
                            '"recommendations": [{"priority": "high", "action": "x"}], '
                            '"confidence": 75, "business_impact": ["i"], '
                            '"limitations": ["static only"]}')


def _ctx():
    return {
        "file": {"filename": "f", "file_type": "x", "family": "script", "sha256": "h", "size": 1},
        "classification": "Suspicious",
        "score": {"total": 30, "severity": "high", "verdict": "suspicious",
                  "breakdown": [{"category": "c", "points": 15}]},
        "findings": [{"severity": "high", "title": "t", "confidence": 0.8,
                      "module": "m", "mitre": "T1059.001"}],
        "iocs": [{"type": "url", "value": "http://x.y/z", "severity": "medium", "confidence": 0.8}],
        "mitre": [{"technique_id": "T1071", "technique": "App", "tactic": "C2", "confidence": 0.8}],
        "evidence": [{"category": "network", "value": "http://x.y/z"}],
        "static": {"entropy": 6.0, "yara": []},
    }


def test_completed_result_carries_structured_fields_and_provenance():
    res = run_ai_analysis(_ctx(), FakeProvider())
    assert res["status"] == "completed"
    for field in ("executive_summary", "technical_summary", "threat_explanation",
                  "key_findings", "risk_factors", "mitre_explanation",
                  "recommendations", "confidence", "limitations"):
        assert field in res
    assert res["provenance"]["findings_used"] == 1
    assert res["provenance"]["iocs_used"] == 1
    assert res["provenance"]["mitre_used"] == 1
    assert res["score_total"] == 30
    assert res["verdict"] == "suspicious"
    assert res["model"] == "fake-model"


def test_unavailable_returns_status_with_deterministic_note():
    res = run_ai_analysis(_ctx(), FakeProvider(mode="down"))
    assert res["status"] == "unavailable"
    assert "deterministic" in res["note"].lower()
    assert "findings" not in res


def test_validation_failure_returns_error():
    res = run_ai_analysis(_ctx(), FakeProvider(mode="garbage"))
    assert res["status"] == "error"
    assert "rejected" in res["note"].lower()


def test_never_blocks_and_never_raises():
    # even a provider raising is converted into a structured response
    class Boom(FakeProvider):
        def generate(self, prompt, model):
            raise RuntimeError("unexpected")

    res = run_ai_analysis(_ctx(), Boom())
    assert res["status"] in ("error", "unavailable")
