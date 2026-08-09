"""Prompt builder: deterministic output only, constraints enforced in the text."""
from app.services.ai.prompt import build_prompt


def _ctx():
    return {
        "file": {"filename": "evil.ps1", "file_type": "PowerShell script",
                 "family": "script", "sha256": "a" * 64, "size": 42},
        "classification": "Suspicious — powershell, downloader",
        "score": {"total": 45, "severity": "high", "verdict": "suspicious",
                  "breakdown": [{"category": "downloader", "points": 15},
                                {"category": "powershell", "points": 15}]},
        "findings": [{"severity": "high", "title": "Suspicious PowerShell",
                      "confidence": 0.85, "module": "detection", "mitre": "T1059.001",
                      "detail": "encoded command", "evidence": "powershell -enc"}],
        "iocs": [{"type": "url", "value": "http://evil.example/p", "severity": "medium",
                  "confidence": 0.8}],
        "mitre": [{"technique_id": "T1059.001", "technique": "PowerShell",
                   "tactic": "Execution", "confidence": 0.85}],
        "evidence": [{"category": "network", "value": "http://evil.example/p"},
                     {"category": "execution", "value": "powershell"}],
        "static": {"entropy": 6.1, "yara": [{"rule": "R1"}]},
    }


def test_prompt_contains_deterministic_inputs():
    p = build_prompt(_ctx())
    assert "evil.ps1" in p
    assert "T1059.001" in p
    assert "http://evil.example/p" in p
    assert "45" in p and "suspicious" in p
    assert "PowerShell" in p


def test_prompt_forbids_invention():
    p = build_prompt(_ctx())
    assert "Never invent" in p
    assert "ids ONLY from the list below" in p
    assert "never add to this list" in p
    assert "authoritative" in p


def test_prompt_requires_json_schema_fields():
    p = build_prompt(_ctx())
    for field in ("executive_summary", "technical_summary", "threat_explanation",
                  "key_findings", "risk_factors", "mitre_explanation",
                  "recommendations", "confidence", "limitations"):
        assert field in p


def test_prompt_handles_empty_context():
    p = build_prompt({})
    assert p  # must not raise, and still contains the rules
    assert "You are a malware-analysis assistant" in p


def test_prompt_limits_findings_and_iocs():
    ctx = _ctx()
    ctx["findings"] = [dict(f) for f in ctx["findings"]] * 60
    ctx["iocs"] = [dict(i) for i in ctx["iocs"]] * 60
    p = build_prompt(ctx)
    # bounded: at most 40 findings + 30 iocs lines are rendered
    assert p.count("\n- [") <= 40
    assert p.count("http://evil.example/p") <= 30
