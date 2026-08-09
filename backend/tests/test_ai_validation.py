"""Strict validation: schema coercion, bounding, anti-hallucination."""
import pytest

from app.services.ai.errors import AIValidationError
from app.services.ai.validation import parse_response


def _ctx():
    return {
        "mitre": [{"technique_id": "T1059.001"}, {"technique_id": "T1071"}],
        "findings": [{"mitre": "T1059.001"}],
    }


def _valid_raw():
    return """```json
    {
        "executive_summary": "summary here",
        "technical_summary": "tech",
        "threat_explanation": "explain",
        "key_findings": ["a", "b"],
        "risk_factors": ["c"],
        "mitre_explanation": [
            {"technique_id": "T1059.001", "explanation": "ps"},
            {"technique_id": "T9999", "explanation": "invented"}
        ],
        "recommendations": [{"priority": "high", "action": "block"}],
        "confidence": 80,
        "business_impact": ["cost"],
        "limitations": ["static only"]
    }
    ```"""


def test_valid_fenced_json_parses_and_strips_invented_technique():
    out = parse_response(_valid_raw(), _ctx())
    ids = [m["technique_id"] for m in out["mitre_explanation"]]
    assert ids == ["T1059.001"]  # T9999 dropped, never surfaced


def test_bad_priority_defaults_to_medium():
    raw = '{"recommendations": [{"priority": "critical", "action": "x"}, {"action": "y"}]}'
    out = parse_response(raw, _ctx())
    assert [r["priority"] for r in out["recommendations"]] == ["medium", "medium"]


def test_confidence_clamped():
    assert parse_response('{"confidence": 250}', _ctx())["confidence"] == 100
    assert parse_response('{"confidence": -5}', _ctx())["confidence"] == 0
    assert parse_response('{"confidence": "abc"}', _ctx())["confidence"] == 0


def test_wrong_types_become_empty():
    out = parse_response('{"key_findings": "not-a-list", "risk_factors": 3, "mitre_explanation": null}', _ctx())
    assert out["key_findings"] == []
    assert out["risk_factors"] == []
    assert out["mitre_explanation"] == []


def test_trailing_commas_tolerated():
    raw = '{"executive_summary": "ok", "key_findings": ["a",], "confidence": 10,}'
    assert parse_response(raw, _ctx())["executive_summary"] == "ok"


def test_non_json_rejected():
    with pytest.raises(AIValidationError):
        parse_response("I am not JSON", _ctx())


def test_non_object_rejected():
    with pytest.raises(AIValidationError):
        parse_response("[1, 2, 3]", _ctx())


def test_empty_response_rejected():
    with pytest.raises(AIValidationError):
        parse_response("", _ctx())


def test_sizes_bounded():
    long = '"' + "x" * 1000 + '"'
    raw = '{"key_findings": [' + ",".join(long for _ in range(50)) + ']}'
    out = parse_response(raw, _ctx())
    assert len(out["key_findings"]) <= 8
    assert all(len(k) <= 240 for k in out["key_findings"])


def test_no_iocs_field_survives():
    # even if a model sneaks an "iocs" field in, it must not be in the result
    raw = '{"iocs": [{"type": "ip", "value": "9.9.9.9"}], "confidence": 5}'
    assert "iocs" not in parse_response(raw, _ctx())
