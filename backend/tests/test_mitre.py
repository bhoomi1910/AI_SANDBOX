"""MITRE mapping: only evidence-backed techniques, provenance attached."""
from app.services.detection.mitre import build_mitre, technique_name, tactic_for, supported


def test_catalog_covers_used_categories():
    for tid in ("T1055", "T1059.001", "T1547.001", "T1071", "T1105", "T1027"):
        assert supported(tid)
        assert technique_name(tid) != "Unknown"
        assert tactic_for(tid) != "Unknown"


def test_unknown_technique_not_emitted():
    mitre = build_mitre([{"mitre": "T9999", "category": "x", "confidence": 0.9,
                          "severity": "high", "module": "pe", "title": "x"}])
    assert mitre == []


def test_finding_without_mitre_maps_via_category():
    findings = [{"category": "process-injection", "severity": "high", "confidence": 0.9,
                 "module": "pe", "title": "injection apis", "detail": "VirtualAllocEx"}]
    mitre = build_mitre(findings)
    assert mitre and mitre[0]["technique_id"] == "T1055"
    assert mitre[0]["provenance"]["finding_count"] == 1


def test_confidence_is_max_of_contributing_findings():
    findings = [
        {"mitre": "T1071", "category": "network", "severity": "low", "confidence": 0.7,
         "module": "strings", "title": "a", "evidence": "url"},
        {"mitre": "T1071", "category": "network", "severity": "medium", "confidence": 0.85,
         "module": "yara", "title": "b", "evidence": "yara hit"},
    ]
    mitre = build_mitre(findings)
    m = next(x for x in mitre if x["technique_id"] == "T1071")
    assert m["confidence"] == 0.85
    assert set(m["source_modules"]) == {"strings", "yara"}
