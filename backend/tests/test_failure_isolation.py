"""Failure isolation: one bad rule/file/context must never kill the pipeline."""
from app.services.analysis import yara_lite
from app.services.detection import run_detection


MALFORMED = """
rule good_rule {
    meta:
        description = "matches a known string"
        severity = "high"
        mitre = "T1105"
    strings:
        $a = "PING_PAYLOAD"
    condition:
        $a
}

rule broken_hex {
    strings:
        $a = { ZZ 4D ?? }
    condition:
        any of them
}

rule broken_condition {
    strings:
        $a = "SOME_STRING"
    condition:
        this is not valid condition syntax ((
}
"""


def test_malformed_rules_are_skipped_but_good_rule_survives():
    rules = yara_lite.parse_rules(MALFORMED)
    names = [r.name for r in rules]
    assert "good_rule" in names
    assert "broken_hex" not in names
    assert "broken_condition" not in names


def test_matching_failure_is_isolated_per_rule():
    rules = yara_lite.parse_rules(MALFORMED)
    # data matching PING_PAYLOAD should still yield the good rule's hit
    hits = yara_lite.match_file(rules, b"x PING_PAYLOAD y")
    assert [h["rule"] for h in hits] == ["good_rule"]
    assert hits[0]["mitre"] == "T1105"


def test_detection_tolerates_missing_static_sections():
    res = run_detection({"file": {"filename": "x.bin", "extension": ".bin", "family": "other"},
                         "static": {}, "findings": None})
    assert "evidence" in res and "iocs" in res and "graph" in res


def test_detection_tolerates_empty_ctx():
    res = run_detection({})
    assert res["findings"] == []
