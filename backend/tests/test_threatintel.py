"""Unit tests for the optional threat-intel enrichment service.

The service must never touch the network unless a provider key is configured,
must never raise into the request path, and must serve cached results on repeat
requests. All provider calls below are monkeypatched — no real API is contacted.
"""
from types import SimpleNamespace

from app.services import threatintel


def _ioc(ioc_type: str, value: str) -> dict:
    return {"type": ioc_type, "value": value, "severity": "low",
            "confidence": 0.8, "sources": [], "count": 1}


def test_configured_providers_empty_without_keys():
    settings = SimpleNamespace(virustotal_api_key="", otx_api_key="  ",
                               abuseipdb_api_key=None)
    assert threatintel.configured_providers(settings) == {}


def test_configured_providers_returns_only_keyed_providers():
    settings = SimpleNamespace(virustotal_api_key="vt-key",
                               otx_api_key="",
                               abuseipdb_api_key="abuse-key")
    providers = threatintel.configured_providers(settings)
    assert set(providers) == {"virustotal", "abuseipdb"}


def test_provider_labels_maps_names():
    assert threatintel.provider_labels({"virustotal": "k", "otx": "k"}) == [
        "VirusTotal", "AlienVault OTX"
    ]


def test_virustotal_clean_lookup(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: {
        "data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10
        }, "reputation": 0}}
    })
    recs = threatintel._virustotal_lookup("deadbeef" * 8, "hash", "key", 5.0)
    assert recs[0]["status"] == "clean"
    assert recs[0]["provider"] == "virustotal"


def test_virustotal_malicious_lookup(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: {
        "data": {"attributes": {"last_analysis_stats": {
            "malicious": 25, "suspicious": 3, "harmless": 2, "undetected": 0
        }, "reputation": 10}}
    })
    recs = threatintel._virustotal_lookup("1.2.3.4", "ip", "key", 5.0)
    assert recs[0]["status"] == "malicious"
    assert recs[0]["score"] >= 70


def test_virustotal_not_found(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: None)
    recs = threatintel._virustotal_lookup("unknown" * 8, "hash", "key", 5.0)
    assert recs[0]["status"] == "not_found"


def test_virustotal_skips_urls_without_submission():
    assert threatintel._virustotal_lookup(
        "http://evil.example/p", "url", "key", 5.0) == []


def test_otx_suspicious_pulses(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: {
        "pulse_info": {"count": 2}, "false_positive": False
    })
    recs = threatintel._otx_lookup("evil.example", "domain", "key", 5.0)
    assert recs[0]["status"] == "suspicious"


def test_abuseipdb_clean(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: {
        "data": {"abuseConfidenceScore": 0, "totalReports": 0,
                 "usageType": "", "countryCode": "", "isWhitelisted": False}
    })
    recs = threatintel._abuseipdb_lookup("1.2.3.4", "key", 5.0)
    assert recs[0]["status"] == "clean"


def test_abuseipdb_malicious(monkeypatch):
    monkeypatch.setattr(threatintel, "_fetch_json", lambda *a, **k: {
        "data": {"abuseConfidenceScore": 90, "totalReports": 12,
                 "usageType": "Data Center", "countryCode": "US",
                 "isWhitelisted": False}
    })
    recs = threatintel._abuseipdb_lookup("8.8.8.8", "key", 5.0)
    assert recs[0]["status"] == "malicious"
    assert recs[0]["score"] == 90


def test_abuseipdb_skips_ipv6():
    assert threatintel._abuseipdb_lookup("2606:4700::1111", "key", 5.0) == []


def test_enrich_never_raises_on_provider_error(monkeypatch):
    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(threatintel, "_lookup", boom)
    cache, enriched = threatintel.enrich_iocs(
        [_ioc("ip", "1.2.3.4")], {"virustotal": "k"}, timeout=1.0)
    assert cache["virustotal|ip|1.2.3.4"][0]["status"] == "error"
    assert enriched[0]["enrichments"][0]["status"] == "error"


def test_enrich_caches_results_and_reuses_cache(monkeypatch):
    calls = {"n": 0}

    def fake_lookup(provider, ioc, api_key, timeout):
        calls["n"] += 1
        return [threatintel._record(provider, ioc["type"], ioc["value"],
                                    "clean", 0, "ok")]
    monkeypatch.setattr(threatintel, "_lookup", fake_lookup)

    first_cache, _ = threatintel.enrich_iocs(
        [_ioc("domain", "evil.example")], {"otx": "k"}, timeout=1.0)
    second_cache, _ = threatintel.enrich_iocs(
        [_ioc("domain", "evil.example")], {"otx": "k"},
        existing=first_cache, timeout=1.0)

    assert calls["n"] == 1
    assert "otx|domain|evil.example" in second_cache


def test_enrich_caps_new_lookups_per_request(monkeypatch):
    calls = {"n": 0}

    def fake_lookup(provider, ioc, api_key, timeout):
        calls["n"] += 1
        return [threatintel._record(provider, ioc["type"], ioc["value"],
                                    "clean", 0, "ok")]
    monkeypatch.setattr(threatintel, "_lookup", fake_lookup)

    iocs = [_ioc("domain", f"s{i}.example") for i in range(5)]
    threatintel.enrich_iocs(iocs, {"otx": "k"}, timeout=1.0, max_new=2)
    assert calls["n"] == 2


def test_enrich_only_attaches_to_supported_types():
    cache, enriched = threatintel.enrich_iocs(
        [_ioc("mutex", "Global\\foo"), _ioc("domain", "bad.example")],
        {}, timeout=1.0)
    by_type = {i["type"]: i for i in enriched}
    assert by_type["mutex"]["enrichments"] == []
    assert by_type["domain"]["enrichments"] == []