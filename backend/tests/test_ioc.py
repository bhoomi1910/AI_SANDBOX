"""IOC extraction: normalization, false-positive control, provenance dedup."""
import pytest

from app.services.detection.ioc import extract_iocs


def _ioc(types, value):
    return extract_iocs([{"id": "ev-0001", "type": "url", "value": value,
                         "source_module": "strings", "evidence": value}], raw_strings=[])


def test_valid_ip_extracted_and_normalised():
    iocs = extract_iocs([{"id": "ev-0001", "value": "Connecting to 203.0.113.9:443",
                          "source_module": "strings"}], raw_strings=[])
    ips = [i for i in iocs if i["type"] == "ip"]
    assert any(i["value"] == "203.0.113.9" for i in ips)


def test_version_string_not_an_ip():
    iocs = extract_iocs([{"id": "ev-0001", "value": "build 1.999.999.999 beta",
                          "source_module": "strings"}], raw_strings=[])
    assert not [i for i in iocs if i["type"] == "ip"]


def test_octets_over_255_rejected():
    iocs = extract_iocs([{"id": "ev-0001", "value": "999.1.1.1", "source_module": "strings"}], raw_strings=[])
    assert not [i for i in iocs if i["type"] == "ip"]


def test_private_ip_gets_lower_confidence():
    iocs = extract_iocs([{"id": "ev-0001", "value": "http://10.0.0.1/x", "source_module": "strings"}], raw_strings=[])
    ip = next(i for i in iocs if i["type"] == "ip")
    assert ip["confidence"] < 0.70


def test_email_extracted_from_raw_strings():
    iocs = extract_iocs([], raw_strings=["contact me at attacker@evil.example now"])
    emails = [i for i in iocs if i["type"] == "email"]
    assert any(i["value"] == "attacker@evil.example" for i in emails)


def test_hash_extracted():
    iocs = extract_iocs([], raw_strings=["d41d8cd98f00b204e9800998ecf8427e of file"])
    hashes = [i for i in iocs if i["type"] == "hash"]
    assert any(i["value"] == "d41d8cd98f00b204e9800998ecf8427e" for i in hashes)


def test_file_extension_not_a_domain():
    iocs = extract_iocs([{"id": "ev-0001", "value": "kernel32.dll!VirtualAllocEx",
                          "source_module": "pe"}], raw_strings=["update.exe"])
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    assert "kernel32.dll" not in domains
    assert "update.exe" not in domains


def test_defanged_url_restored():
    iocs = extract_iocs([], raw_strings=["http://evil[.]example/payload.bin"])
    urls = [i["value"] for i in iocs if i["type"] == "url"]
    assert any("evil.example" in u for u in urls)


def test_dedup_merges_provenance():
    evidence = [
        {"id": "ev-0001", "value": "http://evil.example/a", "source_module": "strings"},
        {"id": "ev-0002", "value": "http://evil.example/a", "source_module": "yara"},
    ]
    iocs = extract_iocs(evidence, raw_strings=[])
    url = next(i for i in iocs if i["type"] == "url" and i["value"] == "http://evil.example/a")
    assert url["count"] == 2
    assert {s["module"] for s in url["sources"]} == {"strings", "yara"}


def test_cap_is_bounded():
    iocs = extract_iocs([{"id": f"ev-{i:04d}", "value": f"http://a{i}.example/{i}",
                          "source_module": "strings"} for i in range(500)], raw_strings=[])
    assert len(iocs) <= 200
