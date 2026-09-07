"""External threat-intelligence enrichment (VirusTotal, AlienVault OTX, AbuseIPDB).

Design rules (see docs/SECURITY_MODULES.md):
- OPTIONAL: enrichment runs only for providers whose API key is configured in the
  environment. With no keys configured the app stays fully offline and the
  behaviour is identical to before this module existed.
- Failure-isolated: any provider error (network, HTTP, rate limit, bad JSON) is
  converted into a per-provider ``status=error`` record and logged — it NEVER
  raises into the request path or breaks the investigation.
- Cached: results are stored in the investigation's own analysis payload, keyed
  by ``provider|ioc_type|value``, so repeat requests are instant and free-tier
  daily quotas are protected.
- Bounded: at most ``MAX_NEW_PER_REQUEST`` fresh lookups per request, within a
  ``REQUEST_TIME_BUDGET_SECONDS`` wall-clock budget.
- Privacy: sending hashes/IPs/domains to third parties is inherent to the
  feature. Only indicator types a provider actually supports are sent, and only
  when the operator has explicitly enabled the provider.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

PROVIDER_LABELS = {
    "virustotal": "VirusTotal",
    "otx": "AlienVault OTX",
    "abuseipdb": "AbuseIPDB",
}

SUPPORTED_IOC_TYPES = {"hash", "domain", "ip", "url"}

MAX_NEW_PER_REQUEST = 8
REQUEST_TIME_BUDGET_SECONDS = 20.0


class ThreatIntelError(Exception):
    """Provider returned an unexpected/error response."""


@dataclass
class Enrichment:
    provider: str
    ioc_type: str
    value: str
    status: str        # malicious | suspicious | clean | unknown | not_found | error
    score: int         # 0-100 (0 when unknown/not_found/error)
    summary: str
    detail: dict
    checked_at: str

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "status": self.status,
            "score": self.score,
            "summary": self.summary,
            "detail": self.detail,
            "checked_at": self.checked_at,
        }


def configured_providers(settings=None) -> dict[str, str]:
    """Return {provider_name: api_key} for every provider with a key set."""
    settings = settings or get_settings()
    out: dict[str, str] = {}
    for name, key in (
        ("virustotal", settings.virustotal_api_key),
        ("otx", settings.otx_api_key),
        ("abuseipdb", settings.abuseipdb_api_key),
    ):
        if key and key.strip():
            out[name] = key.strip()
    return out


def provider_labels(providers: dict[str, str]) -> list[str]:
    return [PROVIDER_LABELS.get(name, name.title()) for name in providers]


def cache_key(provider: str, ioc: dict) -> str:
    return f"{provider}|{ioc.get('type', '')}|{ioc.get('value', '')}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_json(url: str, headers: dict[str, str], timeout: float) -> dict | None:
    """GET a JSON endpoint. None = 404 (indicator unknown). Raises otherwise."""
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(url, headers=headers)
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise ThreatIntelError(f"HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError as exc:
            raise ThreatIntelError("invalid JSON response") from exc


def _record(
    provider: str, ioc_type: str, value: str, status: str,
    score: int, summary: str, detail: dict | None = None,
) -> dict:
    return Enrichment(
        provider=provider, ioc_type=ioc_type, value=value, status=status,
        score=score, summary=summary, detail=detail or {},
        checked_at=_utc_now(),
    ).as_dict()


# ── VirusTotal (hashes, IPs, domains; URLs require prior submission) ────────

def _virustotal_lookup(value: str, ioc_type: str, api_key: str, timeout: float) -> list[dict]:
    if ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{quote(value)}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(value)}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{quote(value)}"
    else:
        return []  # URLs are not lookupable without a prior analysis submission

    data = _fetch_json(url, {"x-apikey": api_key}, timeout)
    if data is None:
        return [_record("virustotal", ioc_type, value, "not_found", 0,
                        "No VirusTotal record for this indicator")]
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    engines = sum(int(v or 0) for v in stats.values())
    reputation = int(attrs.get("reputation", 0) or 0)
    if engines == 0:
        return [_record("virustotal", ioc_type, value, "unknown", 0,
                        "Sample not yet analysed on VirusTotal")]
    score = round(100 * (malicious + 0.6 * suspicious) / engines)
    if malicious >= 2 or (malicious >= 1 and score >= 40):
        status = "malicious"
    elif malicious + suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"
    summary = f"{malicious} of {engines} engines detected it"
    return [_record("virustotal", ioc_type, value, status, score, summary,
                    {"malicious": malicious, "suspicious": suspicious,
                     "engines": engines, "reputation": reputation})]


# ── AlienVault OTX (file hashes, URLs, domains, IPv4/IPv6) ───────────────────

def _otx_type(ioc_type: str, value: str) -> str | None:
    if ioc_type == "hash":
        return "file"
    if ioc_type == "url":
        return "url"
    if ioc_type == "domain":
        return "domain"
    if ioc_type == "ip":
        return "IPv6" if ":" in value else "IPv4"
    return None


def _otx_lookup(value: str, ioc_type: str, api_key: str, timeout: float) -> list[dict]:
    otx_t = _otx_type(ioc_type, value)
    if otx_t is None:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_t}/{quote(value)}/general"
    data = _fetch_json(url, {"X-OTX-API-KEY": api_key}, timeout)
    if data is None:
        return [_record("otx", ioc_type, value, "not_found", 0,
                        "No AlienVault OTX record for this indicator")]
    pulses = int((data.get("pulse_info") or {}).get("count", 0) or 0)
    false_positive = bool(data.get("false_positive"))
    if pulses == 0:
        status, score = "clean", 0
        summary = "No known OTX pulses for this indicator"
    elif false_positive:
        status, score = "clean", 20
        summary = "Listed in OTX but marked false positive"
    elif pulses < 3:
        status, score = "suspicious", min(100, 40 + 10 * pulses)
        summary = f"Referenced in {pulses} OTX pulse(s)"
    else:
        status, score = "malicious", min(100, 60 + 5 * pulses)
        summary = f"Referenced in {pulses} OTX pulse(s)"
    return [_record("otx", ioc_type, value, status, score, summary,
                    {"pulses": pulses, "false_positive": false_positive})]


# ── AbuseIPDB (IPv4 only) ───────────────────────────────────────────────────

def _abuseipdb_lookup(value: str, api_key: str, timeout: float) -> list[dict]:
    if ":" in value or value.count(".") != 3:
        return []  # IPv6 unsupported by the free check endpoint
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(value)}"
    data = _fetch_json(url, {"Key": api_key, "Accept": "application/json"}, timeout)
    if data is None:
        return [_record("abuseipdb", "ip", value, "not_found", 0,
                        "IP not listed on AbuseIPDB")]
    d = data.get("data") or {}
    confidence = int(d.get("abuseConfidenceScore", 0) or 0)
    reports = int(d.get("totalReports", 0) or 0)
    if confidence == 0 and reports == 0:
        status, score = "clean", 0
        summary = "No abuse reports for this IP"
    elif confidence >= 75:
        status, score = "malicious", confidence
        summary = f"{reports} abuse report(s), {confidence}% confidence"
    elif confidence >= 30:
        status, score = "suspicious", confidence
        summary = f"{reports} abuse report(s), {confidence}% confidence"
    else:
        status, score = "unknown", confidence
        summary = f"{reports} abuse report(s), low confidence"
    return [_record("abuseipdb", "ip", value, status, score, summary,
                    {"reports": reports, "confidence": confidence,
                     "usage_type": d.get("usageType"),
                     "country": d.get("countryCode"),
                     "whitelisted": d.get("isWhitelisted")})]


# ── Orchestration ───────────────────────────────────────────────────────────

def _lookup(provider: str, ioc: dict, api_key: str, timeout: float) -> list[dict]:
    value = ioc.get("value", "")
    ioc_type = ioc.get("type", "")
    if provider == "virustotal":
        return _virustotal_lookup(value, ioc_type, api_key, timeout)
    if provider == "otx":
        return _otx_lookup(value, ioc_type, api_key, timeout)
    if provider == "abuseipdb":
        return _abuseipdb_lookup(value, api_key, timeout)
    return []


def _safe_lookup(provider: str, ioc: dict, api_key: str, timeout: float) -> list[dict]:
    try:
        return _lookup(provider, ioc, api_key, timeout)
    except Exception as exc:  # noqa: BLE001 — intentional fail-safe
        logger.info("Threat-intel %s lookup failed for %s: %s",
                    provider, ioc.get("value"), exc)
        return [_record(provider, ioc.get("type", ""), ioc.get("value", ""),
                        "error", 0, "Provider lookup failed",
                        {"error": type(exc).__name__})]


def enrich_iocs(
    iocs: list[dict],
    providers: dict[str, str],
    timeout: float | None = None,
    existing: dict[str, list[dict]] | None = None,
    max_new: int = MAX_NEW_PER_REQUEST,
    time_budget: float = REQUEST_TIME_BUDGET_SECONDS,
) -> tuple[dict[str, list[dict]], list[dict]]:
    """Return (updated_cache, iocs_with_enrichments). Never raises.

    Each returned IOC is a copy with an extra ``enrichments`` list attached.
    Items already present in ``existing`` are served from cache; new lookups are
    capped by ``max_new`` and ``time_budget`` so the endpoint stays responsive.
    """
    settings = get_settings()
    timeout = timeout if timeout is not None else settings.threat_intel_timeout_seconds

    results = dict(existing or {})
    pending: list[tuple[str, dict, str]] = []
    for ioc in iocs:
        if ioc.get("type") not in SUPPORTED_IOC_TYPES:
            continue
        for provider in providers:
            key = cache_key(provider, ioc)
            if key not in results:
                pending.append((key, ioc, provider))

    start = time.monotonic()
    done = 0
    for key, ioc, provider in pending:
        if done >= max_new or (time.monotonic() - start) > time_budget:
            break
        results[key] = _safe_lookup(provider, ioc, providers[provider], timeout)
        done += 1

    enriched: list[dict] = []
    for ioc in iocs:
        out = dict(ioc)
        enrichments: list[dict] = []
        if ioc.get("type") in SUPPORTED_IOC_TYPES:
            for provider in providers:
                key = cache_key(provider, ioc)
                enrichments.extend(results.get(key, []))
        out["enrichments"] = enrichments
        enriched.append(out)
    return results, enriched