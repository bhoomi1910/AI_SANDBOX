"""IOC extraction, normalization and deduplication.

Rules of thumb (see docs/SECURITY_MODULES.md):
- Version-like numbers are NOT IPs: every IPv4 is validated octet-by-octet.
- Documentation URLs are recorded but start with conservative severity; an IOC
  is an indicator, not a verdict.
- Windows paths and mutexes are recorded with low severity/confidence.
- The same IOC appearing in strings + YARA + an analyzer is deduplicated; all
  source provenance is preserved.

Supported IOC types: url, domain, ip (v4+v6), email, hash (md5/sha1/sha256),
registry, windows_path, command, mutex.
"""
from __future__ import annotations

import ipaddress
import re

from app.services.detection.mitre import IOC_MITRE_HINTS

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>]{5,}")
_IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_IPV6_RE = re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_REGISTRY_RE = re.compile(r"(?i)(?:HKLM|HKCU|HKCR|HKU|HKPD)\\[\\A-Za-z0-9_.$-]+")
_WINPATH_RE = re.compile(r"(?i)(?:[a-z]:\\(?:[^\\\s]+\\)*[^\\\s]*|\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\\\s]*)*|%[A-Z_]+%\\(?:[^\\\s]+\\)*[^\\\s]*)")
_COMMAND_RE = re.compile(r"(?i)\b(?:cmd(?:\.exe)?\s*/c\s+[^\s]{1,120}|powershell[^\n]{0,160}|rundll32[^\n]{0,120}|certutil[^\n]{0,120}|regsvr32[^\n]{0,120}|wscript[^\n]{0,120}|cscript[^\n]{0,120}|schtasks[^\n]{0,120})")
_MUTEX_RE = re.compile(r"(?i)(?:Global|Local)\\\\[^\s]{1,64}")

# TLDs that are far more likely file extensions -> drop as domain false positives
_COMMON_EXTENSIONS = {
    "exe", "dll", "so", "bin", "py", "jar", "war", "bat", "cmd", "ps1", "vbs",
    "js", "msi", "dat", "tmp", "txt", "md", "html", "htm", "cfg", "ini", "log",
    "sys", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg",
    "jpeg", "gif", "svg", "ico", "mp3", "mp4", "zip", "rar", "7z", "tar", "gz",
    "asm", "c", "cpp", "h", "class", "xml", "json", "yml", "yaml", "cs", "go",
    "rs", "php", "rb", "sh", "reg", "drv", "ocx", "tmp", "lock", "cache",
}

# base (severity, confidence) per IOC type
_BASE: dict[str, tuple[str, float]] = {
    "url": ("medium", 0.80),
    "domain": ("low", 0.75),
    "ip": ("low", 0.70),
    "email": ("low", 0.70),
    "hash": ("medium", 0.85),
    "registry": ("medium", 0.75),
    "windows_path": ("low", 0.55),
    "command": ("medium", 0.75),
    "mutex": ("low", 0.60),
}

MAX_IOCS = 200


def extract_iocs(evidence: list[dict], raw_strings: list[str] | None = None) -> list[dict]:
    """Scan evidence + raw strings for normalized IOCs, deduplicated with provenance."""
    merged: dict[tuple[str, str], dict] = {}

    def _consume(value: str, module: str, evidence_id: str | None) -> None:
        for ioc_type, ioc_value in _scan(value):
            key = (ioc_type, ioc_value)
            entry = merged.get(key)
            if entry is None:
                sev, conf = _BASE[ioc_type]
                if ioc_type == "ip" and _is_private_ip(ioc_value):
                    conf = 0.55
                entry = {
                    "id": f"ioc-{len(merged) + 1:04d}",
                    "type": ioc_type,
                    "value": ioc_value,
                    "severity": sev,
                    "confidence": conf,
                    "sources": [],
                    "count": 0,
                    "mitre_techniques": list(IOC_MITRE_HINTS.get(ioc_type, [])),
                }
                merged[key] = entry
            # provenance
            src = {"module": module, "evidence_id": evidence_id, "context": value[:200]}
            if src not in entry["sources"]:
                entry["sources"].append(src)
            entry["count"] += 1
            if module == "yara":
                entry["confidence"] = min(0.99, entry["confidence"] + 0.05)

    for ev in evidence:
        _consume(ev.get("value", ""), ev.get("source_module", "?"), ev.get("id"))
    for value in raw_strings or []:
        _consume(value, "strings", None)

    iocs = list(merged.values())
    for entry in iocs:
        entry["confidence"] = round(min(0.99, entry["confidence"] + 0.03 * (len(entry["sources"]) - 1)), 2)
    return iocs[:MAX_IOCS]


def _scan(value: str) -> list[tuple[str, str]]:
    """Return (ioc_type, normalized_value) pairs found inside `value`."""
    out: list[tuple[str, str]] = []

    for m in _IPV4_RE.finditer(value):
        raw = m.group(0)
        if _valid_ipv4(raw):
            out.append(("ip", _norm_ip(raw)))

    for m in _IPV6_RE.finditer(value):
        raw = m.group(0)
        try:
            out.append(("ip", str(ipaddress.IPv6Address(raw))))
        except ValueError:
            pass

    for m in _EMAIL_RE.finditer(value):
        out.append(("email", m.group(0).lower()))

    for m in _HASH_RE.finditer(value):
        out.append(("hash", m.group(0).lower()))

    for m in _DOMAIN_RE.finditer(value):
        dom = _norm_domain(m.group(0))
        if dom and not _looks_like_ip(dom) and dom not in ("localhost",):
            out.append(("domain", dom))

    for m in _URL_RE.finditer(value):
        out.append(("url", _norm_url(m.group(0))))

    for m in _REGISTRY_RE.finditer(value):
        out.append(("registry", _norm_registry(m.group(0))))

    for m in _WINPATH_RE.finditer(value):
        out.append(("windows_path", _norm_path(m.group(0))))

    for m in _COMMAND_RE.finditer(value):
        out.append(("command", m.group(0).strip()))

    for m in _MUTEX_RE.finditer(value):
        out.append(("mutex", m.group(0)))

    return out


# ---- validation / normalization -------------------------------------------------

def _valid_ipv4(raw: str) -> bool:
    parts = raw.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
        if p != str(int(p)):  # leading zeros -> reject to avoid FP
            return False
    return True


def _norm_ip(raw: str) -> str:
    return str(ipaddress.IPv4Address(raw))


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _norm_domain(raw: str) -> str | None:
    dom = raw.strip().rstrip(".").lower()
    if not dom or "." not in dom:
        return None
    tld = dom.rsplit(".", 1)[-1]
    if len(tld) < 2 or not tld.isalpha() or tld in _COMMON_EXTENSIONS:
        return None
    return dom


def _norm_url(raw: str) -> str:
    url = raw.strip().strip("'\"").rstrip(".,;)")
    # defang: restore [.] and (dot)
    url = url.replace("[.]", ".").replace("(dot)", ".").replace("[dot]", ".")
    if "://" in url:
        scheme, rest = url.split("://", 1)
        host, _, tail = rest.partition("/")
        host = host.split(":", 1)[0].lower()
        return f"{scheme.lower()}://{host}/{tail}".rstrip("/")
    return url.lower()


def _norm_registry(raw: str) -> str:
    reg = raw.replace("/", "\\")
    parts = reg.split("\\", 1)
    if parts and parts[0].isalpha():
        parts[0] = parts[0].upper()
    return "\\".join(parts).rstrip("\\")


def _norm_path(raw: str) -> str:
    return raw.strip().strip("'\"").lower().replace("/", "\\")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
