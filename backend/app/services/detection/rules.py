"""Deterministic detection rules.

Each rule correlates normalized OBSERVED evidence into a DERIVED finding
(a capability statement). Rules only fire on real evidence — never on the mere
fact that a file is executable. Findings carry provenance: the evidence ids
that produced them and a confidence score.

Rules that would merely repeat an analyzer finding are skipped so the finding
list stays noise-free; the scoring layer independently deduplicates by category
so a signal observed by several modules is never weighted multiple times.
"""
from __future__ import annotations

import re

from app.services.detection.mitre import CATEGORY_MITRE, MITRE_CATALOG, supported

_FAMILY_BY_EXT = {
    ".exe": "pe", ".dll": "pe", ".sys": "pe", ".scr": "pe",
    ".pdf": "pdf",
    ".ps1": "script", ".py": "script", ".js": "script", ".vbs": "script",
    ".bat": "script", ".sh": "script", ".psm1": "script",
    ".docx": "ooxml", ".xlsx": "ooxml", ".pptx": "ooxml",
    ".doc": "ole", ".xls": "ole", ".ppt": "ole",
}


def run_rules(evidence: list[dict], findings: list[dict], ctx: dict | None = None) -> list[dict]:
    """Emit derived findings that are not already covered by an analyzer."""
    ctx = ctx or {}
    existing = {f.get("category") for f in findings}
    out: list[dict] = []

    def add(rule: str, category: str, severity: str, title: str, detail: str,
            confidence: float, mitre: str, ev_ids: list[str], evidence_txt: str) -> None:
        if category in existing:
            return  # analyzer already reported this category
        out.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "confidence": round(confidence, 2),
            "mitre": mitre if supported(mitre) else None,
            "mitre_techniques": [mitre] if supported(mitre) else [],
            "evidence_ids": ev_ids[:8],
            "module": f"detection:{rule}",
            "evidence": evidence_txt[:300],
        })

    # ---- PowerShell execution capability (T1059.001)
    ps = [e for e in evidence if _PS_RE.search(e["value"])]
    ps_obf = [e for e in evidence if _PS_OBF_RE.search(e["value"])]
    if ps and ps_obf:
        add("powershell", "powershell", "high",
            "PowerShell execution with obfuscation/execution primitives",
            "PowerShell command strings combined with encoded/execution indicators "
            "(EncodedCommand, IEX, DownloadString).",
            0.85, "T1059.001", [e["id"] for e in ps + ps_obf],
            "; ".join(dict.fromkeys(e["value"] for e in (ps + ps_obf)[:4])))

    # ---- Command / shell execution (T1059.003)
    cmd = [e for e in evidence if _CMD_RE.search(e["value"])]
    if cmd and not ps:
        add("command-shell", "command-execution", "medium",
            "Command shell / LOLBin execution strings",
            "Strings reference cmd.exe, cscript, wscript, mshta, rundll32 or certutil.",
            0.75, "T1059.003", [e["id"] for e in cmd],
            "; ".join(dict.fromkeys(e["value"] for e in cmd[:4])))

    # ---- Downloader (T1105)
    url_ev = [e for e in evidence if e["type"] in ("url", "domain", "ip")]
    dl = [e for e in evidence if _DL_RE.search(e["value"])]
    if url_ev and dl:
        add("downloader", "downloader", "high",
            "Remote content download / retrieval primitive",
            "Network indicator combined with a download primitive "
            "(Invoke-WebRequest, DownloadString, UrlDownloadToFile, BITS, certutil -urlcache).",
            0.80, "T1105", [e["id"] for e in url_ev + dl],
            "; ".join(dict.fromkeys(e["value"] for e in (url_ev + dl)[:4])))

    # ---- Network communication (T1071)
    net = [e for e in evidence if e["type"] in ("url", "domain", "ip") and e["value"]]
    if net:
        add("network", "network-communication", "medium",
            "Potential network communication",
            "Embedded URLs, domains or IP addresses observed in the sample.",
            0.70, "T1071", [e["id"] for e in net],
            "; ".join(dict.fromkeys(e["value"] for e in net[:5])))

    # ---- Registry persistence (T1547.001)
    reg = [e for e in evidence if _RUNKEY_RE.search(e["value"])]
    if reg:
        add("persistence-registry", "persistence-registry", "high",
            "Registry Run-key persistence reference",
            "Strings reference a Run key (CurrentVersion\\Run) used for autostart persistence.",
            0.85, "T1547.001", [e["id"] for e in reg],
            "; ".join(e["value"] for e in reg[:3]))

    # ---- Service / scheduled-task persistence (T1543.003, T1053.005)
    svc = [e for e in evidence if _SVC_RE.search(e["value"])]
    if svc:
        add("persistence-service", "persistence-service", "medium",
            "Service / scheduled-task persistence primitive",
            "Strings reference service creation or schtasks scheduling primitives.",
            0.70, "T1543.003", [e["id"] for e in svc],
            "; ".join(e["value"] for e in svc[:3]))

    # ---- Obfuscation (T1027)
    obf = [e for e in evidence if _OBF_RE.search(e["value"])]
    if obf:
        add("obfuscation", "obfuscation", "medium",
            "Obfuscation / encoding primitives",
            "Base64, encoded-command, chr() or similar encoding primitives observed.",
            0.80, "T1027", [e["id"] for e in obf],
            "; ".join(e["value"] for e in obf[:3]))

    # ---- Sandbox evasion (T1497)
    ev = [e for e in evidence if _EVASION_RE.search(e["value"])]
    if ev:
        add("sandbox-evasion", "sandbox-evasion", "low",
            "Sandbox / VM evasion hints",
            "APIs or strings associated with timing checks or VM detection observed.",
            0.60, "T1497", [e["id"] for e in ev],
            "; ".join(e["value"] for e in ev[:3]))

    # ---- Credential access (T1555 / T1056.001)
    cred = [e for e in evidence if _CRED_RE.search(e["value"])]
    if cred:
        add("credential-access", "credential-access", "high",
            "Credential access primitives",
            "DPAPI/crypto or keylogging APIs observed (CryptUnprotectData, GetAsyncKeyState).",
            0.80, "T1555", [e["id"] for e in cred],
            "; ".join(e["value"] for e in cred[:3]))

    # ---- Remote access (T1219)
    ra = [e for e in evidence if _RAT_RE.search(e["value"])]
    if ra:
        add("remote-access", "remote-access", "medium",
            "Remote access / RAT software strings",
            "Strings reference remote-administration tooling (TeamViewer, AnyDesk, VNC, RAT names).",
            0.65, "T1219", [e["id"] for e in ra],
            "; ".join(e["value"] for e in ra[:3]))

    # ---- Masquerading (T1036) — content/extension mismatch, evidence-backed
    f = ctx.get("file") or {}
    ext = (f.get("extension") or "").lower()
    family = f.get("family", "")
    if ext in _FAMILY_BY_EXT and _FAMILY_BY_EXT[ext] != family and family not in ("other", "text", "archive", "image"):
        add("masquerading", "masquerading", "low",
            "File extension does not match content",
            f"Filename suggests {_FAMILY_BY_EXT[ext]} but magic bytes identify {family}.",
            0.60, "T1036", [e["id"] for e in evidence if e["type"] == "file_meta"],
            f"{f.get('filename','')} (extension .{ext.strip('.')}) vs content {family}")

    return out


def enrich_findings(findings: list[dict], evidence: list[dict]) -> list[dict]:
    """Attach confidence / MITRE / provenance to analyzer-produced findings."""
    ev_by_cat: dict[str, list[str]] = {}
    for e in evidence:
        if e["type"] == "capability":
            ev_by_cat.setdefault("capability", []).append(e["id"])
    for f in findings:
        f.setdefault("confidence", _default_confidence(f.get("severity", "info")))
        f.setdefault("evidence_ids", [])
        f.setdefault("mitre_techniques", [])
        f["mitre"] = f.get("mitre") or CATEGORY_MITRE.get(f.get("category"))
        if f.get("mitre") and not f["mitre_techniques"]:
            f["mitre_techniques"] = [f["mitre"]]
    return findings


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Merge exact (category, title) duplicates, keeping the strongest fields."""
    merged: dict[tuple, dict] = {}
    for f in findings:
        key = (f.get("category", ""), f.get("title", ""))
        prev = merged.get(key)
        if prev is None:
            merged[key] = dict(f)
            continue
        _merge(prev, f)
    return list(merged.values())


def _merge(target: dict, other: dict) -> None:
    order = ["critical", "high", "medium", "low", "info"]
    if order.index(other.get("severity", "info")) < order.index(target.get("severity", "info")):
        target["severity"] = other["severity"]
    target["confidence"] = round(max(target.get("confidence", 0), other.get("confidence", 0)), 2)
    target["evidence_ids"] = list(dict.fromkeys([*target.get("evidence_ids", []), *other.get("evidence_ids", [])]))
    mods = list(dict.fromkeys([*target.get("_modules", []), *([other.get("module")] if other.get("module") else [])]))
    target["_modules"] = mods
    target["module"] = "+".join(m for m in mods if m) or target.get("module")


def _default_confidence(severity: str) -> float:
    return {"critical": 0.95, "high": 0.9, "medium": 0.8, "low": 0.7, "info": 0.5}.get(severity, 0.6)


# ---- rule patterns (intentionally conservative to limit false positives) ----
_PS_RE = re.compile(r"(?i)(?:powershell|pwsh)")
_PS_OBF_RE = re.compile(r"(?i)(?:-enc(?:oded)?command|-enc\s|-e\s+|encodedcommand|invoke-expression|\biex\b|downloadstring|\$executioncontext|-windowstyle\s+hidden|-nop(?:rofile)?)")
_CMD_RE = re.compile(r"(?i)(?:cmd(?:\.exe)?\s*/[ck]|\/bin\/(?:ba)?sh|bash\s+-c|wscript|cscript|mshta|rundll32|certutil|regsvr32|forfiles)")
_DL_RE = re.compile(r"(?i)(?:invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|urlmon|urldownloadtofile|bitsadmin|certutil\s+-urlcache|curl\b|wget\b|net\s+use)")
_RUNKEY_RE = re.compile(r"(?i)currentversion\\run|\\\\run\b|run\s*=\s*\S")
_SVC_RE = re.compile(r"(?i)(?:createservice|startservicea|openscmanager|sc\s+create|schtasks\s+/create|systemctl\s+enable)")
_OBF_RE = re.compile(r"(?i)(?:frombase64|tobase64|base64|encodedcommand|chrw?\(|chr\()|[-_$]e\s*[= ]|string\.fromcharcode|unescape\(")
_EVASION_RE = re.compile(r"(?i)(?:getasynckeystate|gettickcount|vmware|virtualbox|qemu|sandboxie|checkremotedebuggerpresent|isdebuggerpresent|outputdebugstring|sleep\s*\()")
_CRED_RE = re.compile(r"(?i)(?:cryptunprotectdata|cryptprotectdata|cryptacquirecontext|getasynckeystate|getkeystate|vaultcli|dpapi|mimikatz|sekurlsa|lsass)")
_RAT_RE = re.compile(r"(?i)(?:teamviewer|anydesk|radmin|ammyy|vnc\b|ultravnc|nano\s*core|njrat|quasar\b|imminent|darkcomet|spynet|asyncrat)")
