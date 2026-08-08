"""MITRE ATT&CK technique catalog and mapping helpers.

The engine only emits a technique mapping when deterministic evidence supports
it (an analyzer finding, a detection rule, or an IOC). No technique is invented
because an AI "thinks" it is plausible — Phase 4 AI can only *explain* mappings
that already exist.

Confidence semantics (documented in docs/SECURITY_MODULES.md):
  0.90 - 1.00  direct observation (PE import, YARA match, exact string)
  0.70 - 0.85  strong derived correlation (detection rule over multiple evidence)
  0.50 - 0.65  moderate inference (weak context, e.g. generic network strings)
  <0.50        speculative — avoided unless explicitly justified
"""
from __future__ import annotations

# technique_id -> (name, tactic)
MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1056.001": ("Keylogging", "Credential Access"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.007": ("JavaScript", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1116": ("Code Signing", "Defense Evasion"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1555": ("Credentials from Password Stores", "Credential Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1622": ("Debugger Evasion", "Defense Evasion"),
}

# Analyzer/detection finding category -> primary technique id. Used to attach
# MITRE context to findings that do not declare one explicitly.
CATEGORY_MITRE: dict[str, str] = {
    "anti-debug": "T1622",
    "code-signature": "T1116",
    "command-execution": "T1059.003",
    "credential-access": "T1555",
    "downloader": "T1105",
    "keylogging": "T1056.001",
    "network-communication": "T1071",
    "network-api": "T1071",
    "obfuscation": "T1027",
    "office-autorun": "T1204.002",
    "office-suspicious-macro": "T1204.002",
    "pdf-embedded": "T1203",
    "pdf-javascript": "T1059.007",
    "pdf-launch": "T1203",
    "pdf-links": "T1566",
    "pdf-openaction": "T1203",
    "pdf-xfa": "T1203",
    "persistence": "T1547.001",
    "persistence-registry": "T1547.001",
    "persistence-service": "T1543.003",
    "powershell": "T1059.001",
    "privilege-escalation": "T1134",
    "process-injection": "T1055",
    "registry-persistence": "T1547.001",
    "remote-access": "T1219",
    "sandbox-evasion": "T1497",
    "script-io": "T1071",
}

# IOC type -> candidate techniques (informative only; not emitted alone).
IOC_MITRE_HINTS: dict[str, list[str]] = {
    "url": ["T1071"],
    "domain": ["T1071"],
    "ip": ["T1071"],
    "registry": ["T1547.001", "T1112"],
    "command": ["T1059.001", "T1059.003"],
    "mutex": ["T1497"],
    "hash": [],
}


def technique_name(technique_id: str) -> str:
    return MITRE_CATALOG.get(technique_id, ("Unknown", "Unknown"))[0]


def tactic_for(technique_id: str) -> str:
    return MITRE_CATALOG.get(technique_id, ("Unknown", "Unknown"))[1]


def supported(technique_id: str) -> bool:
    return technique_id in MITRE_CATALOG


def build_mitre(findings: list[dict], evidence: list[dict] | None = None,
                iocs: list[dict] | None = None) -> list[dict]:
    """Aggregate findings into evidence-backed technique mappings.

    Only techniques carried by at least one finding are emitted. Each mapping
    records the supporting evidence text and the modules that observed it.
    """
    evidence = evidence or []
    iocs = iocs or []
    ev_by_id = {e["id"]: e for e in evidence}

    grouped: dict[str, dict] = {}
    for f in findings:
        techniques = list(f.get("mitre_techniques") or [])
        if f.get("mitre"):
            techniques.append(f["mitre"])
        elif f.get("category") in CATEGORY_MITRE:
            techniques.append(CATEGORY_MITRE[f["category"]])
        for tid in dict.fromkeys(t for t in techniques if supported(t)):
            entry = grouped.setdefault(tid, {
                "technique_id": tid,
                "technique": technique_name(tid),
                "tactic": tactic_for(tid),
                "confidence": 0.0,
                "severity": "info",
                "source_modules": [],
                "findings": [],
                "evidence": [],
            })
            entry["confidence"] = max(entry["confidence"], float(f.get("confidence") or 0.5))
            if f.get("module"):
                entry["source_modules"].append(f["module"])
            entry["findings"].append(f.get("title", f.get("category", "")))
            snippet = f.get("evidence") or f.get("detail") or ""
            if snippet and snippet not in entry["evidence"]:
                entry["evidence"].append(str(snippet)[:300])
            entry["severity"] = _higher(entry["severity"], f.get("severity", "info"))

    # IOC corroboration: a technique hinted by an IOC but not yet mapped still
    # needs a finding to be emitted, so IOCs only add evidence, never techniques.
    for tid, entry in grouped.items():
        entry["source_modules"] = list(dict.fromkeys(entry["source_modules"]))
        entry["findings"] = list(dict.fromkeys(entry["findings"]))
        entry["evidence"] = entry["evidence"][:5]
        entry["confidence"] = round(entry["confidence"], 2)
        entry["provenance"] = {
            "finding_count": len(entry["findings"]),
            "source_modules": entry["source_modules"],
            "evidence_observed": [ev_by_id[e]["value"][:160] for e in ev_by_id if e][:5],
        }
    return sorted(grouped.values(), key=lambda m: (m["confidence"]), reverse=True)


def _higher(a: str, b: str) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    return a if order.index(a) <= order.index(b) else b
