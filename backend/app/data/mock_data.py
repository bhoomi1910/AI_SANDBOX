"""
Realistic simulated SOC dataset.

In the production topology these values are produced by the sandbox
(CAPE/Cuckoo), static analysis workers, threat-intel connectors and the
LLM. For the prototype they are served verbatim so the full workflow is
demonstrable without any external service.
"""
from __future__ import annotations

INVESTIGATIONS: list[dict] = [
    {
        "id": "inv-0412",
        "caseId": "AGS-2026-0412",
        "sample": {
            "id": "smp-0412",
            "filename": "Invoice_scan_04829.exe",
            "fileType": "exe",
            "size": 486912,
            "sha256": "9f2c4e8b1a7d5f3c9e0b6a4d8f2e1c7b5a3d9f0e2c4b6a8d1f3e5c7b9a0d2f4e",
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "submittedAt": "2026-07-29T08:41:00Z",
            "submittedBy": "j.okafor",
        },
        "status": "ai-processing",
        "progress": 82,
        "severity": "critical",
        "riskScore": 94,
        "malwareFamily": "Emotet",
        "classification": "Trojan.Banker / Loader",
        "verdict": "malicious",
        "aiConfidence": 96,
        "detections": 61,
        "totalEngines": 72,
        "createdAt": "2026-07-29T08:41:00Z",
        "assignedTo": "J. Okafor",
        "tags": ["banking-trojan", "loader", "spam-campaign", "c2"],
        "mitreTechniques": ["T1566", "T1204", "T1055", "T1547", "T1071", "T1573", "T1112", "T1005"],
        "currentStage": "AI correlating behaviour with threat intel",
    },
    {
        "id": "inv-0411",
        "caseId": "AGS-2026-0411",
        "sample": {
            "id": "smp-0411",
            "filename": "Q3_Financials.docx",
            "fileType": "docx",
            "size": 132400,
            "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "md5": "7c8f2a1b9d3e4f5a6b7c8d9e0f1a2b3c",
            "sha1": "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00",
            "submittedAt": "2026-07-29T08:12:00Z",
            "submittedBy": "s.nakamura",
        },
        "status": "completed",
        "progress": 100,
        "severity": "high",
        "riskScore": 78,
        "malwareFamily": "Qakbot",
        "classification": "Maldoc / VBA Downloader",
        "verdict": "malicious",
        "aiConfidence": 91,
        "detections": 44,
        "totalEngines": 68,
        "createdAt": "2026-07-29T08:12:00Z",
        "completedAt": "2026-07-29T08:23:00Z",
        "assignedTo": "S. Nakamura",
        "tags": ["maldoc", "vba", "downloader"],
        "mitreTechniques": ["T1566", "T1204", "T1059", "T1105"],
    },
    {
        "id": "inv-0410",
        "caseId": "AGS-2026-0410",
        "sample": {
            "id": "smp-0410",
            "filename": "update_installer.msi",
            "fileType": "zip",
            "size": 2940112,
            "sha256": "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f",
            "md5": "9e107d9d372bb6826bd81d3542a419d6",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "submittedAt": "2026-07-29T07:55:00Z",
            "submittedBy": "a.petrov",
        },
        "status": "completed",
        "progress": 100,
        "severity": "critical",
        "riskScore": 88,
        "malwareFamily": "LockBit 3.0",
        "classification": "Ransomware",
        "verdict": "malicious",
        "aiConfidence": 94,
        "detections": 58,
        "totalEngines": 71,
        "createdAt": "2026-07-29T07:55:00Z",
        "completedAt": "2026-07-29T08:09:00Z",
        "assignedTo": "A. Petrov",
        "tags": ["ransomware", "lockbit", "encryption", "double-extortion"],
        "mitreTechniques": ["T1486", "T1490", "T1489", "T1047", "T1082"],
    },
    {
        "id": "inv-0409",
        "caseId": "AGS-2026-0409",
        "sample": {
            "id": "smp-0409",
            "filename": "chrome_setup.exe",
            "fileType": "exe",
            "size": 1204224,
            "sha256": "b3a1f5e9d7c2048f6e3b1a9d7c5e2048f6e3b1a9d7c5e2048f6e3b1a9d7c5e20",
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "b1a9d7c5e2048f6e3b1a9d7c5e2048f6e3b1a9d7",
            "submittedAt": "2026-07-29T07:30:00Z",
            "submittedBy": "j.okafor",
        },
        "status": "analysing",
        "progress": 47,
        "severity": "medium",
        "riskScore": 55,
        "malwareFamily": "RedLine Stealer",
        "classification": "Infostealer",
        "verdict": "suspicious",
        "aiConfidence": 73,
        "detections": 22,
        "totalEngines": 70,
        "createdAt": "2026-07-29T07:30:00Z",
        "assignedTo": "J. Okafor",
        "tags": ["stealer", "credential-theft", "fake-installer"],
        "mitreTechniques": ["T1555", "T1005", "T1071"],
        "currentStage": "Dynamic detonation in sandbox VM-07",
    },
    {
        "id": "inv-0408",
        "caseId": "AGS-2026-0408",
        "sample": {
            "id": "smp-0408",
            "filename": "shipping_label.pdf",
            "fileType": "pdf",
            "size": 98204,
            "sha256": "c4d5e6f7a8b90112c3d4e5f6a7b8c9d0c4d5e6f7a8b90112c3d4e5f6a7b8c9d0",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "356a192b7913b04c54574d18c28d46e6395428ab",
            "submittedAt": "2026-07-29T07:04:00Z",
            "submittedBy": "m.silva",
        },
        "status": "running",
        "progress": 28,
        "severity": "low",
        "riskScore": 34,
        "malwareFamily": "Unknown",
        "classification": "Phishing / Credential Harvest",
        "verdict": "suspicious",
        "aiConfidence": 62,
        "detections": 8,
        "totalEngines": 66,
        "createdAt": "2026-07-29T07:04:00Z",
        "assignedTo": "M. Silva",
        "tags": ["phishing", "pdf", "url-lure"],
        "mitreTechniques": ["T1566", "T1204"],
        "currentStage": "Static analysis — extracting embedded objects",
    },
    {
        "id": "inv-0407",
        "caseId": "AGS-2026-0407",
        "sample": {
            "id": "smp-0407",
            "filename": "driver_pack.iso",
            "fileType": "iso",
            "size": 6291456,
            "sha256": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "md5": "e2fc714c4727ee9395f324cd2e7f331f",
            "sha1": "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
            "submittedAt": "2026-07-29T06:48:00Z",
            "submittedBy": "a.petrov",
        },
        "status": "queued",
        "progress": 0,
        "severity": "info",
        "riskScore": 0,
        "malwareFamily": "Pending",
        "classification": "Pending triage",
        "verdict": "suspicious",
        "aiConfidence": 0,
        "detections": 0,
        "totalEngines": 0,
        "createdAt": "2026-07-29T06:48:00Z",
        "assignedTo": "Unassigned",
        "tags": ["iso", "container", "awaiting-detonation"],
        "mitreTechniques": [],
        "currentStage": "Waiting for sandbox slot",
    },
]

DASHBOARD_STATS = {
    "totalInvestigations": {"value": 1284, "delta": 12.4},
    "activeDetonations": {"value": 7, "delta": 2},
    "criticalAlerts": {"value": 23, "delta": 5},
    "meanTimeToVerdict": {"value": 6.4, "unit": "min", "delta": -18.2},
}

MALWARE_FAMILIES = [
    {"name": "Emotet", "value": 284},
    {"name": "Qakbot", "value": 212},
    {"name": "LockBit", "value": 176},
    {"name": "RedLine", "value": 148},
    {"name": "Cobalt Strike", "value": 121},
    {"name": "AgentTesla", "value": 98},
    {"name": "Other", "value": 245},
]

THREAT_FEED = [
    {"id": "f1", "time": "2m ago", "title": "New Emotet C2 cluster observed — 14 IPs added to blocklist", "source": "AlienVault OTX", "severity": "critical"},
    {"id": "f2", "time": "8m ago", "title": "CVE-2026-21882 actively exploited in the wild (Win32k EoP)", "source": "CISA KEV", "severity": "high"},
    {"id": "f3", "time": "15m ago", "title": "LockBit 3.0 affiliate targeting healthcare — new TTPs", "source": "MITRE ATT&CK", "severity": "critical"},
    {"id": "f4", "time": "24m ago", "title": "Phishing kit 'EvilProxy' bypassing MFA — 2FA session theft", "source": "VirusTotal", "severity": "high"},
]

# ── Deep-dive analysis for the featured case AGS-2026-0412 ──────────────────
STATIC_ANALYSIS = {
    "entropy": 7.42,
    "compiler": "Microsoft Visual C/C++ (2019 v16.x)",
    "packer": "Custom loader stub (partial UPX-like)",
    "arch": "x86 (32-bit)",
    "subsystem": "Windows GUI",
    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "signatureStatus": "invalid",
    "capabilities": [
        "Process injection (VirtualAllocEx / WriteProcessMemory)",
        "Anti-analysis / sandbox evasion checks",
        "Registry Run-key persistence",
        "HTTP(S) C2 communication",
        "Credential & email harvesting",
    ],
    "yara": [
        {"rule": "Emotet_Loader_v5", "severity": "critical", "description": "Detects Emotet loader stub and RWX unpacking layout"},
        {"rule": "SUSP_Process_Injection_APIs", "severity": "high", "description": "Classic CreateRemoteThread injection triad"},
        {"rule": "Credential_Access_Browser_DB", "severity": "high", "description": "References browser credential stores + DPAPI"},
    ],
}

THREAT_INTEL = [
    {"source": "VirusTotal", "score": 61, "verdict": "61 / 72 engines flag as malicious", "tone": "danger"},
    {"source": "AlienVault OTX", "score": 92, "verdict": "Linked to 4 active pulses (TA542)", "tone": "danger"},
    {"source": "AbuseIPDB", "score": 100, "verdict": "185.220.101.47 — 100% abuse confidence", "tone": "danger"},
    {"source": "MITRE ATT&CK", "score": 80, "verdict": "Maps to 8 techniques across 6 tactics", "tone": "warn"},
    {"source": "Hybrid Analysis", "score": 100, "verdict": "Threat score 100/100 — Malicious", "tone": "danger"},
]

MITRE_TECHNIQUES = [
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "severity": "high"},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution", "severity": "high"},
    {"id": "T1218", "name": "System Binary Proxy Execution", "tactic": "Defense Evasion", "severity": "high"},
    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "severity": "critical"},
    {"id": "T1547", "name": "Boot/Logon Autostart Execution", "tactic": "Persistence", "severity": "high"},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence", "severity": "high"},
    {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access", "severity": "critical"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "severity": "critical"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "severity": "critical"},
]

IOCS = [
    {"type": "ip", "value": "185.220.101.47", "context": "Primary C2 / payload host (RU)", "severity": "critical"},
    {"type": "ip", "value": "45.133.216.12", "context": "Secondary C2 over HTTPS (NL)", "severity": "high"},
    {"type": "domain", "value": "finance-docsecure[.]com", "context": "C2 HTTPS handshake", "severity": "critical"},
    {"type": "url", "value": "http://185.220.101.47/gate.php", "context": "C2 gate / check-in", "severity": "critical"},
    {"type": "registry", "value": "HKCU\\...\\Run\\EdgeUpdateCore", "context": "Persistence Run key", "severity": "high"},
]


def get_investigation(inv_id: str) -> dict | None:
    for inv in INVESTIGATIONS:
        if inv["id"] == inv_id or inv["caseId"] == inv_id:
            return inv
    return None
