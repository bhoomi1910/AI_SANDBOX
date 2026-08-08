"""Script / text file analysis (ps1, py, js, vbs, bat, sh, php…).

Scans content for downloader/persistence/obfuscation indicators. Static only —
the script is never executed.
"""
from __future__ import annotations

import re
from pathlib import Path

BASE64_RE = re.compile(r"(?i)(?:frombase64|to?base64|base64decode|enc\s+[a-z0-9+/=]{40,}|-e\s+[a-z0-9+/=]{40,})")
DOWNLOAD_RE = re.compile(r"(?i)\b(invoke-(webrequest|restmethod|expression|command)|downloadstring|downloadfile|wget|curl|fetch|urlretrieve)\b")
EXEC_RE = re.compile(r"(?i)\b(eval\s*\(|exec\s*\(|os\.system|subprocess|shell\s*\(|execute\s*\(|new-activexobject|wscript\.shell|powershell\.exe|cmd\.exe|rundll32|regsvr32|mshta|certutil|bitsadmin)\b")
PERSIST_RE = re.compile(r"(?i)\b(run\s+key|currentversion\\run|scheduled task|schtasks|registry\\|startup\s+folder|service\s+create|taskkill)\b")
OBFUSC_RE = re.compile(r"(?i)\b(chr\s*\(|fromcharcode|replace\s*\([^)]*[,]|\\\\x[0-9a-f]{2}|base64|join\s*\(['\"])\b")


def analyze_script(path: Path, findings: list[dict], strings: list[dict]) -> dict:
    text = _read_text(path)
    caps: list[str] = []
    detections = []

    if BASE64_RE.search(text):
        caps.append("Base64-encoded content (obfuscation)")
        detections.append(("medium", "obfuscation", "Base64-encoded content", "Encoded payloads typically hide commands/URLs from signature detection"))
    if DOWNLOAD_RE.search(text):
        caps.append("Remote download capability (Invoke-WebRequest / downloadstring)")
        detections.append(("high", "downloader", "Script downloads remote content", "Script contains a download/curl/fetch primitive"))
    if EXEC_RE.search(text):
        caps.append("Command / shell execution")
        detections.append(("high", "command-execution", "Script executes commands", "Script contains eval/exec/shell primitives"))
    if PERSIST_RE.search(text):
        caps.append("Persistence mechanism referenced")
        detections.append(("medium", "persistence", "Persistence references", "Run key / scheduled task / service references found"))
    if OBFUSC_RE.search(text):
        caps.append("Obfuscation techniques present")
        detections.append(("low", "obfuscation", "Obfuscation patterns", "Chr()/charCode/base64-style encoding detected"))

    if not detections:
        findings.append(_finding("info", "script-clean", "No suspicious patterns", "No downloader/execution/persistence indicators found in script content", evidence="content scan"))

    for severity, category, title, detail in detections:
        findings.append(_finding(severity, category, title, detail, evidence="script content scan"))

    urls = [s["value"] for s in strings if s["type"] in ("url", "command") and s["interesting"]][:10]
    if urls:
        findings.append(_finding("low", "script-io", "Interesting URLs/commands in script", ", ".join(urls)[:300], evidence="extracted strings"))

    return {"capabilities": caps, "lineCount": text.count("\n") + 1}


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8", "utf-16-le", "cp1252"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "ignore")


def _finding(severity, category, title, detail, evidence) -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail, "evidence": evidence, "mitre": None, "module": "script"}
