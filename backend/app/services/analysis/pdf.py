"""PDF analysis via `pypdf` plus raw-token scanning for suspicious objects.

Detects JavaScript, OpenAction, Launch, embedded files, XFA and URI actions.
Emits evidence-backed findings; never renders or executes the PDF.
"""
from __future__ import annotations

import re
from pathlib import Path

SUSPICIOUS_JS = re.compile(r"(?i)\b(eval\s*\(|execCommand|ActiveXObject|WScript|WScript\.Shell|document\.cookie|unescape|fromCharCode|process\.start|new ActiveX|cm\.system|app\.launchurl)")


def analyze_pdf(path: Path, findings: list[dict], strings: list[dict]) -> dict:
    data = _read_all(path)
    tokens = {
        "JavaScript": data.count(b"/JavaScript"),
        "OpenAction": data.count(b"/OpenAction"),
        "Launch": data.count(b"/Launch"),
        "EmbeddedFile": data.count(b"/EmbeddedFile"),
        "AcroForm": data.count(b"/AcroForm"),
        "XFA": data.count(b"/XFA"),
        "GoToR": data.count(b"/GoToR"),
        "URI": data.count(b"/URI"),
        "AA": data.count(b"/AA"),
        "RichMedia": data.count(b"/RichMedia"),
    }
    metadata = _metadata(path)
    capabilities: list[str] = []
    for name, count in tokens.items():
        if count > 0:
            capabilities.append(f"Contains /{name} object (x{count})")

    js_matches = SUSPICIOUS_JS.findall(data.decode("latin-1", "ignore"))
    if js_matches:
        findings.append(_finding(
            "high", "pdf-javascript", "Suspicious JavaScript in PDF",
            f"JavaScript markers found: {', '.join(dict.fromkeys(js_matches))[:200]}",
            evidence="raw /JavaScript scan",
        ))
    if tokens["OpenAction"]:
        findings.append(_finding("high", "pdf-openaction", "Auto-execute on open (/OpenAction)", "PDF defines an action that runs when the document is opened", evidence="/OpenAction present"))
    if tokens["Launch"]:
        findings.append(_finding("critical", "pdf-launch", "External launch action (/Launch)", "PDF attempts to launch an external application or file", evidence="/Launch present"))
    if tokens["EmbeddedFile"]:
        findings.append(_finding("medium", "pdf-embedded", "Embedded file attachments", "PDF contains embedded files that may carry payloads", evidence="/EmbeddedFile present"))
    if tokens["XFA"]:
        findings.append(_finding("medium", "pdf-xfa", "Dynamic XFA form", "XFA forms can execute logic; historically abused for phishing", evidence="/XFA present"))
    if tokens["JavaScript"] and tokens["AA"]:
        findings.append(_finding("medium", "pdf-auto-js", "Auto-run JavaScript (AA)", "Additional-action JavaScript can run without user interaction", evidence="/AA + /JavaScript"))

    interesting = [s for s in strings if s["interesting"] and s["type"] in ("url", "command")]
    if interesting:
        urls = [s["value"] for s in interesting[:10]]
        findings.append(_finding("low", "pdf-links", "Suspicious links embedded", ", ".join(urls)[:300], evidence="extracted strings"))

    return {"capabilities": capabilities, "metadata": metadata}


def _metadata(path: Path) -> dict:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        info = reader.metadata or {}
        return {
            "title": str(info.get("/Title", "") or ""),
            "author": str(info.get("/Author", "") or ""),
            "producer": str(info.get("/Producer", "") or ""),
            "creator": str(info.get("/Creator", "") or ""),
            "pageCount": len(reader.pages) if reader.pages is not None else 0,
        }
    except Exception as exc:
        return {"error": f"Could not parse PDF metadata: {exc}"}


def _read_all(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(16 * 1024 * 1024)


def _finding(severity, category, title, detail, evidence) -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail, "evidence": evidence, "mitre": None, "module": "pdf"}
