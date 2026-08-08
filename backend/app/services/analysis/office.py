"""Office document (OLE + OOXML) macro analysis via `oletools.olevba`.

Detects embedded VBA macros, auto-execute macros and suspicious/shell keywords.
If the file is macro-free it is reported as such (a clean finding), and macro
code is never executed.
"""
from __future__ import annotations

from pathlib import Path

AUTO_EXEC = {
    "autopen", "auto_open", "autoexec", "document_open", "workbook_open",
    "worksheet_activate", "workbook_activate", "document_open",
    "auto_close", "autoexit", "auto_close",
}
SUSPICIOUS_KEYWORDS = {
    "shell", "wscript.shell", "createobject", "wscript", "cscript", "cmd.exe",
    "powershell", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin",
    "downloadstring", "exec", "eval", "call shell", "kernel32", "virtualalloc",
    "writeprocessmemory", "createremotethread", "selfdelete", "deletefile",
    "environment", "chrw", "chr(", "ascw", "base64", "frombase64", "xmlhttp",
    "winhttp", "adodb.stream", "scripting.filesystemobject", "shell.application",
    "exploit", "macro_shell",
}


def analyze_office(path: Path, findings: list[dict]) -> dict:
    try:
        from oletools.olevba import VBA_Parser
    except Exception as exc:
        findings.append(_finding("medium", "office-error", "Macro analysis unavailable", f"oletools could not be loaded: {exc}", evidence="olevba import"))
        return {"macroDetected": False, "macros": [], "error": str(exc)}

    try:
        parser = VBA_Parser(str(path))
    except Exception as exc:
        findings.append(_finding("low", "office-error", "Not an analysable Office file", str(exc)[:300], evidence="olevba open"))
        return {"macroDetected": False, "macros": [], "error": str(exc)}

    macros: list[dict] = []
    auto_exec = []
    suspicious_hits: list[str] = []
    macro_source_present = False

    try:
        for vba_filename, stream_path, vba_code, _ in parser.extract_macros():
            macro_source_present = True
            lowered = vba_code.lower() if vba_code else ""
            name = _macro_name(vba_filename)
            hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
            is_auto = any(a in lowered for a in AUTO_EXEC)
            if is_auto:
                auto_exec.append(name)
            if hits:
                suspicious_hits.extend(hits)
            macros.append({
                "name": name,
                "size": len(vba_code or ""),
                "suspicious": bool(hits),
                "autoExec": is_auto,
            })
    except Exception as exc:
        findings.append(_finding("low", "office-error", "Macro extraction error", str(exc)[:300], evidence="extract_macros"))
    finally:
        try:
            parser.close()
        except Exception:
            pass

    if not macro_source_present:
        findings.append(_finding("info", "office-clean", "No macros detected", "No VBA macro source found in the document", evidence="olevba scan"))
        return {"macroDetected": False, "macros": [], "autoExec": [], "suspiciousKeywords": []}

    if auto_exec:
        findings.append(_finding(
            "high", "office-autorun", "Auto-execute macro detected",
            f"Auto-run macro(s): {', '.join(auto_exec)}",
            evidence="macro name",
        ))
    if suspicious_hits:
        unique = list(dict.fromkeys(suspicious_hits))
        findings.append(_finding(
            "critical" if any(k in unique for k in ("powershell", "wscript.shell", "cmd.exe", "shell", "createobject")) else "high",
            "office-suspicious-macro",
            "Suspicious macro keywords",
            f"Suspicious keywords in macro code: {', '.join(unique)[:300]}",
            evidence="VBA source scan",
        ))

    return {"macroDetected": True, "macros": macros, "autoExec": auto_exec, "suspiciousKeywords": list(dict.fromkeys(suspicious_hits))}


def _macro_name(vba_filename: str) -> str:
    base = vba_filename.rsplit("/", 1)[-1]
    base = base.rsplit("\\", 1)[-1]
    if base.lower().endswith((".bas", ".cls", ".frm", ".txt")):
        base = base[:-4]
    return base or vba_filename


def _finding(severity, category, title, detail, evidence) -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail, "evidence": evidence, "mitre": None, "module": "office"}
