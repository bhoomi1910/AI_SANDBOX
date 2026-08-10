"""Investigation PDF report service (presentation layer).

`generate_report_pdf(investigation_id, db)` loads the persisted investigation
and its analysis payload, builds a context dict, and renders the PDF.

Guarantees:
- The report NEVER recomputes hashes, entropy, scores, IOCs or MITRE mappings —
  it formats the persisted results.
- The report NEVER calls Ollama. AI content is included only from the validated
  result already cached on the stored payload; otherwise a clear
  unavailable/error state is rendered.
- No internal filesystem paths or secrets are ever placed in the report.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import AnalysisResult, Investigation
from app.services.reports import pdf as pdf_mod

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportNotFoundError(Exception):
    """The investigation does not exist."""


class AnalysisIncompleteError(Exception):
    """The investigation has no persisted (completed) analysis to report on."""


# Category -> safe, generic deterministic recommendation. These actions are
# derived from the deterministic finding categories — they never invent
# technical specifics that the analysis did not observe.
RECOMMENDATION_ACTIONS: dict[str, str] = {
    "anti-debug": "Sandbox the sample only in tooling that tolerates anti-debug checks.",
    "code-signature": "Verify the Authenticode signature on a trusted host; unsigned or mismatched signatures warrant review.",
    "command-execution": "Correlate process-execution logs for the observed commands / LOLBins and quarantine the affected host.",
    "credential-access": "Investigate for credential access; rotate any exposed credentials and review LSASS access.",
    "downloader": "Block the identified download URL/domain/IP and review the host for the downloaded payload.",
    "keylogging": "Scan for keyboard-hooking modules and investigate potential keystroke capture.",
    "malformed-pe": "Treat the malformed executable as suspicious; do not run it on an unisolated host.",
    "masquerading": "Confirm the file's true type; spoofed extensions often mask payloads.",
    "network-communication": "Review egress logs for connections to the observed domains/IPs and block at the firewall if unapproved.",
    "obfuscation": "Treat encoded/obfuscated content as high-risk; scan the environment for files with identical hashes.",
    "office-autorun": "Review auto-open / auto-run content in the Office document only in a sandbox.",
    "office-suspicious-macro": "Do not enable macros from this document; extract and review the VBA in a sandbox.",
    "pdf-auto-js": "Review automatic JavaScript actions in a sandboxed PDF viewer.",
    "pdf-embedded": "Extract and analyse the embedded attachments only in a sandbox.",
    "pdf-javascript": "Review the JavaScript actions in a sandboxed PDF viewer.",
    "pdf-launch": "Do not open this PDF on an unisolated host; extract embedded payloads only in a sandbox.",
    "pdf-links": "Do not visit the embedded links from an unisolated host.",
    "pdf-openaction": "Open the PDF only in a sandboxed viewer; verify the OpenAction behaviour.",
    "pdf-xfa": "Analyse the XFA content in a sandbox; XFA forms are frequently used in phishing.",
    "persistence": "Check scheduled tasks, services and startup folders for references to this sample.",
    "persistence-registry": "Audit the referenced registry Run keys/values on the affected host.",
    "persistence-service": "Review scheduled tasks and services for references to this sample.",
    "powershell": "Hunt for similar encoded PowerShell across the environment and restrict PowerShell execution policy where appropriate.",
    "privilege-escalation": "Check token-privilege usage on the host and investigate privilege-escalation paths.",
    "process-injection": "Look for injected processes with the observed imports; collect memory for further analysis.",
    "remote-access": "Check for remote-access tooling and revoke it if unauthorised.",
    "sandbox-evasion": "Run analysis under multiple sandbox profiles to counter evasion checks.",
    "yara": "Investigate the YARA matches on all hosts that processed this file.",
}


def generate_report_pdf(investigation_id: str, db: Session) -> bytes:
    """Generate the PDF report bytes for a persisted investigation."""
    inv = db.get(Investigation, investigation_id)
    if inv is None:
        raise ReportNotFoundError(investigation_id)

    payload = _load_payload(db, investigation_id)
    if payload is None or payload.get("corrupt"):
        raise AnalysisIncompleteError(
            "Static analysis has not completed for this investigation yet."
        )

    context = build_context(inv, payload)
    try:
        return pdf_mod.build_pdf(context)
    except Exception as exc:  # noqa: BLE001 — surface a safe, generic error
        logger.exception("PDF rendering failed for investigation %s", investigation_id)
        raise ReportGenerationError(str(exc)) from exc


class ReportGenerationError(Exception):
    """The PDF could not be rendered."""


def build_context(inv: Investigation, payload: dict) -> dict:
    """Assemble the report context from the investigation + stored payload.

    Pure data shaping — no analysis is recomputed here.
    """
    static = payload.get("static") or {}
    score = payload.get("score") or {}
    findings = payload.get("findings") or []
    iocs = payload.get("iocs") or []
    mitre = payload.get("mitre") or []
    evidence = payload.get("evidence") or []
    ai = payload.get("ai") if isinstance(payload.get("ai"), dict) else None

    generated = datetime.now(timezone.utc)
    ai_ok = ai is not None and ai.get("status") == "completed"

    ctx: dict = {
        "case_id": inv.case_id,
        "investigation_id": inv.id,
        "report_id": f"RPT-{inv.case_id}-{generated:%Y%m%d%H%M%S}",
        "generated_at": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_at_display": generated.strftime("%d %b %Y %H:%M:%S UTC"),

        "filename": inv.filename,
        "file_type": inv.file_type,
        "mime_type": inv.mime_type or _mime_display(payload),
        "extension": _extension_of(inv.filename),
        "size_bytes": inv.size_bytes,
        "sha256": inv.sha256,
        "sha1": inv.sha1,
        "md5": inv.md5,
        "uploaded_at_display": _format_dt(inv.uploaded_at),

        "status": inv.status,
        "status_display": _status_display(inv.status),
        "classification": inv.classification,
        "severity": inv.severity,
        "verdict": inv.verdict,
        "family": payload.get("family") or inv.file_type,
        "description": payload.get("description", ""),
        "modules": payload.get("modules") or {},
        "score_total": int(score.get("total") or inv.risk_score or 0),

        "static": static,
        "findings": findings,
        "evidence": evidence,
        "iocs": iocs,
        "mitre": mitre,
        "yara": static.get("yara") or [],
        "score": score,
        "ai": ai,
        "ai_label": (f"{ai.get('provider')} / {ai.get('model')}" if ai_ok else None),
        "note": payload.get("note", ""),
    }

    # Executive summary: validated AI text when available, otherwise a clearly
    # labelled deterministic fallback. Never an invented AI summary.
    if ai_ok and ai.get("executive_summary"):
        ctx["executive_summary"] = ai["executive_summary"]
        ctx["executive_label"] = "ai"
    else:
        ctx["executive_summary"] = _deterministic_summary(ctx, findings)
        ctx["executive_label"] = "deterministic"

    ctx["major_findings"] = _major_findings(findings)
    ctx["major_risk_factors"] = _major_risks(findings)
    ctx["recommendations"] = _recommendations(findings, ai)
    return ctx


# ---------------------------------------------------------------------------
# Derivation helpers (formatting only — no analysis recomputed)
# ---------------------------------------------------------------------------

def _deterministic_summary(ctx: dict, findings: list[dict]) -> str:
    top = sorted(
        (f for f in findings if f.get("severity") in ("high", "critical", "medium")),
        key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")),
    )
    top_line = ""
    if top:
        f = top[0]
        top_line = (f" The most significant indicator is \"{f.get('title', '')}\" "
                    f"({f.get('category', '')}, severity {f.get('severity')}).")
    categories = sorted({f.get("category") for f in findings
                         if f.get("severity") in ("high", "critical", "medium")})
    cats = ", ".join(categories) if categories else "no notable indicators"
    return (
        f"Deterministic static analysis classified this sample as "
        f"{ctx['classification']} (verdict {ctx['verdict']}, severity "
        f"{ctx['severity']}, score {ctx['score_total']}/100). Observed: {cats}."
        f"{top_line} Extracted {len(ctx['iocs'])} indicator(s) of compromise and "
        f"mapped {len(ctx['mitre'])} MITRE ATT&CK technique(s). This summary is "
        f"generated from deterministic findings because the AI-assisted "
        f"interpretation was unavailable."
    )


def _major_findings(findings: list[dict]) -> list[str]:
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.get("severity", "info")))
    out: list[str] = []
    seen: set[str] = set()
    for f in ordered:
        key = f.get("title", "")
        if key and key not in seen and len(out) < 6:
            seen.add(key)
            out.append(f"{key} ({f.get('category', '')}, {f.get('severity')})")
    return out


def _major_risks(findings: list[dict]) -> list[str]:
    categories = [f.get("category") for f in findings
                  if f.get("severity") in ("high", "critical")]
    unique = list(dict.fromkeys(c for c in categories if c))
    return unique[:8]


def _recommendations(findings: list[dict], ai: dict | None) -> list[dict]:
    recs: list[dict] = []
    categories = [f.get("category") for f in findings
                  if f.get("severity") in ("medium", "high", "critical")]
    seen: set[str] = set()
    for cat in categories:
        action = RECOMMENDATION_ACTIONS.get(cat)
        if action and cat not in seen:
            seen.add(cat)
            recs.append({"source": "deterministic", "priority": "medium", "action": action})
        if len(recs) >= 8:
            break
    if not recs and findings:
        recs.append({
            "source": "deterministic",
            "priority": "medium",
            "action": "Quarantine the sample and investigate any host that received or executed it.",
        })

    if ai and ai.get("status") == "completed":
        for r in (ai.get("recommendations") or [])[:8]:
            recs.append({
                "source": "ai",
                "priority": r.get("priority", "medium"),
                "action": r.get("action", ""),
            })
    return recs


def _extension_of(filename: str) -> str:
    try:
        return Path(filename).suffix or ""
    except (ValueError, OSError):
        return ""


def _format_dt(value) -> str:
    if value is None:
        return "n/a"
    try:
        return value.strftime("%d %b %Y %H:%M:%S UTC")
    except (AttributeError, ValueError):
        return "n/a"


def _status_display(status: str) -> str:
    return {
        "queued": "Queued",
        "running": "Running",
        "analysing": "Analysing",
        "ai-processing": "AI processing",
        "completed": "Completed",
        "failed": "Failed",
    }.get(status, status.title())


def _mime_display(payload: dict) -> str:
    ft = payload.get("fileType")
    return {
        "exe": "application/vnd.microsoft.portable-executable",
        "pdf": "application/pdf",
        "script": "text/plain",
        "image": "application/octet-stream",
    }.get(ft, "application/octet-stream")


def _load_payload(db: Session, investigation_id: str) -> dict | None:
    result = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.investigation_id == investigation_id)
        .order_by(AnalysisResult.created_at.desc())
        .first()
    )
    if result is None:
        return None
    try:
        payload = json.loads(result.data)
    except (TypeError, ValueError):
        return {"corrupt": True}
    return payload if isinstance(payload, dict) else None
