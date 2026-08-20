"""Prompt builder for the Phase 4 AI engine.

Builds a single deterministic prompt from the Phase 3 output (evidence,
findings, IOCs, MITRE mappings, score). The prompt is deliberately
constraining:

- the AI EXPLAINS the deterministic analysis; it never performs analysis,
- the AI must not invent IOCs, techniques, families, runtime behaviour, or a
  threat score (the score/verdict is already computed and authoritative),
- the AI must answer with JSON only, exactly matching the schema described.

Every important claim should reference the listed findings/evidence.
"""
from __future__ import annotations

import re


def _sanitize_for_prompt(value: str) -> str:
    """Remove newlines and control characters to prevent prompt injection via filenames."""
    return re.sub(r'[\x00-\x1f\x7f\n\r]', '', str(value))[:200]


_SCHEMA_DOC = """Respond with a single JSON object and nothing else. Schema:
{
  "executive_summary": "string, 2-4 sentences, plain language",
  "technical_summary": "string, technical but concise",
  "threat_explanation": "string, explain what the evidence indicates",
  "key_findings": ["string", ...],          // max 8, one per distinct finding
  "risk_factors": ["string", ...],           // max 8, evidence-linked
  "mitre_explanation": [{"technique_id": "T####", "explanation": "string"}], // ids ONLY from the list below
  "recommendations": [{"priority": "immediate|high|medium", "action": "string"}], // max 8
  "confidence": 0,                            // integer 0-100: confidence in YOUR explanation
  "business_impact": ["string", ...],         // max 5, best-effort impact assessment
  "limitations": ["string", ...]              // max 5, what this static analysis cannot show
}
Do not add markdown, commentary, or fields outside this schema."""

_RULES = (
    "You are a malware-analysis assistant for an automated sandbox.\n"
    "Input below is the OUTPUT of a deterministic static-analysis engine. "
    "It was produced without executing the sample.\n"
    "Your only job is to interpret and explain that output for an analyst.\n"
    "Hard rules (these are enforced programmatically, violations are rejected):\n"
    "1. Never invent IOCs, domains, IPs, hashes, file paths or email addresses.\n"
    "2. Never invent MITRE technique ids: every id in 'mitre_explanation' must "
    "appear in the 'Deterministic MITRE mappings' section.\n"
    "3. Never assign a malware family or threat score: the verdict and score are "
    "already computed and authoritative. You may summarize them, not override them.\n"
    "4. Never claim runtime behaviour (process injection, network traffic, "
    "execution, persistence happening) that the evidence below does not show.\n"
    "5. Never contradict a deterministic finding; flag uncertainty in 'limitations'.\n"
    "6. Base every conclusion on the data below and reference it where possible."
)


def build_prompt(context: dict) -> str:
    """Render `context` (see service module docstring) into a model prompt."""
    score = context.get("score") or {}
    mitre = context.get("mitre") or []
    findings = context.get("findings") or []
    iocs = context.get("iocs") or []
    evidence = context.get("evidence") or []
    static = context.get("static") or {}
    file_info = context.get("file") or {}

    lines = [_RULES, "", "## Deterministic analysis output", ""]

    lines.append("### File")
    safe_filename = _sanitize_for_prompt(file_info.get('filename', 'unknown'))
    lines.append(f"- filename: {safe_filename}")
    lines.append(f"- type: {file_info.get('file_type', 'unknown')} / family: {file_info.get('family', 'unknown')}")
    lines.append(f"- classification: {context.get('classification', 'n/a')}")
    lines.append("")

    lines.append("### Threat score (authoritative, do not recompute)")
    lines.append(f"- total: {score.get('total')} severity: {score.get('severity')} verdict: {score.get('verdict')}")
    for row in (score.get("breakdown") or [])[:10]:
        lines.append(f"- {row.get('category')}: {row.get('points')} points")
    if static.get("entropy") is not None:
        lines.append(f"- entropy: {static.get('entropy')} (max 8)")
    if static.get("yara"):
        lines.append(f"- YARA rule hits: {len(static.get('yara'))}")
    lines.append("")

    lines.append("### Findings (detections and correlations)")
    if not findings:
        lines.append("- none")
    for f in findings[:40]:
        mitre_ids = ", ".join(f.get("mitre_techniques") or ([f["mitre"]] if f.get("mitre") else []))
        lines.append(
            f"- [{f.get('severity', 'info')}] {f.get('title')} | confidence "
            f"{f.get('confidence')} | module {f.get('module', '?')} | mitre {mitre_ids or 'n/a'}"
        )
        if f.get("detail"):
            lines.append(f"    detail: {str(f.get('detail'))[:200]}")
        if f.get("evidence"):
            lines.append(f"    evidence: {str(f.get('evidence'))[:200]}")
    lines.append("")

    lines.append("### IOCs (deterministic — never add to this list)")
    if not iocs:
        lines.append("- none")
    for i in iocs[:30]:
        lines.append(f"- {i.get('type')}: {i.get('value')} | severity {i.get('severity')} | confidence {i.get('confidence')}")
    lines.append("")

    lines.append("### Deterministic MITRE mappings (ids are the ONLY ids allowed below)")
    if not mitre:
        lines.append("- none")
    for m in mitre[:15]:
        lines.append(
            f"- {m.get('technique_id')} {m.get('technique')} "
            f"({m.get('tactic')}) confidence {m.get('confidence')}"
        )
    lines.append("")

    cats: dict[str, int] = {}
    for ev in evidence:
        cats[ev.get("category", "other")] = cats.get(ev.get("category", "other"), 0) + 1
    lines.append("### Evidence inventory (observed signals by category)")
    if not cats:
        lines.append("- none")
    for cat, n in sorted(cats.items(), key=lambda kv: kv[1], reverse=True):
        lines.append(f"- {cat}: {n}")
    lines.append("")

    lines.append(_SCHEMA_DOC)
    return "\n".join(lines)
