"""Report section builders.

Each function turns the report context dict into a list of ReportLab flowables
(sections are pure presentation — all data comes from the persisted analysis
payload, never recomputed here).
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from app.services.reports.styles import (
    HEADER_BG,
    MARGIN,
    PAGE_WIDTH,
    ROW_ALT,
    SEVERITY_COLORS,
    WHITE,
    build_styles,
)

_STYLES = build_styles()

USABLE = PAGE_WIDTH - 2 * MARGIN  # ~504pt on A4

# IOC types in display order; only non-empty groups are rendered.
IOC_ORDER = ["ip", "domain", "url", "email", "hash", "registry",
             "windows_path", "command", "mutex"]
IOC_LABELS = {
    "ip": "IP addresses",
    "domain": "Domains",
    "url": "URLs",
    "email": "Email addresses",
    "hash": "Hashes",
    "registry": "Registry keys",
    "windows_path": "File paths",
    "command": "Suspicious commands",
    "mutex": "Mutexes",
}

_SECTION_NUMBER = {"n": 0}


def _next_number() -> str:
    _SECTION_NUMBER["n"] += 1
    return f"{_SECTION_NUMBER['n']}."


def _s(style: str) -> ParagraphStyle:
    return _STYLES[style]


def _P(text: str, style: str, **kwargs) -> Paragraph:
    return Paragraph(escape(str(text or "")), _s(style), **kwargs)


def _bullet(text: str, style: str = "Bullet") -> Paragraph:
    return Paragraph(escape(str(text or "")), _s(style), bulletText="\u2022")


def _table(headers: list[str], rows: list[list[str]], col_widths: list[float],
           cell_style: str = "TableCell", mono_cols: set[int] | None = None) -> Table:
    mono_cols = mono_cols or set()
    header_row = [_P(h, "TableHeader") for h in headers]
    body = []
    for row in rows:
        cells = []
        for i, value in enumerate(row):
            style = "TableCellMono" if i in mono_cols else cell_style
            cells.append(_P(value, style))
        body.append(cells)
    table = Table([header_row, *body], colWidths=col_widths, repeatRows=1, splitByRow=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
    ]))
    return table


def _empty(text: str = "None observed") -> Paragraph:
    return _P(text, "BodyMuted")


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------

def cover_page(ctx: dict) -> list:
    meta = [
        ("Investigation ID", ctx["case_id"]),
        ("Report ID", ctx["report_id"]),
        ("Generated", ctx["generated_at_display"]),
        ("Analysis status", ctx["status_display"]),
        ("Classification", ctx["classification"]),
        ("Severity", ctx["severity"].upper()),
        ("Threat score", f"{ctx['score_total']}/100"),
        ("File", ctx["filename"]),
    ]
    rows = [[_P(k, "CoverMetaKey"), _P(v, "CoverMetaValue")] for k, v in meta]
    meta_table = Table(rows, colWidths=[USABLE * 0.34, USABLE * 0.66])
    meta_table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    return [
        Spacer(1, 60),
        _P("AI-Powered Intelligent Sandbox", "CoverProduct"),
        _P("Secure File Investigation Report", "CoverTitle"),
        _P("Static analysis, detection & evidence, and AI-assisted interpretation", "CoverSubtitle"),
        HRFlowable(width="40%", thickness=1.2, color=SEVERITY_COLORS.get("info", colors.HexColor("#4F46E5")), spaceAfter=24),
        Spacer(1, 30),
        meta_table,
        Spacer(1, 30),
        _P("This report is generated from deterministic static-analysis results. "
           "The sample was never executed. AI content, when present, is an "
           "interpretation of those results and is clearly labelled.",
           "CoverSubtitle"),
        PageBreak(),
    ]


# ---------------------------------------------------------------------------
# 1. Executive summary
# ---------------------------------------------------------------------------

def executive_summary(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Executive Summary", "SectionTitle")]

    summary = ctx.get("executive_summary") or "No summary available."
    if ctx.get("executive_label") == "ai":
        flow.append(_P(
            f"AI-assisted interpretation ({ctx.get('ai_label') or 'local model'}): {summary}",
            "Body",
        ))
    else:
        flow.append(_P("AI-assisted interpretation unavailable", "SectionSub"))
        flow.append(_P(summary, "Body"))

    # Key metrics strip
    flow.append(Spacer(1, 2))
    metrics = [
        ("Verdict", ctx["verdict"].upper()),
        ("Severity", ctx["severity"].upper()),
        ("Threat score", f"{ctx['score_total']}/100"),
        ("Classification", ctx["classification"]),
    ]
    rows = [[_P("<b>%s</b>" % k, "TableCell"), _P(v, "TableCell")] for k, v in metrics]
    flow.append(Table(rows, colWidths=[USABLE / 2, USABLE / 2],
                      splitByRow=1))
    flow.append(Spacer(1, 6))

    findings = ctx.get("major_findings") or []
    risks = ctx.get("major_risk_factors") or []
    flow.append(_P("Major findings", "SectionSub"))
    flow += [_bullet(f) for f in findings] if findings else [_empty("No major findings.")]
    flow.append(_P("Major risk factors", "SectionSub"))
    flow += [_bullet(r) for r in risks] if risks else [_empty("No major risk factors identified.")]
    return flow


# ---------------------------------------------------------------------------
# 2. File information
# ---------------------------------------------------------------------------

def file_information(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} File Information", "SectionTitle")]
    rows = [
        ("Original filename", ctx["filename"]),
        ("File size", f"{ctx['size_bytes']:,} bytes"),
        ("Detected file type", ctx["file_type"]),
        ("Family", ctx["family"]),
        ("MIME type", ctx["mime_type"]),
        ("Extension", ctx["extension"] or "none"),
        ("SHA-256", ctx["sha256"]),
        ("SHA-1", ctx["sha1"]),
        ("MD5", ctx["md5"]),
        ("Uploaded", ctx["uploaded_at_display"]),
        ("Investigation ID", f"{ctx['case_id']}  ({ctx['investigation_id']})"),
    ]
    table_rows = [[_P(k, "TableCell"), _P(v, "TableCellMono")] for k, v in rows]
    flow.append(Table(table_rows, colWidths=[USABLE * 0.3, USABLE * 0.7],
                      repeatRows=1, splitByRow=1))
    flow.append(Spacer(1, 2))
    flow.append(_P(
        "The sample is stored under an internal random identifier; the original "
        "filename is shown as submitted by the analyst.",
        "SectionCaption",
    ))
    return flow


# ---------------------------------------------------------------------------
# 3. Static analysis
# ---------------------------------------------------------------------------

def static_analysis(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Static Analysis", "SectionTitle")]
    static = ctx.get("static") or {}
    family = ctx.get("family", "other")

    flow.append(_P(
        "Deterministic static analysis of the file bytes. The sample was never "
        "executed during analysis.",
        "BodyMuted",
    ))

    # Header table: entropy + module status
    modules = ctx.get("modules") or {}
    module_summary = ", ".join(f"{k}: {v}" for k, v in sorted(modules.items())) or "n/a"
    entropy = static.get("entropy")
    header_rows = [
        ["Whole-file entropy", f"{entropy:.2f}" if isinstance(entropy, (int, float)) else "n/a"],
        ["Analysis modules", module_summary],
    ]
    flow.append(_table(["Property", "Value"], header_rows,
                       [USABLE * 0.32, USABLE * 0.68]))
    flow.append(Spacer(1, 6))

    # Family-specific sections (only applicable family is rendered)
    sections = _family_sections(family, static)
    if sections:
        flow += sections
    else:
        flow.append(_P("No family-specific analyzer output for this file type.", "BodyMuted"))

    # Metadata (PDF/Office)
    metadata = static.get("metadata") or {}
    if isinstance(metadata, dict) and metadata:
        flow.append(_P("Metadata", "SectionSub"))
        rows = [[str(k), str(v)[:160]] for k, v in list(metadata.items())[:30]]
        flow.append(_table(["Key", "Value"], rows, [USABLE * 0.32, USABLE * 0.68],
                           mono_cols={0}))

    # Strings
    strings = static.get("strings") or []
    flow.append(_P("Extracted strings", "SectionSub"))
    flow.append(_P(f"{len(strings)} strings extracted "
                   f"({sum(1 for s in strings if s.get('interesting'))} flagged interesting).", "SectionCaption"))
    interesting = [s for s in strings if s.get("interesting")][:40]
    if interesting:
        rows = [[s.get("type", "generic"), str(s.get("value", ""))[:200]]
                for s in interesting]
        flow.append(_table(["Type", "Value"], rows, [USABLE * 0.2, USABLE * 0.8],
                           mono_cols={1}))
    elif strings:
        flow.append(_P("No interesting strings flagged; generic strings only.", "BodyMuted"))
    else:
        flow.append(_empty("No strings extracted."))

    # PE sections (sections/imports) only for PE files
    if family == "pe":
        secs = static.get("sections") or []
        if secs:
            flow.append(_P("PE sections", "SectionSub"))
            rows = [[str(s.get("name", "")), str(s.get("virtual_size", "")),
                     str(s.get("raw_size", "")), str(s.get("flags", ""))] for s in secs[:30]]
            flow.append(_table(["Name", "Virtual size", "Raw size", "Flags"], rows,
                               [USABLE * 0.2, USABLE * 0.24, USABLE * 0.24, USABLE * 0.32],
                               mono_cols={0}))
        imports = static.get("imports") or []
        if imports:
            flow.append(_P("PE imports (suspicious)", "SectionSub"))
            rows = []
            for group in imports[:30]:
                dll = group.get("dll", "")
                for fn in (group.get("suspicious") or [])[:12]:
                    rows.append([dll, fn])
            flow.append(_table(["DLL", "Function"], rows,
                               [USABLE * 0.35, USABLE * 0.65], mono_cols={0, 1}))

    return flow


def _family_sections(family: str, static: dict) -> list:
    flow: list = []
    if family == "pdf":
        flow.append(_P("PDF analysis", "SectionSub"))
        flow.append(_P("PDF structure flags (actions, launch, embedded files) are "
                       "reported as detection findings below.", "BodyMuted"))
    elif family in ("ooxml", "ole"):
        flow.append(_P("Office document analysis", "SectionSub"))
        flow.append(_P("Office macro/auto-run indicators are reported as detection "
                       "findings below.", "BodyMuted"))
    elif family == "script":
        line_count = (static.get("lineCount") or 0)
        caps = static.get("capabilities") or []
        rows = [["Line count", str(line_count)]]
        for cap in caps[:20]:
            rows.append(["Capability", str(cap)[:200]])
        flow.append(_table(["Property", "Value"], rows,
                           [USABLE * 0.32, USABLE * 0.68], mono_cols={1}))
    return flow


# ---------------------------------------------------------------------------
# 4. Observed evidence
# ---------------------------------------------------------------------------

def observed_evidence(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Observed Evidence", "SectionTitle")]
    flow.append(_P(
        "Normalized signals observed directly in the file (strings, imports, "
        "YARA matches, metadata). Evidence is observed — never inferred. "
        "Inferences live in the detection findings.",
        "BodyMuted",
    ))
    evidence = ctx.get("evidence") or []
    if not evidence:
        flow.append(_empty("No observed evidence."))
        return flow
    flow.append(_P(f"{len(evidence)} evidence records.", "SectionCaption"))
    rows = []
    for e in evidence[:250]:
        rows.append([
            e.get("id", ""),
            e.get("type", ""),
            e.get("severity", "info"),
            e.get("source_module", ""),
            str(e.get("value", ""))[:160],
        ])
    flow.append(_table(
        ["ID", "Type", "Sev", "Module", "Value"],
        rows,
        [USABLE * 0.12, USABLE * 0.14, USABLE * 0.08, USABLE * 0.14, USABLE * 0.52],
        mono_cols={0, 4},
    ))
    return flow


# ---------------------------------------------------------------------------
# 5. Detection findings
# ---------------------------------------------------------------------------

def detection_findings(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Detection Findings", "SectionTitle")]
    flow.append(_P(
        "Findings combine analyzer output with deterministic correlation rules. "
        "Origin legend — <b>Observed</b>: analyzer signal (strings, imports, YARA). "
        "<b>Derived</b>: detection rule correlated over evidence "
        "(module starts with \u201cdetection:\u201d). The AI never produces "
        "detections.",
        "BodyMuted",
    ))
    findings = ctx.get("findings") or []
    if not findings:
        flow.append(_empty("No findings."))
        return flow
    flow.append(_P(f"{len(findings)} findings.", "SectionCaption"))
    rows = []
    for f in findings[:250]:
        module = f.get("module", "")
        origin = "Derived" if str(module).startswith("detection:") else "Observed"
        rows.append([
            f.get("severity", "info"),
            f.get("category", ""),
            f.get("title", ""),
            str(f.get("detail", ""))[:220],
            f"{float(f.get('confidence') or 0):.2f}",
            origin,
            module,
        ])
    flow.append(_table(
        ["Sev", "Category", "Finding", "Detail", "Conf", "Origin", "Module"],
        rows,
        [USABLE * 0.07, USABLE * 0.14, USABLE * 0.19, USABLE * 0.26,
         USABLE * 0.08, USABLE * 0.09, USABLE * 0.17],
        mono_cols={6},
    ))
    return flow


# ---------------------------------------------------------------------------
# 6. YARA results
# ---------------------------------------------------------------------------

def yara_results(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} YARA Results", "SectionTitle")]
    hits = ctx.get("yara") or []
    flow.append(_P(
        "Matched by the built-in pure-Python \u201cyara-lite\u201d subset engine. "
        "YARA-lite is not the full YARA engine; matches are deterministic and "
        "require the supported literal/regex/hex string and condition grammar.",
        "BodyMuted",
    ))
    if not hits:
        flow.append(_empty("No YARA rules matched."))
        return flow
    flow.append(_P(f"{len(hits)} rule(s) matched.", "SectionCaption"))
    rows = []
    for hit in hits[:100]:
        rows.append([
            hit.get("rule", ""),
            str(hit.get("description", ""))[:180],
            hit.get("severity", "medium"),
            hit.get("mitre", ""),
            ", ".join(hit.get("matchedStrings") or [])[:160],
        ])
    flow.append(_table(
        ["Rule", "Description", "Sev", "MITRE", "Matched strings"],
        rows,
        [USABLE * 0.18, USABLE * 0.3, USABLE * 0.08, USABLE * 0.12, USABLE * 0.32],
        mono_cols={0},
    ))
    return flow


# ---------------------------------------------------------------------------
# 7. Indicators of compromise
# ---------------------------------------------------------------------------

def iocs(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Indicators of Compromise", "SectionTitle")]
    iocs = ctx.get("iocs") or []
    flow.append(_P(
        "De-duplicated indicators extracted deterministically from observed "
        "evidence and strings. Provenance lists the modules that observed each "
        "indicator. An IOC is an indicator, not a verdict.",
        "BodyMuted",
    ))
    if not iocs:
        flow.append(_empty("No IOCs extracted."))
        return flow

    grouped: dict[str, list[dict]] = {}
    for ioc in iocs:
        grouped.setdefault(ioc.get("type", "other"), []).append(ioc)

    for ioc_type in IOC_ORDER:
        items = grouped.get(ioc_type)
        if not items:
            continue
        flow.append(_P(IOC_LABELS.get(ioc_type, ioc_type.title()), "SectionSub"))
        rows = []
        for ioc in items[:250]:
            sources = sorted({s.get("module", "") for s in ioc.get("sources") or []})
            rows.append([
                str(ioc.get("value", "")),
                f"{float(ioc.get('confidence') or 0):.2f}",
                ", ".join(sources)[:120],
                ",".join(ioc.get("mitre_techniques") or []),
            ])
        flow.append(_table(
            ["Value", "Conf", "Observed by", "MITRE"],
            rows,
            [USABLE * 0.52, USABLE * 0.1, USABLE * 0.24, USABLE * 0.14],
            mono_cols={0},
        ))

    for ioc_type in grouped:
        if ioc_type not in IOC_ORDER:
            flow.append(_P(ioc_type.title(), "SectionSub"))
            rows = [[str(i.get("value", ""))] for i in grouped[ioc_type][:250]]
            flow.append(_table(["Value"], rows, [USABLE], mono_cols={0}))
    return flow


# ---------------------------------------------------------------------------
# 8. Threat assessment
# ---------------------------------------------------------------------------

def threat_assessment(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Threat Assessment", "SectionTitle")]
    flow.append(_P(
        "<b>Deterministic threat assessment.</b> The numerical score, severity, "
        "verdict and classification below were produced by the deterministic "
        "scoring engine from observed findings — not by the AI. The AI only "
        "interprets this output.",
        "BodyMuted",
    ))
    score = ctx.get("score") or {}
    rows = [
        ["Score", f"{ctx['score_total']}/100"],
        ["Severity", ctx["severity"].upper()],
        ["Verdict", ctx["verdict"].upper()],
        ["Classification", ctx["classification"]],
    ]
    flow.append(_table(["Property", "Value"], rows, [USABLE * 0.32, USABLE * 0.68]))
    flow.append(Spacer(1, 4))
    breakdown = score.get("breakdown") or []
    if breakdown:
        flow.append(_P("Score breakdown (points per category, capped at 100)", "SectionSub"))
        rows = [[str(b.get("category", "")), f"{int(b.get('points') or 0)}",
                 str(b.get("max", ""))] for b in breakdown[:30]]
        flow.append(_table(["Category", "Points", "Max"], rows,
                           [USABLE * 0.4, USABLE * 0.2, USABLE * 0.2], mono_cols={1}))
    method = score.get("method")
    if method:
        flow.append(Spacer(1, 2))
        flow.append(_P(f"Scoring method: {method}", "SectionCaption"))
    return flow


# ---------------------------------------------------------------------------
# 9. MITRE ATT&CK
# ---------------------------------------------------------------------------

def mitre(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} MITRE ATT&amp;CK Mapping", "SectionTitle")]
    flow.append(_P(
        "Evidence-backed technique mappings. Only techniques supported by "
        "observed findings are listed — no mapping is generated inside the "
        "report.",
        "BodyMuted",
    ))
    techniques = ctx.get("mitre") or []
    if not techniques:
        flow.append(_empty("No MITRE ATT&CK techniques were mapped for this sample."))
        return flow
    flow.append(_P(f"{len(techniques)} technique(s) mapped.", "SectionCaption"))
    rows = []
    for t in techniques[:100]:
        evidence = (t.get("evidence") or [])
        rows.append([
            t.get("technique_id", ""),
            t.get("technique", ""),
            t.get("tactic", ""),
            f"{float(t.get('confidence') or 0):.2f}",
            ", ".join(t.get("source_modules") or [])[:120],
            str(evidence[0])[:160] if evidence else "",
        ])
    flow.append(_table(
        ["ID", "Technique", "Tactic", "Conf", "Sources", "Evidence"],
        rows,
        [USABLE * 0.11, USABLE * 0.2, USABLE * 0.14, USABLE * 0.08,
         USABLE * 0.17, USABLE * 0.3],
        mono_cols={0},
    ))
    return flow


# ---------------------------------------------------------------------------
# 10. AI-assisted investigation
# ---------------------------------------------------------------------------

def ai_investigation(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} AI-Assisted Investigation", "SectionTitle")]
    ai = ctx.get("ai")
    status = (ai or {}).get("status")

    if status != "completed":
        if status == "error":
            flow.append(_P(
                "AI-assisted interpretation could not be validated at the time of "
                "report generation. The response was rejected and is not shown.",
                "CalloutMuted",
            ))
        else:
            flow.append(_P(
                "AI-assisted interpretation was unavailable at the time of report "
                "generation. The deterministic sections of this report are complete "
                "and unaffected.",
                "CalloutMuted",
            ))
        return flow

    flow.append(_P(
        f"Validated AI interpretation. Provider: {escape(ai.get('provider') or 'ollama')} "
        f"{escape('· ' + ai.get('model')) if ai.get('model') else ''} · "
        f"generated {escape(ai.get('generated_at') or '')}. "
        "The AI interprets deterministic results only; it cannot add detections, "
        "IOCs or MITRE techniques.",
        "SectionCaption",
    ))

    if ai.get("executive_summary"):
        flow.append(_P("Executive summary", "SectionSub"))
        flow.append(_P(ai["executive_summary"], "Callout"))
    if ai.get("technical_summary"):
        flow.append(_P("Technical summary", "SectionSub"))
        flow.append(_P(ai["technical_summary"], "Body"))
    if ai.get("threat_explanation"):
        flow.append(_P("Threat explanation", "SectionSub"))
        flow.append(_P(ai["threat_explanation"], "Body"))

    for label, key in (("Key findings", "key_findings"), ("Risk factors", "risk_factors"),
                       ("Business impact", "business_impact"), ("Limitations", "limitations")):
        items = ai.get(key) or []
        if items:
            flow.append(_P(label, "SectionSub"))
            flow += [_bullet(i) for i in items]

    mitre_exp = ai.get("mitre_explanation") or []
    if mitre_exp:
        flow.append(_P("MITRE explanation", "SectionSub"))
        rows = [[m.get("technique_id", ""), str(m.get("explanation", ""))[:240]]
                for m in mitre_exp]
        flow.append(_table(["Technique", "Explanation"], rows,
                           [USABLE * 0.16, USABLE * 0.84], mono_cols={0}))

    ai_recs = ai.get("recommendations") or []
    if ai_recs:
        flow.append(_P("AI recommendations", "SectionSub"))
        for r in ai_recs[:8]:
            flow.append(_bullet(f"[{escape(str(r.get('priority', 'medium')).upper())}] "
                                f"{escape(r.get('action', ''))}"))

    confidence = ai.get("confidence")
    if isinstance(confidence, (int, float)):
        flow.append(_P(f"Model confidence: {int(confidence)}/100", "SectionSub"))

    provenance = ai.get("provenance") or {}
    flow.append(Spacer(1, 2))
    flow.append(_P(
        f"Provenance: interpreted {provenance.get('findings_used', 0)} findings, "
        f"{provenance.get('iocs_used', 0)} IOCs and "
        f"{provenance.get('mitre_used', 0)} MITRE mappings.",
        "SectionCaption",
    ))
    return flow


# ---------------------------------------------------------------------------
# 11. Recommendations
# ---------------------------------------------------------------------------

def recommendations(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Recommendations", "SectionTitle")]
    recs = ctx.get("recommendations") or []
    deterministic = [r for r in recs if r.get("source") == "deterministic"]
    ai_recs = [r for r in recs if r.get("source") == "ai"]

    if deterministic:
        flow.append(_P("Deterministic recommendations (derived from findings)", "SectionSub"))
        for r in deterministic[:8]:
            flow.append(_bullet(r["action"]))

    if ai_recs:
        flow.append(_P("AI-assisted recommendations", "SectionSub"))
        for r in ai_recs[:8]:
            flow.append(_bullet(f"[{escape(r.get('priority', 'medium').upper())}] {r['action']}"))
        flow.append(_P(
            "AI recommendations are interpretations and should be validated "
            "against the deterministic findings above.",
            "SectionCaption",
        ))

    if not recs:
        flow.append(_empty("No recommendations were derived for this sample."))
    return flow


# ---------------------------------------------------------------------------
# 12. Limitations
# ---------------------------------------------------------------------------

def limitations(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Limitations", "SectionTitle")]
    items = [
        "Static analysis only — the file was not executed.",
        "Runtime behaviour was not observed (no detonation).",
        "Network behaviour was not observed.",
        "The investigation graph represents observed evidence, not actual runtime execution.",
        "Detection results depend on the available analysis modules and rules.",
        "YARA matching uses the built-in yara-lite subset engine, not the full YARA engine.",
        "Digital signatures are reported as present/absent; they are not cryptographically verified on this host.",
        "AI-assisted interpretation may be unavailable or unvalidated; deterministic sections are unaffected.",
    ]
    flow += [_bullet(i) for i in items]
    return flow


# ---------------------------------------------------------------------------
# 13. Report metadata
# ---------------------------------------------------------------------------

def report_metadata(ctx: dict) -> list:
    flow = [_P(f"{_next_number()} Report Metadata", "SectionTitle")]
    rows = [
        ["Report ID", ctx["report_id"]],
        ["Generated (UTC)", ctx["generated_at"]],
        ["Investigation ID", ctx["case_id"]],
        ["AI-assisted interpretation", ctx["ai_label"] or "not used"],
        ["Data source", "Persisted deterministic analysis results"],
    ]
    flow.append(_table(["Field", "Value"], rows, [USABLE * 0.32, USABLE * 0.68],
                       mono_cols={1}))
    return flow


def reset() -> None:
    _SECTION_NUMBER["n"] = 0
