"""ReportLab document builder for the investigation PDF report.

`build_pdf(context)` assembles every section into a single professional
document with a header, footer and page numbers, and returns the PDF bytes.
No analysis logic lives here — the report is a presentation of the context
built by `service.py`.
"""
from __future__ import annotations

from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate

from app.services.reports import sections
from app.services.reports.styles import MARGIN, MUTED, PAGE_HEIGHT, PAGE_WIDTH, PRIMARY

_HEADER_TEXT = "AI-Powered Intelligent Sandbox \u2014 Secure File Investigation Report"
_FOOTER_TEXT = "Generated from deterministic static analysis \u2014 the sample was never executed."


def build_pdf(context: dict) -> bytes:
    """Render the report to bytes. Raises on rendering failure."""
    sections.reset()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=f"Secure File Investigation Report \u2014 {context.get('case_id', '')}",
        author="AI-Powered Intelligent Sandbox",
        subject=f"Investigation report for {context.get('case_id', '')}",
    )

    story: list = []
    story += sections.cover_page(context)
    story += sections.executive_summary(context)
    story += sections.file_information(context)
    story += sections.static_analysis(context)
    story += sections.observed_evidence(context)
    story += sections.detection_findings(context)
    story += sections.yara_results(context)
    story += sections.iocs(context)
    story += sections.threat_assessment(context)
    story += sections.mitre(context)
    story += sections.ai_investigation(context)
    story += sections.recommendations(context)
    story += sections.limitations(context)
    story += sections.report_metadata(context)

    doc.build(story, onFirstPage=_first_page, onLaterPages=_later_page)
    return buffer.getvalue()


def _first_page(cv, doc):
    cv.setStrokeColor(PRIMARY)
    cv.setLineWidth(1.2)
    cv.line(MARGIN, PAGE_HEIGHT - 14 * mm, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 14 * mm)
    cv.setFont("Helvetica", 8)
    cv.setFillColor(MUTED)
    cv.drawCentredString(PAGE_WIDTH / 2, PAGE_HEIGHT - 16 * mm,
                         "Secure File Investigation Report")
    _footer(cv, 1)


def _later_page(cv, doc):
    cv.setFont("Helvetica-Bold", 8)
    cv.setFillColor(PRIMARY)
    cv.drawString(MARGIN, PAGE_HEIGHT - 10 * mm, _HEADER_TEXT)
    cv.setFont("Helvetica", 8)
    cv.setFillColor(MUTED)
    cv.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 10 * mm, str(doc.page))
    cv.setStrokeColor(MUTED)
    cv.setLineWidth(0.5)
    cv.line(MARGIN, PAGE_HEIGHT - 11.5 * mm, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 11.5 * mm)
    _footer(cv, doc.page)


def _footer(cv, page_no):
    cv.setFont("Helvetica", 7.5)
    cv.setFillColor(MUTED)
    cv.drawCentredString(PAGE_WIDTH / 2, 12 * mm, _FOOTER_TEXT)
    cv.drawRightString(PAGE_WIDTH - MARGIN, 12 * mm, f"Page {page_no}")
