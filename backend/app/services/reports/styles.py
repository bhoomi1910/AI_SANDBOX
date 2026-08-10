"""ReportLab styles shared by the investigation PDF report.

Kept in one module so the PDF layout is consistent and easy to adjust. All
content is produced by `sections.py` (flowables) and rendered by `pdf.py`.
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 16 * mm

# Palette (matches the frontend theme)
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6B7280")
PRIMARY = colors.HexColor("#4F46E5")
ACCENT = colors.HexColor("#8B5CF6")
GRID = colors.HexColor("#E5E7EB")
HEADER_BG = colors.HexColor("#EEF2FF")
ROW_ALT = colors.HexColor("#F9FAFB")
WHITE = colors.white

SEVERITY_COLORS: dict[str, colors.Color] = {
    "critical": colors.HexColor("#B91C1C"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#B45309"),
    "low": colors.HexColor("#15803D"),
    "info": colors.HexColor("#475569"),
}

FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"
FONT_MONO_BOLD = "Courier-Bold"


def _base(font: str = FONT) -> ParagraphStyle:
    return ParagraphStyle(
        name="base",
        fontName=font,
        fontSize=9.5,
        leading=13,
        textColor=INK,
        spaceAfter=4,
        alignment=TA_LEFT,
        wordWrap="CJK",  # wraps long tokens (URLs, hashes, paths) without spaces
    )


def build_styles() -> dict[str, ParagraphStyle]:
    """Return the style sheet used by every section."""
    base = _base()
    return {
        # Cover page
        "CoverProduct": ParagraphStyle(
            "CoverProduct", parent=base, fontName=FONT_BOLD, fontSize=22,
            leading=28, textColor=PRIMARY, alignment=TA_CENTER, spaceAfter=6,
        ),
        "CoverTitle": ParagraphStyle(
            "CoverTitle", parent=base, fontName=FONT_BOLD, fontSize=16,
            leading=22, textColor=INK, alignment=TA_CENTER, spaceAfter=2,
        ),
        "CoverSubtitle": ParagraphStyle(
            "CoverSubtitle", parent=base, fontSize=10, leading=15,
            textColor=MUTED, alignment=TA_CENTER, spaceAfter=18,
        ),
        "CoverMetaKey": ParagraphStyle(
            "CoverMetaKey", parent=base, fontSize=8, leading=12,
            textColor=MUTED, alignment=TA_LEFT, spaceAfter=1,
        ),
        "CoverMetaValue": ParagraphStyle(
            "CoverMetaValue", parent=base, fontName=FONT_BOLD, fontSize=10.5,
            leading=14, textColor=INK, alignment=TA_LEFT, spaceAfter=7,
        ),

        # Body
        "Body": ParagraphStyle("Body", parent=base, spaceAfter=6),
        "BodyMuted": ParagraphStyle(
            "BodyMuted", parent=base, textColor=MUTED, spaceAfter=6,
        ),
        "Small": ParagraphStyle(
            "Small", parent=base, fontSize=8, leading=11, textColor=MUTED,
        ),
        "Bullet": ParagraphStyle(
            "Bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3,
        ),

        # Section headings
        "SectionTitle": ParagraphStyle(
            "SectionTitle", parent=base, fontName=FONT_BOLD, fontSize=12.5,
            leading=16, textColor=PRIMARY, spaceBefore=12, spaceAfter=2,
            keepWithNext=1,
        ),
        "SectionSub": ParagraphStyle(
            "SectionSub", parent=base, fontName=FONT_BOLD, fontSize=10,
            leading=14, textColor=INK, spaceBefore=6, spaceAfter=2,
            keepWithNext=1,
        ),
        "SectionCaption": ParagraphStyle(
            "SectionCaption", parent=base, fontSize=8, leading=11,
            textColor=MUTED, spaceAfter=4,
        ),

        # Tables
        "TableHeader": ParagraphStyle(
            "TableHeader", parent=base, fontName=FONT_BOLD, fontSize=7.5,
            leading=10, textColor=INK, spaceAfter=0, alignment=TA_LEFT,
        ),
        "TableCell": ParagraphStyle(
            "TableCell", parent=base, fontSize=7.5, leading=10,
            spaceAfter=0, wordWrap="CJK",
        ),
        "TableCellMono": ParagraphStyle(
            "TableCellMono", parent=base, fontName=FONT_MONO, fontSize=7,
            leading=9.5, spaceAfter=0, textColor=INK, wordWrap="CJK",
        ),
        "TableNote": ParagraphStyle(
            "TableNote", parent=base, fontSize=7.5, leading=10,
            textColor=MUTED, spaceAfter=0, wordWrap="CJK",
        ),

        # AI / callouts
        "Callout": ParagraphStyle(
            "Callout", parent=base, backColor=colors.HexColor("#F5F3FF"),
            borderColor=ACCENT, borderWidth=0.6, borderPadding=6,
            spaceBefore=4, spaceAfter=8, textColor=INK,
        ),
        "CalloutMuted": ParagraphStyle(
            "CalloutMuted", parent=base, backColor=colors.HexColor("#F8FAFC"),
            borderColor=GRID, borderWidth=0.6, borderPadding=6,
            spaceBefore=4, spaceAfter=8, textColor=MUTED,
        ),
    }
