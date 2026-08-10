"""Phase 7 — investigation PDF report generation (presentation layer).

Public API:
    generate_report_pdf(investigation_id, db) -> bytes
    ReportNotFoundError, AnalysisIncompleteError, ReportGenerationError
"""
from app.services.reports.service import (
    AnalysisIncompleteError,
    ReportGenerationError,
    ReportNotFoundError,
    build_context,
    generate_report_pdf,
)

__all__ = [
    "AnalysisIncompleteError",
    "ReportGenerationError",
    "ReportNotFoundError",
    "build_context",
    "generate_report_pdf",
]
