"""Dashboard statistics computed from the database."""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Investigation

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITY_COLORS = {
    "critical": "#f43f5e",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#38bdf8",
    "clean": "#34d399",
    "info": "#38bdf8",
}


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Investigation.id)).scalar() or 0
    active = (
        db.query(func.count(Investigation.id))
        .filter(Investigation.status.in_(["queued", "running", "analysing", "ai-processing"]))
        .scalar()
        or 0
    )
    critical = (
        db.query(func.count(Investigation.id))
        .filter(Investigation.severity == "critical")
        .scalar()
        or 0
    )
    completed = (
        db.query(func.count(Investigation.id)).filter(Investigation.status == "completed").scalar()
        or 0
    )

    status_counts = dict(
        db.query(Investigation.status, func.count(Investigation.id)).group_by(Investigation.status).all()
    )
    severity_counts = dict(
        db.query(Investigation.severity, func.count(Investigation.id))
        .group_by(Investigation.severity)
        .all()
    )

    severity_breakdown = [
        {
            "name": sev.capitalize(),
            "value": severity_counts.get(sev, 0),
            "color": SEVERITY_COLORS.get(sev, "#64748b"),
        }
        for sev in ("critical", "high", "medium", "low", "clean", "info")
        if severity_counts.get(sev, 0) > 0
    ]

    recent = (
        db.query(Investigation)
        .order_by(Investigation.uploaded_at.desc())
        .limit(8)
        .all()
    )

    return {
        "totalInvestigations": {"value": total, "delta": None, "spark": []},
        "activeAnalyses": {"value": active, "delta": None, "spark": []},
        "criticalAlerts": {"value": critical, "delta": None, "spark": []},
        "completedAnalyses": {"value": completed, "delta": None, "spark": []},
        "statusDistribution": status_counts,
        "severityBreakdown": severity_breakdown,
        "recentInvestigations": [inv.to_dict() for inv in recent],
        "malwareFamilies": [],
        "threatFeed": [],
        "systemHealth": _system_health(),
        "topAnalysts": [],
        "note": "Live dashboard data — trend/threat-intel widgets populate as analysis modules come online",
    }


def _system_health() -> list[dict]:
    from app.config import get_settings

    settings = get_settings()
    return [
        {"name": "Analysis API", "detail": "FastAPI + SQLite", "status": "operational", "load": 0},
        {"name": "Static Analysis", "detail": "PE/PDF/Office/Script + YARA-lite + scoring", "status": "operational", "load": 0},
        {"name": "AI Inference (LLM)", "detail": settings.ai_provider_label, "status": "degraded", "load": 0},
        {"name": "Threat Intel Feeds", "detail": "Module not yet implemented", "status": "degraded", "load": 0},
    ]
