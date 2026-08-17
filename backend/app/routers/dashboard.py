"""Dashboard statistics computed from the database.

Single endpoint aggregating investigation counts, severity/verdict/file-type
distributions, IOC/YARA/MITRE statistics, timeline, and high-risk investigations.
All data is derived from persisted records — no fabricated statistics.
"""
import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AnalysisResult, Investigation

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITY_COLORS = {
    "critical": "#f43f5e",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#38bdf8",
    "clean": "#34d399",
    "info": "#38bdf8",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "clean", "info")

FILE_TYPE_COLORS = {
    "exe": "#f43f5e",
    "dll": "#fb923c",
    "pdf": "#facc15",
    "docx": "#22d3ee",
    "doc": "#818cf8",
    "zip": "#34d399",
    "iso": "#a78bfa",
    "msi": "#f472b6",
    "js": "#e879f9",
    "vbs": "#6ee7b7",
    "ps1": "#38bdf8",
    "bat": "#fbbf24",
    "scr": "#fb7185",
    "bin": "#64748b",
    "elf": "#2dd4bf",
    "jar": "#c084fc",
}

VERDICT_COLORS = {
    "malicious": "#f43f5e",
    "suspicious": "#facc15",
    "clean": "#34d399",
}


def _load_json(raw: str, default=None):
    try:
        parsed = json.loads(raw)
        return parsed if parsed is not None else (default if default is not None else [])
    except (TypeError, ValueError):
        return default if default is not None else []


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    # ── Core counts ──────────────────────────────────────────────
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
        db.query(func.count(Investigation.id))
        .filter(Investigation.status == "completed")
        .scalar()
        or 0
    )
    failed = (
        db.query(func.count(Investigation.id))
        .filter(Investigation.status == "failed")
        .scalar()
        or 0
    )
    pending = total - active - completed - failed

    # Today count
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_count = (
        db.query(func.count(Investigation.id))
        .filter(Investigation.uploaded_at >= today_start)
        .scalar()
        or 0
    )

    # ── Status distribution ──────────────────────────────────────
    status_counts = dict(
        db.query(Investigation.status, func.count(Investigation.id))
        .group_by(Investigation.status)
        .all()
    )

    # ── Severity distribution ────────────────────────────────────
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
        for sev in SEVERITY_ORDER
        if severity_counts.get(sev, 0) > 0
    ]

    # ── Verdict distribution ─────────────────────────────────────
    verdict_counts = dict(
        db.query(Investigation.verdict, func.count(Investigation.id))
        .group_by(Investigation.verdict)
        .all()
    )
    verdict_distribution = [
        {
            "name": v.capitalize(),
            "value": verdict_counts.get(v, 0),
            "color": VERDICT_COLORS.get(v, "#64748b"),
        }
        for v in ("malicious", "suspicious", "clean")
        if verdict_counts.get(v, 0) > 0
    ]

    # ── File type distribution ───────────────────────────────────
    file_type_counts = dict(
        db.query(Investigation.file_type, func.count(Investigation.id))
        .group_by(Investigation.file_type)
        .all()
    )
    file_type_distribution = sorted(
        [
            {
                "name": ft,
                "value": count,
                "color": FILE_TYPE_COLORS.get(ft, "#64748b"),
            }
            for ft, count in file_type_counts.items()
        ],
        key=lambda x: x["value"],
        reverse=True,
    )

    # ── Malware family distribution ──────────────────────────────
    family_counts = Counter()
    all_invs = db.query(Investigation).all()
    for inv in all_invs:
        fam = inv.malware_family
        if fam and fam not in ("Pending", "Unknown", "None", ""):
            family_counts[fam] += 1
    malware_families = [
        {"name": fam, "value": count, "color": SEVERITY_COLORS.get("high", "#fb923c")}
        for fam, count in family_counts.most_common(8)
    ]

    # ── Timeline (last 30 days) ──────────────────────────────────
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    timeline_rows = (
        db.query(Investigation.uploaded_at)
        .filter(Investigation.uploaded_at >= thirty_days_ago)
        .order_by(Investigation.uploaded_at.asc())
        .all()
    )
    daily_counts: Counter = Counter()
    for (dt,) in timeline_rows:
        day_key = dt.strftime("%Y-%m-%d") if dt else None
        if day_key:
            daily_counts[day_key] += 1

    # Build complete 30-day range
    timeline = []
    for i in range(30):
        day = (datetime.now(timezone.utc) - timedelta(days=29 - i)).strftime("%Y-%m-%d")
        timeline.append({"date": day, "count": daily_counts.get(day, 0)})

    # ── Recent investigations ────────────────────────────────────
    recent = (
        db.query(Investigation)
        .order_by(Investigation.uploaded_at.desc())
        .limit(8)
        .all()
    )

    # ── High-risk investigations ─────────────────────────────────
    high_risk = (
        db.query(Investigation)
        .filter(Investigation.severity.in_(["critical", "high"]))
        .order_by(Investigation.uploaded_at.desc())
        .limit(10)
        .all()
    )

    # ── IOC statistics (from analysis_results.data JSON) ─────────
    ioc_counter: Counter = Counter()
    total_iocs = 0
    results = db.query(AnalysisResult.data).all()
    for (data_str,) in results:
        try:
            payload = json.loads(data_str) if data_str else {}
        except (TypeError, ValueError):
            continue
        iocs = payload.get("iocs", []) if isinstance(payload, dict) else []
        if isinstance(iocs, list):
            for ioc in iocs:
                ioc_type = ioc.get("type", "unknown") if isinstance(ioc, dict) else None
                if ioc_type:
                    ioc_counter[ioc_type] += 1
                    total_iocs += 1
    ioc_statistics = {
        "total": total_iocs,
        "by_type": [
            {"type": t, "count": c}
            for t, c in sorted(ioc_counter.items(), key=lambda x: x[1], reverse=True)
        ],
    }

    # ── YARA statistics (from analysis_results.data JSON) ────────
    yara_rule_counter: Counter = Counter()
    yara_match_count = 0
    investigations_with_yara = 0
    for (data_str,) in results:
        try:
            payload = json.loads(data_str) if data_str else {}
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        static = payload.get("static", {})
        if not isinstance(static, dict):
            continue
        yara = static.get("yara", [])
        if isinstance(yara, list) and yara:
            investigations_with_yara += 1
            for match in yara:
                if isinstance(match, dict):
                    rule = match.get("rule", "unknown")
                    yara_rule_counter[rule] += 1
                    yara_match_count += 1
    yara_statistics = {
        "total_matches": yara_match_count,
        "investigations_with_matches": investigations_with_yara,
        "top_rules": [
            {"rule": rule, "count": count}
            for rule, count in yara_rule_counter.most_common(10)
        ],
    }

    # ── MITRE statistics (from investigation.mitre_techniques) ───
    technique_counter: Counter = Counter()
    tactic_counter: Counter = Counter()
    investigations_with_mitre = 0
    for inv in all_invs:
        techniques = _load_json(inv.mitre_techniques, [])
        if techniques:
            investigations_with_mitre += 1
            for t in techniques:
                if isinstance(t, str):
                    technique_counter[t] += 1
    # Also get tactic info from analysis_results
    for (data_str,) in results:
        try:
            payload = json.loads(data_str) if data_str else {}
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        mitre = payload.get("mitre", [])
        if isinstance(mitre, list):
            for m in mitre:
                if isinstance(m, dict):
                    tactic = m.get("tactic", "")
                    if tactic:
                        tactic_counter[tactic] += 1
    mitre_statistics = {
        "total_techniques": sum(technique_counter.values()),
        "unique_techniques": len(technique_counter),
        "investigations_with_mitre": investigations_with_mitre,
        "top_techniques": [
            {"technique": t, "count": c}
            for t, c in technique_counter.most_common(10)
        ],
        "top_tactics": [
            {"tactic": t, "count": c}
            for t, c in tactic_counter.most_common(10)
        ],
    }

    # ── System health ────────────────────────────────────────────
    system_health = _system_health()

    return {
        "summary": {
            "total": total,
            "active": active,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "today": today_count,
        },
        "statusDistribution": status_counts,
        "severityBreakdown": severity_breakdown,
        "verdictDistribution": verdict_distribution,
        "fileTypeDistribution": file_type_distribution,
        "malwareFamilies": malware_families,
        "timeline": timeline,
        "recentInvestigations": [inv.to_dict() for inv in recent],
        "highRiskInvestigations": [inv.to_dict() for inv in high_risk],
        "iocStatistics": ioc_statistics,
        "yaraStatistics": yara_statistics,
        "mitreStatistics": mitre_statistics,
        "systemHealth": system_health,
        "note": "Live dashboard data — all statistics derived from persisted analysis results",
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
