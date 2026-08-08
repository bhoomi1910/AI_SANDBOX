"""Investigation queue + detail endpoints (DB-backed).

Static analysis, threat intel, MITRE and AI deep-dive endpoints keep a stable
URL contract but return structured "pending" payloads until those modules are
implemented in later phases (static: Phase 2, AI: Phase 4).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Investigation

router = APIRouter(prefix="/investigations", tags=["investigations"])

STATUS_FILTERS = {"queued", "running", "analysing", "ai-processing", "completed", "failed"}


@router.get("")
def list_investigations(status: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Investigation).order_by(Investigation.uploaded_at.desc())
    if status and status != "all" and status in STATUS_FILTERS:
        query = query.filter(Investigation.status == status)
    return [inv.to_dict() for inv in query.all()]


@router.get("/{inv_id}")
def get_investigation(inv_id: str, db: Session = Depends(get_db)):
    inv = _require(db, inv_id)
    return inv.to_dict()


@router.get("/{inv_id}/static")
def static_analysis(inv_id: str, db: Session = Depends(get_db)):
    _require(db, inv_id)
    return _pending("Static analysis has not run for this investigation yet")


@router.get("/{inv_id}/threat-intel")
def threat_intel(inv_id: str, db: Session = Depends(get_db)):
    _require(db, inv_id)
    return {"sources": [], "iocs": [], "note": "Threat intelligence enrichment lands in Phase 3"}


@router.get("/{inv_id}/mitre")
def mitre(inv_id: str, db: Session = Depends(get_db)):
    inv = _require(db, inv_id)
    return {"techniques": [], "note": "MITRE ATT&CK mapping lands in Phase 3"}


@router.get("/{inv_id}/ai")
def ai_investigation(inv_id: str, db: Session = Depends(get_db)):
    _require(db, inv_id)
    return {
        "status": "unavailable",
        "provider": settings_ai_provider(),
        "note": "AI engine is not configured yet — no model available on this host",
    }


def _require(db: Session, inv_id: str) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


def _pending(detail: str) -> dict:
    return {"status": "pending", "detail": detail}


def settings_ai_provider() -> str:
    from app.config import get_settings

    return get_settings().ai_provider_label
