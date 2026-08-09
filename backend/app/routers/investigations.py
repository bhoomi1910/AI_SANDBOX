"""Investigation queue + detail endpoints (DB-backed).

Static analysis results are served from the stored `AnalysisResult` row;
threat intel, MITRE and AI deep-dive endpoints keep a stable URL contract.
Phase 3 serves real findings/IOCs/MITRE/graph; Phase 4 serves the AI
interpretation of that deterministic output (or a graceful unavailable/error
state when Ollama cannot be reached).
"""
import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AnalysisResult, Investigation
from app.services import ai as ai_service

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
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    return {"status": "completed", "investigation": inv.case_id, "result": payload}


@router.get("/{inv_id}/findings")
def findings(inv_id: str, db: Session = Depends(get_db)):
    """Derived findings: analyzer findings enriched with confidence/MITRE and
    rule-correlated detections, de-duplicated for display."""
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    return {"status": "completed", "investigation": inv.case_id,
            "findings": payload.get("findings", [])}


@router.get("/{inv_id}/iocs")
def iocs(inv_id: str, db: Session = Depends(get_db)):
    """De-duplicated indicators of compromise with source provenance."""
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    return {"status": "completed", "investigation": inv.case_id,
            "iocs": payload.get("iocs", [])}


@router.get("/{inv_id}/mitre")
def mitre(inv_id: str, db: Session = Depends(get_db)):
    """Evidence-backed MITRE ATT&CK technique mappings."""
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    return {"status": "completed", "investigation": inv.case_id,
            "techniques": payload.get("mitre", [])}


@router.get("/{inv_id}/graph")
def graph(inv_id: str, db: Session = Depends(get_db)):
    """Provenance graph: file -> evidence -> iocs/findings -> MITRE techniques."""
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    return {"status": "completed", "investigation": inv.case_id,
            "graph": payload.get("graph", {"nodes": [], "edges": []})}


@router.get("/{inv_id}/threat-intel")
def threat_intel(inv_id: str, db: Session = Depends(get_db)):
    inv = _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return {"sources": [], "iocs": [], "note": "Static analysis has not completed yet"}
    return {
        "sources": [],
        "iocs": payload.get("iocs", []),
        "note": "Deterministic IOC extraction only — no external threat-intel feeds yet.",
    }


@router.get("/{inv_id}/ai")
def ai_investigation(inv_id: str, db: Session = Depends(get_db)):
    """AI interpretation of the deterministic analysis (Phase 4).

    Completed results are cached on the stored payload so repeat requests are
    instant. Unavailable/error states are NOT cached, so a later-installed
    Ollama is picked up automatically. The AI never replaces the deterministic
    verdict — when it is unavailable the deterministic endpoints keep working.
    """
    _require(db, inv_id)
    payload = _load_result(db, inv_id)
    if payload is None:
        return _pending("Static analysis has not completed for this investigation yet")
    if payload.get("corrupt"):
        return {"status": "error", "provider": "n/a",
                "note": "Stored analysis payload is corrupt — deterministic data is unavailable."}
    if payload.get("ai"):
        return payload["ai"]

    inv = db.get(Investigation, inv_id)
    result = ai_service.run_ai_analysis(_ai_context(payload, inv))
    if result["status"] == "completed":
        payload["ai"] = result
        _save_result(db, inv_id, payload)
    return result


def _require(db: Session, inv_id: str) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


def _load_result(db: Session, inv_id: str) -> dict | None:
    result = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.investigation_id == inv_id)
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


def _pending(detail: str) -> dict:
    return {"status": "pending", "detail": detail}


def _ai_context(payload: dict, inv: Investigation) -> dict:
    """Deterministic context handed to the AI engine (never AI-authored)."""
    return {
        "file": {
            "filename": inv.filename,
            "file_type": payload.get("fileType"),
            "family": payload.get("family"),
            "sha256": inv.sha256,
            "size": inv.size_bytes,
        },
        "classification": payload.get("classification"),
        "score": payload.get("score", {}),
        "findings": payload.get("findings", []),
        "iocs": payload.get("iocs", []),
        "mitre": payload.get("mitre", []),
        "evidence": payload.get("evidence", []),
        "static": payload.get("static", {}),
    }


def _save_result(db: Session, inv_id: str, payload: dict) -> None:
    result = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.investigation_id == inv_id)
        .order_by(AnalysisResult.created_at.desc())
        .first()
    )
    if result is None:
        return
    result.data = json.dumps(payload)
    db.commit()
