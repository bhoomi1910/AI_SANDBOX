"""Investigation queue + detailed analysis endpoints."""
from fastapi import APIRouter, HTTPException

from app.data import mock_data
from app.ai import engine

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.get("")
def list_investigations(status: str | None = None):
    items = mock_data.INVESTIGATIONS
    if status and status != "all":
        items = [i for i in items if i["status"] == status]
    return items


@router.get("/{inv_id}")
def get_investigation(inv_id: str):
    inv = mock_data.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/{inv_id}/static")
def static_analysis(inv_id: str):
    _require(inv_id)
    return mock_data.STATIC_ANALYSIS


@router.get("/{inv_id}/threat-intel")
def threat_intel(inv_id: str):
    _require(inv_id)
    return {"sources": mock_data.THREAT_INTEL, "iocs": mock_data.IOCS}


@router.get("/{inv_id}/mitre")
def mitre(inv_id: str):
    _require(inv_id)
    return mock_data.MITRE_TECHNIQUES


@router.get("/{inv_id}/ai")
def ai_investigation(inv_id: str):
    inv = _require(inv_id)
    return engine.analyse(inv)


def _require(inv_id: str) -> dict:
    inv = mock_data.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv
