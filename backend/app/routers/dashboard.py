"""Dashboard aggregation endpoints."""
from fastapi import APIRouter

from app.data import mock_data

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def stats():
    return mock_data.DASHBOARD_STATS


@router.get("/malware-families")
def malware_families():
    return mock_data.MALWARE_FAMILIES


@router.get("/threat-feed")
def threat_feed():
    return mock_data.THREAT_FEED
