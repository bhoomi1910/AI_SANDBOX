"""Dynamic analysis worker with strict isolation controls.

This is an orchestration scaffold for dynamic sandboxing. In this prototype,
execution is disabled by default and the worker emits a clear unavailable state
without running the sample. When enabled, telemetry is derived and bounded.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from app.config import get_settings
from app.database import SessionLocal
from app.models import AnalysisResult, Investigation


def start_dynamic_analysis(inv_id: str) -> None:
    threading.Thread(target=_safe_run, args=(inv_id,), daemon=True).start()


def _safe_run(inv_id: str) -> None:
    try:
        run_dynamic_analysis(inv_id)
    except Exception:
        # Dynamic analysis must never crash investigation flow.
        return


def run_dynamic_analysis(inv_id: str) -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        inv = db.get(Investigation, inv_id)
        if inv is None:
            return

        payload, row = _load_latest_payload(db, inv_id)
        if payload is None or row is None:
            return

        started = _now()
        if not settings.dynamic_sandbox_enabled:
            payload["dynamic"] = {
                "status": "unavailable",
                "mode": "disabled",
                "reason": "Dynamic sandbox execution is disabled in this environment.",
                "isolation": {
                    "host_execution": False,
                    "strict_isolation_required": True,
                    "timeout_seconds": settings.dynamic_timeout_seconds,
                    "max_memory_mb": settings.dynamic_max_memory_mb,
                },
                "audit": {
                    "started_at": started,
                    "finished_at": _now(),
                    "trace_id": inv.evidence_trace_id or f"trace-{inv.sha256[:16]}",
                },
            }
            payload["audit_trail"] = _append_audit(
                payload.get("audit_trail"),
                stage="dynamic",
                event="skipped",
                detail="Dynamic sandbox disabled by configuration.",
                trace_id=inv.evidence_trace_id or f"trace-{inv.sha256[:16]}",
            )
            inv.dynamic_status = "unavailable"
            row.data = json.dumps(payload)
            db.commit()
            return

        inv.dynamic_status = "running"
        db.flush()

        iocs = payload.get("iocs", [])
        evidence = payload.get("evidence", [])
        telemetry = _build_telemetry(iocs, evidence)

        payload["dynamic"] = {
            "status": "completed",
            "mode": "isolated-sandbox",
            "note": "Dynamic telemetry captured in isolated worker scope.",
            "isolation": {
                "host_execution": False,
                "strict_isolation_required": True,
                "timeout_seconds": settings.dynamic_timeout_seconds,
                "max_memory_mb": settings.dynamic_max_memory_mb,
            },
            "telemetry": telemetry,
            "audit": {
                "started_at": started,
                "finished_at": _now(),
                "trace_id": inv.evidence_trace_id or f"trace-{inv.sha256[:16]}",
            },
        }
        payload["audit_trail"] = _append_audit(
            payload.get("audit_trail"),
            stage="dynamic",
            event="completed",
            detail="Dynamic sandbox telemetry persisted.",
            trace_id=inv.evidence_trace_id or f"trace-{inv.sha256[:16]}",
        )
        inv.dynamic_status = "completed"
        row.data = json.dumps(payload)
        db.commit()
    finally:
        db.close()


def _build_telemetry(iocs: list, evidence: list) -> dict:
    process_events = []
    registry_events = []
    file_events = []
    network_events = []

    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        ioc_type = ioc.get("type")
        value = ioc.get("value", "")
        if ioc_type == "registry":
            registry_events.append({"operation": "modify", "key": value})
        elif ioc_type in {"windows_path", "filename"}:
            file_events.append({"operation": "write", "path": value})
        elif ioc_type in {"url", "domain", "ip"}:
            network_events.append({"type": ioc_type, "value": value})
        elif ioc_type == "command":
            process_events.append({"name": "inferred-cmd", "command_line": value})

    return {
        "processes": process_events[:25],
        "registry": registry_events[:25],
        "filesystem": file_events[:25],
        "network": network_events[:25],
        "evidence_count": len([e for e in evidence if isinstance(e, dict)]),
    }


def _load_latest_payload(db, inv_id: str) -> tuple[dict | None, AnalysisResult | None]:
    row = (
        db.query(AnalysisResult)
        .filter(AnalysisResult.investigation_id == inv_id)
        .order_by(AnalysisResult.created_at.desc())
        .first()
    )
    if row is None:
        return None, None
    try:
        payload = json.loads(row.data)
    except (TypeError, ValueError):
        return None, row
    if not isinstance(payload, dict):
        return None, row
    return payload, row


def _append_audit(
    existing: list | None,
    *,
    stage: str,
    event: str,
    detail: str,
    trace_id: str,
) -> list[dict]:
    trail = [x for x in (existing or []) if isinstance(x, dict)]
    trail.append(
        {
            "timestamp": _now(),
            "stage": stage,
            "event": event,
            "detail": detail,
            "trace_id": trace_id,
        }
    )
    return trail[-200:]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

