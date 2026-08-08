"""SQLAlchemy models.

Follows the documented schema (see docs/DATABASE.md). Analysis-result tables
(metadata, hashes, static analysis, YARA, IOCs, AI, MITRE, reports) are added
as those modules are implemented; the investigation record is the anchor.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    """One uploaded file -> one investigation. Status lifecycle:

    queued -> running -> analysing -> ai-processing -> completed | failed
    """

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(32), default="bin")
    mime_type: Mapped[str] = mapped_column(String(128), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32))
    sha1: Mapped[str] = mapped_column(String(40))
    storage_path: Mapped[str] = mapped_column(Text)

    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str] = mapped_column(String(255), default="Waiting for analysis")

    severity: Mapped[str] = mapped_column(String(16), default="info")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    malware_family: Mapped[str] = mapped_column(String(64), default="Pending")
    classification: Mapped[str] = mapped_column(String(128), default="Pending analysis")
    verdict: Mapped[str] = mapped_column(String(16), default="suspicious")
    ai_confidence: Mapped[int] = mapped_column(Integer, default=0)
    detections: Mapped[int] = mapped_column(Integer, default=0)
    total_engines: Mapped[int] = mapped_column(Integer, default=0)

    tags: Mapped[str] = mapped_column(Text, default="[]")          # JSON list
    mitre_techniques: Mapped[str] = mapped_column(Text, default="[]")  # JSON list

    assigned_to: Mapped[str] = mapped_column(String(64), default="Unassigned")
    submitted_by: Mapped[str] = mapped_column(String(64), default="analyst")

    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        """API representation matching the frontend Investigation type."""
        return {
            "id": self.id,
            "caseId": self.case_id,
            "sample": {
                "id": self.id,
                "filename": self.filename,
                "fileType": self.file_type,
                "size": self.size_bytes,
                "sha256": self.sha256,
                "md5": self.md5,
                "sha1": self.sha1,
                "submittedAt": self.uploaded_at.isoformat(),
                "submittedBy": self.submitted_by,
            },
            "status": self.status,
            "progress": self.progress,
            "severity": self.severity,
            "riskScore": self.risk_score,
            "malwareFamily": self.malware_family,
            "classification": self.classification,
            "verdict": self.verdict,
            "aiConfidence": self.ai_confidence,
            "detections": self.detections,
            "totalEngines": self.total_engines,
            "createdAt": self.uploaded_at.isoformat(),
            "completedAt": self.completed_at.isoformat() if self.completed_at else None,
            "assignedTo": self.assigned_to,
            "tags": _load_json_list(self.tags),
            "mitreTechniques": _load_json_list(self.mitre_techniques),
            "currentStage": self.current_stage,
        }


def _load_json_list(raw: str) -> list[str]:
    import json

    try:
        return json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
