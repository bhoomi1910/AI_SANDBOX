"""Sample upload endpoint.

Security model:
- size enforced while streaming (413 if over the configured limit)
- empty uploads rejected (422)
- client filename sanitised; file stored under a random UUID name
- SHA-256 / MD5 / SHA-1 computed at write time
- an Investigation record is created and queued for analysis
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import Investigation, new_id, utcnow
from app.services.analysis import start_analysis
from app.services.storage import EmptyFileError, FileTooLargeError, save_upload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/samples", tags=["samples"])

settings = get_settings()


@router.post("/upload", status_code=201)
def upload_sample(file: UploadFile, db: Session = Depends(get_db)):
    try:
        stored = save_upload(file, settings.upload_dir_path, settings.max_upload_size)
    except FileTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except EmptyFileError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    case_id = _next_case_id(db)
    inv = Investigation(
        id=new_id(),
        case_id=case_id,
        filename=stored["original_name"],
        file_type=stored["file_type"],
        mime_type=_mime_for(stored["file_type"]),
        size_bytes=stored["size_bytes"],
        sha256=stored["sha256"],
        md5=stored["md5"],
        sha1=stored["sha1"],
        storage_path=stored["storage_path"],
        status="queued",
        progress=0,
        current_stage="Queued for analysis",
        dynamic_status="pending",
        quarantine_state="quarantined",
        evidence_trace_id=f"trace-{stored['sha256'][:16]}",
        uploaded_at=utcnow(),
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)

    logger.info("Sample stored id=%s case=%s sha256=%s", inv.id, inv.case_id, inv.sha256)
    start_analysis(inv.id)
    return {"message": "Sample received and queued for analysis", "investigation": inv.to_dict()}


def _next_case_id(db: Session) -> str:
    """Return the next INV-YYYY-NNNN case id (last four-digit ordinal + 1)."""
    year = utcnow().year
    last = (
        db.query(Investigation.case_id)
        .filter(Investigation.case_id.like(f"INV-{year}-%"))
        .order_by(Investigation.case_id.desc())
        .first()
    )
    if last and last[0]:
        ordinal = int(last[0].rsplit("-", 1)[-1]) + 1
    else:
        ordinal = 1
    return f"INV-{year}-{ordinal:04d}"


def _mime_for(file_type: str) -> str:
    return {
        "exe": "application/vnd.microsoft.portable-executable",
        "dll": "application/x-msdownload",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "zip": "application/zip",
        "iso": "application/x-iso9660-image",
        "image": "application/octet-stream",
        "script": "text/plain",
        "text": "text/plain",
        "bin": "application/octet-stream",
    }.get(file_type, "application/octet-stream")
