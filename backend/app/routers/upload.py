"""Sample submission endpoint."""
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File

router = APIRouter(prefix="/samples", tags=["samples"])

ALLOWED = {"exe", "dll", "pdf", "docx", "zip", "iso"}


@router.post("/upload")
async def upload_sample(file: UploadFile = File(...)):
    """
    Accept a sample, compute its hashes, and (in production) enqueue it for
    detonation. The prototype computes real hashes then returns a queued case.
    """
    contents = await file.read()
    sha256 = hashlib.sha256(contents).hexdigest()
    md5 = hashlib.md5(contents).hexdigest()
    ext = (file.filename or "").rsplit(".", 1)[-1].lower()

    return {
        "caseId": "AGS-2026-0413",
        "status": "queued",
        "sample": {
            "filename": file.filename,
            "fileType": ext if ext in ALLOWED else "bin",
            "size": len(contents),
            "sha256": sha256,
            "md5": md5,
            "submittedAt": datetime.now(timezone.utc).isoformat(),
        },
        "message": "Sample queued for detonation in sandbox VM-07.",
        "supported": ext in ALLOWED,
    }
