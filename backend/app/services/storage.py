"""Secure storage helpers for uploaded samples.

Security rules enforced here:
- Never trust the client filename: strip path components and sanitise.
- Enforce a maximum size while streaming (no unbounded reads).
- Store under a generated unique name inside the configured uploads directory.
- Compute SHA-256 / MD5 / SHA-1 hashes while the file is written.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

from fastapi import UploadFile


class FileTooLargeError(Exception):
    pass


class EmptyFileError(Exception):
    pass


# Extension -> broad file-type bucket used before magic-byte detection (Phase 2).
ALLOWED_TYPES = {
    "exe": "exe",
    "dll": "dll",
    "sys": "exe",
    "pdf": "pdf",
    "docx": "docx",
    "xlsx": "docx",
    "pptx": "docx",
    "doc": "docx",
    "xls": "docx",
    "ppt": "docx",
    "zip": "zip",
    "rar": "zip",
    "7z": "zip",
    "iso": "iso",
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "svg": "image",
    "ps1": "script",
    "py": "script",
    "sh": "script",
    "bat": "script",
    "js": "script",
    "vbs": "script",
    "txt": "text",
    "csv": "text",
    "json": "text",
    "xml": "text",
}

_CHUNK = 64 * 1024
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_NAME_LEN = 120


def sanitize_filename(filename: str | None) -> str:
    """Return a filesystem-safe basename derived from the client filename."""
    name = (filename or "file").replace("\\", "/").rsplit("/", 1)[-1].strip()
    name = name.replace("\x00", "")
    name = _SAFE_NAME_RE.sub("_", name).strip("._ ")
    if not name:
        name = "file"
    return name[: _MAX_NAME_LEN]


def file_type_from_name(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ALLOWED_TYPES.get(ext, "bin")


def save_upload(upload: UploadFile, upload_dir: Path, max_size: int) -> dict:
    """Stream an uploaded file to disk, hashing and enforcing size limits.

    Returns a dict of {original_name, stored_name, file_type, size_bytes,
    sha256, md5, sha1, storage_path}.
    """
    original_name = sanitize_filename(upload.filename)
    stored_name = f"{uuid.uuid4().hex}"
    storage_path = upload_dir / stored_name

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    total = 0

    with open(storage_path, "wb") as out:
        while True:
            chunk = upload.file.read(_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > max_size:
                out.close()
                storage_path.unlink(missing_ok=True)
                raise FileTooLargeError(
                    f"File exceeds maximum size of {max_size} bytes"
                )
            sha256.update(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            out.write(chunk)

    if total == 0:
        storage_path.unlink(missing_ok=True)
        raise EmptyFileError("Uploaded file is empty")

    return {
        "original_name": original_name,
        "stored_name": stored_name,
        "file_type": file_type_from_name(original_name),
        "size_bytes": total,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "storage_path": str(storage_path),
    }
