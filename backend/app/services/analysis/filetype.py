"""File type detection by magic bytes — independent of the file extension.

Returns a coarse family (pe/pdf/ooxml/ole/image/script/archive/text/other)
plus a friendly mime/description. Uses the `filetype` library for common
formats and manual signatures for PE and OOXML containers.
"""
from __future__ import annotations

import struct
from pathlib import Path

import filetype

PE_SECTION_MAX = 0x2000


def detect_file_type(path: Path, original_ext: str = "") -> dict:
    """Inspect magic bytes and return {file_type, mime, family, description}."""
    head = _read_head(path)
    ext, mime = _magic_guess(head)

    if _is_pe(head):
        return {"file_type": "pe", "mime": "application/vnd.microsoft.portable-executable", "family": "pe", "description": "Windows PE executable"}
    if ext == "zip" or _is_zip(head):
        ooxml = _ooxml_kind(path)
        if ooxml:
            return {"file_type": ooxml, "mime": _OOXML_MIME[ooxml], "family": "ooxml", "description": _OOXML_DESC[ooxml]}
        if _is_iso(head):
            return {"file_type": "iso", "mime": "application/x-iso9660-image", "family": "archive", "description": "ISO disk image"}
        return {"file_type": "zip", "mime": "application/zip", "family": "archive", "description": "ZIP archive"}
    if ext == "pdf":
        return {"file_type": "pdf", "mime": "application/pdf", "family": "pdf", "description": "PDF document"}
    if ext in _IMAGE_EXT:
        return {"file_type": ext, "mime": _IMAGE_MIME[ext], "family": "image", "description": f"Image ({ext.upper()})"}
    if ext == "xls" or _is_ole(head):
        return {"file_type": "xls", "mime": "application/vnd.ms-excel", "family": "ole", "description": "OLE compound document"}
    if ext == "doc":
        return {"file_type": "doc", "mime": "application/msword", "family": "ole", "description": "OLE compound document (Word)"}
    if ext == "ppt":
        return {"file_type": "ppt", "mime": "application/vnd.ms-powerpoint", "family": "ole", "description": "OLE compound document (PowerPoint)"}

    family = _script_family(path, original_ext, head)
    if family:
        return {"file_type": family, "mime": "text/plain", "family": "script", "description": f"{family.upper()} script"}
    if ext in ("txt", "csv", "json", "xml", "log", "ini"):
        return {"file_type": "text", "mime": "text/plain", "family": "text", "description": "Text file"}

    return {"file_type": "bin", "mime": "application/octet-stream", "family": "other", "description": "Unknown binary format"}


def _read_head(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read(0x10000)


def _magic_guess(head: bytes) -> tuple[str, str]:
    kind = filetype.guess(head)
    if kind is None:
        return "", ""
    return kind.extension.lower(), kind.mime


def _is_pe(head: bytes) -> bool:
    if not head.startswith(b"MZ"):
        return False
    try:
        pe_off = struct.unpack_from("<I", head, 0x3C)[0]
    except struct.error:
        return False
    return 0 < pe_off < PE_SECTION_MAX and head[pe_off : pe_off + 4] == b"PE\x00\x00"


def _is_zip(head: bytes) -> bool:
    return head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08")


def _is_iso(head: bytes) -> bool:
    return head[0x8001 : 0x8006] == b"CD001"


def _is_ole(head: bytes) -> bool:
    return head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")


def _ooxml_kind(path: Path) -> str | None:
    """docx/xlsx/pptx containers share the ZIP signature; sniff content type."""
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
    except zipfile.BadZipFile:
        return None
    if any(n.startswith("word/") for n in names):
        return "docx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    return None


def _script_family(path: Path, original_ext: str, head: bytes) -> str | None:
    ext = original_ext.lower().lstrip(".")
    if ext in ("ps1", "py", "js", "vbs", "bat", "cmd", "sh", "php", "rb", "pl", "hta"):
        return ext
    text = head[:4096].decode("utf-8", errors="ignore").lower()
    if "@echo off" in text or "\r\nrem " in text:
        return "bat"
    return None


_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "svg", "webp", "ico"}
_IMAGE_MIME = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tif": "image/tiff",
    "tiff": "image/tiff",
    "svg": "image/svg+xml",
    "webp": "image/webp",
    "ico": "image/vnd.microsoft.icon",
}
_OOXML_MIME = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
_OOXML_DESC = {
    "docx": "Office Open XML document (Word)",
    "xlsx": "Office Open XML spreadsheet (Excel)",
    "pptx": "Office Open XML presentation (PowerPoint)",
}
