"""String extraction and classification from a file's raw bytes.

Extracts printable ASCII runs and UTF-16LE runs, classifies them by type
(url/ip/domain/registry/path/command/mutex/api/generic) and marks "interesting"
strings that a malware analyst would care about.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

MIN_ASCII_LEN = 6
MAX_STRINGS = 500

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_ASCII_LEN)
# UTF-16LE printable runs: printable byte followed by NUL, at least 6 chars.
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>]{5,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?\b", re.IGNORECASE)
_REGISTRY_RE = re.compile(r"(?i)(?:HKLM|HKCU|HKCR|HKU)\\[\\A-Za-z0-9_.-]+|\\Software\\Microsoft\\Windows\\CurrentVersion")
_MUTEX_RE = re.compile(r"(?i)(?:Global|Local)\\\\[^\s]{1,64}|mutex[^\s]{0,48}")
_COMMAND_RE = re.compile(r"(?i)(?:cmd(?:\.exe)?\s*/c|powershell|rundll32|certutil|regsvr32|schtasks|wscript|cscript)\b")

_SUSPICIOUS_API = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ReadProcessMemory",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "CreateProcessA", "WinExec", "ShellExecuteA", "ShellExecuteExA", "NtUnmapViewOfSection",
    "SetWindowsHookExA", "GetAsyncKeyState", "keybd_event", "CryptUnprotectData",
    "RegSetValueExA", "RegCreateKeyExA", "DeleteFileA", "UrlDownloadToFileA",
}


def extract_strings(path: Path, limit: int = MAX_STRINGS) -> list[dict]:
    """Return a list of {value, type, offset, interesting} strings."""
    data = read_safe(path)
    if not data:
        return []

    results: list[tuple[str, str, int, bool]] = []
    for m in _ASCII_RE.finditer(data):
        value = m.group().decode("ascii", "ignore").strip()
        if _too_noisy(value):
            continue
        _add(result=results, value=value, offset=m.start())
    for m in _UTF16_RE.finditer(data):
        value = m.group().decode("utf-16-le", "ignore").strip()
        if _too_noisy(value):
            continue
        _add(result=results, value=value, offset=m.start())

    results.sort(key=lambda r: r[2])
    strings = []
    for value, kind, offset, interesting in results:
        strings.append({
            "value": value[:512],
            "type": kind,
            "offset": f"0x{offset:08X}",
            "interesting": interesting,
        })
        if len(strings) >= limit:
            break
    return strings


def read_safe(path: Path, cap: int = 64 * 1024 * 1024) -> bytes:
    """Read up to `cap` bytes (avoid loading multi-hundred-MB samples)."""
    with open(path, "rb") as f:
        return f.read(cap)


def _add(result: list[tuple[str, str, int, bool]], value: str, offset: int) -> None:
    kind = _classify(value)
    interesting = kind in ("url", "ip", "command", "registry", "mutex", "api") or _URL_RE.search(value) is not None
    result.append((value, kind, offset, interesting))


def _classify(value: str) -> str:
    if _URL_RE.search(value):
        return "url"
    if _IP_RE.match(value) and _is_public_ip(value):
        return "ip"
    if _REGISTRY_RE.search(value):
        return "registry"
    if _MUTEX_RE.search(value):
        return "mutex"
    if _COMMAND_RE.search(value):
        return "command"
    if _looks_like_path(value):
        return "path"
    if value in _SUSPICIOUS_API:
        return "api"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "generic"


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not ip.is_private and not ip.is_loopback and not ip.is_multicast
    except ValueError:
        return False


def _looks_like_path(value: str) -> bool:
    low = value.lower()
    return (
        low.startswith(("c:\\", "d:\\", "\\\\", "\\", "/", "%appdata%", "%temp%", "%programfiles%", "%windir%", "%userprofile%", "$env:"))
        or low.startswith("http")
    )


def _too_noisy(value: str) -> bool:
    """Drop strings that are pure punctuation or ultra-long junk (packed data)."""
    if len(value) < MIN_ASCII_LEN:
        return True
    if len(value) > 4096:
        return True
    letters = sum(c.isalnum() for c in value)
    return letters == 0
