"""PE executable analysis via `pefile`.

Extracts headers, sections (with entropy), imports (with suspicious API flags),
imphash, architecture, subsystem and compile time. Emits evidence-backed
"capabilities" from the imported APIs — no simulation.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.services.analysis.entropy import shannon

SUSPICIOUS_APIS = {
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "OpenProcess", "NtUnmapViewOfSection", "SetWindowsHookExA", "SetWindowsHookExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "OutputDebugStringA", "GetProcAddress", "LoadLibraryA",
    "RegSetValueExA", "RegCreateKeyExA", "RegOpenKeyExA", "DeleteFileA", "RemoveDirectoryA",
    "WinExec", "ShellExecuteA", "ShellExecuteExA", "CreateProcessA", "CreateProcessW",
    "CryptUnprotectData", "CryptEncrypt", "GetAsyncKeyState", "GetKeyState",
    "UrlDownloadToFileA", "InternetOpenA", "InternetConnectA", "HttpSendRequestA",
    "Socket", "connect", "send", "recv", "CreateServiceA", "StartServiceA",
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcessModules",
    "AdjustTokenPrivileges", "LookupPrivilegeValueA", "OpenProcessToken",
}

PACKER_HINTS = {
    "UPX0": "UPX packer (compressed stub)",
    "UPX1": "UPX packer (compressed stub)",
    "UPX2": "UPX packer (compressed stub)",
    ".vmp0": "VMProtect (heavily obfuscated)",
    ".vmp1": "VMProtect (heavily obfuscated)",
    ".themida": "Themida / WinLicense protector",
    ".aspack": "ASPack packer",
    ".petite": "Petite packer",
    "MPRESS1": "MPRESS packer",
    "MPRESS2": "MPRESS packer",
    ".ndata": "NSPack / NPack",
    "nsp0": "NSPack / NPack",
    "nsp1": "NSPack / NPack",
}

_ARCH = {0x014C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x01C4: "ARM32", 0xAA64: "ARM64"}
_SUBSYSTEM = {2: "Windows GUI", 3: "Windows Console", 1: "Native", 9: "Windows CE"}


def analyze_pe(path: Path, findings: list[dict]) -> dict:
    import pefile

    result: dict = {
        "arch": "Unknown",
        "subsystem": "Unknown",
        "timestamp": None,
        "imphash": "",
        "signatureStatus": "unsigned",
        "compiler": "Unknown",
        "packer": None,
        "sections": [],
        "imports": [],
        "capabilities": [],
    }
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        findings.append(_finding("high", "malformed-pe", "Malformed PE header", str(exc), evidence="PE header could not be parsed"))
        return result

    try:
        result["arch"] = _ARCH.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04X}")
        result["subsystem"] = _SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts:
            import datetime as dt

            result["timestamp"] = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        try:
            result["imphash"] = pe.get_imphash() or ""
        except Exception:
            result["imphash"] = ""

        result["sections"] = _sections(pe)
        result["imports"] = _imports(pe)
        result["capabilities"] = _capabilities(result["imports"], result["sections"], findings)
        result["packer"] = _packer(result["sections"])
        result["compiler"] = _compiler(pe)
        result["signatureStatus"] = _signature(pe, findings)
    finally:
        try:
            pe.close()
        except Exception:
            pass

    whole_entropy = shannon(_read_all(path))
    if whole_entropy > 7.0 and not result["packer"]:
        result["packer"] = "Potential packer (high entropy)"
    return result


def _sections(pe) -> list[dict]:
    out = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", "ignore") or "?"
        flags = _section_flags(sec.Characteristics)
        entropy = round(sec.get_entropy(), 2)
        suspicious = entropy > 7.0 or ("X" in flags and "W" in flags)
        out.append({
            "name": name,
            "virtualSize": sec.Misc_VirtualSize,
            "rawSize": sec.SizeOfRawData,
            "entropy": entropy,
            "flags": flags,
            "suspicious": suspicious,
        })
    return out


def _section_flags(ch: int) -> str:
    flags = []
    if ch & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        flags.append("X")
    elif ch & 0x40000000:  # IMAGE_SCN_MEM_READ
        flags.append("R")
    if ch & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        flags.append("W")
    if not flags:
        flags.append("R")
    return "-".join(flags)


def _imports(pe) -> list[dict]:
    groups = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return groups
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            dll = entry.dll.decode("ascii", "ignore")
        except Exception:
            continue
        funcs, suspicious = [], []
        for imp in entry.imports or []:
            name = None
            if imp.name:
                name = imp.name.decode("ascii", "ignore")
            elif imp.ordinal:
                name = f"ordinal_{imp.ordinal}"
            if not name:
                continue
            funcs.append(name)
            if name in SUSPICIOUS_APIS:
                suspicious.append(name)
        groups.append({"dll": dll, "functions": funcs, "suspicious": suspicious})
    return groups


def _capabilities(imports: list[dict], sections: list[dict], findings: list[dict]) -> list[str]:
    funcs = {f for grp in imports for f in grp["functions"]}
    caps = []
    if {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}.issubset(funcs) or "SetWindowsHookExA" in funcs or "SetWindowsHookExW" in funcs:
        caps.append("Process injection (VirtualAllocEx / WriteProcessMemory / CreateRemoteThread)")
        findings.append(_finding("high", "process-injection", "Process injection API triad", "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread imported together", evidence="PE imports"))
    if funcs & {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}:
        caps.append("Anti-analysis / debugger evasion checks")
        findings.append(_finding("medium", "anti-debug", "Anti-debug APIs imported", "Debugger-detection APIs present", evidence="PE imports"))
    if funcs & {"RegSetValueExA", "RegCreateKeyExA"}:
        caps.append("Registry persistence / configuration (RegSetValueEx)")
        findings.append(_finding("medium", "registry-persistence", "Registry write APIs imported", "APIs that write registry values for persistence present", evidence="PE imports"))
    if funcs & {"CryptUnprotectData", "CryptEncrypt"}:
        caps.append("Credential / crypto data access (CryptUnprotectData)")
        findings.append(_finding("medium", "credential-access", "DPAPI / crypto APIs imported", "CryptUnprotectData or CryptEncrypt present", evidence="PE imports"))
    if funcs & {"InternetOpenA", "InternetConnectA", "HttpSendRequestA", "UrlDownloadToFileA"}:
        caps.append("Network / HTTP communication (WININET)")
        findings.append(_finding("low", "network-api", "Network APIs imported", "WININET/WinHTTP functions present", evidence="PE imports"))
    if funcs & {"GetProcAddress", "LoadLibraryA"} and funcs & {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"}:
        caps.append("Dynamic API resolution (GetProcAddress / LoadLibraryA)")
    if funcs & {"GetAsyncKeyState", "GetKeyState"}:
        caps.append("Keyboard monitoring (GetAsyncKeyState)")
        findings.append(_finding("high", "keylogging", "Keyboard hooking API imported", "GetAsyncKeyState/GetKeyState present", evidence="PE imports"))
    if funcs & {"CreateServiceA", "StartServiceA"}:
        caps.append("Windows service installation (CreateService)")
    if funcs & {"AdjustTokenPrivileges", "LookupPrivilegeValueA", "OpenProcessToken"}:
        caps.append("Privilege escalation / token manipulation")
        findings.append(_finding("medium", "privilege-escalation", "Token manipulation APIs imported", "AdjustTokenPrivileges / LookupPrivilegeValue present", evidence="PE imports"))
    if any(s["suspicious"] for s in sections):
        caps.append("Suspicious section layout (RWX or high-entropy)")
    return caps


def _packer(sections: list[dict]) -> str | None:
    for sec in sections:
        hint = PACKER_HINTS.get(sec["name"])
        if hint:
            return hint
    if sections and max(s["entropy"] for s in sections) > 7.0:
        return "High-entropy sections (possible packing / encryption)"
    return None


def _compiler(pe) -> str:
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", "ignore")
        if name in (".text", ".rdata", ".data"):
            return "Unknown"
    return "Unknown"


def _signature(pe, findings: list[dict]) -> str:
    has_cert = False
    if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # Security directory
            has_cert = dd.VirtualAddress > 0 and dd.Size > 8
        except IndexError:
            has_cert = False
    if has_cert:
        findings.append(_finding("low", "code-signature", "Authenticode signature present", "Certificate directory present — signature NOT cryptographically verified on this host", evidence="PE security directory"))
        return "unsigned"
    return "unsigned"


def _read_all(path: Path) -> bytes:
    size = os.path.getsize(path)
    if size > 64 * 1024 * 1024:
        return b""
    with open(path, "rb") as f:
        return f.read()


def _finding(severity, category, title, detail, evidence) -> dict:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "evidence": evidence,
        "mitre": None,
        "module": "pe",
    }
