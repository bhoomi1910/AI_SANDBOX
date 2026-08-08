"""Normalized evidence model.

Analyzers emit raw signals (strings, imports, capabilities, YARA hits,
metadata). This module converts them into a single normalized structure so the
rest of the engine can reason over a uniform representation:

    {
      "id": "ev-0001",
      "category": "network",      # coarse domain grouping
      "type": "url",              # fine-grained type
      "value": "http://…",
      "source_module": "strings", # which analyzer produced it
      "severity": "medium",
      "confidence": 0.8,
      "description": "…",
      "evidence": "…",            # human readable raw context
      "mitre_techniques": [...],
      "metadata": {...},
    }

Evidence is OBSERVED, never inferred. Inferences live in findings (rules.py).
"""
from __future__ import annotations

from app.services.detection.mitre import CATEGORY_MITRE, IOC_MITRE_HINTS

# Evidence type -> (category, default severity, default confidence)
_TYPE_META: dict[str, tuple[str, str, float]] = {
    "url": ("network", "medium", 0.80),
    "ip": ("network", "low", 0.75),
    "domain": ("network", "low", 0.75),
    "email": ("network", "low", 0.70),
    "hash": ("execution", "medium", 0.85),
    "registry": ("persistence", "medium", 0.75),
    "windows_path": ("file", "low", 0.55),
    "command": ("execution", "medium", 0.75),
    "mutex": ("evasion", "low", 0.60),
    "api": ("api", "medium", 0.80),
    "yara_rule": ("yara", "medium", 0.95),
    "capability": ("capability", "low", 0.70),
    "metadata": ("metadata", "info", 1.00),
    "file_meta": ("metadata", "info", 1.00),
}

MAX_EVIDENCE = 250


def normalize_evidence(ctx: dict) -> list[dict]:
    """Turn raw analyzer output (ctx) into a flat, de-duplicated evidence list.

    `ctx` keys used: file, static (strings/yara/sections/imports/capabilities/
    metadata), findings.
    """
    evidence: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def _emit(e: dict) -> None:
        key = (e["source_module"], e["type"], e["value"][:512])
        if key in seen:
            return
        seen.add(key)
        evidence.append(e)

    static = ctx.get("static") or {}

    # 1) Extracted strings.
    for s in static.get("strings", []):
        value = (s.get("value") or "").strip()
        if not value:
            continue
        etype = _normalize_string_type(s.get("type", "generic"))
        if etype is None:
            continue
        _emit(_base(etype, value, "strings", evidence,
                    metadata={"offset": s.get("offset")},
                    raw=s.get("interesting", False)))

    # 2) YARA rule hits.
    for hit in static.get("yara", []):
        rule = hit.get("rule", "")
        if not rule:
            continue
        mitre = [m] if (m := hit.get("mitre")) else []
        _emit({
            **_base("yara_rule", rule, "yara", evidence,
                    severity=hit.get("severity", "medium"), confidence=0.95,
                    description=hit.get("description", "")),
            "evidence": f"matched strings: {', '.join(hit.get('matchedStrings', []))[:200]}",
            "mitre_techniques": mitre,
            "metadata": {"tags": hit.get("tags", [])},
        })

    # 3) Suspicious PE imports (imports -> per-dll function lists).
    for group in static.get("imports", []):
        dll = group.get("dll", "")
        for fn in group.get("suspicious", []):
            _emit(_base("api", f"{dll}!{fn}", "pe", evidence,
                        description=f"Suspicious import: {fn}",
                        mitre=CATEGORY_MITRE.get("process-injection")))

    # 4) Capabilities reported by family analyzers.
    for cap in static.get("capabilities", []):
        _emit(_base("capability", str(cap), _module_for(ctx), evidence,
                    description="Analyzer-reported capability"))

    # 5) PDF metadata.
    for meta in static.get("metadata", {}).items():
        _emit(_base("metadata", f"{meta[0]}={meta[1]}", "pdf", evidence,
                    description="PDF metadata", severity="info"))

    # 6) File identity.
    f = ctx.get("file") or {}
    if f.get("file_type"):
        _emit(_base("file_meta", f"{f.get('file_type')} / {f.get('family', '')}".strip(" /"),
                    "filetype", evidence, description="Detected file type"))

    return evidence[:MAX_EVIDENCE]


def _base(etype: str, value: str, module: str, evidence: list[dict],
          severity: str | None = None, confidence: float | None = None,
          description: str = "", mitre: str | None = None,
          raw: bool = True, metadata: dict | None = None) -> dict:
    category, sev, conf = _TYPE_META.get(etype, ("generic", "info", 0.5))
    mitres: list[str] = []
    if mitre:
        mitres = [mitre]
    elif etype in IOC_MITRE_HINTS:
        mitres = IOC_MITRE_HINTS[etype]
    return {
        "id": f"ev-{len(evidence) + 1:04d}",
        "category": category,
        "type": etype,
        "value": value,
        "source_module": module,
        "severity": severity or sev,
        "confidence": round(confidence if confidence is not None else conf, 2),
        "description": description,
        "evidence": value if raw else description,
        "mitre_techniques": mitres,
        "metadata": metadata or {},
    }


def _normalize_string_type(stype: str) -> str | None:
    """Map strings-classifier types to evidence types (drop noisy generics)."""
    if stype == "generic":
        return None
    if stype == "ip":
        return "ip"
    if stype == "path":
        return "windows_path"
    return stype  # url, domain, registry, command, mutex, api


def _module_for(ctx: dict) -> str:
    family = (ctx.get("file") or {}).get("family", "")
    return {"pe": "pe", "pdf": "pdf", "ooxml": "office", "ole": "office",
            "script": "script"}.get(family, "family")
