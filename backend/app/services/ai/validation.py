"""Strict validation of the AI response.

Two layers:
1. Parse: the model's text must be a JSON object (code fences and trailing
   commas tolerated; anything else raises AIValidationError and is discarded).
2. Sanitize + anti-hallucination: field types are coerced, sizes bounded, and
   any MITRE technique NOT present in the deterministic mappings is dropped.
   The model can never introduce IOCs, techniques, or a score — the engine
   simply refuses those fields.
"""
from __future__ import annotations

import json
import re

from app.services.ai.errors import AIValidationError

_MAX_TEXT = 1200
_MAX_LIST = 8
_MAX_ITEM = 240
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def parse_response(raw: str, context: dict) -> dict:
    """Validate a model response against the context's deterministic data."""
    data = _parse_json(raw)
    allowed_ids = _deterministic_technique_ids(context)

    return {
        "executive_summary": _text(data.get("executive_summary"), _MAX_TEXT),
        "technical_summary": _text(data.get("technical_summary"), _MAX_TEXT),
        "threat_explanation": _text(data.get("threat_explanation"), _MAX_TEXT),
        "key_findings": _str_list(data.get("key_findings")),
        "risk_factors": _str_list(data.get("risk_factors")),
        "mitre_explanation": _mitre_list(data.get("mitre_explanation"), allowed_ids),
        "recommendations": _recommendations(data.get("recommendations")),
        "business_impact": _str_list(data.get("business_impact"), max_items=5),
        "limitations": _str_list(data.get("limitations"), max_items=5),
        "confidence": _confidence(data.get("confidence")),
    }


# ---- parsing ---------------------------------------------------------------

def _parse_json(raw: str) -> dict:
    if not isinstance(raw, str) or not raw.strip():
        raise AIValidationError("empty model response")
    text = raw.strip()
    fence = _FENCE_RE.search(text)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise AIValidationError("model response is not a JSON object")
    text = text[start:end + 1]
    try:
        data = json.loads(text)
    except ValueError:
        data = json.loads(_TRAILING_COMMA_RE.sub(r"\1", text))
    if not isinstance(data, dict):
        raise AIValidationError("model response JSON is not an object")
    return data


# ---- sanitizers -------------------------------------------------------------

def _text(value, max_len: int) -> str:
    text = str(value or "").strip()
    if len(text) > max_len:
        text = text[:max_len]
    return text


def _str_list(value, max_items: int = _MAX_LIST, max_len: int = _MAX_ITEM) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            out.append(text[:max_len])
        if len(out) >= max_items:
            break
    return out


def _confidence(value) -> int:
    try:
        conf = int(value)
    except (TypeError, ValueError):
        conf = 0
    return max(0, min(100, conf))


def _recommendations(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    priorities = {"immediate", "high", "medium"}
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        priority = str(item.get("priority", "medium")).lower()
        if priority not in priorities:
            priority = "medium"
        action = str(item.get("action") or "").strip()[:240]
        if action:
            out.append({"priority": priority, "action": action})
        if len(out) >= _MAX_LIST:
            break
    return out


def _mitre_list(value, allowed_ids: set[str]) -> list[dict]:
    if not isinstance(value, list):
        return []
    out: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("technique_id") or "").strip().upper()
        if tid not in allowed_ids:  # invented or unknown -> drop, never show
            continue
        explanation = str(item.get("explanation") or "").strip()[:_MAX_ITEM]
        out.append({"technique_id": tid, "explanation": explanation})
    return out


def _deterministic_technique_ids(context: dict) -> set[str]:
    ids = set()
    for m in context.get("mitre") or []:
        tid = m.get("technique_id")
        if tid:
            ids.add(str(tid).upper())
    for f in context.get("findings") or []:
        for tid in f.get("mitre_techniques") or ([f["mitre"]] if f.get("mitre") else []):
            if tid:
                ids.add(str(tid).upper())
    return ids
