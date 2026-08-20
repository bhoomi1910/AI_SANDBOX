"""Phase 4 AI analysis service.

run_ai_analysis(context) -> dict with one of three stable shapes:

    completed    structured interpretation + provenance (cached by the router)
    unavailable  Ollama unreachable / no model / missing model — deterministic
                 analysis is unaffected
    error        the model responded but output failed strict validation and
                 was rejected (never stored or shown)

`context` contract (built by the router from the stored analysis payload):
    file          {filename, file_type, family, sha256, size}
    classification str
    score         compute_score() dict (total/severity/verdict/breakdown)
    findings      deterministic findings
    iocs          deterministic IOCs
    mitre         deterministic MITRE mappings
    evidence      normalized evidence
    static        static analysis summary
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.services.ai import validation
from app.services.ai.errors import AIUnavailable, AIValidationError
from app.services.ai.prompt import build_prompt
from app.services.ai.providers import AIProvider

logger = logging.getLogger(__name__)


def run_ai_analysis(context: dict, provider: AIProvider | None = None) -> dict:
    from app.services.ai import providers  # resolve at call time for test injection

    provider = provider or providers.get_provider()
    try:
        model = provider.select_model()
        raw = provider.generate(build_prompt(context), model)
        parsed = validation.parse_response(raw, context)
    except AIValidationError as exc:
        return {
            "status": "error",
            "provider": provider.label(),
            "reason": str(exc),
            "note": "The AI response failed strict validation and was rejected. "
                    "Deterministic analysis is unaffected.",
        }
    except AIUnavailable as exc:
        return {
            "status": "unavailable",
            "provider": provider.label(),
            "reason": str(exc),
            "note": "AI analysis is unavailable because Ollama cannot be reached. "
                    "The deterministic verdict, findings, IOCs and MITRE mappings "
                    "are still shown.",
        }
    except Exception as exc:  # noqa: BLE001 — the AI layer must never crash the API
        logger.exception("Unexpected AI engine failure")
        return {
            "status": "error",
            "provider": provider.label(),
            "reason": "Unexpected AI engine failure",
            "note": "AI analysis failed unexpectedly and was rejected. "
                    "Deterministic analysis is unaffected.",
        }

    parsed.update({
        "status": "completed",
        "provider": provider.label(),
        "model": model,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        # deterministic context attached for the frontend (never AI-authored)
        "severity": (context.get("score") or {}).get("severity", "info"),
        "verdict": (context.get("score") or {}).get("verdict", "clean"),
        "score_total": (context.get("score") or {}).get("total", 0),
        "family": (context.get("file") or {}).get("family", "unknown"),
        "classification": context.get("classification", ""),
        "provenance": {
            "findings_used": len(context.get("findings") or []),
            "iocs_used": len(context.get("iocs") or []),
            "mitre_used": len(context.get("mitre") or []),
            "note": "The AI interprets the deterministic analysis only. It cannot "
                    "add detections, IOCs or MITRE techniques.",
        },
    })
    return parsed
