"""Phase 4 — AI/Ollama engine.

The AI layer is strictly an *interpreter*: it explains the deterministic
Phase 3 output (evidence, findings, IOCs, MITRE mappings, score) and can never
replace it. If Ollama is unreachable the investigation still completes with the
full deterministic analysis; AI results are marked unavailable/error instead.
"""
from __future__ import annotations

from app.services.ai.errors import AIUnavailable, AIValidationError
from app.services.ai.providers import AIProvider, get_provider
from app.services.ai.service import run_ai_analysis

__all__ = ["AIProvider", "AIUnavailable", "AIValidationError", "get_provider", "run_ai_analysis"]
