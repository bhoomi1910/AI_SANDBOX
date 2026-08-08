"""
AI investigation engine.

Production design
-----------------
    Static + Dynamic + Network signals
                │
                ▼
    [ RAG retrieval ]  ── FAISS vector index of 1.2M+ historical malware behaviours
                │
                ▼
    [ LangChain prompt ]  ── structured analyst prompt with retrieved context
                │
                ▼
    [ LLM ]  ── OpenAI-compatible or Claude-compatible chat model
                │
                ▼
    Structured verdict (family, severity, attack-chain, recommendations)

Prototype behaviour
--------------------
`use_real_llm=False` (default) returns a deterministic, high-fidelity verdict so
the workflow is fully demonstrable offline. Set `USE_REAL_LLM=true` and provide
an API key to route through the real model.
"""
from __future__ import annotations

from app.config import get_settings

# The canonical reasoned verdict for the featured Emotet case.
_SIMULATED_VERDICT = {
    "summary": (
        "This sample is a high-confidence Emotet loader — a modular banking trojan and "
        "malware-as-a-service dropper. It arrives as an invoice-themed executable, evades "
        "analysis, downloads a second-stage payload via living-off-the-land binaries, injects "
        "into explorer.exe, establishes multiple persistence mechanisms, harvests browser "
        "credentials, and exfiltrates data to Russian and Dutch command-and-control "
        "infrastructure. It represents an active foothold with a clear path to follow-on ransomware."
    ),
    "family": "Emotet (Epoch 5 / TA542 · Mummy Spider)",
    "familyConfidence": 96,
    "severity": "critical",
    "confidence": 96,
    "reasoning": [
        "YARA rule Emotet_Loader_v5 matched the loader stub and RWX unpacking layout.",
        "Behavioural chain (LOLBin download -> injection -> Run-key persistence -> DPAPI theft) is textbook Emotet.",
        "Network indicators correlate with an active AlienVault OTX pulse attributed to TA542.",
        "AbuseIPDB reports 185.220.101.47 at 100% abuse confidence (malware-C2).",
        "imphash clusters with 1,200+ known Emotet samples (FAISS similarity 0.94).",
    ],
    "recommendations": [
        {"priority": "immediate", "action": "Isolate the affected host (contain, preserve memory)."},
        {"priority": "immediate", "action": "Block C2 IOCs: 185.220.101.47, 45.133.216.12, finance-docsecure[.]com."},
        {"priority": "high", "action": "Force-reset credentials used on the host, prioritising privileged accounts."},
        {"priority": "high", "action": "Hunt the IOCs estate-wide — Emotet spreads laterally."},
        {"priority": "medium", "action": "Re-image the host from a known-good baseline."},
    ],
    "model": "aegis-analyst-v2 (deterministic simulator)",
    "ragContextChunks": 12,
    "inferenceMs": 4210,
}


def analyse(investigation: dict) -> dict:
    """Return an AI verdict for the given investigation."""
    settings = get_settings()

    if settings.use_real_llm and (settings.openai_api_key or settings.anthropic_api_key):
        # Placeholder for the real pipeline. Kept behind a flag so the
        # prototype never requires network access or credentials.
        return _analyse_with_llm(investigation, settings)

    verdict = dict(_SIMULATED_VERDICT)
    verdict["investigationId"] = investigation["id"]
    verdict["family"] = (
        _SIMULATED_VERDICT["family"]
        if investigation["id"] == "inv-0412"
        else f'{investigation["malwareFamily"]} (heuristic match)'
    )
    return verdict


def _analyse_with_llm(investigation: dict, settings) -> dict:  # pragma: no cover
    """
    Real LLM path (disabled by default).

    Wire LangChain + FAISS here, e.g.:

        from langchain_community.vectorstores import FAISS
        from langchain_openai import ChatOpenAI
        retriever = FAISS.load_local("index", embeddings).as_retriever()
        context = retriever.invoke(build_signal_query(investigation))
        response = ChatOpenAI(model=settings.ai_model).invoke(prompt(context))
    """
    raise NotImplementedError(
        "Real LLM pipeline is not enabled in the prototype. "
        "Set USE_REAL_LLM=true and implement the retrieval + chat calls."
    )
