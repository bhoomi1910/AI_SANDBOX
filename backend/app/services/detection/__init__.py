"""Phase 3 — Detection & Evidence Engine.

`run_detection` turns raw deterministic analyzer output into an explainable,
evidence-backed security assessment:

    static/raw analysis
      -> normalized EVIDENCE (observed)
      -> IOCs (deduplicated, provenance-preserving)
      -> findings enriched + correlated (derived)
      -> MITRE technique mappings (evidence-backed, inferred)
      -> investigation GRAPH (why the verdict is what it is)

The engine is fully deterministic. Nothing here executes a sample, calls an
external service, or invents a technique that evidence does not support.
"""
from __future__ import annotations

from app.services.detection.evidence import normalize_evidence
from app.services.detection.graph import build_graph
from app.services.detection.ioc import extract_iocs
from app.services.detection.mitre import build_mitre
from app.services.detection.rules import deduplicate_findings, enrich_findings, run_rules


def run_detection(ctx: dict) -> dict:
    """Run the full detection pipeline over one analysis context.

    `ctx` expects at minimum: {file, static, findings}. The result keys map to
    the dedicated API endpoints (/findings, /iocs, /mitre, /graph):
      - evidence: normalized observed evidence (strings, imports, YARA, …)
      - findings: analyzer findings enriched with confidence/MITRE + derived
        findings from correlated evidence, de-duplicated for display
      - iocs: de-duplicated indicators with provenance
      - mitre: evidence-backed technique mappings
      - graph: provenance graph (nodes + typed edges)
    """
    evidence = normalize_evidence(ctx)
    raw_strings = [s.get("value", "") for s in (ctx.get("static") or {}).get("strings", [])]
    iocs = extract_iocs(evidence, raw_strings)
    findings = enrich_findings(list(ctx.get("findings") or []), evidence)
    findings += run_rules(evidence, findings, ctx)
    findings = deduplicate_findings(findings)
    mitre = build_mitre(findings, evidence, iocs)
    graph = build_graph(ctx, evidence, findings, iocs, mitre)

    return {
        "evidence": evidence,
        "findings": findings,
        "iocs": iocs,
        "mitre": mitre,
        "graph": graph,
    }
