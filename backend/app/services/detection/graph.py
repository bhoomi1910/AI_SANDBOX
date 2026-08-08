"""Investigation graph: why the verdict is what it is.

A directed provenance graph connecting the file, the OBSERVED evidence, the
DERIVED findings, the IOCs and the INFERRED MITRE techniques. Edges are typed
so the frontend can render meaningful relationships:

  file     --contains-->     evidence
  evidence --indicates-->    technique
  evidence --yields-->       ioc
  finding  --supported_by--> evidence
  finding  --maps_to-->      technique

Graphs are capped; the most relevant nodes (highest severity/confidence) are
kept first.
"""
from __future__ import annotations

from app.services.detection.mitre import supported

MAX_NODES = 160
MAX_EDGES = 320


def build_graph(ctx: dict, evidence: list[dict], findings: list[dict],
                iocs: list[dict], mitre: list[dict]) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()
    edge_keys: set[tuple[str, str, str]] = set()

    def _add_node(node: dict) -> None:
        if len(nodes) >= MAX_NODES or node["id"] in node_ids:
            return
        node_ids.add(node["id"])
        nodes.append(node)

    def _add_edge(source: str, target: str, etype: str) -> None:
        key = (source, target, etype)
        if len(edges) >= MAX_EDGES or key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"source": source, "target": target, "type": etype})

    # Root: the analyzed file.
    f = ctx.get("file") or {}
    file_id = f"file:{f.get('sha256', 'unknown')[:12]}"
    _add_node({"id": file_id, "kind": "file", "label": f.get("filename", "file"),
               "value": f.get("sha256", ""), "severity": "info", "confidence": 1.0})

    # Evidence nodes.
    for e in evidence:
        if len(node_ids) >= MAX_NODES:
            break
        _add_node({"id": e["id"], "kind": "evidence", "label": e["type"],
                   "value": e["value"][:120], "severity": e.get("severity", "info"),
                   "confidence": e.get("confidence", 0.5)})
        _add_edge(file_id, e["id"], "contains")
        for tid in e.get("mitre_techniques", []):
            if supported(tid):
                _add_edge(e["id"], tid, "indicates")

    # IOC nodes (deduplicated; only reachable via an evidence edge).
    for ioc in iocs:
        _add_node({"id": ioc["id"], "kind": "ioc", "label": ioc["type"],
                   "value": ioc["value"][:120], "severity": ioc.get("severity", "info"),
                   "confidence": ioc.get("confidence", 0.5)})
        for src in ioc.get("sources", []):
            _add_edge(src.get("evidence_id") or "", ioc["id"], "yields")

    # Finding nodes.
    for i, fnd in enumerate(findings, start=1):
        fid = f"finding:{fnd.get('module', 'analyzer')}:{i:03d}"
        _add_node({"id": fid, "kind": "finding", "label": fnd.get("category", ""),
                   "value": (fnd.get("title") or "")[:120],
                   "severity": fnd.get("severity", "info"),
                   "confidence": fnd.get("confidence", 0.5)})
        for eid in fnd.get("evidence_ids", []):
            _add_edge(fid, eid, "supported_by")
        techniques = list(fnd.get("mitre_techniques") or [])
        if fnd.get("mitre"):
            techniques.append(fnd["mitre"])
        for tid in dict.fromkeys(t for t in techniques if supported(t)):
            _add_edge(fid, tid, "maps_to")

    # Technique nodes come last so mappings collapse into a shared technique node.
    for m in mitre:
        _add_node({"id": m["technique_id"], "kind": "technique",
                   "label": m["technique"], "value": m["tactic"],
                   "severity": m.get("severity", "info"),
                   "confidence": m.get("confidence", 0.5)})

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "evidence": len(evidence),
            "findings": len(findings),
            "iocs": len(iocs),
            "techniques": len(mitre),
        },
    }
