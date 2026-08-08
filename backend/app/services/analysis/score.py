"""Evidence-based threat scoring.

Each finding carries a severity; weights are fixed and documented so the score
is reproducible. Whole-file entropy adds a bounded bonus. Verdict thresholds:
  >= 60  -> malicious
  >= 25  -> suspicious
  else   -> clean (static evidence only; no ground truth)
"""
from __future__ import annotations

WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
MAX_SCORE = 100
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def compute_score(findings: list[dict], entropy: float) -> dict:
    severity = _max_severity(findings)

    by_category: dict[str, int] = {}
    total = 0
    for f in findings:
        weight = WEIGHTS.get(f.get("severity", "info"), 0)
        if weight:
            total += weight
            cat = f.get("category", "other")
            by_category[cat] = by_category.get(cat, 0) + weight

    if entropy >= 7.5:
        total += 5
        by_category["entropy"] = by_category.get("entropy", 0) + 5
    elif entropy >= 7.0:
        total += 3
        by_category["entropy"] = by_category.get("entropy", 0) + 3

    total = min(total, MAX_SCORE)

    verdict = "malicious" if (total >= 60 or severity == "critical") else "suspicious" if total >= 25 else "clean"

    breakdown = [
        {"category": cat, "points": pts, "max": MAX_SCORE}
        for cat, pts in sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)
    ]
    return {"total": total, "severity": severity, "verdict": verdict, "breakdown": breakdown, "method": "documented weighted findings (critical 25 / high 15 / medium 7 / low 2) + entropy bonus (max 5)"}


def _max_severity(findings: list[dict]) -> str:
    for sev in SEVERITY_ORDER:
        if any(f.get("severity") == sev for f in findings):
            return sev
    return "info"
