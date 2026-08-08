"""Evidence-based threat scoring (deterministic, deduplicated).

Design (documented in docs/SECURITY_MODULES.md):
- Each finding carries a severity; weights are fixed and reproducible.
- DEDUP: per category only the strongest finding's weight counts. A signal
  observed by N modules in the same category (e.g. several YARA hits) is
  evidence of one capability, not N capabilities — so it is never weighted
  multiple times. Cross-category signals (process-injection + downloader +
  persistence) still stack, which is the intended behaviour.
- The reported severity is the worst single indicator, not the sum.
- Verdict thresholds:
    malicious   total >= 60   OR worst indicator == critical
    suspicious  total >= 25   OR (worst indicator == high AND total >= 15)
    clean       otherwise (static evidence only; no ground truth)

The formula and weights are frozen so two runs over the same sample always
produce the same score and verdict.
"""
from __future__ import annotations

WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
MAX_SCORE = 100
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def compute_score(findings: list[dict], entropy: float) -> dict:
    severity = _max_severity(findings)

    # Dedup: per category, only the strongest finding contributes.
    by_category: dict[str, int] = {}
    total = 0
    for f in findings:
        cat = f.get("category") or "other"
        weight = WEIGHTS.get(f.get("severity", "info"), 0)
        prev = by_category.get(cat, 0)
        if weight > prev:
            total += weight - prev
            by_category[cat] = weight

    if entropy >= 7.5:
        total += 5
        by_category["entropy"] = 5
    elif entropy >= 7.0:
        total += 3
        by_category["entropy"] = 3

    total = min(total, MAX_SCORE)

    verdict = "malicious"
    if total < 60 and severity != "critical":
        verdict = "suspicious" if (total >= 25 or (severity == "high" and total >= 15)) else "clean"

    breakdown = [
        {"category": cat, "points": pts, "max": MAX_SCORE}
        for cat, pts in sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)
    ]
    return {
        "total": total,
        "severity": severity,
        "verdict": verdict,
        "breakdown": breakdown,
        "method": ("deduplicated weighted findings per category (max weight per category: "
                   "critical 25 / high 15 / medium 7 / low 2) + entropy bonus (max 5); "
                   "verdict: malicious >=60 or critical indicator, suspicious >=25 or "
                   "(high indicator and >=15), else clean"),
    }


def _max_severity(findings: list[dict]) -> str:
    for sev in SEVERITY_ORDER:
        if any(f.get("severity") == sev for f in findings):
            return sev
    return "info"
