"""Scoring: per-category dedup, severity/verdict consistency."""
from app.services.analysis.score import compute_score


def _finding(severity, category):
    return {"severity": severity, "category": category}


def test_per_category_dedup_prevents_inflation():
    # 10 medium findings in ONE category must not stack 10x.
    findings = [_finding("medium", "network-communication") for _ in range(10)]
    score = compute_score(findings, 5.0)
    assert score["total"] == 7  # only the max weight per category counts


def test_distinct_categories_stack():
    findings = [
        _finding("medium", "network-communication"),
        _finding("medium", "downloader"),
    ]
    assert compute_score(findings, 5.0)["total"] == 14


def test_high_single_indicator_but_low_total_is_suspicious_not_clean():
    findings = [_finding("high", "yara")]
    score = compute_score(findings, 5.0)
    assert score["total"] == 15
    assert score["severity"] == "high"
    # high indicator + total >= 15 -> suspicious (not "high + clean")
    assert score["verdict"] == "suspicious"


def test_critical_indicator_implies_malicious_even_at_low_total():
    findings = [_finding("critical", "process-injection")]
    score = compute_score(findings, 5.0)
    assert score["total"] == 25
    assert score["verdict"] == "malicious"


def test_malicious_threshold():
    findings = [_finding("high", c) for c in ("yara", "downloader", "persistence", "injection")]
    assert compute_score(findings, 5.0)["verdict"] == "malicious"  # 60

def test_three_high_signals_still_suspicious():
    findings = [_finding("high", c) for c in ("yara", "downloader", "persistence")]
    assert compute_score(findings, 5.0)["verdict"] == "suspicious"  # 45 < 60


def test_clean_when_only_weak_signal():
    findings = [_finding("low", "network-communication")]
    score = compute_score(findings, 5.0)
    assert score["verdict"] == "clean"


def test_entropy_bonus_bounded():
    findings = []
    assert compute_score(findings, 8.0)["total"] == 5
    assert compute_score([], 8.0)["total"] <= 100


def test_verdict_never_says_clean_with_high_severity():
    # A single high indicator always scores >= 15 -> never "clean".
    score = compute_score([_finding("high", "x")], 0.0)
    assert score["severity"] == "high"
    assert score["total"] == 15
    assert score["verdict"] in ("suspicious", "malicious")
