"""Stage 4: severity aggregation and host risk score."""
from __future__ import annotations

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def summarize(findings) -> dict:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts


def host_score(findings) -> float:
    """top severity + 0.1 per medium-or-worse finding, capped at 10."""
    real = [f for f in findings if f.severity != "info"]
    if not real:
        return 0.0
    top = max(f.score for f in real)
    volume = sum(1 for f in real if f.severity in ("critical", "high", "medium"))
    return round(min(10.0, top + 0.1 * volume), 1)


def grade(score: float, findings) -> str:
    if not any(f.severity != "info" for f in findings):
        return "A"
    if score < 4.0:
        return "B"
    if score < 7.0:
        return "C"
    if score < 9.0:
        return "D"
    return "F"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 99
