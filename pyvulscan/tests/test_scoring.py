from pyvulscan.models import Finding
from pyvulscan.scoring import grade, host_score, summarize


def _f(sev, score, port=80):
    return Finding(rule_id="X", title="t", severity=sev, score=score, port=port,
                   service="http", evidence="e", remediation="r")


def test_clean_host_scores_zero_with_grade_a():
    findings = [_f("info", 0.0)]
    assert host_score(findings) == 0.0
    assert grade(0.0, findings) == "A"


def test_one_critical_dominates_lows():
    critical = [_f("critical", 9.5), _f("low", 2.5, 81), _f("low", 2.5, 82)]
    assert host_score(critical) >= 9.5
    assert grade(host_score(critical), critical) == "F"


def test_volume_raises_score():
    findings = [_f("medium", 5.3, p) for p in (80, 81, 82, 83)]
    assert host_score(findings) == 5.7


def test_summary_counts():
    findings = [_f("high", 8.0), _f("low", 2.5), _f("info", 0.0)]
    s = summarize(findings)
    assert s["high"] == 1 and s["low"] == 1 and s["info"] == 1 and s["total"] == 3
