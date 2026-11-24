from pyvulscan.models import Finding, ScanReport
from pyvulscan.report import render_html, write_json
from pyvulscan.scoring import grade, host_score, summarize


def _report(findings):
    return ScanReport(target="127.0.0.1", started_at="2026-01-01 00:00:00",
                      finished_at="2026-01-01 00:00:05", findings=findings,
                      score=host_score(findings), grade=grade(host_score(findings), findings),
                      summary=summarize(findings))


def test_html_and_json_are_written(tmp_path):
    findings = [Finding(rule_id="VULN-001", title="Plaintext telnet", severity="high",
                        score=8.0, port=23, service="telnet",
                        evidence="banner: login:", remediation="use ssh")]
    r = _report(findings)
    html = render_html(r, tmp_path / "r.html")
    js = write_json(r, tmp_path / "r.json")
    assert "VULN-001" in html.read_text()
    assert "Plaintext telnet" in html.read_text()
    assert "\"score\"" in js.read_text()


def test_empty_report_still_renders(tmp_path):
    r = _report([])
    html = render_html(r, tmp_path / "empty.html")
    assert "No findings" in html.read_text()
