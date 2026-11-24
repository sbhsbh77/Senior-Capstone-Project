from pyvulscan.checks import load_rules, run_checks
from pyvulscan.checks.engine import _REGISTRY
from pyvulscan.fingerprint import Fingerprint


def test_every_rule_has_metadata():
    rules = load_rules()
    ids = {r["id"] for r in rules["rules"]}
    assert ids == set(_REGISTRY), "registered checks and rules.json drifted apart"
    for rule in rules["rules"]:
        assert rule["severity"] in rules["severities"]
        assert rule["remediation"]


def test_missing_headers_flagged():
    fp = Fingerprint(port=8099, service="http", http_status=200,
                     headers={"server": "DemoWeb/1.4.2", "content-type": "text/html"},
                     product="DemoWeb", version="1.4.2")
    findings = run_checks("127.0.0.1", [fp], allow_active_probe=False)
    ids = {f.rule_id for f in findings}
    assert "VULN-002" in ids
    assert "VULN-003" in ids


def test_hardened_host_produces_no_vulns():
    fp = Fingerprint(port=443, service="https", http_status=200,
                     headers={"content-security-policy": "default-src 'self'",
                              "x-frame-options": "DENY",
                              "x-content-type-options": "nosniff",
                              "referrer-policy": "no-referrer",
                              "strict-transport-security": "max-age=31536000",
                              "server": "nginx"},
                     tls={"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"})
    findings = run_checks("127.0.0.1", [fp], allow_active_probe=False)
    assert [f for f in findings if f.severity != "info"] == []


def test_plaintext_telnet_flagged():
    fp = Fingerprint(port=23, service="telnet", banner="Welcome to Demo Telnet Service\r\nlogin:")
    findings = run_checks("127.0.0.1", [fp], allow_active_probe=False)
    assert "VULN-001" in {f.rule_id for f in findings}


def test_weak_tls_flagged():
    fp = Fingerprint(port=443, service="https",
                     headers={"server": "nginx"},
                     tls={"version": "TLSv1", "cipher": "DES-CBC3-SHA"})
    findings = run_checks("127.0.0.1", [fp], allow_active_probe=False)
    assert "VULN-004" in {f.rule_id for f in findings}
