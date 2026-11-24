"""End-to-end: real sockets, real checks, no mocking."""
import time

from labs.weak_target import start_telnet_stub, start_web
from pyvulscan.checks import run_checks
from pyvulscan.fingerprint import fingerprint_host
from pyvulscan.portscan import scan


def test_full_pipeline_finds_the_planted_weaknesses():
    httpd = start_web(port=0)
    telnet = start_telnet_stub(port=0)
    web_port = httpd.server_address[1]
    telnet_port = telnet.getsockname()[1]
    try:
        time.sleep(0.5)
        results = scan("127.0.0.1", ports=[web_port, telnet_port], timeout=1.0)
        fps = fingerprint_host("127.0.0.1", results)
        findings = run_checks("127.0.0.1", fps)
        ids = {f.rule_id for f in findings}
        assert "VULN-001" in ids          # plaintext telnet
        assert "VULN-002" in ids          # missing headers
        assert "VULN-003" in ids          # verbose Server
        assert "VULN-005" in ids          # /admin without auth
        assert "VULN-006" in ids          # /files listing
    finally:
        httpd.shutdown()
        telnet.close()
