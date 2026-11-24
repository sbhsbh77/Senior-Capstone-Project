"""CI smoke test: plant the weak target, scan it, fail if nothing is found."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from labs.weak_target import start_all                      # noqa: E402
from pyvulscan.checks import run_checks                     # noqa: E402
from pyvulscan.fingerprint import fingerprint_host          # noqa: E402
from pyvulscan.portscan import scan                         # noqa: E402


def main() -> int:
    httpd, telnet = start_all(web_port=8099, telnet_port=9001)
    time.sleep(1.0)
    results = scan("127.0.0.1", ports=[8099, 9001], timeout=1.0)
    fingerprints = fingerprint_host("127.0.0.1", results)
    findings = run_checks("127.0.0.1", fingerprints)

    ids = {f.rule_id for f in findings}
    expected = {"VULN-001", "VULN-002", "VULN-003", "VULN-005", "VULN-006"}
    missing = expected - ids
    print(f"open ports: {[r.port for r in results]}")
    print(f"findings  : {sorted(ids)}")
    if missing:
        print(f"[fail] expected rules not triggered: {sorted(missing)}")
        return 1
    print("[ok] pipeline produced the planted findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
