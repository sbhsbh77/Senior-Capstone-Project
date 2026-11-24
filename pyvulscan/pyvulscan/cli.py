"""PyVulScan CLI: scan -> fingerprint -> checks -> score -> report."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import load_rules, run_checks
from .fingerprint import fingerprint_host
from .models import ScanReport, now_iso
from .portscan import DEFAULT_PORTS, scan
from .report import render_html, write_json
from .scoring import grade, host_score, summarize


def parse_ports(raw: str) -> list[int]:
    """'22,80,8080' or '1-1024' or a mix of both."""
    ports: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(chunk))
    return sorted({p for p in ports if 0 < p < 65536})


def print_findings(findings, target: str, score: float, grade_letter: str) -> None:
    if not findings:
        print(f"\n{target}: no findings")
        return
    print(f"\n{'SEV':<9}{'RULE':<11}{'PORT':>6}  TITLE")
    print("-" * 88)
    for f in findings:
        print(f"{f.severity:<9}{f.rule_id:<11}{str(f.port or '-'):>6}  {f.title}")
    print("-" * 88)
    print(f"risk score {score}/10  grade {grade_letter}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pyvulscan",
        description="Lab-scoped network vulnerability scanner (loopback / RFC1918 only).",
    )
    parser.add_argument("--target", required=True, help="literal IP inside loopback or RFC1918")
    parser.add_argument("--ports", default=None, help="e.g. 22,80,8080 or 1-1024 (default: triage set)")
    parser.add_argument("--timeout", type=float, default=0.8)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--json", metavar="PATH", default=None)
    parser.add_argument("--html", metavar="PATH", default=None)
    parser.add_argument("--no-report", action="store_true", help="print only, write nothing")
    parser.add_argument("--no-probe", action="store_true", help="skip active probes (/admin, /files)")
    parser.add_argument("--show-closed", action="store_true")
    parser.add_argument("--rules", default=None, help="alternative rules.json")
    args = parser.parse_args(argv)

    started = now_iso()
    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
        results = scan(args.target, ports=ports, workers=args.workers,
                       timeout=args.timeout, show_closed=args.show_closed)
    except (ValueError, PermissionError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2

    print(f"\nPyVulScan 1.0  target={args.target}  ports={len(ports)}")
    open_ports = [r for r in results if r.status == "open"]
    print(f"open: {', '.join(str(r.port) for r in open_ports) or 'none'}")

    fingerprints = fingerprint_host(args.target, open_ports)
    rules = load_rules(args.rules)
    findings = run_checks(args.target, fingerprints, rules, allow_active_probe=not args.no_probe)

    score = host_score(findings)
    grade_letter = grade(score, findings)
    report = ScanReport(
        target=args.target,
        started_at=started,
        finished_at=now_iso(),
        ports=[r.to_dict() for r in results],
        fingerprints=[fp.to_dict() for fp in fingerprints],
        findings=findings,
        score=score,
        grade=grade_letter,
        summary=summarize(findings),
    )

    print_findings(findings, args.target, score, grade_letter)

    if not args.no_report:
        out_dir = Path("reports")
        json_path = args.json or out_dir / f"scan_{args.target.replace(':', '_')}.json"
        html_path = args.html or out_dir / f"scan_{args.target.replace(':', '_')}.html"
        write_json(report, json_path)
        render_html(report, html_path)
        print(f"\n[json] {json_path}\n[html] {html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
