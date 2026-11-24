# PyVulScan

**Bohan Shen (沈博涵)** · Student ID 202384014073 · Senior Capstone Project

A small, lab-scoped network vulnerability scanner in Python.
Built as a capstone project: it discovers hosts and services on **my own machine
/ lab network**, fingerprints what it finds, matches the results against a rule
knowledge base, scores the risk, and writes a report with evidence and
remediation.

> **Scope & ethics.** PyVulScan only accepts literal IPs inside loopback
> (`127.0.0.0/8`) or RFC1918 ranges (`10/8`, `172.16/12`, `192.168/16`).
> Public addresses and hostnames are rejected *before* a packet is sent.
> Everything is tested against a deliberately weak local target that I start
> myself (`labs/weak_target.py`). The tool detects and reports only: no
> exploitation, no credential brute forcing, no payloads.

## Pipeline

```
target ──► scope guard ──► port scan ──► fingerprint ──► rule engine ──► scoring ──► report
           (refuse unless   (TCP connect   (headers,       (rules.json    (CVSS-lite   (JSON +
            loopback/RFC1918) + banner)     version, TLS)   + checks)      + volume)    HTML)
```

## Quickstart

```bash
git clone https://github.com/sbhshb77/Senior-Capstone-Project.git
cd Senior-Capstone-Project/pyvulscan
pip install -e ".[dev]"          # jinja2 runtime, pytest for tests

# 1) stand up the deliberately weak local target
python labs/weak_target.py
# 2) in a second shell, scan it
pyvulscan --target 127.0.0.1 --ports 8099,9001,22,80,443,3306
```

Output:

```
PyVulScan 1.0  target=127.0.0.1  ports=6
open: 8099, 9001

SEV      RULE         PORT  TITLE
----------------------------------------------------------------------------------------
high     VULN-005     8099  Administrative path reachable without authentication
high     VULN-001     9001  Plaintext administrative protocol exposed
medium   VULN-003     8099  Verbose server banner discloses product version
medium   VULN-006     8099  Directory listing enabled
low      VULN-002     8099  HTTP response missing hardening headers
info     INFO-001     8099  Service inventory
info     INFO-001     9001  Service inventory
----------------------------------------------------------------------------------------
risk score 8.4/10  grade D
[json] reports/scan_127.0.0.1.json
[html] reports/scan_127.0.0.1.html
```

`--no-probe` skips the two active HTTP probes, `--no-report` prints only,
`--rules custom.json` swaps the knowledge base.

## Rules

| Rule | What it detects | Severity |
| ---- | --------------- | ----- |
| VULN-001 | plaintext admin protocol exposed (telnet/ftp) | High |
| VULN-002 | HTTP response missing CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / HSTS | Low |
| VULN-003 | `Server` header discloses an exact product version | Medium |
| VULN-004 | TLS 1.0/1.1 negotiated, or weak cipher (3DES/RC4/NULL/EXPORT/MD5) | Medium |
| VULN-005 | `/admin` answers 200 without an auth challenge | High |
| VULN-006 | browsable directory index | Medium |
| INFO-001 | service inventory | Info |

Rules live in `pyvulscan/data/rules.json` (metadata, severity, remediation,
references) and the logic lives in `pyvulscan/checks/`. A test asserts the two
never drift apart: every registered check must have a rule entry.

## Scoring

Severity weights: critical 9.5, high 8.0, medium 5.3, low 2.5, info 0.0.
Host score = `min(10, top_severity + 0.1 × count(medium-or-worse))`, so one
critical outranks a pile of lows while volume still counts. Grades: A (nothing),
B (<4), C (<7), D (<9), F (≥9).

## Architecture

`docs/architecture.md` holds the Mermaid diagrams: pipeline, module layers, data
model and the authorization guard. Quick version:

| Module | Responsibility |
| ------ | -------------- |
| `scope.py` | authorization guard, refuses anything outside the lab |
| `portscan.py` | TCP connect scan + banner grab, thread pool |
| `fingerprint.py` | HTTP headers/title, product+version, TLS facts, service class |
| `checks/engine.py` | rule loading, dispatch, `Finding` construction |
| `checks/*.py` | one function per rule id, registered by decorator |
| `scoring.py` | severity aggregation, host score, grade |
| `report.py` | JSON + Jinja2 HTML |
| `cli.py` | wiring and console output |

## Why this design

* **Authorization before reconnaissance.** The guard sits in front of every
  scanning call, so a one-character mistake in a command line cannot turn a
  demo into a scan of somebody else's host.
* **Stdlib transport.** Raw sockets need root; TCP connect works unprivileged
  in Colab, which is where this was developed.
* **Rules as data.** Adding a rule means one JSON entry plus one decorated
  function — measured, reviewable, and easy to extend without touching the
  engine.
* **Evidence-carrying findings.** Each finding stores the bytes that triggered
  it (banner line, missing header list, probe response) so a reader can verify
  the claim instead of trusting a score.
* **No false-positive theatre.** A hardened configuration is covered by a test
  that must produce zero non-info findings.

## Development

```bash
pytest -q            # 17 tests: scope, scan, fingerprints, rules, scoring, report, e2e
```

CI runs the same suite on Python 3.10–3.12 (`.github/workflows/ci.yml`).

## Roadmap

- [x] Stage 1 — scope guard, connect scan, banner grab, local weak target
- [x] Stage 2 — fingerprints: HTTP headers, product/version, TLS facts
- [x] Stage 3 — rule engine + `rules.json` + scoring
- [x] Stage 4 — JSON/HTML report, CLI, tests, CI
- [ ] Next — port profile files (top-1000), per-rule confidence tuning, optional
      `nmap` cross-check for service names, JSON schema for the report

## Disclaimer

Educational project. Use it only on systems you own or are explicitly
authorized to test. Scanning third-party systems is illegal in most
jurisdictions.
