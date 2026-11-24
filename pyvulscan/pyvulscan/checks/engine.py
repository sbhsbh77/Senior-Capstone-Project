"""Rule-driven check engine: rules live in data/rules.json, logic lives in checks/."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..fingerprint import Fingerprint, _http_request
from ..models import Finding

RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "rules.json"

_REGISTRY: dict[str, Callable[["CheckContext", Fingerprint], "CheckHit | None"]] = {}


def register(rule_id: str):
    def deco(fn):
        _REGISTRY[rule_id] = fn
        return fn
    return deco


@dataclass
class CheckHit:
    evidence: str
    confidence: float = 0.9


@dataclass
class CheckContext:
    host: str
    allow_active_probe: bool = True

    def http_get(self, port: int, path: str, use_tls: bool = False):
        return _http_request(self.host, port, path, use_tls)


def load_rules(path: Path | str | None = None) -> dict:
    p = Path(path) if path else RULES_PATH
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def run_checks(host: str, fingerprints: list[Fingerprint],
               rules: dict | None = None,
               allow_active_probe: bool = True) -> list[Finding]:
    rules = rules or load_rules()
    severity_weight = rules["severities"]
    rule_map = {r["id"]: r for r in rules["rules"]}
    ctx = CheckContext(host=host, allow_active_probe=allow_active_probe)

    findings: list[Finding] = []
    for fp in fingerprints:
        for rule_id, fn in _REGISTRY.items():
            rule = rule_map.get(rule_id)
            if not rule:
                continue                      # code added without a rule entry
            try:
                hit = fn(ctx, fp)
            except Exception:                 # a broken check must not kill the scan
                continue
            if not hit:
                continue
            findings.append(Finding(
                rule_id=rule_id,
                title=rule["title"],
                severity=rule["severity"],
                score=float(severity_weight[rule["severity"]]),
                port=fp.port,
                service=fp.service,
                product=fp.product,
                version=fp.version,
                evidence=hit.evidence,
                remediation=rule["remediation"],
                references=rule.get("references", []),
                confidence=hit.confidence,
                category=rule.get("category", ""),
            ))

    findings.sort(key=lambda f: (-f.score, f.port or 0))
    return findings
