"""Shared data models: findings and the scan report."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    score: float
    port: int | None
    service: str
    evidence: str
    remediation: str
    product: str = ""
    version: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 0.9
    category: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str
    ports: list = field(default_factory=list)
    fingerprints: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    score: float = 0.0
    grade: str = "A"
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "ports": self.ports,
            "fingerprints": self.fingerprints,
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
