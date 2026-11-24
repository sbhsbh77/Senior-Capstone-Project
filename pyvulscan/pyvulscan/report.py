"""Stage 5: JSON + HTML reporting."""
from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .scoring import severity_rank

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def write_json(report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def render_html(report, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,          # every value in the report is attacker-influenced
    )
    env.filters["severity_rank"] = severity_rank
    tpl = env.get_template("report.html.j2")
    html = tpl.render(r=report, findings=sorted(report.findings, key=lambda f: (-f.score, f.port or 0)))
    path.write_text(html, encoding="utf-8")
    return path
