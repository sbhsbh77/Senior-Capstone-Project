"""HTTP checks: hardening headers, banner disclosure, admin surface, listing."""
from __future__ import annotations

import re

from ..fingerprint import Fingerprint
from .engine import CheckContext, CheckHit, register

REQUIRED_HEADERS = {
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


@register("VULN-002")
def missing_headers(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    if fp.service not in ("http", "https") or not fp.headers:
        return None
    missing = [label for key, label in REQUIRED_HEADERS.items() if key not in fp.headers]
    if fp.service == "https" and "strict-transport-security" not in fp.headers:
        missing.append("Strict-Transport-Security")
    if not missing:
        return None
    present = ", ".join(sorted(fp.headers.keys()))
    evidence = (
        f"GET / -> HTTP {fp.http_status}; missing {', '.join(missing)}. "
        f"Headers actually returned: {present}"
    )
    return CheckHit(evidence=evidence, confidence=1.0)


@register("VULN-003")
def verbose_server_banner(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    server = fp.headers.get("server", "")
    if not server:
        return None
    if not fp.version:
        return None
    evidence = f"Server header reads {server!r}, exposing {fp.product} {fp.version}"
    return CheckHit(evidence=evidence, confidence=0.95)


@register("VULN-005")
def admin_without_auth(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    if fp.service not in ("http", "https") or not ctx.allow_active_probe:
        return None
    status, headers, body, _ = ctx.http_get(fp.port, "/admin", fp.service == "https")
    if status is None or status != 200:
        return None
    if any(k in headers for k in ("www-authenticate",)):
        return None
    snippet = " ".join(re.sub(r"<[^>]+>", " ", body).split())
    if len(snippet) > 90:
        snippet = snippet[:90].rstrip() + "…"
    evidence = f"GET /admin -> {status} with no WWW-Authenticate challenge; body: {snippet!r}"
    return CheckHit(evidence=evidence, confidence=0.85)


@register("VULN-006")
def directory_listing(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    if fp.service not in ("http", "https") or not ctx.allow_active_probe:
        return None
    status, headers, body, _ = ctx.http_get(fp.port, "/files/", fp.service == "https")
    if status is None or status != 200:
        return None
    lowered = body.lower()
    if "index of /" not in lowered and "directory listing for" not in lowered:
        return None
    return CheckHit(evidence=f"GET /files/ -> 200 with a browsable index page", confidence=0.9)
