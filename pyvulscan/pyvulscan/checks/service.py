"""Service-level checks: plaintext protocols and inventory."""
from __future__ import annotations

from ..fingerprint import Fingerprint
from .engine import CheckContext, CheckHit, register

PLAINTEXT_ADMIN = {21: "ftp", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}


@register("VULN-001")
def plaintext_admin_protocol(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    if fp.service not in ("telnet", "ftp") and fp.port not in PLAINTEXT_ADMIN:
        return None
    proto = PLAINTEXT_ADMIN.get(fp.port) or fp.service
    first_line = " ".join((fp.banner.splitlines() or [""])[0].split())
    if len(first_line) > 80:
        first_line = first_line[:80].rstrip() + "…"
    evidence = (
        f"{fp.port}/tcp answers as {proto} and speaks before the client sends "
        f"anything, so credentials and session data travel in clear text: {first_line!r}"
    )
    return CheckHit(evidence=evidence, confidence=1.0)


@register("INFO-001")
def service_inventory(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    detail = f"{fp.port}/tcp {fp.service}"
    if fp.product:
        detail += f" ({fp.product} {fp.version})".replace(" )", ")")
    if fp.http_status:
        detail += f", HTTP {fp.http_status}"
    return CheckHit(evidence=detail, confidence=1.0)
