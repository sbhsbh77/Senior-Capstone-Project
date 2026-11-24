"""TLS configuration check."""
from __future__ import annotations

from ..fingerprint import Fingerprint
from .engine import CheckContext, CheckHit, register

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES_", "NULL", "EXPORT", "MD5")


@register("VULN-004")
def weak_tls(ctx: CheckContext, fp: Fingerprint) -> CheckHit | None:
    info = fp.tls or {}
    version = info.get("version", "")
    cipher = info.get("cipher", "")
    if not version:
        return None
    problems = []
    if version in WEAK_PROTOCOLS:
        problems.append(f"negotiated {version}")
    if any(tok in cipher.upper() for tok in WEAK_CIPHER_TOKENS):
        problems.append(f"cipher {cipher}")
    if not problems:
        return None
    evidence = (
        f"{fp.port}/tcp TLS handshake succeeded with "
        + " and ".join(problems)
        + "; certificate was not validated (self-signed/internal PKI likely)"
    )
    return CheckHit(evidence=evidence, confidence=0.9)
