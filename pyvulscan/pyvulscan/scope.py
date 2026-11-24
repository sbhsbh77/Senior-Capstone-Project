"""Scope guard: the scanner refuses to touch anything outside the lab."""
from __future__ import annotations

import ipaddress

_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
]


class OutOfScopeError(PermissionError):
    """Raised when a target is not an authorized (private/loopback) address."""


def assert_in_scope(target: str) -> str:
    """Validate a target and return its normalized string form.

    Only literal IP addresses inside loopback or RFC1918 ranges are accepted.
    Public addresses are rejected before any packet is sent, so an accidental
    typo can never turn a demo into a scan of somebody else's host.
    """
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(
            f"only literal IPv4/IPv6 addresses are allowed, got {target!r}"
        ) from exc

    if not any(ip in net for net in _PRIVATE_NETS):
        raise OutOfScopeError(
            f"{ip} is outside the authorized lab scope "
            "(loopback + RFC1918 only)."
        )
    return str(ip)


def is_in_scope(target: str) -> bool:
    try:
        assert_in_scope(target)
        return True
    except (ValueError, OutOfScopeError):
        return False
