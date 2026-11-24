"""Check registry. Engine imports every check module so decorators register."""
from __future__ import annotations

from .engine import CheckContext, CheckHit, load_rules, run_checks
from . import service, web, tls  # noqa: F401  (import side effect: registration)

__all__ = ["CheckContext", "CheckHit", "load_rules", "run_checks"]
