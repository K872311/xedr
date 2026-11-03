"""Production safety switches (env). Default off for destructive / code-update paths."""
from __future__ import annotations

import os


def _truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def code_updates_allowed() -> bool:
    """Allow system upgrade packages that may overwrite server code."""
    return _truthy("FORENSIC_ALLOW_CODE_UPDATE")


def device_ops_allowed() -> bool:
    """Allow reboot / shutdown / factory_reset API."""
    return _truthy("FORENSIC_DEVICE_OPS")
