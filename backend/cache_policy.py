"""Shared policy for small in-process caches.

Large report details stay in per-report SQLite databases and are never copied to Redis.
"""
from __future__ import annotations

import os
from typing import Any


CACHE_VERSION = (os.environ.get("FORENSIC_CACHE_VERSION") or "v1").strip()[:32] or "v1"


def ttl(name: str, default: float, *, minimum: float = 1.0, maximum: float = 3600.0) -> float:
    raw = os.environ.get(f"FORENSIC_CACHE_{name.upper()}_TTL")
    try:
        value = float(raw) if raw is not None else float(default)
    except (TypeError, ValueError):
        value = float(default)
    return max(minimum, min(maximum, value))


def capacity(name: str, default: int, *, minimum: int = 16, maximum: int = 100_000) -> int:
    raw = os.environ.get(f"FORENSIC_CACHE_{name.upper()}_MAX")
    try:
        value = int(raw) if raw is not None else int(default)
    except (TypeError, ValueError):
        value = int(default)
    return max(minimum, min(maximum, value))


def versioned(*parts: Any) -> str:
    return ":".join([CACHE_VERSION] + [str(x) for x in parts])
