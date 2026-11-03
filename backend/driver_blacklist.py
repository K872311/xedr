"""LOLDrivers 驱动黑名单（rules/driver/1.json）加载与哈希匹配。"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import config

_CACHE: Optional["DriverBlacklist"] = None


@dataclass
class DriverBlacklistHit:
    name: str
    category: str
    hash_type: str
    hash_value: str


class DriverBlacklist:
    def __init__(self, entries: Optional[List[Dict]] = None):
        self.entries: List[Dict] = list(entries or [])
        self.md5_map: Dict[str, Dict] = {}
        self.sha1_map: Dict[str, Dict] = {}
        self.sha256_map: Dict[str, Dict] = {}
        self._build_indexes()

    def _build_indexes(self) -> None:
        for item in self.entries:
            if not isinstance(item, dict):
                continue
            for h in item.get("md5") or []:
                if h:
                    self.md5_map[str(h).lower()] = item
            for h in item.get("sha1") or []:
                if h:
                    self.sha1_map[str(h).lower()] = item
            for h in item.get("sha256") or []:
                if h:
                    self.sha256_map[str(h).lower()] = item

    def match_hash(self, value: str) -> Optional[Tuple[Dict, str]]:
        hv = (value or "").strip().lower()
        if not hv:
            return None
        n = len(hv)
        if n == 32:
            item = self.md5_map.get(hv)
            return (item, "MD5") if item else None
        if n == 40:
            item = self.sha1_map.get(hv)
            return (item, "SHA1") if item else None
        if n == 64:
            item = self.sha256_map.get(hv)
            return (item, "SHA256") if item else None
        return None

    @property
    def size(self) -> int:
        return len(self.entries)


def _blacklist_paths() -> List[Path]:
    roots = [Path(config.RULES_DIR), Path(config.ROOT)]
    out: List[Path] = []
    seen = set()
    for base in roots:
        for rel in ("driver/1.json", "rules/driver/1.json"):
            p = base / rel
            key = str(p.resolve()) if p.exists() else str(p)
            if key in seen:
                continue
            seen.add(key)
            if p.is_file():
                out.append(p)
    return out


def load_driver_blacklist(force: bool = False) -> DriverBlacklist:
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    for path in _blacklist_paths():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                _CACHE = DriverBlacklist(data)
                return _CACHE
        except Exception as e:
            print(f"[DriverBlacklist] skip {path}: {e}")
    _CACHE = DriverBlacklist([])
    return _CACHE
