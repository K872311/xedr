# -*- coding: utf-8 -*-
"""干净系统基线库（win11_baseline）：匹配阶段过滤已知正常服务/计划任务/启动项。"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config
from .models import Finding

_LOCK = threading.RLock()
_CACHE: Optional[Dict[str, Any]] = None
_CACHE_MTIME: float = -1.0


def baselines_dir() -> Path:
    d = Path(config.ROOT) / "baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def baseline_path(name: str = "win11_baseline") -> Path:
    return baselines_dir() / f"{name}.json"


def _norm(s: str) -> str:
    t = str(s or "").strip().lower().replace("/", "\\")
    for a, b in (
        ("%systemroot%", "c:\\windows"),
        ("%windir%", "c:\\windows"),
        ("%programfiles%", "c:\\program files"),
        ("%programfiles(x86)%", "c:\\program files (x86)"),
        ("%programdata%", "c:\\programdata"),
    ):
        t = t.replace(a, b)
    while "\\\\" in t:
        t = t.replace("\\\\", "\\")
    return t


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime if p.is_file() else -1.0
    except OSError:
        return -1.0


def load(force: bool = False) -> Dict[str, Any]:
    """加载 win11_baseline.json；返回带索引的结构。"""
    global _CACHE, _CACHE_MTIME
    p = baseline_path()
    mt = _mtime(p)
    with _LOCK:
        if not force and _CACHE is not None and mt == _CACHE_MTIME:
            return _CACHE
        empty = {
            "id": "win11_baseline",
            "enabled": False,
            "services": [],
            "tasks": [],
            "startup": [],
            "svc_names": set(),
            "svc_paths": set(),
            "task_names": set(),
            "task_cmds": set(),
            "startup_cmds": set(),
            "path": str(p),
        }
        if not p.is_file():
            _CACHE = empty
            _CACHE_MTIME = mt
            return _CACHE
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            _CACHE = empty
            _CACHE_MTIME = mt
            return _CACHE
        if not isinstance(raw, dict):
            _CACHE = empty
            _CACHE_MTIME = mt
            return _CACHE

        svc_names: Set[str] = set()
        svc_paths: Set[str] = set()
        for s in raw.get("services") or []:
            if not isinstance(s, dict):
                continue
            n = str(s.get("name") or "").strip().lower()
            if n:
                svc_names.add(n)
            ip = _norm(str(s.get("image_path_norm") or s.get("image_path") or ""))
            if ip:
                svc_paths.add(ip)

        task_names: Set[str] = set()
        task_cmds: Set[str] = set()
        for t in raw.get("tasks") or []:
            if not isinstance(t, dict):
                continue
            n = str(t.get("task_name") or "").strip().lower()
            if n:
                task_names.add(n)
            c = _norm(str(t.get("command_norm") or t.get("command") or ""))
            if c:
                task_cmds.add(c[:240])

        startup_cmds: Set[str] = set()
        for s in raw.get("startup") or []:
            if not isinstance(s, dict):
                continue
            c = _norm(str(s.get("command_norm") or s.get("command") or ""))
            if c:
                startup_cmds.add(c[:240])

        out = {
            "id": raw.get("id") or "win11_baseline",
            "name": raw.get("name") or "Win11 baseline",
            "enabled": raw.get("enabled", True) is not False,
            "services": raw.get("services") or [],
            "tasks": raw.get("tasks") or [],
            "startup": raw.get("startup") or [],
            "stats": raw.get("stats") or {},
            "source_report": raw.get("source_report") or "",
            "svc_names": svc_names,
            "svc_paths": svc_paths,
            "task_names": task_names,
            "task_cmds": task_cmds,
            "startup_cmds": startup_cmds,
            "path": str(p),
        }
        _CACHE = out
        _CACHE_MTIME = mt
        return _CACHE


def reload() -> Dict[str, Any]:
    return load(force=True)


def _finding_blob(f: Any) -> str:
    if hasattr(f, "to_dict"):
        d = f.to_dict()
    elif isinstance(f, dict):
        d = f
    else:
        d = {}
    parts = [
        str(d.get("title") or d.get("name") or ""),
        str(d.get("evidence") or ""),
        str(d.get("reason") or ""),
        str(d.get("path") or ""),
    ]
    ev = d.get("evidence")
    if isinstance(ev, list):
        parts.extend(str(x) for x in ev[:20])
    return _norm(" \n ".join(parts))


def is_baseline_noise(finding: Any, bl: Optional[Dict[str, Any]] = None) -> bool:
    """判断告警是否命中干净基线（已知正常服务/任务/启动项）。"""
    data = bl or load()
    if not data.get("enabled"):
        return False
    blob = _finding_blob(finding)
    if not blob:
        return False

    # 服务：证据里出现基线服务名，且 ImagePath/路径也在基线或为 system32\\svchost
    svc_names: Set[str] = data.get("svc_names") or set()
    svc_paths: Set[str] = data.get("svc_paths") or set()
    if svc_names:
        hit_name = next((n for n in svc_names if n and n in blob), "")
        if hit_name:
            if any(p and p in blob for p in svc_paths):
                return True
            # 常见系统服务宿主
            if "\\system32\\svchost.exe" in blob or "%systemroot%\\system32\\svchost.exe" in blob:
                return True
            if f"services\\{hit_name}" in blob or f"\\services\\{hit_name}" in blob:
                # 注册表服务键 + 基线服务名，且无可疑扩展路径
                if not any(x in blob for x in ("\\temp\\", "\\users\\public\\", "\\downloads\\", "appdata\\local\\temp")):
                    return True

    # 计划任务
    task_names: Set[str] = data.get("task_names") or set()
    task_cmds: Set[str] = data.get("task_cmds") or set()
    if task_names:
        hit_task = next((n for n in task_names if n and n in blob), "")
        if hit_task:
            if any(c and c in blob for c in task_cmds):
                return True
            # 任务名命中且命令落在 Windows\\System32
            if "\\windows\\system32\\" in blob or "%windir%\\system32\\" in blob or "%systemroot%\\system32\\" in blob:
                if not any(x in blob for x in ("\\temp\\", "\\users\\public\\", "\\downloads\\")):
                    return True

    # 启动项命令
    for c in data.get("startup_cmds") or set():
        if c and len(c) >= 12 and c in blob:
            return True

    return False


def filter_findings(findings: List[Finding]) -> Tuple[List[Finding], Dict[str, int]]:
    """匹配后过滤：丢掉命中 win11_baseline 的告警。"""
    bl = load()
    if not bl.get("enabled") or not findings:
        return findings, {"dropped_baseline": 0, "baseline": bl.get("id") or ""}
    kept: List[Finding] = []
    dropped = 0
    for f in findings:
        if is_baseline_noise(f, bl):
            dropped += 1
            continue
        kept.append(f)
    return kept, {
        "dropped_baseline": dropped,
        "baseline": bl.get("id") or "win11_baseline",
        "services": len(bl.get("svc_names") or []),
        "tasks": len(bl.get("task_names") or []),
    }


def stats() -> Dict[str, Any]:
    bl = load()
    return {
        "enabled": bool(bl.get("enabled")),
        "id": bl.get("id"),
        "name": bl.get("name"),
        "path": bl.get("path"),
        "source_report": bl.get("source_report"),
        "services": len(bl.get("svc_names") or []),
        "tasks": len(bl.get("task_names") or []),
        "startup": len(bl.get("startup_cmds") or []),
        "stats": bl.get("stats") or {},
    }
