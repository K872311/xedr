# -*- coding: utf-8 -*-
"""主机时间线降噪：Agent 自身采集命令、同一进程多源重复、PowerShell 自动生成模块代码；ETW 时间戳纠正为本地时间。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

AGENT_EXES = frozenset({"forensic-agent.exe"})
_CHILD_TTL = 600.0
_EXIT_GRACE = 30.0
_DEDUP_TTL = 300.0

_lock = threading.Lock()
# agent_id -> {pid: last_seen}；Agent 自己拉起的采集进程（tasklist / netstat / powershell …）及其子进程
_children: Dict[str, Dict[int, float]] = {}
# agent_id -> {(kind, pid, name): last_seen}
_seen: Dict[str, Dict[Tuple[str, int, str], float]] = {}

KIND_ORDER = ("proc", "exit", "file", "net", "module", "script", "persist", "alert", "other")


def etype_kind(etype: str) -> str:
    e = str(etype or "").lower()
    if "remote_thread" in e or "protect_block" in e or "driver" in e:
        return "alert"
    if "image_load" in e:
        return "module"
    if "scriptblock" in e or e.startswith("win_ps"):
        return "script"
    if "file" in e or e.startswith("fim_"):
        return "file"
    if "exit" in e:
        return "exit"
    if "dns" in e or "network" in e:
        return "net"
    if any(k in e for k in ("persist", "registry", "service", "task", "account", "logon", "group", "audit", "priv")):
        return "persist"
    if "process" in e or "live" in e or "thread" in e or "access" in e:
        return "proc"
    return "other"


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _lower_name(v: Any) -> str:
    s = str(v or "").replace("/", "\\").rstrip("\\")
    return s.rsplit("\\", 1)[-1].lower()


def _prune(d: Dict[Any, float], ttl: float, now: float) -> None:
    if len(d) > 4000:
        for k in [k for k, t in d.items() if now - t > ttl]:
            d.pop(k, None)


def is_collector_noise(agent_id: str, etype: str, detail: Dict[str, Any], *, now: Optional[float] = None) -> bool:
    """Agent 采集时拉起的子进程及其 conhost / 孙进程：创建、退出及其模块加载 / 文件 / 网络活动都不进时间线。"""
    kind = etype_kind(etype)
    if kind in ("alert", "other") or not isinstance(detail, dict):
        return False
    now = now or time.time()
    pid = _int(detail.get("pid"))
    ppid = _int(detail.get("ppid"))
    parent = _lower_name(detail.get("parent_name") or detail.get("parent_path"))
    with _lock:
        kids = _children.setdefault(agent_id, {})
        _prune(kids, _CHILD_TTL, now)
        if kind not in ("proc", "exit"):
            actor = _lower_name(detail.get("process_name") or detail.get("host_process") or "")
            if kind in ("module", "file", "net") and actor in AGENT_EXES:
                return True
            if pid and pid in kids and now - kids[pid] <= _CHILD_TTL:
                kids[pid] = now
                return True
            return False
        if kind == "exit":
            if pid and pid in kids and now - kids[pid] <= _CHILD_TTL:
                # 退出后只留短暂宽限（其他来源的重复退出 / 迟到的模块事件），防止 PID 复用误吞新进程
                kids[pid] = min(kids[pid], now - _CHILD_TTL + _EXIT_GRACE)
                return True
            return False
        if parent in AGENT_EXES or (ppid and ppid in kids and now - kids[ppid] <= _CHILD_TTL):
            if pid:
                kids[pid] = now
            return True
        if pid:
            kids.pop(pid, None)
    return False


def is_duplicate(agent_id: str, etype: str, detail: Dict[str, Any], *, now: Optional[float] = None) -> bool:
    """同一进程被 Agent / WMI / ETW 各报一次：保留先到的一条。"""
    kind = etype_kind(etype)
    if kind not in ("proc", "exit") or not isinstance(detail, dict):
        return False
    pid = _int(detail.get("pid"))
    name = _lower_name(detail.get("name") or detail.get("path") or detail.get("image"))
    if not pid or not name:
        return False
    now = now or time.time()
    key = (kind, pid, name)
    with _lock:
        seen = _seen.setdefault(agent_id, {})
        _prune(seen, _DEDUP_TTL, now)
        last = seen.get(key)
        seen[key] = now
    return last is not None and now - last <= _DEDUP_TTL


def is_generated_script(etype: str, detail: Dict[str, Any]) -> bool:
    """PowerShell 4104 里 CIM/CDXML 模块自动生成的代理代码（$__cmdletization_*），无研判价值。"""
    if etype_kind(etype) != "script" or not isinstance(detail, dict):
        return False
    return "$__cmdletization_" in str(detail.get("script_block") or "")


def _local_offset() -> timedelta:
    return timedelta(seconds=time.localtime().tm_gmtoff or 0)


def fix_etw_ts(etype: str, ts: str, received: str) -> str:
    """ETW 事件时间是 UTC：与接收时间相差恰好一个本地时区偏移时，换算成本地时间。"""
    if not str(etype or "").endswith("_etw"):
        return ts
    try:
        t = datetime.fromisoformat(str(ts)[:19])
        r = datetime.fromisoformat(str(received)[:19])
    except ValueError:
        return ts
    off = _local_offset()
    if abs(off.total_seconds()) < 600:
        return ts
    if abs((r - t - off).total_seconds()) <= 900:
        return (t + off).strftime("%Y-%m-%dT%H:%M:%S")
    return ts


def drop_reason(agent_id: str, etype: str, detail: Dict[str, Any]) -> str:
    if is_collector_noise(agent_id, etype, detail):
        return "collector"
    if is_generated_script(etype, detail):
        return "generated_script"
    if is_duplicate(agent_id, etype, detail):
        return "duplicate"
    return ""


def clean_history(conn: sqlite3.Connection, *, batch: int = 5000) -> Dict[str, int]:
    """按同样规则清理已入库的时间线，并纠正 ETW 时间戳。按 id 升序重放以复现进程父子关系。"""
    stats = {"collector": 0, "generated_script": 0, "duplicate": 0, "ts_fixed": 0}
    with _lock:
        saved_children, saved_seen = dict(_children), dict(_seen)
        _children.clear()
        _seen.clear()
    try:
        last_id = 0
        while True:
            rows = conn.execute(
                "SELECT id, agent_id, etype, detail_json, ts, created_at FROM agent_timeline WHERE id>? ORDER BY id LIMIT ?",
                (last_id, batch),
            ).fetchall()
            if not rows:
                break
            drop, fix = [], []
            for r in rows:
                last_id = r["id"]
                try:
                    d = json.loads(r["detail_json"] or "{}")
                except Exception:
                    d = {}
                when = _epoch(r["created_at"])
                reason = ""
                if is_collector_noise(r["agent_id"], r["etype"], d, now=when):
                    reason = "collector"
                elif is_generated_script(r["etype"], d):
                    reason = "generated_script"
                elif is_duplicate(r["agent_id"], r["etype"], d, now=when):
                    reason = "duplicate"
                if reason:
                    stats[reason] += 1
                    drop.append((r["id"],))
                    continue
                nts = fix_etw_ts(r["etype"], r["ts"], r["created_at"])
                if nts != r["ts"]:
                    fix.append((nts, r["id"]))
            if drop:
                conn.executemany("DELETE FROM agent_timeline WHERE id=?", drop)
            if fix:
                conn.executemany("UPDATE agent_timeline SET ts=? WHERE id=?", fix)
                stats["ts_fixed"] += len(fix)
            conn.commit()
    finally:
        with _lock:
            _children.clear()
            _children.update(saved_children)
            _seen.clear()
            _seen.update(saved_seen)
    return stats


def _epoch(s: Any) -> float:
    try:
        return datetime.fromisoformat(str(s)[:19]).timestamp()
    except ValueError:
        return time.time()
