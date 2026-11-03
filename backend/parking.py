"""待办线索：AI/溯检预算耗尽或延期时暂存线索，供人工后续消化。

存储：reports/parking.jsonl（轻量追加日志，非 ClickHouse）。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

STORE_PATH = config.REPORTS_DIR / "parking.jsonl"
_lock = threading.RLock()


def _path() -> Path:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return STORE_PATH


def _read_all() -> List[Dict[str, Any]]:
    p = _path()
    if not p.is_file():
        return []
    out: List[Dict[str, Any]] = []
    try:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if isinstance(row, dict) and row.get("id"):
                    out.append(row)
    except OSError:
        return []
    return out


def _rewrite(rows: List[Dict[str, Any]]) -> None:
    p = _path()
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(p)


def list_items(
    *,
    status: str = "parked",
    rid: str = "",
    limit: int = 200,
) -> List[Dict[str, Any]]:
    lim = max(1, min(int(limit or 200), 1000))
    want = (status or "").strip().lower()
    rid_f = (rid or "").strip()
    with _lock:
        rows = _read_all()
    if want and want != "all":
        rows = [r for r in rows if str(r.get("status") or "").lower() == want]
    if rid_f:
        rows = [r for r in rows if str(r.get("rid") or "") == rid_f]
    rows.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
    return rows[:lim]


def add_item(
    *,
    title: str,
    reason: str = "",
    rid: str = "",
    hostname: str = "",
    source: str = "",
    kind: str = "lead",
    payload: Optional[Dict[str, Any]] = None,
    severity: str = "medium",
) -> Dict[str, Any]:
    title = (title or "").strip()[:300]
    if not title:
        raise ValueError("标题不能为空")
    now = time.time()
    item = {
        "id": uuid.uuid4().hex[:16],
        "title": title,
        "reason": (reason or "").strip()[:2000],
        "rid": (rid or "").strip()[:240],
        "hostname": (hostname or "").strip()[:120],
        "source": (source or "").strip()[:80],
        "kind": (kind or "lead").strip()[:40],
        "severity": (severity or "medium").strip()[:20],
        "status": "parked",
        "created_at": now,
        "updated_at": now,
        "payload": payload if isinstance(payload, dict) else {},
        "candidate": True,
    }
    with _lock:
        p = _path()
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
    return item


def park_deferred(
    *,
    rid: str = "",
    hostname: str = "",
    source: str,
    title: str = "",
    reason: str = "",
    payload: Optional[Dict[str, Any]] = None,
    severity: str = "medium",
) -> Dict[str, Any]:
    """AI/溯检预算或延期时的便捷入口。"""
    src = (source or "ai").strip()
    ttl = (title or "").strip() or f"{src} 线索已暂存（候选）"
    why = (reason or "").strip() or "预算耗尽或延期，已放入待办线索待后续研判"
    return add_item(
        title=ttl if "候选" in ttl else f"{ttl}（候选）",
        reason=why,
        rid=rid,
        hostname=hostname,
        source=src,
        kind="deferred",
        payload=payload,
        severity=severity,
    )


def _set_status(item_id: str, status: str, *, note: str = "") -> Dict[str, Any]:
    iid = (item_id or "").strip()
    st = (status or "").strip().lower()
    if not iid:
        raise ValueError("缺少 id")
    if st not in ("parked", "dismissed", "promoted"):
        raise ValueError("状态须为 parked / dismissed / promoted")
    with _lock:
        rows = _read_all()
        found = None
        for r in rows:
            if r.get("id") == iid:
                r["status"] = st
                r["updated_at"] = time.time()
                if note:
                    r["note"] = str(note)[:500]
                found = r
                break
        if not found:
            raise ValueError("线索不存在")
        _rewrite(rows)
        return dict(found)


def dismiss(item_id: str, note: str = "") -> Dict[str, Any]:
    return _set_status(item_id, "dismissed", note=note)


def promote(item_id: str, note: str = "") -> Dict[str, Any]:
    """提升：标记为 promoted（前端可跳转报告研判）；不自动改 finding 裁决。"""
    return _set_status(item_id, "promoted", note=note or "已提升待审")


def get_item(item_id: str) -> Optional[Dict[str, Any]]:
    iid = (item_id or "").strip()
    if not iid:
        return None
    with _lock:
        for r in _read_all():
            if r.get("id") == iid:
                return r
    return None
