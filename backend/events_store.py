"""事件工作台：把多份报告挂到同一「事件」下研判（非「案件」）。

存储：reports/events.db（sqlite），不引入 PG/ClickHouse。
"""
from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import config

DB_PATH = config.REPORTS_DIR / "events.db"
_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    note TEXT DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS event_reports (
    event_id TEXT NOT NULL,
    rid TEXT NOT NULL,
    attached_at REAL NOT NULL,
    PRIMARY KEY (event_id, rid)
);
CREATE INDEX IF NOT EXISTS idx_event_reports_rid ON event_reports(rid);
"""


def _connect() -> sqlite3.Connection:
    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def ensure_db() -> Path:
    with _lock:
        conn = _connect()
        conn.close()
    return DB_PATH


def _row_event(r: sqlite3.Row, report_count: int = 0) -> Dict[str, Any]:
    return {
        "id": r["id"],
        "name": r["name"],
        "note": r["note"] or "",
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
        "report_count": report_count,
    }


def list_events(limit: int = 100) -> List[Dict[str, Any]]:
    lim = max(1, min(int(limit or 100), 500))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT e.*,
                       (SELECT COUNT(*) FROM event_reports er WHERE er.event_id=e.id) AS report_count
                FROM events e
                ORDER BY e.updated_at DESC
                LIMIT ?
                """,
                (lim,),
            ).fetchall()
            return [_row_event(r, int(r["report_count"] or 0)) for r in rows]
        finally:
            conn.close()


def get_event(event_id: str) -> Optional[Dict[str, Any]]:
    eid = (event_id or "").strip()
    if not eid:
        return None
    with _lock:
        conn = _connect()
        try:
            r = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
            if not r:
                return None
            reps = conn.execute(
                "SELECT rid, attached_at FROM event_reports WHERE event_id=? ORDER BY attached_at DESC",
                (eid,),
            ).fetchall()
            out = _row_event(r, len(reps))
            out["reports"] = [
                {"rid": x["rid"], "attached_at": x["attached_at"]} for x in reps
            ]
            return out
        finally:
            conn.close()


def create_event(name: str, note: str = "") -> Dict[str, Any]:
    name = (name or "").strip()
    if not name:
        raise ValueError("事件名称不能为空")
    if len(name) > 200:
        raise ValueError("事件名称过长")
    now = time.time()
    eid = uuid.uuid4().hex[:16]
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO events(id, name, note, created_at, updated_at) VALUES(?,?,?,?,?)",
                (eid, name, (note or "").strip()[:1000], now, now),
            )
            conn.commit()
        finally:
            conn.close()
    return get_event(eid) or {"id": eid, "name": name, "note": note, "created_at": now, "updated_at": now, "reports": [], "report_count": 0}


def update_event(event_id: str, *, name: Optional[str] = None, note: Optional[str] = None) -> Dict[str, Any]:
    ev = get_event(event_id)
    if not ev:
        raise ValueError("事件不存在")
    new_name = ev["name"] if name is None else (name or "").strip()
    new_note = ev["note"] if note is None else (note or "").strip()[:1000]
    if not new_name:
        raise ValueError("事件名称不能为空")
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE events SET name=?, note=?, updated_at=? WHERE id=?",
                (new_name, new_note, now, event_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_event(event_id) or ev


def delete_event(event_id: str) -> bool:
    eid = (event_id or "").strip()
    if not eid:
        return False
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM event_reports WHERE event_id=?", (eid,))
            cur = conn.execute("DELETE FROM events WHERE id=?", (eid,))
            conn.commit()
            return int(cur.rowcount or 0) > 0
        finally:
            conn.close()


def attach_reports(event_id: str, rids: Sequence[str]) -> Dict[str, Any]:
    ev = get_event(event_id)
    if not ev:
        raise ValueError("事件不存在")
    now = time.time()
    cleaned = []
    for r in rids or []:
        rid = str(r or "").strip()
        if rid and rid not in cleaned:
            cleaned.append(rid)
    if not cleaned:
        raise ValueError("请指定要挂载的报告")
    with _lock:
        conn = _connect()
        try:
            for rid in cleaned:
                conn.execute(
                    """
                    INSERT INTO event_reports(event_id, rid, attached_at)
                    VALUES(?,?,?)
                    ON CONFLICT(event_id, rid) DO UPDATE SET attached_at=excluded.attached_at
                    """,
                    (event_id, rid, now),
                )
            conn.execute("UPDATE events SET updated_at=? WHERE id=?", (now, event_id))
            conn.commit()
        finally:
            conn.close()
    return get_event(event_id) or ev


def detach_report(event_id: str, rid: str) -> Dict[str, Any]:
    ev = get_event(event_id)
    if not ev:
        raise ValueError("事件不存在")
    rid = (rid or "").strip()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "DELETE FROM event_reports WHERE event_id=? AND rid=?",
                (event_id, rid),
            )
            conn.execute("UPDATE events SET updated_at=? WHERE id=?", (time.time(), event_id))
            conn.commit()
        finally:
            conn.close()
    return get_event(event_id) or ev


def pending_findings_summary(event_id: str) -> Dict[str, Any]:
    """汇总事件下各报告的告警数（聚合 pending 口径：总数/高危）。"""
    ev = get_event(event_id)
    if not ev:
        raise ValueError("事件不存在")
    from .db_store import get_index_meta
    from . import paths as P
    import json

    items = []
    total = 0
    high = 0
    for row in ev.get("reports") or []:
        rid = row.get("rid") or ""
        meta = get_index_meta(rid) or {}
        issues = int(meta.get("issues") or 0)
        # 尝试读 result 摘要高危
        hi = 0
        rp = P.resolve_result_json(rid)
        if rp and Path(rp).is_file():
            try:
                data = json.loads(Path(rp).read_text(encoding="utf-8"))
                an = (data or {}).get("analysis") or {}
                sa = an.get("summary_aggregated") or an.get("summary") or {}
                hi = int(sa.get("high") or 0)
                issues = int(sa.get("total") or issues)
            except Exception:
                pass
        total += issues
        high += hi
        items.append({
            "rid": rid,
            "hostname": meta.get("hostname") or "",
            "issues": issues,
            "high": hi,
            "attached_at": row.get("attached_at"),
        })
    return {
        "event_id": event_id,
        "name": ev.get("name"),
        "total_findings": total,
        "high_findings": high,
        "reports": items,
    }
