"""操作审计日志：优先 MySQL，失败回退 SQLite。"""
from __future__ import annotations
import csv
import io
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import config
from .db_store import _connect

AUDIT_DB = config.REPORTS_DIR / "audit.db"

AUDIT_MYSQL_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    ts DOUBLE NOT NULL,
    username VARCHAR(64) DEFAULT '',
    role VARCHAR(32) DEFAULT '',
    action VARCHAR(64) NOT NULL,
    target VARCHAR(255) DEFAULT '',
    detail TEXT,
    ip VARCHAR(64) DEFAULT '',
    KEY idx_audit_ts (ts),
    KEY idx_audit_action (action),
    KEY idx_audit_user (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def _init_sqlite(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            ts REAL NOT NULL,
            username TEXT DEFAULT '',
            role TEXT DEFAULT '',
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            detail TEXT,
            ip TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
        """
    )


def ensure_audit_table(conn=None) -> None:
    from . import mysql_db
    own = conn is None
    if own:
        if not mysql_db.mysql_ready():
            return
        conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(AUDIT_MYSQL_SQL)
        conn.commit()
    finally:
        if own:
            conn.close()


class AuditStore:
    def __init__(self):
        from . import mysql_db
        self.mysql = False
        self.cur = None
        if mysql_db.mysql_ready():
            try:
                ensure_audit_table()
                self.conn = mysql_db.connect_mysql()
                self.cur = self.conn.cursor()
                self.mysql = True
                return
            except Exception as e:
                try:
                    mysql_db.mark_mysql_down(str(e))
                except Exception:
                    pass
                print(f"[audit] mysql unavailable → sqlite: {e}")
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = _connect(AUDIT_DB)
        _init_sqlite(self.conn)
        self.cur = None

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.mysql else sql

    def execute(self, sql: str, args=()):
        if self.mysql:
            self.cur.execute(self._q(sql), args)
        else:
            self.conn.execute(sql, args)

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            if self.mysql and self.cur:
                self.cur.close()
            self.conn.close()
        except Exception:
            pass

    def query_all(self, sql: str, args=()) -> List[Dict[str, Any]]:
        if self.mysql:
            self.cur.execute(self._q(sql), args)
            return list(self.cur.fetchall() or [])
        cur = self.conn.execute(sql, args)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def write_audit(
    action: str,
    *,
    username: str = "",
    role: str = "",
    target: str = "",
    detail: Any = None,
    ip: str = "",
    user: Optional[Dict[str, Any]] = None,
) -> None:
    """写入一条审计；失败不影响主流程。"""
    try:
        if user:
            username = username or (user.get("username") or "")
            role = role or (user.get("role") or "")
        detail_s = ""
        if detail is None:
            detail_s = ""
        elif isinstance(detail, str):
            detail_s = detail[:2000]
        else:
            try:
                detail_s = json.dumps(detail, ensure_ascii=False)[:2000]
            except Exception:
                detail_s = str(detail)[:2000]
        store = AuditStore()
        try:
            store.execute(
                "INSERT INTO audit_logs (id, ts, username, role, action, target, detail, ip) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    uuid.uuid4().hex[:16],
                    time.time(),
                    (username or "")[:64],
                    (role or "")[:32],
                    (action or "unknown")[:64],
                    (target or "")[:255],
                    detail_s,
                    (ip or "")[:64],
                ),
            )
            store.commit()
        finally:
            store.close()
    except Exception as e:
        print("[audit] write failed:", e)


def _parse_bound_ts(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        n = float(value)
        return n / 1000.0 if n >= 1e12 else n
    s = str(value).strip()
    if not s:
        return None
    if s.replace(".", "", 1).isdigit():
        n = float(s)
        return n / 1000.0 if n >= 1e12 else n
    try:
        from datetime import datetime
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _audit_filters(
    *,
    action: str = "",
    username: str = "",
    q: str = "",
    since: Any = None,
    until: Any = None,
) -> Tuple[str, List[Any], str]:
    where: List[str] = []
    args: List[Any] = []
    if action:
        where.append("action=?")
        args.append(action.strip())
    if username:
        where.append("username=?")
        args.append(username.strip())
    q = (q or "").strip()
    if q:
        like = f"%{q[:120]}%"
        where.append(
            "(username LIKE ? OR role LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)"
        )
        args.extend([like, like, like, like, like, like])
    since_ts = _parse_bound_ts(since)
    until_ts = _parse_bound_ts(until)
    if since_ts is not None:
        where.append("ts>=?")
        args.append(float(since_ts))
    if until_ts is not None:
        where.append("ts<=?")
        args.append(float(until_ts))
    wh = (" WHERE " + " AND ".join(where)) if where else ""
    return wh, args, q


def _row_to_item(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": r.get("id"),
        "ts": r.get("ts"),
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(r.get("ts") or 0))),
        "username": r.get("username") or "",
        "role": r.get("role") or "",
        "action": r.get("action") or "",
        "target": r.get("target") or "",
        "detail": r.get("detail") or "",
        "ip": r.get("ip") or "",
    }


def list_audit(
    limit: int = 100,
    offset: int = 0,
    action: str = "",
    username: str = "",
    q: str = "",
    since: Any = None,
    until: Any = None,
) -> Dict[str, Any]:
    limit = max(1, min(500, int(limit or 100)))
    offset = max(0, int(offset or 0))
    wh, args, q = _audit_filters(action=action, username=username, q=q, since=since, until=until)
    store = AuditStore()
    try:
        total_row = store.query_all(f"SELECT COUNT(1) AS c FROM audit_logs{wh}", tuple(args))
        total = int((total_row[0] or {}).get("c") or 0) if total_row else 0
        rows = store.query_all(
            f"SELECT id, ts, username, role, action, target, detail, ip FROM audit_logs{wh} "
            f"ORDER BY ts DESC LIMIT ? OFFSET ?",
            tuple(args) + (limit, offset),
        )
        items = [_row_to_item(r) for r in rows]
        return {"total": total, "offset": offset, "limit": limit, "items": items, "q": q}
    finally:
        store.close()


def export_audit_csv(
    *,
    action: str = "",
    username: str = "",
    q: str = "",
    since: Any = None,
    until: Any = None,
    max_rows: int = 50000,
) -> Tuple[bytes, str, int]:
    """导出审计 CSV（UTF-8 BOM，便于 Excel 打开）。"""
    cap = max(1, min(50000, int(max_rows or 50000)))
    wh, args, _ = _audit_filters(action=action, username=username, q=q, since=since, until=until)
    store = AuditStore()
    try:
        total_row = store.query_all(f"SELECT COUNT(1) AS c FROM audit_logs{wh}", tuple(args))
        total = int((total_row[0] or {}).get("c") or 0) if total_row else 0
        rows = store.query_all(
            f"SELECT id, ts, username, role, action, target, detail, ip FROM audit_logs{wh} "
            f"ORDER BY ts DESC LIMIT ?",
            tuple(args) + (cap,),
        )
        items = [_row_to_item(r) for r in rows]
    finally:
        store.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["时间", "用户", "角色", "动作", "目标", "详情", "IP", "ID"])
    for it in items:
        writer.writerow([
            it.get("time") or "",
            it.get("username") or "",
            it.get("role") or "",
            it.get("action") or "",
            it.get("target") or "",
            it.get("detail") or "",
            it.get("ip") or "",
            it.get("id") or "",
        ])
    stamp = time.strftime("%Y%m%d_%H%M%S")
    truncated = total > len(items)
    name = f"audit_{stamp}.csv" if not truncated else f"audit_{stamp}_top{len(items)}.csv"
    return buf.getvalue().encode("utf-8-sig"), name, len(items)


def audit_actions() -> List[str]:
    store = AuditStore()
    try:
        rows = store.query_all("SELECT DISTINCT action FROM audit_logs ORDER BY action")
        return [str(r.get("action") or "") for r in rows if r.get("action")]
    finally:
        store.close()


def list_user_login_history(username: str, *, limit: int = 50) -> Dict[str, Any]:
    """某用户的登录成功 / 失败记录（含 IP）。失败事件常写在 target。"""
    uname = (username or "").strip()
    if not uname:
        return {"username": "", "total": 0, "ok": 0, "failed": 0, "items": []}
    limit = max(1, min(200, int(limit or 50)))
    store = AuditStore()
    try:
        rows = store.query_all(
            """
            SELECT id, ts, username, role, action, target, detail, ip FROM audit_logs
            WHERE action IN ('login', 'login_failed')
              AND (username=? OR target=?)
            ORDER BY ts DESC LIMIT ?
            """,
            (uname, uname, limit),
        )
        items = [_row_to_item(r) for r in rows]
        ok_n = sum(1 for it in items if it.get("action") == "login")
        fail_n = sum(1 for it in items if it.get("action") == "login_failed")
        return {
            "username": uname,
            "total": len(items),
            "ok": ok_n,
            "failed": fail_n,
            "items": items,
        }
    finally:
        store.close()
