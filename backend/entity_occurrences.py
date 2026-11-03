"""跨报告实体出现记录（sqlite：reports/entities.db）。"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import config
from . import entity_keys as EK

DB_PATH = config.REPORTS_DIR / "entities.db"
_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entity_occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'global',
    hostname TEXT NOT NULL DEFAULT '',
    rid TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    context TEXT NOT NULL DEFAULT '',
    seen_at REAL NOT NULL,
    UNIQUE(kind, value, hostname, rid, path)
);
CREATE INDEX IF NOT EXISTS idx_ent_kind_val ON entity_occurrences(kind, value);
CREATE INDEX IF NOT EXISTS idx_ent_host ON entity_occurrences(hostname);
CREATE INDEX IF NOT EXISTS idx_ent_rid ON entity_occurrences(rid);
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


def upsert_occurrence(
    *,
    kind: str,
    value: str,
    hostname: str = "",
    rid: str = "",
    path: str = "",
    context: str = "",
    seen_at: Optional[float] = None,
) -> bool:
    info = EK.to_dict(kind, value, hostname=hostname)
    if not info:
        return False
    ts = float(seen_at if seen_at is not None else time.time())
    host = (hostname or "").strip()
    if info["scope"] == "host_scoped" and not host:
        return False
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """
                INSERT INTO entity_occurrences(kind, value, scope, hostname, rid, path, context, seen_at)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(kind, value, hostname, rid, path) DO UPDATE SET
                  context=excluded.context,
                  seen_at=excluded.seen_at,
                  scope=excluded.scope
                """,
                (
                    info["kind"],
                    info["value"],
                    info["scope"],
                    host if info["scope"] == "host_scoped" else host,
                    (rid or "").strip(),
                    (path or "")[:800],
                    (context or "")[:500],
                    ts,
                ),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def upsert_many(rows: Sequence[Dict[str, Any]]) -> int:
    n = 0
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        if upsert_occurrence(
            kind=str(r.get("kind") or ""),
            value=str(r.get("value") or ""),
            hostname=str(r.get("hostname") or ""),
            rid=str(r.get("rid") or ""),
            path=str(r.get("path") or ""),
            context=str(r.get("context") or ""),
            seen_at=r.get("seen_at"),
        ):
            n += 1
    return n


def delete_for_rid(rid: str) -> int:
    rid = (rid or "").strip()
    if not rid:
        return 0
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM entity_occurrences WHERE rid=?", (rid,))
            conn.commit()
            return int(cur.rowcount or 0)
        finally:
            conn.close()


def list_hosts_for_key(
    kind: str,
    value: str,
    *,
    limit: int = 100,
) -> Dict[str, Any]:
    """按实体键列出出现过的主机（去重）。"""
    norm = EK.normalize(kind, value)
    if not norm:
        return {"kind": kind, "value": value, "hosts": [], "total": 0}
    k, n = norm
    lim = max(1, min(int(limit or 100), 500))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """
                SELECT hostname, rid, path, context, seen_at, COUNT(*) AS hits
                FROM entity_occurrences
                WHERE kind=? AND value=?
                GROUP BY hostname, rid
                ORDER BY seen_at DESC
                LIMIT ?
                """,
                (k, n, lim),
            ).fetchall()
            hosts_map: Dict[str, Dict[str, Any]] = {}
            items = []
            for r in rows:
                host = (r["hostname"] or "").strip() or "(unknown)"
                item = {
                    "hostname": host,
                    "rid": r["rid"] or "",
                    "path": r["path"] or "",
                    "context": r["context"] or "",
                    "seen_at": r["seen_at"],
                    "hits": int(r["hits"] or 1),
                }
                items.append(item)
                slot = hosts_map.setdefault(host, {"hostname": host, "rids": [], "hits": 0})
                if item["rid"] and item["rid"] not in slot["rids"]:
                    slot["rids"].append(item["rid"])
                slot["hits"] += item["hits"]
            hosts = sorted(hosts_map.values(), key=lambda x: (-x["hits"], x["hostname"]))
            return {
                "kind": k,
                "value": n,
                "scope": EK.scope_for_kind(k),
                "hosts": hosts,
                "occurrences": items,
                "total": len(hosts),
            }
        finally:
            conn.close()


def extract_from_report(report: Dict[str, Any], rid: str = "") -> List[Dict[str, Any]]:
    """从报告轻量字段抽取实体，供入库。"""
    host = str(report.get("hostname") or "").strip()
    rid = (rid or report.get("_rid") or "").strip()
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, value: Any, path: str = "", context: str = "") -> None:
        info = EK.to_dict(kind, value, hostname=host)
        if not info:
            return
        key = (info["kind"], info["value"], host, path)
        if key in seen:
            return
        seen.add(key)
        out.append({
            "kind": info["kind"],
            "value": info["value"],
            "hostname": host,
            "rid": rid,
            "path": path,
            "context": context,
        })

    # 主机 IP
    for ip in (report.get("ip") or "").replace(";", ",").split(","):
        add("ip", ip, context="host.ip")

    for c in (report.get("established_connections") or [])[:2000]:
        if not isinstance(c, dict):
            continue
        add("ip", c.get("remote_ip") or c.get("RemoteAddress") or c.get("foreign_address"), context="connection")
        add("ip", c.get("local_ip") or c.get("LocalAddress"), context="connection.local")
        add("domain", c.get("remote_host") or c.get("hostname"), context="connection")

    for d in (report.get("dns_cache_entries") or [])[:3000]:
        if isinstance(d, dict):
            add("domain", d.get("name") or d.get("Name") or d.get("domain"), context="dns")
            add("ip", d.get("ip") or d.get("Address"), context="dns")
        elif isinstance(d, str):
            add("domain", d, context="dns")

    for u in (report.get("users") or [])[:500]:
        if not isinstance(u, dict):
            continue
        add("account", u.get("name") or u.get("Name") or u.get("username"), context="user")

    for p in (report.get("processes") or [])[:3000]:
        if not isinstance(p, dict):
            continue
        add("account", p.get("user") or p.get("User") or p.get("username"), context="process")
        add("hash", p.get("sha256") or p.get("SHA256"), path=str(p.get("path") or p.get("image_path") or ""), context="process")
        add("hash", p.get("md5") or p.get("MD5"), path=str(p.get("path") or ""), context="process")

    # 文件表哈希在 save 后由 ingest_file_hashes 补；这里只扫 report 内嵌
    for f in (report.get("file_scans") or [])[:5000]:
        if not isinstance(f, dict):
            continue
        fp = str(f.get("full_path") or f.get("path") or "")
        add("hash", f.get("sha256") or f.get("SHA256"), path=fp, context="file")
        add("hash", f.get("md5") or f.get("MD5"), path=fp, context="file")

    return out


def ingest_report_entities(report: Dict[str, Any], rid: str = "") -> int:
    rows = extract_from_report(report, rid=rid)
    if not rows:
        return 0
    # 先清本报告旧记录再写入，避免陈旧 path
    if rid:
        delete_for_rid(rid)
    return upsert_many(rows)


def ingest_file_hashes_from_db(rid: str, hostname: str = "", limit: int = 20000) -> int:
    """从 analysis.db files 表补哈希实体。"""
    from . import paths as P
    from .db_store import _connect

    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return 0
    conn = _connect(Path(dbp))
    rows_out: List[Dict[str, Any]] = []
    try:
        try:
            rows = conn.execute(
                "SELECT full_path, sha256, md5 FROM files "
                "WHERE (IFNULL(sha256,'')!='' OR IFNULL(md5,'')!='') LIMIT ?",
                (max(1, min(int(limit), 50000)),),
            ).fetchall()
        except Exception:
            return 0
        for r in rows:
            fp = r["full_path"] or ""
            if r["sha256"]:
                rows_out.append({
                    "kind": "hash", "value": r["sha256"], "hostname": hostname,
                    "rid": rid, "path": fp, "context": "files.db",
                })
            if r["md5"]:
                rows_out.append({
                    "kind": "hash", "value": r["md5"], "hostname": hostname,
                    "rid": rid, "path": fp, "context": "files.db",
                })
    finally:
        conn.close()
    return upsert_many(rows_out)
