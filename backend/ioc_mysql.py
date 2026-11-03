# -*- coding: utf-8 -*-
"""IOC 情报 MySQL 索引（替代 ES 作为默认同步目标）。

数据流：ioc/ioc_data.db (SQLite 源) → MySQL ioc_records → 查询热路径
查询路径（ioc_db）：LRU → Redis → MySQL → SQLite（ES 可选）
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config
from . import mysql_db

TABLE = "ioc_records"
MANUAL_SOURCE = "manual"
# 人工条目 ID 区间，避开常见情报库自增 ID
MANUAL_ID_BASE = 9_000_000_000_000

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id BIGINT NOT NULL PRIMARY KEY,
    type VARCHAR(32) NOT NULL,
    value VARCHAR(2048) NOT NULL,
    ip_only VARCHAR(64) DEFAULT NULL,
    source VARCHAR(256) DEFAULT '',
    malware VARCHAR(512) DEFAULT '',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    KEY idx_ioc_type_value (type, value(191)),
    KEY idx_ioc_ip_only (ip_only),
    KEY idx_ioc_value (value(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

_sync_lock = threading.Lock()
_sync_state: Dict[str, Any] = {
    "running": False,
    "last_ok": False,
    "last_error": "",
    "indexed": 0,
    "added": 0,
    "skipped": 0,
    "scanned": 0,
    "total": 0,
    "mode": "",
    "started_at": "",
    "finished_at": "",
    "elapsed_ms": 0,
    "errors": 0,
    "mysql_count_before": None,
    "mysql_count_after": None,
}
_tables_ready = False


def _sync_state_path() -> Path:
    return (
        Path(getattr(config, "CONFIG_DIR", None) or (Path(__file__).resolve().parent.parent / "config"))
        / "ioc_mysql_sync_state.json"
    )


def _load_persisted_sync_state() -> None:
    p = _sync_state_path()
    if not p.is_file():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
        for k in (
            "last_ok", "last_error", "indexed", "added", "skipped", "scanned",
            "total", "mode", "started_at", "finished_at", "elapsed_ms", "errors",
            "mysql_count_before", "mysql_count_after",
        ):
            if k in data:
                _sync_state[k] = data[k]
        _sync_state["running"] = False
    except Exception as e:
        print(f"[ioc_mysql] load sync state failed: {e}")


def _persist_sync_state() -> None:
    try:
        p = _sync_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_ok": bool(_sync_state.get("last_ok")),
            "last_error": _sync_state.get("last_error") or "",
            "indexed": int(_sync_state.get("indexed") or 0),
            "added": int(_sync_state.get("added") or 0),
            "skipped": int(_sync_state.get("skipped") or 0),
            "scanned": int(_sync_state.get("scanned") or 0),
            "total": int(_sync_state.get("total") or 0),
            "mode": _sync_state.get("mode") or "",
            "started_at": _sync_state.get("started_at") or "",
            "finished_at": _sync_state.get("finished_at") or "",
            "elapsed_ms": int(_sync_state.get("elapsed_ms") or 0),
            "errors": int(_sync_state.get("errors") or 0),
            "mysql_count_before": _sync_state.get("mysql_count_before"),
            "mysql_count_after": _sync_state.get("mysql_count_after"),
        }
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[ioc_mysql] persist sync state failed: {e}")


_load_persisted_sync_state()


def is_available() -> bool:
    try:
        return bool(mysql_db.mysql_ready())
    except Exception:
        return False


def ensure_table(conn=None) -> bool:
    global _tables_ready
    if _tables_ready and conn is None:
        return True
    own = conn is None
    if not is_available() and own:
        return False
    try:
        if own:
            conn = mysql_db.connect_mysql()
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
        _tables_ready = True
        return True
    except Exception as e:
        print(f"[ioc_mysql] ensure_table failed: {e}")
        if own and conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        return False
    finally:
        if own and conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def count_docs() -> int:
    if not is_available():
        return -1
    conn = None
    try:
        if not ensure_table():
            return -1
        conn = mysql_db.connect_mysql()
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS c FROM {TABLE}")
            row = cur.fetchone() or {}
            return int(row.get("c") or 0)
    except Exception as e:
        print(f"[ioc_mysql] count failed: {e}")
        return -1
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _normalize_row(row: Any) -> Optional[Tuple[Any, ...]]:
    try:
        rid = int(row[0])
        typ = (row[1] or "").strip().lower()
        val = (row[2] or "").strip().lower()
        if not typ or not val:
            return None
        ip_only = (row[3] or "").strip().lower() or None
        if ip_only and len(ip_only) > 64:
            # 异常脏数据：保留前 64，避免整批插入失败
            ip_only = ip_only[:64]
        source = (row[4] or "")[:256]
        malware = (row[5] or "")[:512]
        if len(val) > 2048:
            val = val[:2048]
        return (rid, typ, val, ip_only, source, malware)
    except Exception:
        return None


def _existing_ids(conn, ids: List[int]) -> Set[int]:
    if not ids:
        return set()
    out: Set[int] = set()
    # 分批 IN，避免包过大
    with conn.cursor() as cur:
        for i in range(0, len(ids), 800):
            chunk = ids[i : i + 800]
            ph = ",".join(["%s"] * len(chunk))
            cur.execute(f"SELECT id FROM {TABLE} WHERE id IN ({ph})", chunk)
            for row in cur.fetchall() or []:
                try:
                    out.add(int(row["id"]))
                except Exception:
                    pass
    return out


def _clear_lookup_caches() -> Dict[str, Any]:
    try:
        from . import ioc_db
        return ioc_db.clear_redis_ioc_cache()
    except Exception as e:
        return {"ok": False, "deleted": 0, "error": str(e)}


def _truncate_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(f"TRUNCATE TABLE {TABLE}")
    conn.commit()


def empty_table() -> Dict[str, Any]:
    """清空 MySQL ioc_records，不依赖 SQLite；同时清 Redis/进程查询缓存。"""
    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "error": "同步进行中", **dict(_sync_state)}
    started = time.time()
    before = count_docs()
    conn = None
    try:
        if not is_available():
            raise RuntimeError("MySQL 不可用（请检查 config/db_config.json）")
        conn = mysql_db.connect_mysql()
        if not ensure_table(conn):
            raise RuntimeError("无法创建/确认 MySQL ioc_records 表")
        _truncate_table(conn)
        cache = _clear_lookup_caches()
        restored = reapply_manual_sqlite_to_mysql(conn)
        after = count_docs()
        elapsed = int((time.time() - started) * 1000)
        _sync_state.update({
            "running": False,
            "last_ok": True,
            "last_error": "",
            "indexed": 0,
            "added": 0,
            "skipped": 0,
            "scanned": 0,
            "total": 0,
            "mode": "empty",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": elapsed,
            "errors": 0,
            "mysql_count_before": before if before >= 0 else None,
            "mysql_count_after": after if after >= 0 else None,
        })
        _persist_sync_state()
        print(f"[ioc_mysql] empty table {before}->{after} in {elapsed}ms manual={restored}")
        hint = "已清空 MySQL ioc_records，并清理查询缓存。"
        if restored:
            hint += f" 已从 ioc_manual.db 回灌人工 IOC {restored} 条。"
        return {
            "ok": True,
            "target": "mysql",
            "table": TABLE,
            "before": before,
            "after": after,
            "elapsed_ms": elapsed,
            "cache": cache,
            "manual_preserved": restored,
            "hint": hint,
        }
    except Exception as e:
        _sync_state.update({
            "running": False,
            "last_ok": False,
            "last_error": str(e),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": int((time.time() - started) * 1000),
        })
        _persist_sync_state()
        print(f"[ioc_mysql] empty table failed: {type(e).__name__}: {e!r}")
        return {"ok": False, "error": f"{type(e).__name__}: {e}", **dict(_sync_state)}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        _sync_lock.release()


def sync_from_sqlite(
    *,
    recreate: bool = False,
    db_path: Optional[str] = None,
    batch_size: int = 2000,
) -> Dict[str, Any]:
    """从 SQLite ioc_records 同步到 MySQL。

    - recreate=True：清空表后全量导入
    - recreate=False：按 id 增量插入（已存在跳过）
    """
    from . import ioc_db

    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "error": "同步进行中", **dict(_sync_state)}

    started = time.time()
    mode = "recreate" if recreate else "incremental"
    before = count_docs()
    _sync_state.update({
        "running": True,
        "last_ok": False,
        "last_error": "",
        "indexed": 0,
        "added": 0,
        "skipped": 0,
        "scanned": 0,
        "total": 0,
        "mode": mode,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "finished_at": "",
        "elapsed_ms": 0,
        "errors": 0,
        "mysql_count_before": before if before >= 0 else None,
        "mysql_count_after": None,
    })
    conn = None
    sqlite_conn = None
    try:
        if not is_available():
            raise RuntimeError("MySQL 不可用（请检查 config/db_config.json）")
        conn = mysql_db.connect_mysql()
        if not ensure_table(conn):
            raise RuntimeError("无法创建/确认 MySQL ioc_records 表")

        path = Path(db_path) if db_path else ioc_db.get_db_path()
        layout = ioc_db.source_layout()
        sqlite_missing = not path or not path.is_file()
        if sqlite_missing and layout.get("hint"):
            if recreate:
                pass  # 下面 recreate 分支会处理缺库
            else:
                raise RuntimeError(layout["hint"])
        if recreate:
            # 人工条目以 ioc_manual.db 为准，不再依赖 MySQL 里 source=manual 的情报脏数据
            _truncate_table(conn)
            _clear_lookup_caches()
            if sqlite_missing:
                restored = reapply_manual_sqlite_to_mysql(conn)
                after = count_docs()
                elapsed = int((time.time() - started) * 1000)
                _sync_state.update({
                    "running": False,
                    "last_ok": True,
                    "last_error": "",
                    "indexed": 0,
                    "added": 0,
                    "skipped": 0,
                    "scanned": 0,
                    "total": 0,
                    "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "elapsed_ms": elapsed,
                    "mysql_count_after": after if after >= 0 else None,
                })
                _persist_sync_state()
                return {
                    "ok": True,
                    "target": "mysql",
                    "table": TABLE,
                    "indexed": 0,
                    "added": 0,
                    "skipped": 0,
                    "scanned": 0,
                    "total": 0,
                    "errors": 0,
                    "elapsed_ms": elapsed,
                    "recreate": True,
                    "mode": mode,
                    "mysql_count_before": before if before >= 0 else None,
                    "mysql_count_after": after if after >= 0 else None,
                    "manual_preserved": restored,
                    "hint": (layout.get("hint") or "SQLite 不存在，已清空 MySQL 表，未导入。")
                    + (f" 已从 ioc_manual.db 回灌人工 IOC {restored} 条。" if restored else ""),
                }
        elif sqlite_missing:
            raise RuntimeError(layout.get("hint") or "IOC SQLite 不存在")

        if not layout.get("ready") and not db_path:
            raise RuntimeError(layout.get("hint") or "IOC SQLite 源库不可用")

        sqlite_conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=60)
        sqlite_conn.text_factory = (
            lambda b: b.decode("utf-8", errors="replace") if isinstance(b, (bytes, bytearray)) else b
        )
        total = sqlite_conn.execute(
            "SELECT COUNT(*) FROM ioc_records WHERE type IS NOT NULL AND type!='' "
            "AND value IS NOT NULL AND value!=''"
        ).fetchone()[0]
        _sync_state["total"] = int(total)

        cur_s = sqlite_conn.execute(
            "SELECT id, type, value, ip_only, source, malware FROM ioc_records "
            "WHERE type IS NOT NULL AND type!='' AND value IS NOT NULL AND value!=''"
        )
        indexed = 0
        added = 0
        skipped = 0
        scanned = 0
        errors_n = 0
        mysql_empty = (before == 0) if before >= 0 else False
        insert_sql = (
            f"INSERT INTO {TABLE} (id, type, value, ip_only, source, malware, updated_at) "
            f"VALUES (%s,%s,%s,%s,%s,%s,NOW())"
        )

        while True:
            rows = cur_s.fetchmany(batch_size)
            if not rows:
                break
            scanned += len(rows)
            prepared: List[Tuple[Any, ...]] = []
            for row in rows:
                norm = _normalize_row(row)
                if norm:
                    prepared.append(norm)
            if not prepared:
                _sync_state.update({"scanned": scanned, "indexed": indexed, "added": added, "skipped": skipped})
                continue

            to_insert = prepared
            if not recreate and not mysql_empty:
                exists = _existing_ids(conn, [p[0] for p in prepared])
                if exists:
                    filtered = []
                    for p in prepared:
                        if p[0] in exists:
                            skipped += 1
                        else:
                            filtered.append(p)
                    to_insert = filtered
                if not to_insert:
                    _sync_state.update({
                        "scanned": scanned,
                        "indexed": indexed,
                        "added": added,
                        "skipped": skipped,
                    })
                    continue

            try:
                with conn.cursor() as cur:
                    cur.executemany(insert_sql, to_insert)
                conn.commit()
                wrote = len(to_insert)
                indexed += wrote
                added += wrote
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                errors_n += 1
                print(f"[ioc_mysql] batch insert failed: {e}")

            _sync_state.update({
                "scanned": scanned,
                "indexed": indexed,
                "added": added,
                "skipped": skipped,
                "errors": errors_n,
            })

        elapsed = int((time.time() - started) * 1000)
        manual_preserved = 0
        if recreate:
            manual_preserved = reapply_manual_sqlite_to_mysql(conn)
        after = count_docs()
        _sync_state.update({
            "running": False,
            "last_ok": True,
            "last_error": "",
            "indexed": indexed,
            "added": added,
            "skipped": skipped,
            "scanned": scanned,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": elapsed,
            "errors": errors_n,
            "mysql_count_after": after if after >= 0 else None,
        })
        _persist_sync_state()
        print(
            f"[ioc_mysql] {mode} added={added} skipped={skipped} "
            f"scanned={scanned}/{total} in {elapsed}ms errors={errors_n} "
            f"mysql {before}->{after} manual_preserved={manual_preserved}"
        )
        hint = ""
        if recreate and manual_preserved:
            hint = f"已从 ioc_manual.db 回灌人工 IOC {manual_preserved} 条。"
        return {
            "ok": True,
            "target": "mysql",
            "table": TABLE,
            "indexed": indexed,
            "added": added,
            "skipped": skipped,
            "scanned": scanned,
            "total": total,
            "errors": errors_n,
            "elapsed_ms": elapsed,
            "recreate": recreate,
            "mode": mode,
            "mysql_count_before": before if before >= 0 else None,
            "mysql_count_after": after if after >= 0 else None,
            "manual_preserved": manual_preserved,
            "hint": hint,
        }
    except Exception as e:
        from .ioc_db import sqlite_error_hint
        err_text = str(e) if isinstance(e, RuntimeError) else sqlite_error_hint(e)
        _sync_state.update({
            "running": False,
            "last_ok": False,
            "last_error": err_text,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": int((time.time() - started) * 1000),
            "mysql_count_after": count_docs() if is_available() else None,
        })
        _persist_sync_state()
        print(f"[ioc_mysql] sync failed: {type(e).__name__}: {e!r}")
        return {"ok": False, "error": err_text, **dict(_sync_state)}
    finally:
        if sqlite_conn is not None:
            try:
                sqlite_conn.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        _sync_lock.release()


def sync_status() -> Dict[str, Any]:
    out = dict(_sync_state)
    out["target"] = "mysql"
    out["table"] = TABLE
    out["mysql_count"] = count_docs()
    out["mysql_available"] = is_available()
    # 兼容前端原先读 es_count_* 的字段
    out["es_count_before"] = out.get("mysql_count_before")
    out["es_count_after"] = out.get("mysql_count_after")
    out["has_result"] = bool(
        out.get("finished_at")
        or out.get("running")
        or int(out.get("scanned") or 0) > 0
        or int(out.get("added") or 0) > 0
        or int(out.get("skipped") or 0) > 0
        or out.get("last_error")
    )
    return out


def sync_status_light() -> Dict[str, Any]:
    """返回同步进度，不执行 COUNT(*) / 连接探测。

    管理页会在同步期间频繁轮询；进度本身都在内存状态中，没必要每次再扫描
    数百万条 IOC。最终数量由同步任务写入 mysql_count_after。
    """
    out = dict(_sync_state)
    out["target"] = "mysql"
    out["table"] = TABLE
    if out.get("mysql_count_after") is not None:
        out["mysql_count"] = out.get("mysql_count_after")
    out["es_count_before"] = out.get("mysql_count_before")
    out["es_count_after"] = out.get("mysql_count_after")
    out["has_result"] = bool(
        out.get("finished_at")
        or out.get("running")
        or int(out.get("scanned") or 0) > 0
        or int(out.get("added") or 0) > 0
        or int(out.get("skipped") or 0) > 0
        or out.get("last_error")
    )
    return out


def start_sync_async(*, recreate: bool = False, only_if_empty: bool = False) -> Dict[str, Any]:
    if only_if_empty:
        n = count_docs()
        if n > 0:
            return {"ok": True, "skipped": True, "reason": "table_not_empty", "mysql_count": n}
        if n < 0:
            return {"ok": False, "error": "mysql_unavailable"}
    if _sync_state.get("running"):
        return {"ok": False, "error": "同步进行中", **sync_status()}

    def _run():
        sync_from_sqlite(recreate=recreate)

    t = threading.Thread(target=_run, name="ioc-mysql-sync", daemon=True)
    t.start()
    return {"ok": True, "started": True, "target": "mysql", "recreate": recreate}


def _hit_from_row(row: Dict[str, Any], match_type: str, matched: str) -> Dict[str, Any]:
    from . import ioc_db

    malware = (row.get("malware") or "").strip()
    source = (row.get("source") or "").strip()
    mt = (match_type or row.get("type") or "").strip().lower()
    name = ioc_db._ioc_hit_title(malware, matched, mt, source)
    db_type = (row.get("type") or "").strip()
    return {
        "hash": matched if mt in ("md5", "sha1", "sha256", "file_hash") else "",
        "domain": matched if mt == "domain" else "",
        "ip": matched if mt == "ip" else "",
        "url": matched if mt == "url" else "",
        "name": (name or matched or "IOC 命中")[:120],
        "severity": "high",
        "tags": [t.strip() for t in malware.replace(";", ",").split(",") if t.strip()][:12],
        "source": source or "ioc_mysql",
        "malware": malware,
        "match_type": mt,
        "matched": matched,
        "db_id": row.get("id"),
        "db_type": db_type,
        "from_db": True,
        "from_mysql": True,
    }


def _query_rows(sql: str, params: tuple, limit: int = 20) -> List[Dict[str, Any]]:
    if not is_available():
        return []
    conn = None
    try:
        if not ensure_table():
            return []
        conn = mysql_db.connect_mysql()
        with conn.cursor() as cur:
            cur.execute(sql + f" LIMIT {int(limit)}", params)
            return list(cur.fetchall() or [])
    except Exception as e:
        print(f"[ioc_mysql] query failed: {e}")
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def lookup_exact(ioc_type: str, values: List[str], *, match_type: Optional[str] = None, size: int = 20) -> List[Dict[str, Any]]:
    typ = (ioc_type or "").strip().lower()
    vals = [str(v).strip().lower() for v in (values or []) if str(v or "").strip()]
    if not typ or not vals:
        return []
    seen = set()
    uniq: List[str] = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    # 分批 IN，禁止静默截断：全量扫描曾用 chunk=128，旧逻辑 uniq[:64] 会丢掉后半批
    mt = match_type or typ
    out: List[Dict[str, Any]] = []
    batch_n = 64
    want = max(1, int(size or 20))
    for i in range(0, len(uniq), batch_n):
        batch = uniq[i : i + batch_n]
        ph = ",".join(["%s"] * len(batch))
        # 每批至少收回本批全部命中（避免默认 LIMIT 20 截掉 IN 结果）
        lim = max(want, len(batch))
        rows = _query_rows(
            f"SELECT id, type, value, ip_only, source, malware FROM {TABLE} "
            f"WHERE type=%s AND value IN ({ph})",
            (typ, *batch),
            limit=lim,
        )
        out.extend(
            _hit_from_row(r, mt, (r.get("value") or "").lower()) for r in rows
        )
    return out


def lookup_ip(ip: str, size: int = 20) -> List[Dict[str, Any]]:
    v = (ip or "").strip().lower().strip("[]")
    if not v:
        return []
    rows = _query_rows(
        f"SELECT id, type, value, ip_only, source, malware FROM {TABLE} "
        f"WHERE type='ip' AND (value=%s OR ip_only=%s)",
        (v, v),
        limit=size,
    )
    return [_hit_from_row(r, "ip", (r.get("ip_only") or r.get("value") or v)) for r in rows]


def lookup_domain(host: str, size: int = 20) -> List[Dict[str, Any]]:
    h = (host or "").strip().lower().strip(".")
    if not h or h.replace(".", "").isdigit():
        return []
    candidates = [h]
    parts = h.split(".")
    if len(parts) > 2:
        for i in range(1, min(len(parts) - 1, 4)):
            suffix = ".".join(parts[i:])
            if len(suffix) >= 4:
                candidates.append(suffix)
    return lookup_exact("domain", candidates, match_type="domain", size=size)


def lookup_url(urls: List[str], size: int = 20) -> List[Dict[str, Any]]:
    vals: List[str] = []
    for u in urls or []:
        u = (u or "").strip().lower()
        if not u:
            continue
        vals.append(u)
        if not u.endswith("/"):
            vals.append(u + "/")
        else:
            vals.append(u.rstrip("/"))
    return lookup_exact("url", vals, match_type="url", size=size)


def lookup_hash(hex_str: str, match_type: str = "md5", size: int = 20) -> List[Dict[str, Any]]:
    v = (hex_str or "").strip().lower()
    if not v:
        return []
    return lookup_exact("file_hash", [v], match_type=match_type or "md5", size=size)


def lookup_hashes(hex_values: List[str], *, chunk_size: int = 64) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    seen = set()
    uniq: List[str] = []
    for raw in hex_values or []:
        v = str(raw or "").strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    if not uniq:
        return out
    # 与 lookup_exact 单批 IN 上限对齐，避免调用方传 128 时误以为整批都查过
    cs = max(8, min(int(chunk_size or 64), 64))
    for i in range(0, len(uniq), cs):
        chunk = uniq[i : i + cs]
        hits = lookup_exact(
            "file_hash",
            chunk,
            match_type="file_hash",
            size=max(len(chunk), min(500, len(chunk) * 8)),
        )
        bucket: Dict[str, List[Dict[str, Any]]] = {v: [] for v in chunk}
        for h in hits:
            matched = str(h.get("matched") or h.get("hash") or "").strip().lower()
            if matched in bucket:
                n = len(matched)
                mt = "md5" if n == 32 else ("sha1" if n == 40 else ("sha256" if n == 64 else "file_hash"))
                row = dict(h)
                row["match_type"] = mt
                bucket[matched].append(row)
        for v, rows in bucket.items():
            out[v] = rows
    return out


def stats() -> Dict[str, Any]:
    return {
        "table": TABLE,
        "available": is_available(),
        "count": count_docs(),
        "sync": sync_status(),
    }


def normalize_manual_ioc_type(raw: str, value: str = "") -> str:
    """与情报库一致：ip / domain / url / file_hash；md5/sha1/sha256 → file_hash。"""
    t = (raw or "").strip().lower()
    v = (value or "").strip().lower()
    if t in ("md5", "sha1", "sha256", "sha128", "hash"):
        return "file_hash"
    if t in ("ip", "domain", "url", "file_hash"):
        return t
    if not t and v:
        if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v):
            return "file_hash"
    return t


def _export_manual_rows(conn) -> List[Tuple[Any, ...]]:
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id, type, value, ip_only, source, malware FROM {TABLE} "
                f"WHERE source=%s OR id>=%s",
                (MANUAL_SOURCE, MANUAL_ID_BASE),
            )
            rows = cur.fetchall() or []
        out: List[Tuple[Any, ...]] = []
        for row in rows:
            if isinstance(row, dict):
                norm = _normalize_row((
                    row.get("id"), row.get("type"), row.get("value"),
                    row.get("ip_only"), row.get("source") or MANUAL_SOURCE, row.get("malware") or "",
                ))
            else:
                norm = _normalize_row(row)
            if norm:
                # 强制 source=manual，便于识别
                rid, typ, val, ip_only, _src, malware = norm
                out.append((rid, typ, val, ip_only, MANUAL_SOURCE, malware))
        return out
    except Exception as e:
        print(f"[ioc_mysql] export manual failed: {e}")
        return []


def _restore_manual_rows(conn, rows: List[Tuple[Any, ...]]) -> int:
    if not rows:
        return 0
    insert_sql = (
        f"INSERT IGNORE INTO {TABLE} (id, type, value, ip_only, source, malware, updated_at) "
        f"VALUES (%s,%s,%s,%s,%s,%s,NOW())"
    )
    try:
        with conn.cursor() as cur:
            cur.executemany(insert_sql, rows)
        conn.commit()
        return len(rows)
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        print(f"[ioc_mysql] restore manual failed: {e}")
        return 0


def _next_manual_id(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT COALESCE(MAX(id), %s) AS m FROM {TABLE} WHERE id >= %s OR source=%s",
            (MANUAL_ID_BASE, MANUAL_ID_BASE, MANUAL_SOURCE),
        )
        row = cur.fetchone() or {}
        m = int(row.get("m") or MANUAL_ID_BASE)
    return max(m + 1, MANUAL_ID_BASE + 1)


def add_manual_ioc(
    *,
    ioc_type: str,
    value: str,
    source: str = MANUAL_SOURCE,
    malware: str = "",
) -> Dict[str, Any]:
    """人工写入：先落 ioc/ioc_manual.db，再镜像到 MySQL（供查询热路径）。"""
    from . import ioc_manual_db

    local = ioc_manual_db.add(
        ioc_type=ioc_type,
        value=value,
        source=source or MANUAL_SOURCE,
        malware=malware or "",
    )
    if not local.get("ok"):
        return local
    item = dict(local.get("item") or {})
    try:
        sid = int(item.get("id") or 0)
    except Exception:
        sid = 0
    mirror_id = MANUAL_ID_BASE + sid if sid > 0 else None

    if not is_available():
        item["mysql_mirrored"] = False
        item["hint"] = "已写入本地 ioc_manual.db；MySQL 不可用，查询仍可读本地库"
        return {"ok": True, "item": item, "path": local.get("path")}

    typ = item.get("type")
    val = item.get("value")
    ip_only = item.get("ip_only")
    src = item.get("source") or MANUAL_SOURCE
    mal = item.get("malware") or ""
    conn = None
    try:
        if not ensure_table():
            item["mysql_mirrored"] = False
            return {"ok": True, "item": item, "path": local.get("path"), "warning": "MySQL 表不可用"}
        conn = mysql_db.connect_mysql()
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT id FROM {TABLE} WHERE type=%s AND value=%s LIMIT 1",
                (typ, val),
            )
            existed = cur.fetchone()
            if existed:
                item["mysql_id"] = existed.get("id")
                item["mysql_mirrored"] = False
                item["hint"] = "本地已保存；MySQL 中已有相同情报条目"
            else:
                rid = mirror_id or _next_manual_id(conn)
                cur.execute(
                    f"INSERT INTO {TABLE} (id, type, value, ip_only, source, malware, updated_at) "
                    f"VALUES (%s,%s,%s,%s,%s,%s,NOW())",
                    (rid, typ, val, ip_only, src, mal),
                )
                item["mysql_id"] = rid
                item["mysql_mirrored"] = True
        conn.commit()
        try:
            from . import ioc_db
            ioc_db.invalidate_cached_values(
                [val], kinds=(typ, "file_hash", "md5", "sha1", "sha256", "ip", "domain", "url")
            )
        except Exception:
            pass
        return {"ok": True, "item": item, "path": local.get("path")}
    except Exception as e:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        item["mysql_mirrored"] = False
        return {
            "ok": True,
            "item": item,
            "path": local.get("path"),
            "warning": f"本地已保存，MySQL 镜像失败: {type(e).__name__}: {e}",
        }
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def add_manual_iocs_batch(
    *,
    text: str = "",
    items: Optional[List[Dict[str, Any]]] = None,
    default_type: str = "file_hash",
    source: str = MANUAL_SOURCE,
    malware: str = "",
) -> Dict[str, Any]:
    """批量人工导入：解析文本或 items → 本地库 → 镜像 MySQL。"""
    from . import ioc_manual_db

    parsed = list(items or [])
    if text and not parsed:
        parsed = ioc_manual_db.parse_batch_text(
            text,
            default_type=default_type or "file_hash",
            default_source=source or MANUAL_SOURCE,
            default_malware=malware or "",
        )
    if not parsed:
        return {"ok": False, "error": "没有可导入的条目"}
    for it in parsed:
        if not it.get("source"):
            it["source"] = source or MANUAL_SOURCE
        if malware and not it.get("malware"):
            it["malware"] = malware
    local = ioc_manual_db.add_batch(parsed)
    if not local.get("ok"):
        return local
    mirrored = 0
    mirror_fail = 0
    added_items = local.get("items") or []
    if is_available() and added_items:
        try:
            if ensure_table():
                conn = mysql_db.connect_mysql()
                try:
                    with conn.cursor() as cur:
                        for item in added_items:
                            typ = item.get("type")
                            val = item.get("value")
                            ip_only = item.get("ip_only")
                            src = item.get("source") or MANUAL_SOURCE
                            mal = item.get("malware") or ""
                            try:
                                sid = int(item.get("id") or 0)
                            except Exception:
                                sid = 0
                            mirror_id = MANUAL_ID_BASE + sid if sid > 0 else _next_manual_id(conn)
                            cur.execute(
                                f"SELECT id FROM {TABLE} WHERE type=%s AND value=%s LIMIT 1",
                                (typ, val),
                            )
                            if cur.fetchone():
                                continue
                            cur.execute(
                                f"INSERT INTO {TABLE} (id, type, value, ip_only, source, malware, updated_at) "
                                f"VALUES (%s,%s,%s,%s,%s,%s,NOW())",
                                (mirror_id, typ, val, ip_only, src, mal),
                            )
                            mirrored += 1
                    conn.commit()
                except Exception as e:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    mirror_fail += 1
                    print(f"[ioc_mysql] batch mirror failed: {e}")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        except Exception as e:
            mirror_fail += 1
            print(f"[ioc_mysql] batch mirror connect failed: {e}")
    try:
        from . import ioc_db
        vals = [str(x.get("value") or "") for x in added_items if x.get("value")]
        if vals:
            ioc_db.invalidate_cached_values(
                vals, kinds=("file_hash", "md5", "sha1", "sha256", "ip", "domain", "url")
            )
    except Exception:
        pass
    return {
        **local,
        "mysql_mirrored": mirrored,
        "mysql_mirror_fail": mirror_fail,
        "parsed": len(parsed),
    }


def delete_manual_ioc(ioc_id: int) -> Dict[str, Any]:
    """删除人工条目：本地 ioc_manual.db + MySQL 镜像。"""
    from . import ioc_manual_db

    local = ioc_manual_db.delete(ioc_id)
    if not local.get("ok"):
        return local
    val = str(local.get("value") or "")
    typ = str(local.get("type") or "")
    mirror_id = MANUAL_ID_BASE + int(local.get("deleted_id") or 0)

    if is_available():
        conn = None
        try:
            conn = mysql_db.connect_mysql()
            with conn.cursor() as cur:
                cur.execute(
                    f"DELETE FROM {TABLE} WHERE id=%s OR (type=%s AND value=%s AND source LIKE %s)",
                    (mirror_id, typ, val, "manual%"),
                )
            conn.commit()
        except Exception as e:
            print(f"[ioc_mysql] delete manual mirror failed: {e}")
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
    try:
        from . import ioc_db
        ioc_db.invalidate_cached_values(
            [val], kinds=(typ, "file_hash", "md5", "sha1", "sha256", "ip", "domain", "url")
        )
    except Exception:
        pass
    return {**local, "ok": True}


def list_manual_iocs(*, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    """仅列出本地人工库，不把情报里 source=manual 的条目混进来。"""
    from . import ioc_manual_db
    return ioc_manual_db.list_items(limit=limit, offset=offset)


def export_manual_iocs(*, fmt: str = "csv"):
    """导出本地人工库（ioc_manual.db），格式见 ioc_manual_db.export_file。"""
    from . import ioc_manual_db
    return ioc_manual_db.export_file(fmt=fmt)


def reapply_manual_sqlite_to_mysql(conn=None) -> int:
    """从 ioc_manual.db 回灌到 MySQL（重建/清空后调用）。"""
    from . import ioc_manual_db

    rows = ioc_manual_db.list_items(limit=10000, offset=0).get("items") or []
    if not rows:
        return 0
    own = conn is None
    if own:
        if not is_available() or not ensure_table():
            return 0
        conn = mysql_db.connect_mysql()
    n = 0
    try:
        insert_sql = (
            f"INSERT IGNORE INTO {TABLE} (id, type, value, ip_only, source, malware, updated_at) "
            f"VALUES (%s,%s,%s,%s,%s,%s,NOW())"
        )
        batch = []
        for it in rows:
            try:
                sid = int(it.get("id") or 0)
            except Exception:
                continue
            if sid <= 0:
                continue
            rid = MANUAL_ID_BASE + sid
            typ = (it.get("type") or "").strip().lower()
            val = (it.get("value") or "").strip().lower()
            if not typ or not val:
                continue
            batch.append((
                rid, typ, val,
                it.get("ip_only"),
                (it.get("source") or MANUAL_SOURCE)[:256],
                (it.get("malware") or "")[:512],
            ))
        if batch:
            with conn.cursor() as cur:
                cur.executemany(insert_sql, batch)
            if own:
                conn.commit()
            n = len(batch)
        return n
    except Exception as e:
        if own:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"[ioc_mysql] reapply manual sqlite failed: {e}")
        return 0
    finally:
        if own and conn is not None:
            try:
                conn.close()
            except Exception:
                pass
