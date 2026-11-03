# -*- coding: utf-8 -*-
"""人工 IOC 独立 SQLite（ioc/ioc_manual.db）。

与情报库 ioc_records 字段一致，不随 ioc_data.db / MySQL 清空而丢失。
查询与 IOC 扫描会读取本库。
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

TABLE = "ioc_records"
DB_NAME = "ioc_manual.db"

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    ip_only TEXT DEFAULT NULL,
    source TEXT DEFAULT 'manual',
    malware TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_manual_type_value ON {TABLE}(type, value);
CREATE INDEX IF NOT EXISTS idx_manual_value ON {TABLE}(value);
CREATE INDEX IF NOT EXISTS idx_manual_ip ON {TABLE}(ip_only);
"""

_lock = threading.RLock()


def db_path() -> Path:
    d = Path(getattr(config, "IOC_DIR", None) or (Path(__file__).resolve().parent.parent / "ioc"))
    d.mkdir(parents=True, exist_ok=True)
    return d / DB_NAME


def _connect() -> sqlite3.Connection:
    path = db_path()
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def ensure_db() -> Path:
    with _lock:
        conn = _connect()
        conn.close()
    return db_path()


def normalize_type(raw: str, value: str = "") -> str:
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


def add(
    *,
    ioc_type: str,
    value: str,
    source: str = "manual",
    malware: str = "",
) -> Dict[str, Any]:
    raw_val = (value or "").strip()
    if not raw_val:
        return {"ok": False, "error": "value 不能为空"}
    typ = normalize_type(ioc_type, raw_val)
    if typ not in ("ip", "domain", "url", "file_hash"):
        return {"ok": False, "error": "type 须为 ip / domain / url / file_hash（或 md5/sha1/sha256）"}
    val = raw_val.lower()
    if len(val) > 2048:
        val = val[:2048]
    if typ == "file_hash":
        if not (all(c in "0123456789abcdef" for c in val) and len(val) in (32, 40, 64)):
            return {"ok": False, "error": "file_hash 须为 32/40/64 位十六进制"}
    ip_only = val[:64] if typ == "ip" else None
    src = (source or "manual").strip()[:256] or "manual"
    if not src.lower().startswith("manual"):
        src = f"manual:{src}"[:256]
    mal = (malware or "").strip()[:512]
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                f"SELECT id, type, value, source, malware FROM {TABLE} WHERE type=? AND value=? LIMIT 1",
                (typ, val),
            ).fetchone()
            if row:
                return {
                    "ok": False,
                    "error": "已存在相同 type+value",
                    "existing": {
                        "id": row["id"],
                        "type": row["type"],
                        "value": row["value"],
                        "source": row["source"],
                        "malware": row["malware"],
                    },
                }
            cur = conn.execute(
                f"INSERT INTO {TABLE} (type, value, ip_only, source, malware, updated_at) "
                f"VALUES (?,?,?,?,?,?)",
                (typ, val, ip_only, src, mal, now),
            )
            conn.commit()
            rid = int(cur.lastrowid)
            return {
                "ok": True,
                "item": {
                    "id": rid,
                    "type": typ,
                    "value": val,
                    "ip_only": ip_only,
                    "source": src,
                    "malware": mal,
                    "updated_at": now,
                },
                "path": str(db_path()),
            }
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            conn.close()


_TYPE_TOKENS = frozenset({
    "ip", "domain", "url", "file_hash", "md5", "sha1", "sha256", "hash",
})


def _looks_like_type_token(raw: str, value: str = "") -> bool:
    t = (raw or "").strip().lower()
    if t in _TYPE_TOKENS:
        return True
    return normalize_type(t, value) in ("ip", "domain", "url", "file_hash") and bool(t)


def parse_batch_text(
    text: str,
    *,
    default_type: str = "file_hash",
    default_source: str = "manual",
    default_malware: str = "",
) -> List[Dict[str, str]]:
    """解析批量文本为条目列表。

    支持：
    - type,value[,malware][,source]
    - type:value 或 type value
    - 仅 value（用 default_type）
    - # 或 // 开头为注释
    """
    out: List[Dict[str, str]] = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        typ = ""
        val = ""
        mal = default_malware
        src = default_source
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            # 跳过导出 CSV 表头
            if (
                len(parts) >= 2
                and parts[0].lower() == "type"
                and parts[1].lower() == "value"
            ):
                continue
            if len(parts) >= 2 and _looks_like_type_token(parts[0], parts[1]):
                typ, val = parts[0], parts[1]
                if len(parts) >= 3 and parts[2]:
                    mal = parts[2]
                if len(parts) >= 4 and parts[3]:
                    src = parts[3]
            else:
                val = parts[0]
                typ = default_type
                if len(parts) >= 2 and parts[1]:
                    mal = parts[1]
        else:
            # type:value 仅当冒号左侧是类型词；避免 url http://… 被拆坏
            used = False
            if ":" in line:
                left, right = line.split(":", 1)
                left, right = left.strip(), right.strip()
                if _looks_like_type_token(left, right):
                    typ, val = left, right
                    used = True
            if not used:
                bits = line.split(None, 1)
                if len(bits) == 2 and _looks_like_type_token(bits[0], bits[1]):
                    typ, val = bits[0], bits[1]
                else:
                    typ, val = default_type, line
        if not val.strip():
            continue
        out.append({
            "type": typ or default_type,
            "value": val.strip(),
            "source": (src or default_source).strip() or "manual",
            "malware": (mal or "").strip(),
        })
    return out


def add_batch(
    items: List[Dict[str, Any]],
    *,
    max_items: int = 5000,
) -> Dict[str, Any]:
    """批量写入本地人工库。返回 added / skipped / errors。"""
    if not isinstance(items, list):
        return {"ok": False, "error": "items 须为列表"}
    if len(items) > max_items:
        return {"ok": False, "error": f"单次最多 {max_items} 条"}
    added = 0
    skipped = 0
    errors: List[Dict[str, Any]] = []
    added_items: List[Dict[str, Any]] = []
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with _lock:
        conn = _connect()
        try:
            for i, it in enumerate(items):
                if not isinstance(it, dict):
                    errors.append({"index": i, "error": "条目须为对象"})
                    continue
                raw_val = str(it.get("value") or "").strip()
                if not raw_val:
                    errors.append({"index": i, "error": "value 不能为空"})
                    continue
                typ = normalize_type(str(it.get("type") or it.get("ioc_type") or ""), raw_val)
                if typ not in ("ip", "domain", "url", "file_hash"):
                    errors.append({"index": i, "value": raw_val[:80], "error": "无效 type"})
                    continue
                val = raw_val.lower()
                if len(val) > 2048:
                    val = val[:2048]
                if typ == "file_hash":
                    if not (all(c in "0123456789abcdef" for c in val) and len(val) in (32, 40, 64)):
                        errors.append({"index": i, "value": val[:80], "error": "非法哈希"})
                        continue
                ip_only = val[:64] if typ == "ip" else None
                src = str(it.get("source") or "manual").strip()[:256] or "manual"
                if not src.lower().startswith("manual"):
                    src = f"manual:{src}"[:256]
                mal = str(it.get("malware") or "").strip()[:512]
                row = conn.execute(
                    f"SELECT id FROM {TABLE} WHERE type=? AND value=? LIMIT 1",
                    (typ, val),
                ).fetchone()
                if row:
                    skipped += 1
                    continue
                cur = conn.execute(
                    f"INSERT INTO {TABLE} (type, value, ip_only, source, malware, updated_at) "
                    f"VALUES (?,?,?,?,?,?)",
                    (typ, val, ip_only, src, mal, now),
                )
                rid = int(cur.lastrowid)
                added += 1
                added_items.append({
                    "id": rid,
                    "type": typ,
                    "value": val,
                    "ip_only": ip_only,
                    "source": src,
                    "malware": mal,
                    "updated_at": now,
                })
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            conn.close()
    return {
        "ok": True,
        "added": added,
        "skipped": skipped,
        "errors": errors[:50],
        "error_count": len(errors),
        "items": added_items[:100],
        "path": str(db_path()),
    }


def fingerprint() -> str:
    """条数 + 自增高水位 + 最近更新时间。高水位取 sqlite_sequence：删光后 MAX(id) 会回落，序列不会。"""
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            count, latest = conn.execute(f"SELECT COUNT(*), MAX(updated_at) FROM {TABLE}").fetchone()
            seq = conn.execute("SELECT seq FROM sqlite_sequence WHERE name=?", (TABLE,)).fetchone()
            return f"{count or 0}:{(seq[0] if seq else 0) or 0}:{latest or ''}"
        finally:
            conn.close()


def delete(ioc_id: int) -> Dict[str, Any]:
    try:
        rid = int(ioc_id)
    except Exception:
        return {"ok": False, "error": "无效 id"}
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                f"SELECT id, type, value, source FROM {TABLE} WHERE id=? LIMIT 1",
                (rid,),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "记录不存在"}
            conn.execute(f"DELETE FROM {TABLE} WHERE id=?", (rid,))
            conn.commit()
            return {
                "ok": True,
                "deleted_id": rid,
                "value": row["value"],
                "type": row["type"],
                "path": str(db_path()),
            }
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            conn.close()


def list_items(*, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 50), 500))
    offset = max(0, int(offset or 0))
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            total = int(conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0])
            rows = conn.execute(
                f"SELECT id, type, value, ip_only, source, malware, updated_at FROM {TABLE} "
                f"ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            items = []
            for r in rows:
                items.append({
                    "id": r["id"],
                    "type": r["type"],
                    "value": r["value"],
                    "ip_only": r["ip_only"],
                    "source": r["source"],
                    "malware": r["malware"],
                    "updated_at": r["updated_at"] or "",
                })
            return {
                "ok": True,
                "items": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "path": str(db_path()),
            }
        finally:
            conn.close()


def export_all_rows() -> List[Tuple[Any, ...]]:
    """供 MySQL 回灌：(id 占位忽略, type, value, ip_only, source, malware)。"""
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"SELECT type, value, ip_only, source, malware FROM {TABLE}"
            ).fetchall()
            out = []
            for r in rows:
                out.append((
                    None,
                    (r["type"] or "").strip().lower(),
                    (r["value"] or "").strip().lower(),
                    (r["ip_only"] or None),
                    (r["source"] or "manual")[:256],
                    (r["malware"] or "")[:512],
                ))
            return out
        finally:
            conn.close()


def export_file(*, fmt: str = "csv") -> Tuple[bytes, str, str, int]:
    """导出全部人工 IOC。

    返回 (blob, filename, media_type, count)。
    - csv：UTF-8 BOM，表头 type,value,malware,source（可再导入）
    - txt：无表头，与批量导入行格式一致
    """
    import csv
    import io

    kind = (fmt or "csv").strip().lower()
    if kind not in ("csv", "txt", "text"):
        kind = "csv"
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"SELECT type, value, malware, source FROM {TABLE} ORDER BY id ASC"
            ).fetchall()
        finally:
            conn.close()
    items = [
        (
            (r["type"] or "").strip(),
            (r["value"] or "").strip(),
            (r["malware"] or "").strip(),
            (r["source"] or "manual").strip() or "manual",
        )
        for r in rows
    ]
    stamp = time.strftime("%Y%m%d_%H%M%S")
    if kind in ("txt", "text"):
        lines = []
        for typ, val, mal, src in items:
            # type,value[,malware][,source] — 与批量导入一致
            if mal or (src and src != "manual"):
                lines.append(f"{typ},{val},{mal},{src}")
            else:
                lines.append(f"{typ},{val}")
        body = "\n".join(lines)
        if body:
            body += "\n"
        blob = body.encode("utf-8")
        return blob, f"ioc_manual_{stamp}.txt", "text/plain; charset=utf-8", len(items)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "malware", "source"])
    for row in items:
        writer.writerow(list(row))
    # Excel 友好：UTF-8 BOM
    blob = ("\ufeff" + buf.getvalue()).encode("utf-8")
    return blob, f"ioc_manual_{stamp}.csv", "text/csv; charset=utf-8", len(items)


def count() -> int:
    try:
        ensure_db()
        with _lock:
            conn = _connect()
            try:
                return int(conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0])
            finally:
                conn.close()
    except Exception:
        return 0


def _hit_from_row(row: sqlite3.Row, match_type: str, matched: str) -> Dict[str, Any]:
    malware = (row["malware"] or "").strip()
    source = (row["source"] or "").strip() or "manual"
    name = malware.split(",")[0].strip() if malware else matched
    if not name:
        name = matched
    return {
        "hash": matched if match_type in ("md5", "sha1", "sha256") else "",
        "domain": matched if match_type == "domain" else "",
        "ip": matched if match_type == "ip" else "",
        "url": matched if match_type == "url" else "",
        "name": (name or matched)[:120],
        "severity": "high",
        "tags": [t.strip() for t in malware.replace(";", ",").split(",") if t.strip()][:12],
        "source": source,
        "malware": malware,
        "match_type": match_type,
        "matched": matched,
        "db_id": row["id"],
        "db_type": row["type"],
        "from_db": True,
        "from_manual_db": True,
    }


def lookup(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    v = (value or "").strip().lower()
    if not v:
        return []
    t = (ioc_type or "").strip().lower()
    if not db_path().is_file():
        return []
    with _lock:
        conn = _connect()
        try:
            results: List[Dict[str, Any]] = []
            if t in ("", "file_hash", "md5", "sha1", "sha256") or (
                len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v)
            ):
                row = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='file_hash' AND value=? LIMIT 1",
                    (v,),
                ).fetchone()
                if row:
                    mt = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v), "md5")
                    if t in ("md5", "sha1", "sha256"):
                        mt = t
                    results.append(_hit_from_row(row, mt, v))
            if t in ("", "ip"):
                row = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='ip' AND (value=? OR ip_only=?) LIMIT 1",
                    (v, v),
                ).fetchone()
                if row:
                    results.append(_hit_from_row(row, "ip", v))
            if t in ("", "domain"):
                row = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='domain' AND value=? LIMIT 1",
                    (v,),
                ).fetchone()
                if row:
                    results.append(_hit_from_row(row, "domain", v))
            if t in ("", "url"):
                row = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='url' AND value=? LIMIT 1",
                    (v,),
                ).fetchone()
                if row:
                    results.append(_hit_from_row(row, "url", v))
            return results
        except Exception:
            return []
        finally:
            conn.close()


def lookup_hashes(hex_values: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    need = []
    seen = set()
    for raw in hex_values or []:
        v = (raw or "").strip().lower()
        if not v or v in seen:
            continue
        if len(v) not in (32, 40, 64):
            continue
        seen.add(v)
        need.append(v)
    if not need or not db_path().is_file():
        return out
    with _lock:
        conn = _connect()
        try:
            for i in range(0, len(need), 200):
                chunk = need[i : i + 200]
                ph = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='file_hash' AND value IN ({ph})",
                    chunk,
                ).fetchall()
                for row in rows:
                    val = (row["value"] or "").lower()
                    mt = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(val), "md5")
                    out.setdefault(val, []).append(_hit_from_row(row, mt, val))
            return out
        except Exception:
            return out
        finally:
            conn.close()


def lookup_ips(ips: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """批量查人工 IP（value / ip_only）。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in ips or []:
        v = (raw or "").strip().lower().strip("[]")
        if not v or v in seen:
            continue
        seen.add(v)
        need.append(v)
    if not need or not db_path().is_file():
        return out
    with _lock:
        conn = _connect()
        try:
            for i in range(0, len(need), 200):
                chunk = need[i : i + 200]
                ph = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type='ip' AND (value IN ({ph}) OR ip_only IN ({ph}))",
                    (*chunk, *chunk),
                ).fetchall()
                for row in rows:
                    val = (row["value"] or "").lower()
                    ip_only = (row["ip_only"] or "").lower()
                    hit_base = _hit_from_row(row, "ip", ip_only or val)
                    for cand in chunk:
                        if cand == val or cand == ip_only:
                            out.setdefault(cand, []).append(dict(hit_base, matched=cand))
            return out
        except Exception:
            return out
        finally:
            conn.close()


def lookup_values(ioc_type: str, values: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """批量精确查 domain / url 等（按 type + value）。"""
    typ = (ioc_type or "").strip().lower()
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in values or []:
        v = (raw or "").strip().lower()
        if typ == "domain":
            v = v.strip(".")
        if not v or v in seen:
            continue
        seen.add(v)
        need.append(v)
    if not need or not typ or not db_path().is_file():
        return out
    with _lock:
        conn = _connect()
        try:
            for i in range(0, len(need), 200):
                chunk = need[i : i + 200]
                ph = ",".join("?" * len(chunk))
                rows = conn.execute(
                    f"SELECT * FROM {TABLE} WHERE type=? AND value IN ({ph})",
                    (typ, *chunk),
                ).fetchall()
                for row in rows:
                    val = (row["value"] or "").lower()
                    out.setdefault(val, []).append(_hit_from_row(row, typ, val))
            return out
        except Exception:
            return out
        finally:
            conn.close()
