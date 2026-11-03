"""主机台账：增删改查；删除主机时连带删除分析结果目录。

优先 MySQL（db_config.json / 本机 root），不可用时回退 SQLite reports/hosts.db。
"""
from __future__ import annotations
import copy
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence

from . import config
from . import paths as P
from .db_store import INDEX_DB, _connect, _init_index, rename_hostname
from .iputil import is_weak_ip, pick_primary_ip

HOSTS_DB = config.REPORTS_DIR / "hosts.db"
_HOST_LIST_CACHE: Optional[List[Dict[str, Any]]] = None
_HOST_LIST_CACHE_AT = 0.0
_HOST_LIST_CACHE_LOCK = threading.RLock()
_HOST_LIST_TTL = 5.0


def _invalidate_host_cache() -> None:
    global _HOST_LIST_CACHE, _HOST_LIST_CACHE_AT
    with _HOST_LIST_CACHE_LOCK:
        _HOST_LIST_CACHE = None
        _HOST_LIST_CACHE_AT = 0.0


def _init_hosts_sqlite(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            ip TEXT DEFAULT '',
            note TEXT DEFAULT '',
            created_at REAL,
            updated_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
        """
    )


class HostStore:
    """统一 ? 占位符；MySQL 内部转 %s。失败自动回退 SQLite。"""

    def __init__(self):
        from . import mysql_db
        self.mysql = False
        self.cur = None
        if mysql_db.mysql_ready():
            try:
                self.conn = mysql_db.connect_mysql()
                self.cur = self.conn.cursor()
                self.mysql = True
                return
            except Exception as e:
                try:
                    mysql_db.mark_mysql_down(str(e))
                except Exception:
                    pass
                print(f"[hosts] mysql unavailable → sqlite: {e}")
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = _connect(HOSTS_DB)
        _init_hosts_sqlite(self.conn)
        self.cur = None

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.mysql else sql

    def execute(self, sql: str, params: Sequence[Any] = ()):
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
        else:
            self.conn.execute(q, tuple(params))
        return self

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
            row = self.cur.fetchone()
            return dict(row) if row else None
        row = self.conn.execute(q, tuple(params)).fetchone()
        return {k: row[k] for k in row.keys()} if row else None

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
            return [dict(r) for r in (self.cur.fetchall() or [])]
        rows = self.conn.execute(q, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            if self.mysql and self.cur:
                self.cur.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


def _hconnect() -> HostStore:
    """兼容旧调用名（rename_hostname 等）。"""
    return HostStore()


def _validate_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("主机名不能为空")
    if name.lower() == "unknown":
        raise ValueError("不能使用保留名 unknown")
    if name in {".", ".."} or name.startswith("."):
        raise ValueError("主机名含非法字符")
    if any(c in name for c in '<>:"/\\|?*'):
        raise ValueError("主机名含非法字符")
    if len(name) > 128:
        raise ValueError("主机名过长")
    return name


def _row(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": r["id"],
        "name": r["name"],
        "ip": r.get("ip") or "",
        "note": r.get("note") or "",
        "created_at": r.get("created_at"),
        "updated_at": r.get("updated_at"),
    }


def migrate_hosts_sqlite_to_mysql() -> int:
    """把本地 hosts.db 迁入 MySQL（仅当 MySQL hosts 为空时）。"""
    from . import mysql_db
    if not mysql_db.mysql_ready() or not HOSTS_DB.exists():
        return 0
    store = HostStore()
    try:
        if store.query_all("SELECT id FROM hosts LIMIT 1"):
            return 0
    finally:
        store.close()

    src = _connect(HOSTS_DB)
    try:
        _init_hosts_sqlite(src)
        rows = src.execute("SELECT * FROM hosts").fetchall()
        if not rows:
            return 0
        dst = HostStore()
        n = 0
        try:
            for r in rows:
                try:
                    dst.execute(
                        "INSERT INTO hosts(id,name,ip,note,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                        (r["id"], r["name"], r["ip"] or "", r["note"] or "", r["created_at"], r["updated_at"]),
                    )
                    n += 1
                except Exception as e:
                    print(f"[hosts] migrate skip {r['name']}: {e}")
            dst.commit()
        finally:
            dst.close()
        return n
    finally:
        src.close()


def sync_hosts_mysql_to_sqlite() -> int:
    """用 MySQL 主机表全量覆盖本地 hosts.db，消除同名不同 id 漂移。"""
    from . import mysql_db
    if not mysql_db.mysql_ready():
        return 0
    store = HostStore()
    try:
        if not store.mysql:
            return 0
        rows = store.query_all("SELECT * FROM hosts")
    finally:
        store.close()
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect(HOSTS_DB)
        try:
            _init_hosts_sqlite(conn)
            conn.execute("DELETE FROM hosts")
            for r in rows:
                conn.execute(
                    "INSERT INTO hosts(id,name,ip,note,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    (
                        r["id"], r["name"], r.get("ip") or "", r.get("note") or "",
                        r.get("created_at") or time.time(),
                        r.get("updated_at") or time.time(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        if rows:
            print(f"[hosts] synced {len(rows)} hosts mysql → sqlite")
        return len(rows)
    except Exception as e:
        print("[hosts] sync mysql→sqlite:", e)
        return 0


def ensure_host(name: str, ip: str = "") -> Dict[str, Any]:
    name = _validate_name(name)
    ip = pick_primary_ip(ip)
    store = HostStore()
    try:
        row = store.query_one("SELECT * FROM hosts WHERE name=?", (name,))
        if row:
            cur = (row.get("ip") or "").strip()
            # 缺 IP，或台账里仍是 169.254/127 等不可用地址时，用更好的地址覆盖
            if ip and (not cur or is_weak_ip(cur)) and ip != cur:
                now = time.time()
                store.execute(
                    "UPDATE hosts SET ip=?, updated_at=? WHERE id=?",
                    (ip, now, row["id"]),
                )
                store.commit()
                row = store.query_one("SELECT * FROM hosts WHERE id=?", (row["id"],))
                if store.mysql and row:
                    _mirror_host_to_sqlite(dict(row))
                _invalidate_host_cache()
            return _row(row)
        hid = uuid.uuid4().hex[:12]
        now = time.time()
        store.execute(
            "INSERT INTO hosts(id,name,ip,note,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (hid, name, ip, "", now, now),
        )
        store.commit()
        row = store.query_one("SELECT * FROM hosts WHERE id=?", (hid,))
        if store.mysql and row:
            _mirror_host_to_sqlite(dict(row))
        _invalidate_host_cache()
        return _row(row) if row else {"id": hid, "name": name, "ip": ip, "note": ""}
    finally:
        store.close()


def get_host(host_id: str) -> Optional[Dict[str, Any]]:
    store = HostStore()
    try:
        row = store.query_one("SELECT * FROM hosts WHERE id=?", (host_id,))
        return _row(row) if row else None
    finally:
        store.close()


def get_host_by_name(name: str) -> Optional[Dict[str, Any]]:
    name = (name or "").strip()
    if not name:
        return None
    store = HostStore()
    try:
        row = store.query_one("SELECT * FROM hosts WHERE name=?", (name,))
        return _row(row) if row else None
    finally:
        store.close()


def _report_stats(*, check_disk: bool = False) -> Dict[str, Dict[str, Any]]:
    """按主机聚合报告数/告警；优先 MySQL，与 list_index 同源。

    check_disk=False：列表接口默认不扫盘。删主机后幽灵索引很多时，逐条 stat 会把 GET /api/hosts 卡死。
    """
    out: Dict[str, Dict[str, Any]] = {}
    try:
        from . import mysql_db
        if mysql_db.mysql_ready():
            store = HostStore()
            try:
                rows = store.query_all(
                    """
                    WITH ranked AS (
                      SELECT hostname,file,ip,collect_time,
                             ROW_NUMBER() OVER (
                               PARTITION BY hostname ORDER BY collect_time DESC,file DESC
                             ) AS rn
                      FROM reports WHERE hostname<>''
                    ),
                    agg AS (
                      SELECT hostname,COUNT(*) AS report_count,MAX(issues) AS issues,
                             SUM(CASE WHEN analyzed<>0 THEN 1 ELSE 0 END) AS analyzed,
                             MAX(collect_time) AS last_time
                      FROM reports WHERE hostname<>'' GROUP BY hostname
                    )
                    SELECT a.hostname,a.report_count,a.issues,a.analyzed,a.last_time,
                           r.file AS last_file,r.ip
                    FROM agg a LEFT JOIN ranked r ON r.hostname=a.hostname AND r.rn=1
                    """
                )
            finally:
                store.close()
            if rows:
                for r in rows:
                    rid = (r.get("last_file") or "").strip()
                    if check_disk and rid and not (
                        P.resolve_report_json(rid)
                        or P.resolve_analysis_db(rid)
                        or P.resolve_result_json(rid)
                    ):
                        continue
                    hn = (r.get("hostname") or "").strip()
                    if not hn:
                        continue
                    st = out.get(hn) or {
                        "report_count": 0, "issues": 0, "last_time": "", "last_file": "", "ip": "", "analyzed": 0,
                    }
                    st["report_count"] = int(r.get("report_count") or 0)
                    st["issues"] = int(r.get("issues") or 0)
                    st["analyzed"] = int(r.get("analyzed") or 0)
                    st["last_time"] = r.get("last_time") or ""
                    st["last_file"] = r.get("last_file") or ""
                    cand = pick_primary_ip(r.get("ip") or "")
                    if cand and (not st.get("ip") or is_weak_ip(st.get("ip") or "")):
                        st["ip"] = cand
                    out[hn] = st
                return out
    except Exception as e:
        print(f"[hosts] report_stats mysql: {e}")

    if not INDEX_DB.exists():
        return out
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        rows = conn.execute(
            """
            WITH ranked AS (
              SELECT hostname,file,ip,collect_time,
                     ROW_NUMBER() OVER (
                       PARTITION BY hostname ORDER BY collect_time DESC,file DESC
                     ) AS rn
              FROM reports WHERE hostname<>''
            ),
            agg AS (
              SELECT hostname,COUNT(*) AS cnt,MAX(issues) AS issues,
                     SUM(CASE WHEN analyzed!=0 THEN 1 ELSE 0 END) AS analyzed,
                     MAX(collect_time) AS last_time
              FROM reports WHERE hostname<>'' GROUP BY hostname
            )
            SELECT a.hostname,a.cnt,a.issues,a.analyzed,a.last_time,
                   r.file AS last_file,r.ip
            FROM agg a LEFT JOIN ranked r ON r.hostname=a.hostname AND r.rn=1
            """
        ).fetchall()
        for r in rows:
            hn = r["hostname"] or ""
            if not hn:
                continue
            out[hn] = {
                "report_count": int(r["cnt"] or 0),
                "issues": int(r["issues"] or 0),
                "analyzed": int(r["analyzed"] or 0),
                "last_time": r["last_time"] or "",
                "last_file": r["last_file"] or "",
                "ip": pick_primary_ip(r["ip"] or ""),
            }
    finally:
        conn.close()
    return out


def _patch_report_ip(rid: str, ip: str) -> None:
    """只更新索引中的 ip 字段，避免整行 upsert 冲掉告警计数。"""
    rid = P.report_id(rid)
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            conn.execute("UPDATE reports SET ip=? WHERE file=?", (ip, rid))
            conn.commit()
        finally:
            conn.close()
    try:
        from . import mysql_db
        if mysql_db.mysql_ready():
            conn = mysql_db.connect_mysql()
            try:
                with conn.cursor() as cur:
                    cur.execute("UPDATE reports SET ip=%s WHERE file=%s", (ip, rid))
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        print(f"[hosts] patch mysql ip {rid}: {e}")
    try:
        from .db_store import invalidate_list_cache
        invalidate_list_cache()
    except Exception:
        pass


def _primary_ip_from_reports(hostname: str) -> str:
    """索引 IP 已被截成 APIPA 时，回源 report.json 重选主 IP。"""
    import json
    files = _list_report_files(hostname)
    for rid in files:
        path = P.resolve_report_json(rid)
        if not path or not path.exists():
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh).get("ip") or ""
            cand = pick_primary_ip(raw)
            if cand and not is_weak_ip(cand):
                try:
                    _patch_report_ip(rid, cand)
                except Exception as e:
                    print(f"[hosts] repair index ip {rid}: {e}")
                return cand
        except Exception as e:
            print(f"[hosts] read report ip {rid}: {e}")
    return ""


def sync_hosts_from_index() -> int:
    stats = _report_stats()
    n = 0
    for name, st in stats.items():
        if not name or name == "unknown":
            continue
        # 无本地报告时不自动建台账（避免删主机后被幽灵索引复活）
        if int(st.get("report_count") or 0) <= 0:
            continue
        lf = (st.get("last_file") or "").strip()
        if lf:
            try:
                if not (
                    P.resolve_report_json(lf)
                    or P.resolve_analysis_db(lf)
                    or P.resolve_result_json(lf)
                ):
                    continue
            except Exception:
                continue
        ip = st.get("ip") or ""
        if not ip or is_weak_ip(ip):
            recovered = _primary_ip_from_reports(name)
            if recovered:
                ip = recovered
                st["ip"] = recovered
        before = get_host_by_name(name)
        ensure_host(name, ip)
        if not before:
            n += 1
    return n


def _list_hosts_uncached() -> List[Dict[str, Any]]:
    """只读台账表。不在 GET 里 prune/sync：删完主机后幽灵索引扫盘会把页面卡在「加载中」。"""
    stats: Dict[str, Dict[str, Any]] = {}
    try:
        stats = _report_stats(check_disk=False)
    except Exception as e:
        print(f"[hosts] report_stats: {e}")
    store = HostStore()
    try:
        rows = store.query_all("SELECT * FROM hosts ORDER BY name")
        out = []
        for r in rows:
            item = _row(r)
            st = stats.get(item["name"]) or {}
            item["report_count"] = st.get("report_count", 0)
            item["issues"] = st.get("issues", 0)
            item["last_time"] = st.get("last_time", "")
            item["last_file"] = st.get("last_file", "")
            # 展示优先用报告里挑出的主 IP；台账为空或为 APIPA 时覆盖
            if st.get("ip") and (not item.get("ip") or is_weak_ip(item.get("ip") or "")):
                item["ip"] = st["ip"]
                if item.get("id") and not is_weak_ip(item.get("ip") or ""):
                    try:
                        store.execute(
                            "UPDATE hosts SET ip=?, updated_at=? WHERE id=?",
                            (item["ip"], time.time(), item["id"]),
                        )
                        store.commit()
                    except Exception:
                        pass
            elif item.get("ip"):
                item["ip"] = pick_primary_ip(item["ip"]) or item["ip"]
            out.append(item)
        out.sort(key=lambda x: (x["name"] or "").lower())
        return out
    finally:
        store.close()


def list_hosts() -> List[Dict[str, Any]]:
    """短缓存聚合后的台账，避免同一页面多组件重复连接 MySQL 和聚合报告。"""
    global _HOST_LIST_CACHE, _HOST_LIST_CACHE_AT
    now = time.time()
    with _HOST_LIST_CACHE_LOCK:
        if _HOST_LIST_CACHE is not None and now - _HOST_LIST_CACHE_AT < _HOST_LIST_TTL:
            return copy.deepcopy(_HOST_LIST_CACHE)
        # 持锁重建：并发 miss 排队等候，命中后直接取缓存，避免雪崩式重复查库。
        rows = _list_hosts_uncached()
        _HOST_LIST_CACHE = copy.deepcopy(rows)
        _HOST_LIST_CACHE_AT = time.time()
        return rows


def create_host(name: str, ip: str = "", note: str = "") -> Dict[str, Any]:
    name = _validate_name(name)
    ip = pick_primary_ip(ip) or (ip or "").strip()
    note = (note or "").strip()
    if get_host_by_name(name):
        raise ValueError(f"主机已存在: {name}")
    hid = uuid.uuid4().hex[:12]
    now = time.time()
    store = HostStore()
    try:
        store.execute(
            "INSERT INTO hosts(id,name,ip,note,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (hid, name, ip, note, now, now),
        )
        store.commit()
        if store.mysql:
            _mirror_host_to_sqlite({
                "id": hid, "name": name, "ip": ip, "note": note,
                "created_at": now, "updated_at": now,
            })
    finally:
        store.close()
    _invalidate_host_cache()
    return get_host(hid) or {"id": hid, "name": name, "ip": ip, "note": note}


def update_host(
    host_id: str,
    name: Optional[str] = None,
    ip: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    host = get_host(host_id)
    if not host:
        raise ValueError("主机不存在")
    old_name = host["name"]
    new_name = old_name
    if name is not None:
        new_name = _validate_name(name)
    new_ip = host["ip"] if ip is None else (pick_primary_ip(ip) or (ip or "").strip())
    new_note = host["note"] if note is None else (note or "").strip()

    if new_name != old_name:
        other = get_host_by_name(new_name)
        if other and other["id"] != host_id:
            raise ValueError(f"主机名已被占用: {new_name}")
        try:
            rename_hostname(old_name, new_name)
        except ValueError as e:
            if "未找到主机" not in str(e):
                raise

    store = HostStore()
    try:
        store.execute(
            "UPDATE hosts SET name=?, ip=?, note=?, updated_at=? WHERE id=?",
            (new_name, new_ip, new_note, time.time(), host_id),
        )
        store.commit()
        if store.mysql:
            _mirror_host_to_sqlite({
                "id": host_id, "name": new_name, "ip": new_ip, "note": new_note,
                "created_at": host.get("created_at") or time.time(),
                "updated_at": time.time(),
            })
    finally:
        store.close()
    _invalidate_host_cache()
    out = get_host(host_id)
    if not out:
        raise ValueError("更新失败")
    return out


def _mirror_host_to_sqlite(row: Dict[str, Any]) -> None:
    """MySQL 写入后镜像到本地；先清同名不同 id，避免 UNIQUE(name) 导致镜像失败。"""
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect(HOSTS_DB)
        try:
            _init_hosts_sqlite(conn)
            hid = row.get("id")
            name = (row.get("name") or "").strip()
            if name and hid:
                conn.execute("DELETE FROM hosts WHERE name=? AND id!=?", (name, hid))
            conn.execute(
                """
                INSERT INTO hosts(id,name,ip,note,created_at,updated_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  name=excluded.name, ip=excluded.ip, note=excluded.note, updated_at=excluded.updated_at
                """,
                (
                    hid, name, row.get("ip") or "", row.get("note") or "",
                    row.get("created_at") or time.time(), row.get("updated_at") or time.time(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print("[hosts] mirror sqlite:", e)


def _mirror_host_delete_sqlite(host_id: str, name: str = "") -> None:
    try:
        if not HOSTS_DB.exists():
            return
        conn = _connect(HOSTS_DB)
        try:
            _init_hosts_sqlite(conn)
            conn.execute("DELETE FROM hosts WHERE id=?", (host_id,))
            if name:
                conn.execute("DELETE FROM hosts WHERE name=?", (name,))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print("[hosts] mirror delete sqlite:", e)


def _list_report_files(hostname: str) -> List[str]:
    if not INDEX_DB.exists():
        return []
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        rows = conn.execute("SELECT file FROM reports WHERE hostname=?", (hostname,)).fetchall()
        return [r["file"] for r in rows]
    finally:
        conn.close()


def delete_host_data(hostname: str) -> Dict[str, Any]:
    from .report_delete import delete_reports_for_host
    return delete_reports_for_host(hostname)


def delete_host(host_id: str) -> Dict[str, Any]:
    host = get_host(host_id)
    if not host:
        raise ValueError("主机不存在")
    data = delete_host_data(host["name"])
    store = HostStore()
    try:
        store.execute("DELETE FROM hosts WHERE id=?", (host_id,))
        store.execute("DELETE FROM hosts WHERE name=?", (host["name"],))
        store.commit()
        if store.mysql:
            _mirror_host_delete_sqlite(host_id, host["name"])
    finally:
        store.close()
    try:
        from .db_store import invalidate_list_cache
        invalidate_list_cache()
    except Exception:
        pass
    _invalidate_host_cache()
    return {"deleted": True, "id": host_id, "name": host["name"], **data}


def _host_os_map() -> Dict[str, Dict[str, str]]:
    """主机名 → 最近报告 OS 信息（供台账检索）。"""
    out: Dict[str, Dict[str, str]] = {}
    try:
        from .db_store import list_index
        rows = list_index(5000)
    except Exception:
        rows = []
    for row in rows or []:
        hn = str(row.get("hostname") or "").strip()
        if not hn:
            continue
        t = str(row.get("time") or row.get("collect_time") or "")
        prev = out.get(hn)
        if prev and t and t < str(prev.get("_time") or ""):
            continue
        out[hn] = {
            "os": str(row.get("os") or "").strip(),
            "os_family": str(row.get("os_family") or "").strip().lower(),
            "_time": t,
        }
    for v in out.values():
        v.pop("_time", None)
    return out


def search_hosts(
    q: str,
    hostname: Optional[str] = None,
    size: int = 50,
) -> List[Dict[str, Any]]:
    """跨主机台账检索：主机名 / IP / 备注 / 系统 / 报告统计等。"""
    from backend.search_sql import text_matches_query

    needle = (q or "").strip()
    if not needle:
        return []
    want_hn = (hostname or "").strip().lower()
    os_map = _host_os_map()
    out: List[Dict[str, Any]] = []
    for h in list_hosts():
        if len(out) >= int(size):
            break
        name = str(h.get("name") or "").strip()
        if not name:
            continue
        if want_hn and name.lower() != want_hn:
            continue
        os_info = os_map.get(name) or {}
        blob = " ".join([
            name,
            str(h.get("ip") or ""),
            str(h.get("note") or ""),
            str(h.get("id") or ""),
            str(h.get("report_count") or ""),
            str(h.get("issues") or ""),
            str(h.get("last_time") or ""),
            str(h.get("last_file") or ""),
            str(os_info.get("os") or ""),
            str(os_info.get("os_family") or ""),
        ])
        if not text_matches_query(blob, needle):
            continue
        evidence_parts: List[str] = []
        ip = str(h.get("ip") or "").strip()
        if ip:
            evidence_parts.append(f"IP: {ip}")
        if os_info.get("os"):
            evidence_parts.append(str(os_info["os"]))
        note = str(h.get("note") or "").strip()
        if note:
            evidence_parts.append(f"备注: {note}")
        rc = int(h.get("report_count") or 0)
        if rc:
            evidence_parts.append(f"报告 {rc} 份")
        iss = int(h.get("issues") or 0)
        if iss:
            evidence_parts.append(f"告警 {iss}")
        lt = str(h.get("last_time") or "").strip()
        if lt:
            evidence_parts.append(f"最近采集 {lt}")
        out.append({
            "hostname": name,
            "host_id": str(h.get("id") or ""),
            "report_id": str(h.get("last_file") or ""),
            "file": str(h.get("last_file") or ""),
            "severity": "info",
            "category": "主机台账",
            "title": name,
            "evidence": " · ".join(evidence_parts) or "主机台账",
            "matcher": "hosts",
            "module": "hosts",
            "kind": "host",
            "_source": "hosts",
            "ip": ip,
            "note": note,
            "report_count": rc,
            "issues": iss,
            "last_time": lt,
            "os": str(os_info.get("os") or ""),
            "os_family": str(os_info.get("os_family") or ""),
        })
    return out


def backend_info() -> Dict[str, Any]:
    from . import mysql_db
    return {
        "hosts_backend": "mysql" if mysql_db.mysql_ready() else "sqlite",
        "mysql": mysql_db.get_status(),
        "sqlite_path": str(HOSTS_DB),
    }
