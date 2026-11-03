"""每份报告对应一个 SQLite 结果库，避免反复解析大 JSON。"""
from __future__ import annotations
import json
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from . import config
from . import paths as P
from .cache_policy import capacity, ttl, versioned
from .iputil import pick_primary_ip

_PARK_FILES = "_park_file_scans.pkl"
_PARK_EVENTS = "_park_event_logs.pkl"

DB_DIR = config.REPORTS_DIR / "dbs"
DB_DIR.mkdir(parents=True, exist_ok=True)
INDEX_DB = config.REPORTS_DIR / "index.db"

# 写入 DB 的报告分段（足够前端各页展示）
BLOB_KEYS = [
    "processes", "services", "scheduled_tasks", "startup_items", "installed_programs",
    "users", "usb_devices", "prefetch_files", "established_connections", "open_ports",
    "network", "hosts_file", "firewall_rules", "ps_history", "ps_artifacts", "browser_artifacts",
    "user_registry", "services_registry", "network_registry", "run_mru",
    "recycle_bin", "wmi_subscriptions", "wmi_namespaces", "environment", "collection_quality",
    "suspicious_items", "hotfixes", "drivers", "driver_entries", "dns_cache_entries",
    "office_artifacts", "wifi_profiles", "event_log_summary", "event_logs",
    "system_info", "usn_journal", "vss_shadows", "bits_jobs", "audit_pol", "vault_creds",
    "net_sessions", "net_shares", "execution_artifacts", "remote_access", "security_extras",
    "event_log_coverage", "system_timezone", "file_scan_roots",
    "linuxsc_raw",
]

# 已下线的内存 / $MFT 取证分段：旧库里的 blob 保留，但平台不再读取 / 展示
RETIRED_BLOB_KEYS = frozenset({"memory_artifacts", "mft_artifacts"})


def db_path_for_report(report_file: str) -> Path:
    """优先返回目录内 analysis.db；写入前会 create 目录。"""
    existing = P.resolve_analysis_db(report_file)
    if existing:
        return existing
    return P.db_path_for_write(report_file)


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-8000")  # ~8MB page cache
    return conn


# 进程模块签名回查按 lower(replace(full_path,'/','\')) 匹配，必须是表达式索引，
# 否则 SQLite 用不上 full_path 主键索引，百万行的 files 表每次都全表扫描。
_FILES_PATH_NORM_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_files_fullpath_norm "
    "ON files(lower(replace(full_path,'/','\\')))"
)


def _ensure_files_path_norm_index(conn: sqlite3.Connection, *, create: bool = True) -> bool:
    """保证 files 路径归一化索引存在。

    create=False：仅探测，绝不在 GET 读路径上 CREATE INDEX（大库首建可达数秒）。
    create=True：入库/分析时补建。
    """
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_files_fullpath_norm' LIMIT 1"
        ).fetchone()
        if row:
            return True
        if not create:
            return False
        conn.execute(_FILES_PATH_NORM_INDEX_SQL)
        return True
    except sqlite3.OperationalError:
        return False


def _ensure_files_hash_indexes(conn: sqlite3.Connection) -> None:
    for col in ("md5", "sha1", "sha256"):
        try:
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_files_{col} ON files({col})")
        except sqlite3.OperationalError:
            pass


_FILE_INSERT_SQL = (
    "INSERT INTO files(full_path,name,path,parent_path_norm,ext,size,company,product,description,"
    "file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,"
    "mtime,mode,owner,file_group,content) "
    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT(full_path) DO UPDATE SET "
    "name=excluded.name,path=excluded.path,parent_path_norm=excluded.parent_path_norm,"
    "ext=excluded.ext,size=excluded.size,company=excluded.company,product=excluded.product,"
    "description=excluded.description,file_version=excluded.file_version,signed=excluded.signed,"
    "signer=excluded.signer,sig_status=excluded.sig_status,sig_type=excluded.sig_type,"
    "magic_hex=excluded.magic_hex,md5=excluded.md5,sha1=excluded.sha1,sha256=excluded.sha256,"
    "hidden=excluded.hidden,system=excluded.system,mtime=excluded.mtime,mode=excluded.mode,"
    "owner=excluded.owner,file_group=excluded.file_group,"
    "content=CASE WHEN excluded.content!='' THEN excluded.content ELSE files.content END"
)


def _norm_ext(ext: Any) -> str:
    e = str(ext or "").strip().lower()
    if not e:
        return ""
    if not e.startswith("."):
        e = "." + e
    return e


def _norm_hash_field(v: Any) -> str:
    s = str(v or "").strip().lower().replace(" ", "").replace("-", "")
    if s.startswith("0x"):
        s = s[2:]
    if len(s) in (32, 40, 64) and all(c in "0123456789abcdef" for c in s):
        return s
    return ""


def _norm_file_path(value: Any) -> str:
    s = re.sub(r"\\+", r"\\", str(value or "").replace("/", "\\").strip()).rstrip("\\")
    return s.lower()


def _file_parent(f: Dict[str, Any]) -> str:
    parent = str(f.get("path") or "").strip()
    if not parent:
        full = re.sub(r"\\+", r"\\", str(f.get("full_path") or "").replace("/", "\\")).rstrip("\\")
        parent = full.rsplit("\\", 1)[0] if "\\" in full else ""
    return re.sub(r"\\+", r"\\", parent.replace("/", "\\")).rstrip("\\")


FILE_CONTENT_MAX_CHARS = 200_000


def _file_content_field(f: Dict[str, Any]) -> str:
    """文本类文件正文（脚本 / log / txt / 配置）；采集端已按日志取尾、配置取头截断。"""
    raw = f.get("content") or f.get("text") or f.get("script_text") or f.get("snippet") or ""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8", errors="replace")
        except Exception:
            return ""
    s = str(raw or "")
    if not s.strip():
        return ""
    return s[:FILE_CONTENT_MAX_CHARS]


def _file_row_tuple(f: Dict[str, Any]) -> tuple:
    return (
        f.get("full_path") or "",
        f.get("name") or "",
        f.get("path") or "",
        _norm_file_path(_file_parent(f)),
        _norm_ext(f.get("ext")),
        int(f.get("size") or 0),
        f.get("company") or "",
        f.get("product") or "",
        f.get("description") or "",
        f.get("file_version") or "",
        1 if f.get("signed") else 0,
        f.get("signer") or "",
        f.get("sig_status") or "",
        f.get("sig_type") or f.get("SigType") or "",
        f.get("magic_hex") or "",
        _norm_hash_field(f.get("md5") or f.get("MD5")),
        _norm_hash_field(f.get("sha1") or f.get("SHA1")),
        _norm_hash_field(f.get("sha256") or f.get("SHA256")),
        1 if f.get("hidden") else 0,
        1 if f.get("system") else 0,
        str(f.get("mtime") or "")[:40],
        str(f.get("mode") or "")[:32],
        str(f.get("owner") or "")[:64],
        str(f.get("group") or f.get("file_group") or f.get("root") or "")[:64],
        _file_content_field(f),
    )


def _directory_rows(files: List[Any]) -> List[tuple]:
    """Build a compact parent/child directory index from file paths."""
    seen: Dict[str, tuple] = {}
    for item in files or []:
        if not isinstance(item, dict):
            continue
        full_raw = str(item.get("full_path") or "")
        unix = full_raw.startswith("/")
        parent = _file_parent(item)
        if not parent:
            continue
        parts = [x for x in parent.replace("/", "\\").split("\\") if x]
        if not parts:
            continue
        current = ""
        parent_current = ""
        for i, part in enumerate(parts):
            parent_current = current
            if i == 0 and unix:
                current = "\\" + part
            elif i == 0:
                current = part
            else:
                current = current + "\\" + part
            norm = _norm_file_path(current)
            parent_norm = _norm_file_path(parent_current)
            display = current.replace("\\", "/") if unix else current
            seen.setdefault(norm, (norm, parent_norm, part, display))
    return list(seen.values())


def _rebuild_directory_index(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT full_path,name,path FROM files").fetchall()
    files = [
        {"full_path": r["full_path"] or "", "name": r["name"] or "", "path": r["path"] or ""}
        for r in rows
    ]
    conn.execute("DELETE FROM file_directories")
    directory_rows = _directory_rows(files)
    if directory_rows:
        conn.executemany(
            "INSERT OR REPLACE INTO file_directories(path_norm,parent_path_norm,name,full_path) "
            "VALUES(?,?,?,?)",
            directory_rows,
        )
    conn.executemany(
        "UPDATE files SET parent_path_norm=? WHERE full_path=?",
        [(_norm_file_path(_file_parent(f)), f.get("full_path") or "") for f in files],
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES('file_directory_index_count',?)",
        (str(len(directory_rows)),),
    )


def _ensure_directory_index(conn: sqlite3.Connection) -> None:
    dir_count = int(conn.execute("SELECT COUNT(1) FROM file_directories").fetchone()[0] or 0)
    need = False
    if dir_count:
        # Windows 报告无需扫描百万 files 判断 Linux 旧索引问题。
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
            fam = str((row["value"] if row else "") or "").strip().lower()
        except Exception:
            fam = ""
        if fam != "linux":
            return
        # Linux 路径曾错误索引为无前导 \ 的 usr\...，仅 Linux 库检查一次。
        try:
            bad = conn.execute(
                "SELECT 1 FROM file_directories "
                "WHERE path_norm NOT LIKE '\\%' AND path_norm NOT LIKE '_:\\%' LIMIT 1"
            ).fetchone()
            need = bool(bad)
        except Exception:
            need = False
    else:
        file_count = int(conn.execute("SELECT COUNT(1) FROM files").fetchone()[0] or 0)
        need = bool(file_count)
    if need:
        _rebuild_directory_index(conn)
        conn.commit()


def _insert_file_rows(conn: sqlite3.Connection, files: List[Any], cancel_check=None) -> int:
    batch = []
    n = 0
    for f in files:
        if not isinstance(f, dict):
            continue
        batch.append(_file_row_tuple(f))
        n += 1
        if len(batch) >= 2000:
            if cancel_check and cancel_check():
                raise InterruptedError("job cancelled")
            conn.executemany(_FILE_INSERT_SQL, batch)
            batch = []
    if batch:
        if cancel_check and cancel_check():
            raise InterruptedError("job cancelled")
        conn.executemany(_FILE_INSERT_SQL, batch)
    return n


_ELOG_INSERT_SQL = (
    "INSERT INTO event_logs(channel,event_id,provider,time,level,computer,message,fields) "
    "VALUES(?,?,?,?,?,?,?,?)"
)


def _elog_row_tuple(e: Dict[str, Any]) -> tuple:
    fields = e.get("fields") if isinstance(e.get("fields"), dict) else {}
    msg = str(e.get("message") or "")
    if len(msg) > 2000:
        msg = msg[:2000] + "..."
    try:
        eid = int(e.get("event_id") or 0)
    except (TypeError, ValueError):
        eid = 0
    return (
        str(e.get("channel") or ""),
        eid,
        str(e.get("provider") or ""),
        str(e.get("time") or ""),
        str(e.get("level") or ""),
        str(e.get("computer") or ""),
        msg,
        _jdump(fields) if fields else "",
    )


def _insert_event_log_rows(conn: sqlite3.Connection, events: List[Any], cancel_check=None) -> int:
    batch = []
    n = 0
    for e in events or []:
        if not isinstance(e, dict):
            continue
        batch.append(_elog_row_tuple(e))
        n += 1
        if len(batch) >= 2000:
            if cancel_check and cancel_check():
                raise InterruptedError("job cancelled")
            conn.executemany(_ELOG_INSERT_SQL, batch)
            batch = []
    if batch:
        if cancel_check and cancel_check():
            raise InterruptedError("job cancelled")
        conn.executemany(_ELOG_INSERT_SQL, batch)
    return n


def _event_log_row_to_dict(r) -> Dict[str, Any]:
    fields = _jload(r["fields"]) if r["fields"] else {}
    if not isinstance(fields, dict):
        fields = {}
    try:
        from .text_fix import fix_mojibake, fix_tree
        fields = fix_tree(fields) if fields else {}
        msg = fix_mojibake(r["message"] or "")
    except Exception:
        msg = r["message"] or ""
    return {
        "channel": r["channel"] or "",
        "event_id": int(r["event_id"] or 0),
        "provider": r["provider"] or "",
        "time": r["time"] or "",
        "level": r["level"] or "",
        "computer": r["computer"] or "",
        "message": msg,
        "fields": fields,
    }


def _ensure_event_logs_table(conn: sqlite3.Connection) -> int:
    """若 event_logs 表空但 blob 有数据，一次性迁移，避免前端拉 10MB+ JSON。"""
    try:
        n = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
    except sqlite3.OperationalError:
        _init_schema(conn)
        n = 0
    if n > 0:
        return n
    raw = _load_one_blob(conn, "event_logs")
    if not isinstance(raw, list) or not raw:
        return 0
    conn.execute("DELETE FROM event_logs")
    n = _insert_event_log_rows(conn, raw)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
        ("count_event_logs", str(n)),
    )
    # 大 blob 改为最多保留 300 条样例，完整数据在表里
    if n > 300:
        conn.execute(
            "INSERT OR REPLACE INTO blobs(name,data) VALUES(?,?)",
            ("event_logs", _jdump(raw[:300])),
        )
    try:
        conn.commit()
    except Exception:
        pass
    return n


def _event_log_channel_stats(conn: sqlite3.Connection) -> Dict[str, int]:
    try:
        rows = conn.execute(
            "SELECT IFNULL(channel,'') AS ch, COUNT(1) AS c FROM event_logs GROUP BY ch ORDER BY c DESC"
        ).fetchall()
        out: Dict[str, int] = {}
        for r in rows:
            ch = str(r["ch"] or "").strip() or "Other"
            out[ch] = int(r["c"] or 0)
        return out
    except Exception:
        return {}


def _parse_event_hit_key(hk: str) -> Optional[Tuple[str, int, str]]:
    parts = str(hk or "").split("|")
    if len(parts) < 3:
        return None
    ch, eid_s, tm = parts[0], parts[1], "|".join(parts[2:])
    try:
        eid = int(eid_s)
    except Exception:
        eid = 0
    return ch, eid, tm


_ELOG_HIT_CACHE: Dict[str, tuple] = {}
_ELOG_HIT_LOCK = threading.Lock()
_ELOG_HIT_TTL = ttl("eventlog_hit_index", 30.0, minimum=5.0, maximum=300.0)
_ELOG_HIT_MAX = capacity("eventlog_hit_index", 64)


def _eventlog_hit_index_for_rid(rid: str) -> Dict[str, Dict[str, Any]]:
    """分析时写入的命中索引：hit_key -> {title, rule_id, level}。不再现场全表重匹配。

    这个索引每次翻页都要用，但重建一次要读整份 summary view（7 万行的库上
    实测 58ms，是系统日志页最大的单项开销），所以按 rid 短时缓存。
    """
    now = time.time()
    with _ELOG_HIT_LOCK:
        hit = _ELOG_HIT_CACHE.get(rid)
        if hit and now - hit[0] < _ELOG_HIT_TTL:
            return hit[1]
    idx = _build_eventlog_hit_index(rid)
    with _ELOG_HIT_LOCK:
        _ELOG_HIT_CACHE[rid] = (now, idx)
        if len(_ELOG_HIT_CACHE) > _ELOG_HIT_MAX:
            trim = max(1, _ELOG_HIT_MAX // 4)
            for key, _ in sorted(_ELOG_HIT_CACHE.items(), key=lambda x: x[1][0])[:trim]:
                _ELOG_HIT_CACHE.pop(key, None)
    return idx


def _build_eventlog_hit_index(rid: str) -> Dict[str, Dict[str, Any]]:
    from .eventlog_rules import event_hit_key

    try:
        view = load_summary_view(rid) or {}
        meta = ((view.get("analysis") or {}).get("meta") or {})
        idx = meta.get("eventlog_hit_index")
        if isinstance(idx, dict) and idx:
            out: Dict[str, Dict[str, Any]] = {}
            for k, v in idx.items():
                if not k:
                    continue
                info = v if isinstance(v, dict) else {}
                out[str(k)] = {
                    "title": str(info.get("title") or ""),
                    "rule_id": str(info.get("rule_id") or ""),
                    "level": str(info.get("level") or "medium"),
                    "evidence": str(info.get("evidence") or ""),
                }
            if out:
                return out
        block = ((view.get("analysis") or {}).get("findings_by_module") or {}).get("eventlog") or {}
        out = {}
        for f in block.get("findings") or []:
            if not isinstance(f, dict):
                continue
            ex = f.get("extra") if isinstance(f.get("extra"), dict) else {}
            ch = ex.get("channel") or f.get("channel")
            eid = ex.get("event_id") if ex.get("event_id") is not None else f.get("event_id")
            tm = ex.get("time") or f.get("time")
            hk = event_hit_key(ch, eid, tm)
            if not hk or hk in out:
                continue
            out[hk] = {
                "title": str(f.get("title") or f.get("name") or ""),
                "rule_id": str(f.get("rule_id") or ""),
                "level": str(f.get("severity") or "medium"),
                "evidence": str(f.get("evidence") or ""),
            }
        return out
    except Exception:
        return {}


def _event_matches_q(d: Dict[str, Any], qq: str) -> bool:
    if not qq:
        return True
    blob = " ".join([
        str(d.get("channel") or ""),
        str(d.get("provider") or ""),
        str(d.get("message") or ""),
        str(d.get("event_id") or ""),
        str(d.get("level") or ""),
        str(d.get("computer") or ""),
        str(d.get("fields") or ""),
    ]).lower()
    tokens = [t for t in qq.split() if t]
    if not tokens:
        return True
    return all(_token_in_blob(t, blob) for t in tokens)


def _fetch_events_for_hit_index(
    conn: sqlite3.Connection,
    idx: Dict[str, Dict[str, Any]],
    *,
    q: str = "",
    channel: str = "",
) -> List[Dict[str, Any]]:
    """按分析命中索引定点取事件，避免全表重跑 Sigma。"""
    from .eventlog_rules import event_hit_key, normalize_event_time

    qq = (q or "").strip().lower()
    ch_exact = (channel or "").strip()
    items: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for hk, info in (idx or {}).items():
        parsed = _parse_event_hit_key(hk)
        if not parsed:
            continue
        ch, eid, tm = parsed
        if ch_exact and str(ch_exact).strip().lower() != ch:
            continue
        tnorm = normalize_event_time(tm)
        like_a = f"%{tnorm}%" if tnorm else "%"
        like_b = f"%{tnorm.replace(' ', 'T')}%" if tnorm else like_a
        try:
            rows = conn.execute(
                "SELECT channel,event_id,provider,time,level,computer,message,fields "
                "FROM event_logs WHERE event_id = ? AND lower(IFNULL(channel,'')) = ? "
                "AND (IFNULL(time,'') LIKE ? OR IFNULL(time,'') LIKE ?) "
                "ORDER BY id DESC LIMIT 12",
                (eid, ch, like_a, like_b),
            ).fetchall()
        except Exception:
            rows = []
        found: Optional[Dict[str, Any]] = None
        for r in rows:
            d = _event_log_row_to_dict(r)
            if event_hit_key(d.get("channel"), d.get("event_id"), d.get("time")) == hk:
                found = d
                break
        if found is None and rows:
            found = _event_log_row_to_dict(rows[0])
        if not found or hk in seen:
            continue
        if not _event_matches_q(found, qq):
            continue
        seen.add(hk)
        found = dict(found)
        found["hit_rule"] = {
            "title": str((info or {}).get("title") or ""),
            "rule_id": str((info or {}).get("rule_id") or ""),
            "level": str((info or {}).get("level") or "medium"),
            "evidence": str((info or {}).get("evidence") or ""),
        }
        items.append(found)
    items.sort(key=lambda x: str(x.get("time") or ""), reverse=True)
    return items


def _attach_eventlog_hit_rules(items: List[Dict[str, Any]], rid: str) -> None:
    if not rid or not items:
        return
    try:
        from .eventlog_rules import event_hit_key
        idx = _eventlog_hit_index_for_rid(rid)
        if not idx:
            return
        for d in items:
            if not isinstance(d, dict) or d.get("hit_rule"):
                continue
            hk = event_hit_key(d.get("channel"), d.get("event_id"), d.get("time"))
            info = idx.get(hk)
            if info:
                d["hit_rule"] = info
    except Exception:
        pass


def _query_event_logs_page(
    conn: sqlite3.Connection,
    *,
    offset: int = 0,
    limit: int = 100,
    q: str = "",
    channel: str = "",
    hit_keys: Optional[Set[str]] = None,
    rid: str = "",
    hits_only: bool = False,
) -> Dict[str, Any]:
    total = _ensure_event_logs_table(conn)
    where = ["1=1"]
    args: List[Any] = []
    ch_exact = (channel or "").strip()
    qq = (q or "").strip().lower()
    if ch_exact:
        where.append("channel = ?")
        args.append(ch_exact)
    if qq:
        where.append(
            "(lower(IFNULL(channel,'')) LIKE ? OR lower(IFNULL(provider,'')) LIKE ? "
            "OR lower(IFNULL(message,'')) LIKE ? OR CAST(event_id AS TEXT) LIKE ? "
            "OR lower(IFNULL(level,'')) LIKE ? OR lower(IFNULL(computer,'')) LIKE ? "
            "OR lower(IFNULL(fields,'')) LIKE ?)"
        )
        like = f"%{qq}%"
        args.extend([like, like, like, like, like, like, like])
    wh = " AND ".join(where)

    if hits_only or hit_keys is not None:
        idx = _eventlog_hit_index_for_rid(rid) if rid else {}
        if hit_keys:
            idx = {str(k): (idx.get(str(k)) or {}) for k in hit_keys if k}
        items = _fetch_events_for_hit_index(conn, idx, q=q, channel=channel)
        total = len(items)
        return {"total": total, "items": items[offset : offset + limit], "hits_only": True}

    # 带筛选时不做精确 COUNT(*)：7 列 LIKE 统计全量命中在 7 万行上要 155ms，
    # 而取本页只要 0.4ms。改成多取一条判断有没有下一页。
    approx = False
    rows = conn.execute(
        f"SELECT channel,event_id,provider,time,level,computer,message,fields "
        f"FROM event_logs WHERE {wh} ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
        (*args, limit + 1, offset),
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    if qq or ch_exact:
        total = offset + len(rows) + (1 if has_more else 0)
        approx = has_more
    items = [_event_log_row_to_dict(r) for r in rows]
    _attach_eventlog_hit_rules(items, rid)
    return {"total": total, "items": items, "total_approx": approx, "has_more": has_more}


def _eventlog_hit_keys_for_rid(rid: str) -> Set[str]:
    """读取系统日志规则命中键集合。"""
    return set((_eventlog_hit_index_for_rid(rid) or {}).keys())


def _park_path(rid: str, name: str) -> Path:
    return P.report_dir(rid, create=True) / name


def park_heavy_arrays(rid: str, report: Dict[str, Any]) -> Dict[str, int]:
    """上传热路径：把超大 file_scans / event_logs 先 pickle 到报告目录，立刻瘦身 JSON。

    SQLite 入库改到分析任务里做，避免 POST /api/collect/report 卡十几秒并拖死 jobs/hosts。
    """
    import pickle

    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    n_files = len(files) if isinstance(files, list) else 0
    n_ev = len(events) if isinstance(events, list) else 0
    if n_files:
        with open(_park_path(rid, _PARK_FILES), "wb") as fh:
            pickle.dump(files, fh, protocol=5)
        report["file_scans"] = []
    if n_ev:
        with open(_park_path(rid, _PARK_EVENTS), "wb") as fh:
            pickle.dump(events, fh, protocol=5)
        report["event_logs"] = []
    if n_files:
        report["_files_count"] = n_files
        report["_files_ingested"] = False
    if n_ev:
        report["_event_logs_count"] = n_ev
        report["_event_logs_ingested"] = False
    if n_files or n_ev:
        report["_heavy_parked"] = True
    return {"files": n_files, "event_logs": n_ev}


def load_parked_heavy(rid: str, report: Dict[str, Any]) -> Dict[str, int]:
    """分析任务：把上传时暂存的大数组装回 report，供 ingest。"""
    import pickle

    n_files = 0
    n_ev = 0
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    pf = P.report_dir(rid) / _PARK_FILES
    pe = P.report_dir(rid) / _PARK_EVENTS
    if (not files) and pf.is_file():
        try:
            with open(pf, "rb") as fh:
                parked = pickle.load(fh)
            if isinstance(parked, list) and parked:
                report["file_scans"] = parked
                n_files = len(parked)
        except Exception as e:
            print(f"[db_store] load parked files: {e}")
    if (not events) and pe.is_file():
        try:
            with open(pe, "rb") as fh:
                parked = pickle.load(fh)
            if isinstance(parked, list) and parked:
                report["event_logs"] = parked
                n_ev = len(parked)
        except Exception as e:
            print(f"[db_store] load parked events: {e}")
    return {"files": n_files, "event_logs": n_ev}


def clear_parked_heavy(rid: str) -> None:
    for name in (_PARK_FILES, _PARK_EVENTS):
        p = P.report_dir(rid) / name
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass


def ingest_file_scans(rid: str, files: Optional[List[Any]] = None, cancel_check=None) -> int:
    """分析前把 file_scans 写入 analysis.db，供按条件查询。

    数量一致时默认跳过；若源数据带 md5/sha* 而库内没有哈希，则强制重写。
    """
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        existing = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
        rows = [f for f in (files or []) if isinstance(f, dict)]

        def _src_has_any_hash() -> bool:
            # 只需判断「有没有」，勿全表计数（大报告入库跳过路径会扫几十万次）
            for f in rows:
                if _norm_hash_field(f.get("md5") or f.get("MD5")) or _norm_hash_field(
                    f.get("sha1") or f.get("SHA1")
                ) or _norm_hash_field(f.get("sha256") or f.get("SHA256")):
                    return True
            return False

        def _db_has_any_hash() -> bool:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
            if not ({"md5", "sha1", "sha256"} & cols):
                return False
            try:
                row = conn.execute(
                    "SELECT 1 AS x FROM files WHERE "
                    "IFNULL(md5,'')!='' OR IFNULL(sha1,'')!='' OR IFNULL(sha256,'')!='' "
                    "LIMIT 1"
                ).fetchone()
                return bool(row)
            except sqlite3.OperationalError:
                return False

        # 数量一致时先走快速跳过；仅在「源有哈希、库无哈希」时强制重写
        force = False
        if existing > 0 and (not rows or existing == len(rows)):
            if rows and not _db_has_any_hash() and _src_has_any_hash():
                force = True
            else:
                _ensure_directory_index(conn)
                _ensure_files_path_norm_index(conn, create=True)
                conn.commit()
                try:
                    _patch_index_file_count(rid, existing)
                except Exception:
                    pass
                return existing
        if not rows:
            conn.commit()
            return existing
        if force:
            print(f"[db] re-ingest file_scans for hashes: rid={rid} files={len(rows)}")
        conn.execute("DELETE FROM files")
        conn.execute("DELETE FROM file_directories")
        n = _insert_file_rows(conn, rows, cancel_check=cancel_check)
        directory_rows = _directory_rows(rows)
        if directory_rows:
            conn.executemany(
                "INSERT OR REPLACE INTO file_directories(path_norm,parent_path_norm,name,full_path) "
                "VALUES(?,?,?,?)",
                directory_rows,
            )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
            ("file_directory_index_count", str(len(directory_rows))),
        )
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(n)))
        roots = _derive_file_scan_roots(rows)
        if roots:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("file_scan_roots", _jdump(roots)),
            )
        # 分析入库时建路径索引，避免进程页首开 GET 时 CREATE INDEX 卡 数秒
        _ensure_files_path_norm_index(conn, create=True)
        conn.commit()
        try:
            _patch_index_file_count(rid, n)
        except Exception:
            pass
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"[db] ingest file_scans rid={rid} n={n} ms={ms}")
        try:
            from . import applog
            applog.info("db", f"ingest file_scans rid={rid} n={n} ms={ms}", rid=rid, n=n, ms=ms)
        except Exception:
            pass
        return n
    finally:
        conn.close()


def ingest_event_logs_iter(rid: str, rows_iter, cancel_check=None) -> int:
    """流式写入 event_logs（jsonl），已有数据则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        try:
            existing = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
        except sqlite3.OperationalError:
            _init_schema(conn)
            existing = 0
        if existing > 0:
            conn.commit()
            return existing
        n = _insert_event_log_rows(conn, rows_iter, cancel_check=cancel_check)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_event_logs", str(n)))
        conn.commit()
        print(f"[db] ingest event_logs jsonl rid={rid} n={n}")
        return n
    finally:
        conn.close()


def ingest_file_scans_iter(rid: str, rows_iter, cancel_check=None) -> int:
    """流式写入 files 表（jsonl），已有数据则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        existing = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
        if existing > 0:
            conn.commit()
            try:
                _patch_index_file_count(rid, existing)
            except Exception:
                pass
            return existing
        n = _insert_file_rows(conn, rows_iter, cancel_check=cancel_check)
        try:
            _rebuild_directory_index(conn)
        except Exception as e:
            print(f"[db] rebuild dir index after jsonl: {e}")
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(n)))
        conn.commit()
        try:
            _patch_index_file_count(rid, n)
        except Exception:
            pass
        print(f"[db] ingest file_scans jsonl rid={rid} n={n}")
        return n
    finally:
        conn.close()


def ingest_event_logs(rid: str, events: Optional[List[Any]] = None, cancel_check=None) -> int:
    """把 event_logs 写入 analysis.db 表；已有且数量一致则跳过。"""
    dbp = P.db_path_for_write(rid)
    dbp.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        try:
            existing = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
        except sqlite3.OperationalError:
            _init_schema(conn)
            existing = 0
        rows = [e for e in (events or []) if isinstance(e, dict)]
        if existing > 0 and (not rows or existing == len(rows)):
            conn.commit()
            return existing
        if not rows:
            conn.commit()
            return existing
        conn.execute("DELETE FROM event_logs")
        n = _insert_event_log_rows(conn, rows, cancel_check=cancel_check)
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", ("count_event_logs", str(n)))
        sample = rows[:300]
        conn.execute("DELETE FROM blobs WHERE name=?", ("event_logs",))
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("event_logs", _jdump(sample)))
        conn.commit()
        ms = int((time.perf_counter() - t0) * 1000)
        print(f"[db] ingest event_logs rid={rid} n={n} ms={ms}")
        try:
            from . import applog
            applog.info("db", f"ingest event_logs rid={rid} n={n} ms={ms}", rid=rid, n=n, ms=ms)
        except Exception:
            pass
        return n
    finally:
        conn.close()


def _meta_int(rid: str, key: str, default: int = 0) -> int:
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return default
    conn = _connect(Path(dbp))
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        return int(row["value"] or default)
    except Exception:
        return default
    finally:
        conn.close()


def detach_and_ingest_heavy(rid: str, report: Dict[str, Any], cancel_check=None) -> Dict[str, int]:
    """把超大 file_scans / event_logs 写入 SQLite，并从 report 字典剥离，便于瘦身落盘。

    调用后 report 仅保留计数与标记；后续匹配走 query_files / event_logs 表。
    """
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    roots = report.get("file_scan_roots") if isinstance(report.get("file_scan_roots"), dict) else None

    n_files = 0
    n_ev = 0
    try:
        if files:
            if not roots:
                roots = _derive_file_scan_roots(files)
            n_files = ingest_file_scans(rid, files, cancel_check=cancel_check)
        else:
            n_files = _meta_int(rid, "count_file_scans", 0)
            if n_files <= 0:
                dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
                if Path(dbp).is_file():
                    conn = _connect(Path(dbp))
                    try:
                        n_files = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
                    except Exception:
                        n_files = 0
                    finally:
                        conn.close()
        if events:
            n_ev = ingest_event_logs(rid, events, cancel_check=cancel_check)
        else:
            n_ev = _meta_int(rid, "count_event_logs", 0)
            if n_ev <= 0:
                dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
                if Path(dbp).is_file():
                    conn = _connect(Path(dbp))
                    try:
                        n_ev = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
                    except Exception:
                        n_ev = 0
                    finally:
                        conn.close()
    except InterruptedError:
        raise
    except Exception as e:
        print(f"[db_store] detach_and_ingest_heavy: {e}")

    if roots:
        report["file_scan_roots"] = roots
        try:
            dbp = P.db_path_for_write(rid)
            if Path(dbp).is_file():
                conn = _connect(dbp)
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                        ("file_scan_roots", _jdump(roots)),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except Exception:
            pass

    report["file_scans"] = []
    report["event_logs"] = []
    report["_files_count"] = int(n_files or 0)
    report["_files_ingested"] = True
    report["_event_logs_count"] = int(n_ev or 0)
    report["_event_logs_ingested"] = True
    try:
        if n_files:
            _patch_index_file_count(rid, int(n_files))
    except Exception:
        pass
    return {"files": int(n_files or 0), "event_logs": int(n_ev or 0)}


def rewrite_report_json_slim(rid: str, report: Dict[str, Any]) -> None:
    """覆盖写入瘦身 report.json（无大数组），降低后续分析加载成本。"""
    try:
        from .store import save_report
        # 避免 save_report 再次 ingest
        save_report(report, rid, ingest_heavy=False)
    except Exception as e:
        print(f"[db_store] rewrite slim report: {e}")


def ensure_heavy_ready(rid: str, report: Dict[str, Any], cancel_check=None) -> Dict[str, int]:
    """分析加载时：若内存/磁盘仍有大数组则入库并剥离；已入库则只打标记。"""
    from .stage_timer import StageTimer
    t = StageTimer("job_timing", "heavy_ready", rid=rid)
    pack_stats = {"files": 0, "event_logs": 0}
    try:
        from .collect_pack import ingest_pack_jsonl
        with t.step("pack_jsonl"):
            pack_stats = ingest_pack_jsonl(rid, cancel_check=cancel_check) or {}
    except InterruptedError:
        raise
    except Exception as e:
        print(f"[db_store] pack jsonl ingest: {e}")
    with t.step("unpark"):
        load_parked_heavy(rid, report)
    files = report.get("file_scans") if isinstance(report.get("file_scans"), list) else []
    events = report.get("event_logs") if isinstance(report.get("event_logs"), list) else []
    fat = len(files) >= 500 or len(events) >= 200
    if files or events:
        t.set(files=len(files), events=len(events))
        with t.step("ingest"):
            stats = detach_and_ingest_heavy(rid, report, cancel_check=cancel_check)
        if fat:
            with t.step("slim"):
                rewrite_report_json_slim(rid, report)
        with t.step("cleanup"):
            clear_parked_heavy(rid)
        t.emit()
        return stats
    # 已瘦身：从 DB 恢复计数
    n_files = _meta_int(rid, "count_file_scans", 0)
    n_ev = _meta_int(rid, "count_event_logs", 0)
    if n_files <= 0:
        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                n_files = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
            except Exception:
                pass
            finally:
                conn.close()
    if n_ev <= 0:
        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                n_ev = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
            except Exception:
                pass
            finally:
                conn.close()
    report["file_scans"] = []
    report["event_logs"] = []
    report["_files_count"] = n_files
    report["_files_ingested"] = True
    report["_event_logs_count"] = n_ev
    report["_event_logs_ingested"] = True
    if t.total_ms >= 50:
        t.emit(files=n_files, events=n_ev)
    return {"files": n_files, "event_logs": n_ev}


def load_event_logs_for_match(rid: str, limit: int = 50000) -> List[Dict[str, Any]]:
    """规则匹配用：从 event_logs 表拉取（已剥离内存数组时）。"""
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    conn = _connect(Path(dbp))
    try:
        _ensure_event_logs_table(conn)
        lim = max(1, min(int(limit or 50000), 100000))
        rows = conn.execute(
            "SELECT channel,event_id,provider,time,level,computer,message,fields "
            "FROM event_logs ORDER BY id DESC LIMIT ?",
            (lim,),
        ).fetchall()
        return [_event_log_row_to_dict(r) for r in rows]
    except Exception as e:
        print(f"[db_store] load_event_logs_for_match: {e}")
        return []
    finally:
        conn.close()


def lookup_file_sigs_by_paths(rid: str, paths: List[str]) -> Dict[str, Dict[str, Any]]:
    """按完整路径批量取签名元数据（供进程模块签名回填）。键为 lower(full_path)。"""
    out: Dict[str, Dict[str, Any]] = {}
    want = []
    seen = set()
    for p in paths or []:
        s = str(p or "").strip().replace("/", "\\")
        if not s:
            continue
        # 与 _norm_path 一致：去掉 \\?\ 前缀再查
        if s.startswith("\\\\?\\UNC\\"):
            s = "\\" + s[7:]
        elif s.startswith("\\\\?\\"):
            s = s[4:]
        low = s.lower()
        if low in seen:
            continue
        seen.add(low)
        want.append(s)
    if not rid or not want:
        return out
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return out
    conn = _connect(Path(dbp))
    try:
        # files 表空但 pack/files.jsonl 在：仅做 O(1) 探测；需要时关闭连接再懒入库。
        try:
            has_files = conn.execute("SELECT 1 FROM files LIMIT 1").fetchone()
        except Exception:
            has_files = None
        if not has_files:
            conn.close()
            try:
                from .collect_pack import ingest_pack_jsonl
                ingest_pack_jsonl(rid)
            except Exception as e:
                print(f"[db_store] lazy ingest files for sig lookup: {e}")
            conn = _connect(Path(dbp))
        _ensure_files_path_norm_index(conn, create=False)
        # SQLite 变量上限约 999；分批查
        for i in range(0, len(want), 400):
            chunk = want[i : i + 400]
            ph = ",".join("?" * len(chunk))
            lows = [x.lower() for x in chunk]
            try:
                rows = conn.execute(
                    "SELECT full_path,signed,signer,sig_status,sig_type,company "
                    f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                    lows,
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT full_path,signed,signer,sig_status,sig_type "
                    f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                    lows,
                ).fetchall()
            for r in rows or []:
                fp = str(r["full_path"] or "").strip()
                if not fp:
                    continue
                keys = r.keys()
                out[fp.replace("/", "\\").lower()] = {
                    "full_path": fp,
                    "signed": bool(r["signed"]),
                    "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (r["company"] if "company" in keys else "") or "",
                }
    except Exception:
        return out
    finally:
        conn.close()
    return out


def query_files(
    rid: str,
    *,
    exts: Optional[List[str]] = None,
    path_contains: Optional[str] = None,
    name_contains: Optional[str] = None,
    name_like: Optional[str] = None,
    min_size: int = 0,
    limit: int = 80,
) -> List[Dict[str, Any]]:
    """按扩展名/路径/文件名从 files 表取候选，避免全表 Python 循环。"""
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    where = ["1=1"]
    args: List[Any] = []
    if exts:
        norms = [_norm_ext(x) for x in exts if str(x).strip()]
        norms = [x for x in norms if x]
        if norms:
            ph = ",".join("?" * len(norms))
            where.append(f"ext IN ({ph})")
            args.extend(norms)
    if path_contains:
        # 用路径片段 LIKE，兼容单/双反斜杠与正斜杠。
        # 目录意图（原文以 \ / 结尾）时强制后接分隔符，避免 drivers ⊂ driverstore。
        raw_pc = str(path_contains).strip()
        parts = [p for p in re.split(r"[/\\]+", raw_pc) if p]
        if parts:
            core = "/".join(p.lower() for p in parts)
            if raw_pc.endswith(("/", "\\")):
                like = "%" + core + "/%"
            else:
                like = "%" + core + "%"
            where.append("lower(replace(full_path,'\\','/')) LIKE ?")
            args.append(like)
        else:
            where.append("instr(lower(replace(full_path,'/','\\')), ?) > 0")
            args.append(str(path_contains).lower().replace("/", "\\"))
    if name_contains:
        where.append("instr(lower(name), ?) > 0")
        args.append(str(name_contains).lower())
    if name_like:
        where.append("lower(name) LIKE ?")
        args.append(str(name_like).lower())
    if min_size and int(min_size) > 0:
        where.append("size >= ?")
        args.append(int(min_size))
    sql = (
        "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
        "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,content "
        f"FROM files WHERE {' AND '.join(where)} LIMIT ?"
    )
    args.append(max(1, min(int(limit or 80), 5000)))
    conn = _connect(Path(dbp))
    try:
        try:
            rows = conn.execute(sql, args).fetchall()
        except sqlite3.OperationalError:
            # 旧库尚无 content 列
            sql_legacy = (
                "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system "
                f"FROM files WHERE {' AND '.join(where)} LIMIT ?"
            )
            rows = conn.execute(sql_legacy, args).fetchall()
        out = []
        for r in rows:
            keys = r.keys()
            item = {
                "full_path": r["full_path"] or "",
                "name": r["name"] or "",
                "path": r["path"] or "",
                "ext": r["ext"] or "",
                "size": r["size"] or 0,
                "company": r["company"] if "company" in keys else "",
                "product": r["product"] if "product" in keys else "",
                "description": r["description"] if "description" in keys else "",
                "file_version": r["file_version"] if "file_version" in keys else "",
                "signed": bool(r["signed"]),
                "signer": r["signer"] or "",
                "sig_status": r["sig_status"] or "",
                "sig_type": r["sig_type"] if "sig_type" in keys else "",
                "magic_hex": r["magic_hex"] or "",
                "md5": r["md5"] if "md5" in keys else "",
                "sha1": r["sha1"] if "sha1" in keys else "",
                "sha256": r["sha256"] if "sha256" in keys else "",
                "hidden": bool(r["hidden"]),
                "system": bool(r["system"]),
            }
            if "content" in keys and r["content"]:
                item["content"] = r["content"]
            out.append(item)
        return out
    except Exception:
        return []
    finally:
        conn.close()


def query_files_under_dir(
    rid: str, dir_path: str, limit: int = 300, offset: int = 0,
) -> Dict[str, Any]:
    """列出目录下的直接子文件（path 列 = 父目录），供可疑目录详情弹窗。"""
    d = (dir_path or "").replace("/", "\\")
    d = re.sub(r"\\+", r"\\", d).rstrip("\\")
    if not d:
        return {"items": [], "total": 0, "path": ""}
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return {"items": [], "total": 0, "path": d}
    needle = _norm_file_path(d)
    lim = max(1, min(int(limit or 300), 2000))
    off = max(0, int(offset or 0))
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        cols = (
            "full_path,name,path,ext,size,company,product,description,file_version,"
            "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system"
        )
        total = int(
            conn.execute(
                "SELECT COUNT(1) FROM files WHERE parent_path_norm=?", (needle,),
            ).fetchone()[0] or 0
        )
        rows = conn.execute(
            f"SELECT {cols} FROM files WHERE parent_path_norm=? "
            "ORDER BY name COLLATE NOCASE, full_path COLLATE NOCASE LIMIT ? OFFSET ?",
            (needle, lim, off),
        ).fetchall()
        items = []
        for r in rows:
            keys = r.keys()
            items.append({
                "full_path": r["full_path"] or "",
                "name": r["name"] or "",
                "path": r["path"] or "",
                "ext": r["ext"] or "",
                "size": r["size"] or 0,
                "company": r["company"] if "company" in keys else "",
                "product": r["product"] if "product" in keys else "",
                "description": r["description"] if "description" in keys else "",
                "file_version": r["file_version"] if "file_version" in keys else "",
                "signed": bool(r["signed"]),
                "signer": r["signer"] or "",
                "sig_status": r["sig_status"] or "",
                "sig_type": r["sig_type"] if "sig_type" in keys else "",
                "magic_hex": r["magic_hex"] or "",
                "md5": r["md5"] if "md5" in keys else "",
                "sha1": r["sha1"] if "sha1" in keys else "",
                "sha256": r["sha256"] if "sha256" in keys else "",
                "hidden": bool(r["hidden"]) if "hidden" in keys else False,
                "system": bool(r["system"]) if "system" in keys else False,
                "dir": False,
            })
        return {
            "items": items, "total": total, "offset": off, "limit": lim, "path": d,
            "has_next": off + len(items) < total, "truncated": off + len(items) < total,
        }
    except Exception as e:
        print(f"[db_store] query_files_under_dir: {e}")
        return {"items": [], "total": 0, "path": d}
    finally:
        conn.close()


def query_dir_subtree_stats(rid: str, dir_paths: Any) -> Dict[str, Dict[str, int]]:
    """按目录返回子树统计：direct_files / subtree_files / subdirs。

    目录聚合规则的 min/maxFileCount 原来只看直接子文件，
    「直接放 3 个文件、子目录里塞几十个」的大软件树会被当成小型白加黑目录命中。
    这里给出整棵子树的文件数与子目录数，供规则判定用。
    返回 key 为 _norm_file_path(dir) 归一化路径。

    子树用区间比较（>= 'dir\\' AND < 'dir\\' + U+FFFF）而不是 LIKE：
    parent_path_norm 已经是小写归一化值，区间谓词能走 idx_files_parent_norm，
    LIKE 因为默认大小写不敏感走不了索引。
    """
    if isinstance(dir_paths, str):
        dir_paths = [dir_paths]
    wanted: List[str] = []
    seen: Set[str] = set()
    for d in dir_paths or []:
        norm = _norm_file_path(d)
        if norm and norm not in seen:
            seen.add(norm)
            wanted.append(norm)
    if not wanted:
        return {}
    out: Dict[str, Dict[str, int]] = {
        d: {"direct_files": 0, "subtree_files": 0, "subdirs": 0} for d in wanted
    }
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return out
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        for norm in wanted:
            lo = norm + "\\"
            hi = norm + "\\￿"
            direct = int(
                conn.execute(
                    "SELECT COUNT(1) FROM files WHERE parent_path_norm=?", (norm,),
                ).fetchone()[0] or 0
            )
            deep = int(
                conn.execute(
                    "SELECT COUNT(1) FROM files WHERE parent_path_norm>=? AND parent_path_norm<?",
                    (lo, hi),
                ).fetchone()[0] or 0
            )
            subdirs = int(
                conn.execute(
                    "SELECT COUNT(1) FROM file_directories "
                    "WHERE parent_path_norm=? OR (parent_path_norm>=? AND parent_path_norm<?)",
                    (norm, lo, hi),
                ).fetchone()[0] or 0
            )
            out[norm] = {
                "direct_files": direct,
                "subtree_files": direct + deep,
                "subdirs": subdirs,
            }
        return out
    except Exception as e:
        print(f"[db_store] query_dir_subtree_stats: {e}")
        return out
    finally:
        conn.close()


def query_file_directory(
    rid: str,
    dir_path: str = "",
    *,
    offset: int = 0,
    limit: int = 300,
    q: str = "",
    hidden_only: bool = False,
) -> Dict[str, Any]:
    """Return one directory level: child directories first, then direct files."""
    display_path = re.sub(
        r"\\+", r"\\", str(dir_path or "").replace("/", "\\").strip(),
    ).rstrip("\\")
    parent_norm = _norm_file_path(display_path)
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return {
            "items": [], "total": 0, "offset": 0, "limit": limit,
            "has_next": False, "path": display_path,
        }
    off = max(0, int(offset or 0))
    lim = max(1, min(2000, int(limit or 300)))
    ql = str(q or "").strip().lower()
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        _ensure_directory_index(conn)
        dir_where = ["d.parent_path_norm=?"]
        dir_args: List[Any] = [parent_norm]
        file_where = ["f.parent_path_norm=?"]
        file_args: List[Any] = [parent_norm]
        if ql:
            from .search_sql import LIKE_ESCAPE, classify, glob_to_like, has_glob_meta
            if has_glob_meta(ql):
                like = glob_to_like(ql).lower()
                esc = LIKE_ESCAPE
                dir_where.append(
                    f"(lower(d.name) LIKE ? ESCAPE '{esc}' OR lower(d.full_path) LIKE ? ESCAPE '{esc}')"
                )
                dir_args.extend([like, like])
                file_where.append(
                    f"(lower(f.name) LIKE ? ESCAPE '{esc}' OR lower(f.full_path) LIKE ? ESCAPE '{esc}')"
                )
                file_args.extend([like, like])
            else:
                dir_where.append("(lower(d.name) LIKE ? OR lower(d.full_path) LIKE ?)")
                dir_args.extend([f"%{ql}%", f"%{ql}%"])
                file_where.append(
                    "(lower(f.name) LIKE ? OR lower(f.full_path) LIKE ? "
                    "OR lower(IFNULL(f.company,'')) LIKE ? OR lower(IFNULL(f.signer,'')) LIKE ? "
                    "OR lower(IFNULL(f.ext,'')) LIKE ? OR lower(REPLACE(IFNULL(f.ext,''), '.', '')) LIKE ?)"
                )
                file_args.extend([f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql}%", f"%{ql.lstrip('.')}%"])
        if hidden_only:
            file_where.append("(f.hidden=1 OR f.system=1)")
            dir_where.append(
                "EXISTS (SELECT 1 FROM files hf WHERE (hf.hidden=1 OR hf.system=1) AND "
                "(hf.parent_path_norm=d.path_norm OR "
                "substr(hf.parent_path_norm,1,length(d.path_norm)+1)=d.path_norm||'\\'))"
            )
        dir_sql_where = " AND ".join(dir_where)
        file_sql_where = " AND ".join(file_where)
        dir_total = int(
            conn.execute(
                f"SELECT COUNT(1) FROM file_directories d WHERE {dir_sql_where}", dir_args,
            ).fetchone()[0] or 0
        )
        file_total = int(
            conn.execute(
                f"SELECT COUNT(1) FROM files f WHERE {file_sql_where}", file_args,
            ).fetchone()[0] or 0
        )
        items: List[Dict[str, Any]] = []
        if off < dir_total:
            directory_rows = conn.execute(
                "SELECT d.path_norm,d.parent_path_norm,d.name,d.full_path,"
                "EXISTS(SELECT 1 FROM file_directories c WHERE c.parent_path_norm=d.path_norm) "
                "OR EXISTS(SELECT 1 FROM files f WHERE f.parent_path_norm=d.path_norm) AS has_children "
                f"FROM file_directories d WHERE {dir_sql_where} "
                "ORDER BY d.name COLLATE NOCASE LIMIT ? OFFSET ?",
                dir_args + [lim, off],
            ).fetchall()
            items.extend({
                "name": r["name"] or "",
                "full_path": r["full_path"] or "",
                "path": str(r["full_path"] or "").replace("\\", "/"),
                "dir": True,
                "has_children": bool(r["has_children"]),
                "children": [],
            } for r in directory_rows)
        remaining = lim - len(items)
        file_offset = max(0, off - dir_total)
        if remaining > 0 and file_offset < file_total:
            rows = conn.execute(
                f"SELECT {_FILE_TREE_COLS},(IFNULL(f.content,'')!='') AS has_content "
                f"FROM files f WHERE {file_sql_where} "
                "ORDER BY f.name COLLATE NOCASE,f.full_path COLLATE NOCASE LIMIT ? OFFSET ?",
                file_args + [remaining, file_offset],
            ).fetchall()
            for row in rows:
                item = _file_row_to_tree_item(row)
                item["name_path"] = item.get("path") or ""
                item["path"] = str(item.get("full_path") or "").replace("\\", "/")
                item["file"] = True
                item["dir"] = False
                items.append(item)
        total = dir_total + file_total
        return {
            "items": items,
            "total": total,
            "offset": off,
            "limit": lim,
            "has_next": off + len(items) < total,
            "path": display_path,
            "directory_total": dir_total,
            "file_total": file_total,
        }
    finally:
        conn.close()


def files_rid(report: Dict[str, Any]) -> str:
    return str(report.get("_files_rid") or report.get("_rid") or "").strip()


def _init_schema_uncached(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS findings_agg (
            id TEXT PRIMARY KEY,
            category TEXT,
            severity TEXT,
            title TEXT,
            count INTEGER,
            evidence TEXT,
            sources TEXT,
            rule_id TEXT,
            matcher TEXT,
            extra TEXT
        );
        CREATE TABLE IF NOT EXISTS blobs (name TEXT PRIMARY KEY, data TEXT);
            CREATE TABLE IF NOT EXISTS files (
            full_path TEXT PRIMARY KEY,
            name TEXT,
            path TEXT,
            parent_path_norm TEXT,
            ext TEXT,
            size INTEGER,
            company TEXT,
            product TEXT,
            description TEXT,
            file_version TEXT,
            signed INTEGER DEFAULT 0,
            signer TEXT,
            sig_status TEXT,
            sig_type TEXT,
            magic_hex TEXT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            hidden INTEGER DEFAULT 0,
            system INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
        CREATE INDEX IF NOT EXISTS idx_files_name ON files(name);
        CREATE INDEX IF NOT EXISTS idx_files_ext ON files(ext);
        CREATE TABLE IF NOT EXISTS file_directories (
            path_norm TEXT PRIMARY KEY,
            parent_path_norm TEXT,
            name TEXT,
            full_path TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_file_dirs_parent ON file_directories(parent_path_norm);
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel TEXT,
            event_id INTEGER,
            provider TEXT,
            time TEXT,
            level TEXT,
            computer TEXT,
            message TEXT,
            fields TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_elog_channel ON event_logs(channel);
        CREATE INDEX IF NOT EXISTS idx_elog_eid ON event_logs(event_id);
        CREATE INDEX IF NOT EXISTS idx_elog_time ON event_logs(time);
        CREATE TABLE IF NOT EXISTS entity_lists (
            section TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            count INTEGER DEFAULT 0
        );
        """
    )
    for col, typ in (
        ("parent_path_norm", "TEXT"),
        ("company", "TEXT"),
        ("product", "TEXT"),
        ("description", "TEXT"),
        ("file_version", "TEXT"),
        ("signed", "INTEGER DEFAULT 0"),
        ("signer", "TEXT"),
        ("sig_status", "TEXT"),
        ("sig_type", "TEXT"),
        ("magic_hex", "TEXT"),
        ("md5", "TEXT"),
        ("sha1", "TEXT"),
        ("sha256", "TEXT"),
        ("hidden", "INTEGER DEFAULT 0"),
        ("system", "INTEGER DEFAULT 0"),
        ("mtime", "TEXT"),
        ("mode", "TEXT"),
        ("owner", "TEXT"),
        ("file_group", "TEXT"),
        ("content", "TEXT"),
    ):
        try:
            conn.execute(f"ALTER TABLE files ADD COLUMN {col} {typ}")
        except sqlite3.OperationalError:
            pass
    for idx_sql in (
        "CREATE INDEX IF NOT EXISTS idx_files_parent_norm ON files(parent_path_norm)",
        "CREATE INDEX IF NOT EXISTS idx_files_md5 ON files(md5)",
        "CREATE INDEX IF NOT EXISTS idx_files_sha1 ON files(sha1)",
        "CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)",
        "CREATE INDEX IF NOT EXISTS idx_files_mtime ON files(mtime)",
        # 路径归一化索引只在进程签名回查时按需建，勿塞进每次读库的 _init_schema：
        # 百万行 files 表上 CREATE INDEX 会把告警/总览首屏拖到十几秒。
    ):
        try:
            conn.execute(idx_sql)
        except sqlite3.OperationalError:
            pass


_SCHEMA_READY: Set[str] = set()
_SCHEMA_READY_LOCK = threading.RLock()


def _schema_conn_key(conn: sqlite3.Connection) -> str:
    try:
        rows = conn.execute("PRAGMA database_list").fetchall()
        for row in rows:
            name = str(row[1] if not hasattr(row, "keys") else row["name"])
            if name == "main":
                path = str(row[2] if not hasattr(row, "keys") else row["file"])
                return str(Path(path).resolve()).lower()
    except Exception:
        pass
    return f"conn:{id(conn)}"


def _schema_cache_valid(conn: sqlite3.Connection) -> bool:
    """缓存命中后再确认核心表真实存在（一次 sqlite_master 查询，走内存页，可忽略不计）。"""
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta' LIMIT 1"
        ).fetchone()
        return row is not None
    except Exception:
        return False


def _init_schema(conn: sqlite3.Connection) -> None:
    """每个数据库/进程只执行一次 DDL 迁移，普通 GET 不重复跑整套 schema/index 检查。

    缓存 key 是库文件路径，而重新分析会删库重建：路径不变、表却没了，
    旧逻辑会跳过建表并让后续查询报 "no such table: meta"（summary 接口 500 的根因）。
    因此命中缓存时再校验一次，发现失效就重建 schema。
    """
    key = _schema_conn_key(conn)
    with _SCHEMA_READY_LOCK:
        if key in _SCHEMA_READY and _schema_cache_valid(conn):
            return
        _init_schema_uncached(conn)
        _SCHEMA_READY.add(key)


def _init_index(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            file TEXT PRIMARY KEY,
            db_path TEXT,
            hostname TEXT,
            collect_time TEXT,
            ip TEXT,
            issues INTEGER DEFAULT 0,
            raw_issues INTEGER DEFAULT 0,
            analyzed INTEGER DEFAULT 0,
            processes INTEGER DEFAULT 0,
            services INTEGER DEFAULT 0,
            files INTEGER DEFAULT 0,
            updated_at REAL,
            owner_id TEXT DEFAULT '',
            owner_username TEXT DEFAULT ''
        )
        """
    )
    # 旧库补列（必须先于依赖新列的 INDEX）
    cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
    if "owner_id" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN owner_id TEXT DEFAULT ''")
    if "owner_username" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN owner_username TEXT DEFAULT ''")
    if "os_family" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN os_family TEXT DEFAULT ''")
    if "os" not in cols:
        conn.execute("ALTER TABLE reports ADD COLUMN os TEXT DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_host ON reports(hostname)")
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_owner ON reports(owner_id)")
    except sqlite3.OperationalError:
        pass
    conn.commit()


def _jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _jload(s: Optional[str], default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def upsert_index(row: Dict[str, Any]) -> None:
    from .ownership import resolve_owner_fields
    owner = resolve_owner_fields(row)
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        conn.execute(
            """
            INSERT INTO reports(file, db_path, hostname, collect_time, ip, issues, raw_issues,
                                analyzed, processes, services, files, updated_at,
                                owner_id, owner_username, os_family, os)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(file) DO UPDATE SET
              db_path=excluded.db_path, hostname=excluded.hostname, collect_time=excluded.collect_time,
              ip=excluded.ip, issues=excluded.issues, raw_issues=excluded.raw_issues,
              analyzed=excluded.analyzed, processes=excluded.processes, services=excluded.services,
              files=excluded.files, updated_at=excluded.updated_at,
              owner_id=CASE WHEN excluded.owner_id!='' THEN excluded.owner_id ELSE reports.owner_id END,
              owner_username=CASE WHEN excluded.owner_username!='' THEN excluded.owner_username ELSE reports.owner_username END,
              os_family=CASE WHEN excluded.os_family!='' THEN excluded.os_family ELSE reports.os_family END,
              os=CASE WHEN excluded.os!='' THEN excluded.os ELSE reports.os END
            """,
            (
                row["file"], row.get("db_path"), row.get("hostname"), row.get("collect_time"),
                row.get("ip"), row.get("issues", 0), row.get("raw_issues", 0),
                1 if row.get("analyzed") else 0, row.get("processes", 0), row.get("services", 0),
                row.get("files", 0), time.time(),
                owner.get("owner_id") or "", owner.get("owner_username") or "",
                str(row.get("os_family") or "").strip().lower(),
                str(row.get("os") or "").strip()[:200],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    invalidate_list_cache()
    # 同步主机台账（失败不影响索引）
    hn = (row.get("hostname") or "").strip()
    if hn and hn != "unknown":
        try:
            from .hosts import ensure_host
            ensure_host(hn, row.get("ip") or "")
        except Exception as e:
            print("[index] ensure_host:", e)
    # 双写 MySQL reports
    try:
        from .mysql_store import upsert_report_row
        payload = dict(row)
        payload["owner_id"] = owner.get("owner_id") or row.get("owner_id") or ""
        payload["owner_username"] = owner.get("owner_username") or row.get("owner_username") or ""
        upsert_report_row(payload)
    except Exception as e:
        print("[index] mysql upsert_report_row:", e)


def clear_index() -> None:
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        conn.execute("DELETE FROM reports")
        conn.commit()
    finally:
        conn.close()
    invalidate_list_cache()


def delete_index_entry(report_file: str, mysql: bool = True) -> None:
    rid = P.report_id(report_file)
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        conn.execute("DELETE FROM reports WHERE file=?", (rid,))
        conn.commit()
    finally:
        conn.close()
    if not mysql:
        return
    try:
        from .mysql_store import delete_report_row
        delete_report_row(rid)
    except Exception as e:
        print("[index] mysql delete_report_row:", e)

def rename_hostname(old_name: str, new_name: str) -> Dict[str, Any]:
    """将某主机下全部报告的显示主机名改为新名称（索引 + analysis.db meta + report.json）。"""
    old_name = (old_name or "").strip()
    new_name = (new_name or "").strip()
    if not old_name or not new_name:
        raise ValueError("主机名不能为空")
    if old_name == new_name:
        return {"updated": 0, "old": old_name, "new": new_name}
    if any(c in new_name for c in '<>:"/\\|?*'):
        raise ValueError("主机名含非法字符")
    if len(new_name) > 128:
        raise ValueError("主机名过长")

    updated_files: List[str] = []
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        rows = conn.execute(
            "SELECT file FROM reports WHERE hostname=?", (old_name,)
        ).fetchall()
        files = [r["file"] for r in rows]
        if not files:
            raise ValueError(f"未找到主机: {old_name}")
        conn.execute(
            "UPDATE reports SET hostname=? WHERE hostname=?",
            (new_name, old_name),
        )
        conn.commit()
    finally:
        conn.close()

    for rid in files:
        # analysis.db meta
        dbp = P.resolve_analysis_db(rid)
        if dbp and dbp.exists():
            try:
                c = _connect(dbp)
                try:
                    _init_schema(c)
                    c.execute(
                        "INSERT INTO meta(key,value) VALUES('hostname',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (new_name,),
                    )
                    c.commit()
                finally:
                    c.close()
            except Exception as e:
                print(f"[rename_hostname] db {rid}:", e)
        # report.json
        jp = P.resolve_report_json(rid)
        if jp and jp.exists():
            try:
                with open(jp, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    data["hostname"] = new_name
                    with open(jp, "w", encoding="utf-8") as fh:
                        json.dump(data, fh, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"[rename_hostname] json {rid}:", e)
        # result.json 里若嵌了 hostname 也改
        rp = P.resolve_result_json(rid)
        if rp and rp.exists():
            try:
                with open(rp, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    if "hostname" in data:
                        data["hostname"] = new_name
                    if isinstance(data.get("report"), dict):
                        data["report"]["hostname"] = new_name
                    with open(rp, "w", encoding="utf-8") as fh:
                        json.dump(data, fh, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"[rename_hostname] result {rid}:", e)
        updated_files.append(rid)

    # 同步主机台账名称
    try:
        from .hosts import get_host_by_name, _hconnect
        h = get_host_by_name(old_name)
        if h:
            conn_h = _hconnect()
            try:
                conn_h.execute(
                    "UPDATE hosts SET name=?, updated_at=? WHERE id=?",
                    (new_name, time.time(), h["id"]),
                )
                conn_h.commit()
            finally:
                conn_h.close()
        else:
            from .hosts import ensure_host
            ensure_host(new_name)
    except Exception as e:
        print("[rename_hostname] hosts:", e)

    try:
        from .mysql_store import rename_reports_hostname
        rename_reports_hostname(old_name, new_name)
    except Exception as e:
        print("[rename_hostname] mysql reports:", e)

    return {"updated": len(updated_files), "old": old_name, "new": new_name, "files": updated_files}


_DISK_CACHE: Dict[str, float] = {}
_DISK_CACHE_TTL = 120.0
_DISK_MISS_TTL = 20.0
_DISK_CACHE_LOCK = threading.Lock()
_DISK_MISS: Dict[str, float] = {}


def _report_on_disk(rid: str) -> bool:
    now = time.time()
    with _DISK_CACHE_LOCK:
        ts = _DISK_CACHE.get(rid)
        if ts is not None and now - ts < _DISK_CACHE_TTL:
            return True
        miss_ts = _DISK_MISS.get(rid)
        if miss_ts is not None and now - miss_ts < _DISK_MISS_TTL:
            return False
    result = bool(
        P.resolve_report_json(rid)
        or P.resolve_analysis_db(rid)
        or P.resolve_result_json(rid)
    )
    with _DISK_CACHE_LOCK:
        if result:
            _DISK_CACHE[rid] = now
            _DISK_MISS.pop(rid, None)
        else:
            _DISK_MISS[rid] = now
            _DISK_CACHE.pop(rid, None)
            if len(_DISK_MISS) > 4000:
                oldest = sorted(_DISK_MISS.items(), key=lambda x: x[1])[:1000]
                for k, _ in oldest:
                    _DISK_MISS.pop(k, None)
    return result


def _invalidate_disk_cache(rid: str) -> None:
    with _DISK_CACHE_LOCK:
        _DISK_CACHE.pop(rid, None)
        _DISK_MISS.pop(rid, None)


def prune_stale_index() -> int:
    """删掉磁盘上已不存在的索引项（SQLite + MySQL），避免幽灵主机/报告。"""
    removed = 0
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            rows = conn.execute("SELECT file FROM reports").fetchall()
            for r in rows:
                rid = r["file"]
                if _report_on_disk(rid):
                    continue
                conn.execute("DELETE FROM reports WHERE file=?", (rid,))
                removed += 1
                folder = P.report_dir(rid)
                if folder.exists() and folder.is_dir():
                    try:
                        if not any(folder.iterdir()):
                            folder.rmdir()
                    except OSError:
                        pass
            conn.commit()
        finally:
            conn.close()
    # MySQL 影子索引也要清，否则 list_hosts → sync_hosts_from_index 会把已删主机建回来
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import list_reports_mysql, delete_report_files
        if mysql_ready():
            rows = list_reports_mysql(limit=5000) or []
            stale = []
            for r in rows:
                rid = (r.get("file") or "").strip()
                if not rid or _report_on_disk(rid):
                    continue
                stale.append(rid)
            if stale:
                delete_report_files(stale)
                removed += len(stale)
    except Exception as e:
        print(f"[index] prune mysql: {e}")
    if removed:
        try:
            invalidate_list_cache()
        except Exception:
            pass
    return removed


_LAST_PRUNE_TS = 0.0
_PRUNE_INTERVAL_SEC = 60.0


def invalidate_list_cache() -> None:
    invalidate_findings_cache()
    with _OWNER_CACHE_LOCK:
        _OWNER_CACHE.clear()
    with _ELOG_HIT_LOCK:
        _ELOG_HIT_CACHE.clear()
    try:
        from .hosts import _invalidate_host_cache
        _invalidate_host_cache()
    except Exception:
        pass
    try:
        from .hot_cache import bump
        bump()
    except Exception:
        pass


def _row_from_sqlite(r) -> Dict[str, Any]:
    keys = set(r.keys()) if hasattr(r, "keys") else set()
    return {
        "file": r["file"],
        "db": r["db_path"],
        "hostname": r["hostname"],
        "time": r["collect_time"],
        "ip": r["ip"] or "",
        "issues": r["issues"] or 0,
        "raw_issues": r["raw_issues"] or 0,
        "analyzed": bool(r["analyzed"]),
        "processes": r["processes"] or 0,
        "services": r["services"] or 0,
        "files": r["files"] or 0,
        "owner_id": (r["owner_id"] if "owner_id" in keys else "") or "",
        "owner_username": (r["owner_username"] if "owner_username" in keys else "") or "",
        "os_family": (r["os_family"] if "os_family" in keys else "") or "",
        "os": (r["os"] if "os" in keys else "") or "",
    }


def list_index(limit: int = 100, user: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """列出报告。传入 user 时按归属过滤（admin 看全部）。"""
    global _LAST_PRUNE_TS
    from .ownership import is_admin

    now = time.time()
    admin = is_admin(user) if user else True  # 无 user 时保持兼容（内部调用）
    uid = str((user or {}).get("id") or "") if user and not admin else ""
    uname = str((user or {}).get("username") or "") if user and not admin else ""
    # 报告列表含告警数，短缓存/Redis 会在分析刚完成后仍返回 0；主机量不大，直接读库。
    out: List[Dict[str, Any]] = []
    # 优先 MySQL；空列表不视为权威（避免挡住本地 index.db）
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import list_reports_mysql
        if mysql_ready():
            rows = list_reports_mysql(limit=max(limit, 200) if not admin else limit, user=user)
            if rows:
                # 热路径：信任索引，后台 prune 清幽灵；仅抽检前若干条，避免每行打磁盘
                if now - _LAST_PRUNE_TS >= _PRUNE_INTERVAL_SEC:
                    _LAST_PRUNE_TS = now

                    def _bg_prune_mysql():
                        try:
                            prune_stale_index()
                        except Exception as e:
                            print("[index] prune:", e)

                    threading.Thread(target=_bg_prune_mysql, daemon=True).start()
                sample_n = min(24, len(rows))
                alive = []
                stale = []
                for i, r in enumerate(rows):
                    rid = (r.get("file") or "").strip()
                    if not rid:
                        continue
                    # 前 sample_n 条做存在性校验；其余直接放行（已有短缓存 + 定时 prune）
                    if i < sample_n:
                        if _report_on_disk(rid):
                            alive.append(r)
                        else:
                            stale.append(rid)
                    else:
                        alive.append(r)
                if stale:
                    try:
                        from .mysql_store import delete_report_files
                        delete_report_files(stale)
                    except Exception as e:
                        print("[index] drop stale mysql rows:", e)
                if alive:
                    return alive[:limit]
                # 全是幽灵 → 继续读 SQLite
            # rows is None（失败）或 []（空）→ 继续读 SQLite
    except Exception as e:
        print("[index] mysql list:", e)
        try:
            from .mysql_db import mark_mysql_down
            mark_mysql_down(str(e))
        except Exception:
            pass

    if not INDEX_DB.exists():
        return []
    if now - _LAST_PRUNE_TS >= _PRUNE_INTERVAL_SEC:
        _LAST_PRUNE_TS = now
        def _bg_prune():
            try:
                prune_stale_index()
            except Exception as e:
                print("[index] prune:", e)
        threading.Thread(target=_bg_prune, daemon=True).start()
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        if admin or not user:
            rows = conn.execute(
                "SELECT * FROM reports ORDER BY collect_time DESC, file DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM reports
                WHERE (owner_id!='' AND owner_id=?)
                   OR (owner_username!='' AND owner_username=?)
                ORDER BY collect_time DESC, file DESC LIMIT ?
                """,
                (uid, uname, limit),
            ).fetchall()
        for r in rows:
            out.append(_row_from_sqlite(r))
        return out
    finally:
        conn.close()


def get_index_meta(report_file: str) -> Optional[Dict[str, Any]]:
    """按逻辑 ID 取索引一行：hostname / owner，不读大 JSON。找不到返回 None。"""
    rid = P.report_id(report_file)
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import get_report_meta_mysql
        if mysql_ready():
            m = get_report_meta_mysql(rid)
            if m:
                return m
    except Exception:
        pass
    if not INDEX_DB.exists():
        return None
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        row = conn.execute(
            "SELECT file, hostname, owner_id, owner_username FROM reports WHERE file=?",
            (rid,),
        ).fetchone()
        if not row:
            return None
        keys = set(row.keys()) if hasattr(row, "keys") else set()
        return {
            "file": row["file"] or rid,
            "hostname": row["hostname"] or "",
            "owner_id": (row["owner_id"] or "") if "owner_id" in keys else "",
            "owner_username": (row["owner_username"] or "") if "owner_username" in keys else "",
        }
    finally:
        conn.close()


_OWNER_CACHE: Dict[str, tuple] = {}
_OWNER_CACHE_LOCK = threading.Lock()
_OWNER_CACHE_TTL = ttl("report_owner", 20.0, minimum=2.0, maximum=120.0)
_OWNER_CACHE_MAX = capacity("report_owner", 2000)


def _owner_cache_put(rid: str, value: Dict[str, str], now: Optional[float] = None) -> None:
    with _OWNER_CACHE_LOCK:
        _OWNER_CACHE[rid] = (float(now or time.time()), dict(value))
        if len(_OWNER_CACHE) > _OWNER_CACHE_MAX:
            trim = max(1, _OWNER_CACHE_MAX // 4)
            for key, _ in sorted(_OWNER_CACHE.items(), key=lambda x: x[1][0])[:trim]:
                _OWNER_CACHE.pop(key, None)


def get_report_owner(report_file: str) -> Dict[str, str]:
    """返回报告归属 {owner_id, owner_username}。"""
    rid = P.report_id(report_file)
    now = time.time()
    with _OWNER_CACHE_LOCK:
        hit = _OWNER_CACHE.get(rid)
        if hit and now - float(hit[0]) < _OWNER_CACHE_TTL:
            return dict(hit[1])
    # MySQL 优先
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import get_report_owner_mysql
        if mysql_ready():
            m = get_report_owner_mysql(rid)
            if m is not None:
                _owner_cache_put(rid, m, now)
                return m
    except Exception:
        pass
    if not INDEX_DB.exists():
        empty = {"owner_id": "", "owner_username": ""}
        _owner_cache_put(rid, empty, now)
        return empty
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        row = conn.execute(
            "SELECT owner_id, owner_username FROM reports WHERE file=?", (rid,)
        ).fetchone()
        if not row:
            out = {"owner_id": "", "owner_username": ""}
        else:
            out = {
                "owner_id": (row["owner_id"] or "") if "owner_id" in row.keys() else "",
                "owner_username": (row["owner_username"] or "") if "owner_username" in row.keys() else "",
            }
        _owner_cache_put(rid, out, now)
        return out
    finally:
        conn.close()


def _finding_search_blob(item: Dict[str, Any], hostname: str = "", rid: str = "") -> str:
    ev = item.get("evidence")
    if isinstance(ev, list):
        ev_s = " ".join(str(x) for x in ev)
    else:
        ev_s = str(ev or "")
    extra = item.get("extra")
    if isinstance(extra, dict):
        extra_s = json.dumps(extra, ensure_ascii=False)
    else:
        extra_s = str(extra or "")
    return " ".join([
        str(item.get("title") or ""),
        str(item.get("name") or ""),
        str(item.get("category") or ""),
        str(item.get("type") or ""),
        str(item.get("rule_id") or ""),
        str(item.get("matcher") or ""),
        str(item.get("reason") or ""),
        str(item.get("severity") or ""),
        ev_s,
        extra_s,
        hostname or "",
        rid or "",
    ]).lower()


def _load_findings_for_search(rid: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    dbp = P.resolve_analysis_db(rid)
    if dbp and dbp.exists():
        conn = _connect(dbp)
        try:
            _init_schema(conn)
            for r in conn.execute("SELECT * FROM findings_agg"):
                extra = _jload(r["extra"] if "extra" in r.keys() else "", {}) or {}
                item = {
                    "id": r["id"],
                    "category": r["category"] or "",
                    "severity": r["severity"] or "medium",
                    "title": r["title"] or "",
                    "count": r["count"] or 1,
                    "evidence": _jload(r["evidence"], []),
                    "sources": _jload(r["sources"], []),
                    "rule_id": r["rule_id"] or "",
                    "matcher": r["matcher"] or "",
                }
                if isinstance(extra, dict):
                    item.update(extra)
                items.append(item)
        except Exception as e:
            print(f"[db_store] load findings {rid}: {e}")
        finally:
            conn.close()
    rp = P.resolve_result_json(rid)
    if rp and rp.exists():
        try:
            with open(rp, encoding="utf-8") as f:
                data = json.load(f)
            analysis = data.get("analysis") if isinstance(data, dict) else None
            if not isinstance(analysis, dict):
                analysis = data if isinstance(data, dict) else {}
            raw = analysis.get("findings_aggregated") or analysis.get("findings") or []
            extra = [x for x in raw if isinstance(x, dict)]
            if len(extra) > len(items):
                return extra
        except Exception as e:
            print(f"[db_store] result.json findings {rid}: {e}")
    return items


#: 行数低于此值不建 trigram 索引：全表扫本来就够快，不值得多占磁盘
SEARCH_INDEX_MIN_ROWS = 200_000
#: event_logs 到这个量级才值得建 FTS5（7 万行时 LIKE 只要 37ms）
FTS_MIN_ROWS = 150_000
#: 单次跨报告检索的墙钟预算，超时就返回已拿到的结果并标记还有更多
CONTENT_SEARCH_BUDGET_S = 3.5
#: 并发打开报告库的线程数
CONTENT_SEARCH_WORKERS = 8


#: 已经备好检索索引的库，进程内只做一次（键为 db 路径）
_SEARCH_PREPPED: Set[str] = set()
#: (db 路径, FTS 表名) -> 是否可用
_FTS_READY: Dict[str, bool] = {}
#: 按 db 路径分片的锁：不同报告库的 FTS 构建可并发，避免全局排队。
_SEARCH_PREP_LOCKS: Dict[str, threading.Lock] = {}
_SEARCH_PREP_LOCKS_LOCK = threading.Lock()


def _invalidate_db_caches(key: str) -> None:
    """库被删库重建后，清掉所有以该库路径为 key 的缓存。

    这些缓存记的是「表已建好/索引可用」，库重建后路径不变但表全没了，
    不清就会拿着失效缓存去查不存在的表。
    """
    _SEARCH_PREPPED.discard(key)
    for ck in [c for c in _FTS_READY if c.split("::", 1)[0] == key]:
        _FTS_READY.pop(ck, None)
    with _SCHEMA_READY_LOCK:
        _SCHEMA_READY.discard(key)

#: 上一版按「前缀匹配」设计时建的索引。前缀匹配会漏结果，方案已废弃；
#: 这些索引在当前查询形态下用不到，留着白占几百 MB，遇到就顺手删掉。
_STALE_INDEXES = (
    "idx_files_name_nc", "idx_files_path_nc", "idx_files_fp_nc",
    "idx_mft_name_nc", "idx_mft_fp_nc", "idx_elog_chan_nc",
)


def _table_rows(conn: sqlite3.Connection, table: str) -> int:
    try:
        return int(conn.execute(f"SELECT COUNT(1) AS c FROM {table}").fetchone()["c"] or 0)
    except Exception:
        return 0


def _has_object(conn: sqlite3.Connection, name: str) -> bool:
    try:
        return bool(conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name=? LIMIT 1", (name,)
        ).fetchone())
    except Exception:
        return False


def prepare_search_db(conn: sqlite3.Connection, key: str) -> None:
    """清掉废弃索引；每个库每进程只做一次。

    缓存 key 是库路径，而重新分析会删库重建（路径不变、表全没）。命中缓存时
    再确认核心表在位，否则连同 FTS 缓存一起失效重做 —— 否则检索会拿着失效缓存
    去查已不存在的表，异常被上层吞掉后表现为「静默搜不到证据」。
    """
    if key in _SEARCH_PREPPED and _schema_cache_valid(conn):
        return
    with _SEARCH_PREP_LOCKS_LOCK:
        lock = _SEARCH_PREP_LOCKS.setdefault(key, threading.Lock())
    with lock:
        if key in _SEARCH_PREPPED and _schema_cache_valid(conn):
            return
        _invalidate_db_caches(key)
        try:
            for name in _STALE_INDEXES:
                if _has_object(conn, name):
                    try:
                        conn.execute(f"DROP INDEX IF EXISTS {name}")
                    except sqlite3.OperationalError:
                        pass
            conn.commit()
        except Exception as e:
            print(f"[db_store] prepare search db: {e}")
        _SEARCH_PREPPED.add(key)


def _ensure_fts(
    conn: sqlite3.Connection,
    key: str,
    *,
    fts_table: str,
    src_table: str,
    column: str,
    rowid: str,
) -> bool:
    """按需建 trigram FTS5 外部内容表；返回是否可用。

    trigram 分词器让 FTS5 表上的 LIKE '%x%' 走倒排，语义与普通 LIKE
    完全一致——这是提速的同时不丢结果的关键。content= 模式只存倒排，
    不复制原文。实测 118 万行 full_path：1006ms -> 4.6ms，结果逐条一致。

    索引只是加速器：建不出来时调用方退回普通 LIKE，结果依旧正确。
    """
    ck = f"{key}::{fts_table}"
    cached = _FTS_READY.get(ck)
    # 缓存说"可用"时确认虚拟表真在：库重建后路径不变而 FTS 表已随之消失，
    # 盲信缓存会让后续 SELECT 打到不存在的表上。
    if cached is True and not _has_object(conn, fts_table):
        cached = None
        _FTS_READY.pop(ck, None)
    if cached is not None:
        return cached
    with _SEARCH_PREP_LOCKS_LOCK:
        lock = _SEARCH_PREP_LOCKS.setdefault(key, threading.Lock())
    with lock:
        cached = _FTS_READY.get(ck)
        if cached is True and not _has_object(conn, fts_table):
            cached = None
            _FTS_READY.pop(ck, None)
        if cached is not None:
            return cached
        ok = False
        try:
            if _has_object(conn, fts_table):
                # 旧版本 FTS 没有同步触发器；首次升级时重建一次，之后由触发器增量维护。
                trigger_name = f"{fts_table}_ai"
                needs_rebuild = not _has_object(conn, trigger_name)
                _ensure_fts_sync_triggers(
                    conn, fts_table=fts_table, src_table=src_table,
                    column=column, rowid=rowid,
                )
                if needs_rebuild:
                    conn.execute(f"INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')")
                    conn.commit()
                ok = True
            elif _table_rows(conn, src_table) >= SEARCH_INDEX_MIN_ROWS:
                t0 = time.perf_counter()
                conn.execute(
                    f"CREATE VIRTUAL TABLE {fts_table} USING fts5("
                    f"{column}, content='{src_table}', content_rowid='{rowid}', "
                    f"tokenize='trigram')"
                )
                conn.execute(
                    f"INSERT INTO {fts_table}(rowid, {column}) "
                    f"SELECT {rowid}, IFNULL({column},'') FROM {src_table}"
                )
                _ensure_fts_sync_triggers(
                    conn, fts_table=fts_table, src_table=src_table,
                    column=column, rowid=rowid,
                )
                conn.commit()
                print(f"[db_store] built {fts_table} in {time.perf_counter()-t0:.1f}s")
                ok = True
        except sqlite3.OperationalError as e:
            print(f"[db_store] {fts_table} unavailable, fallback to LIKE: {e}")
            ok = False
        _FTS_READY[ck] = ok
        return ok


def _ensure_fts_sync_triggers(
    conn: sqlite3.Connection,
    *,
    fts_table: str,
    src_table: str,
    column: str,
    rowid: str,
) -> None:
    """让外部内容 FTS 与源表保持同步，避免入库后命中陈旧索引。"""
    conn.executescript(
        f"""
        CREATE TRIGGER IF NOT EXISTS {fts_table}_ai AFTER INSERT ON {src_table} BEGIN
          INSERT INTO {fts_table}(rowid, {column}) VALUES (new.{rowid}, IFNULL(new.{column}, ''));
        END;
        CREATE TRIGGER IF NOT EXISTS {fts_table}_ad AFTER DELETE ON {src_table} BEGIN
          INSERT INTO {fts_table}({fts_table}, rowid, {column})
          VALUES ('delete', old.{rowid}, IFNULL(old.{column}, ''));
        END;
        CREATE TRIGGER IF NOT EXISTS {fts_table}_au AFTER UPDATE OF {column} ON {src_table} BEGIN
          INSERT INTO {fts_table}({fts_table}, rowid, {column})
          VALUES ('delete', old.{rowid}, IFNULL(old.{column}, ''));
          INSERT INTO {fts_table}(rowid, {column}) VALUES (new.{rowid}, IFNULL(new.{column}, ''));
        END;
        """
    )


def _ensure_files_fts(conn: sqlite3.Connection, key: str) -> bool:
    return _ensure_fts(
        conn, key, fts_table="files_fts", src_table="files",
        column="full_path", rowid="rowid",
    )


def _ensure_eventlog_fts(conn: sqlite3.Connection, key: str) -> bool:
    return _ensure_fts(
        conn, key, fts_table="event_logs_fts", src_table="event_logs",
        column="message", rowid="id",
    )


def _union_rows(conn, queries, limit: int, key_of) -> List[Any]:
    """依次跑多条查询并按 key 去重合并，凑够 limit 就停。

    倒排索引只覆盖单列，其余列得用普通谓词补上，否则会漏结果。
    """
    seen = set()
    out: List[Any] = []
    for sql, params in queries:
        if not sql or len(out) >= limit:
            continue
        try:
            rows = conn.execute(sql, (*params, limit - len(out))).fetchall()
        except sqlite3.OperationalError as e:
            print(f"[db_store] union query: {e}")
            continue
        for r in rows:
            k = key_of(r)
            if k in seen:
                continue
            seen.add(k)
            out.append(r)
            if len(out) >= limit:
                break
    return out


def _search_one_report(
    rid: str,
    hn: str,
    plan,
    limit: int,
) -> List[Dict[str, Any]]:
    """在单个报告库里检索。调用方保证 limit > 0。"""
    from .search_sql import (
        eventlog_where, files_hash_where, files_where, fts_like_pattern,
    )

    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return []
    key = str(dbp)
    out: List[Dict[str, Any]] = []
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        prepare_search_db(conn, key)
        pattern = fts_like_pattern(plan)

        # 路径段 / 通配：不能只用宽 FTS '%Temp%' 召回
        if plan.mode in ("segment", "glob"):
            where, params = files_where(plan)
            queries = [
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {where} LIMIT ?", params),
            ]
        elif pattern and _ensure_files_fts(conn, key):
            hash_where, hash_params = files_hash_where(plan)
            queries = [
                ("SELECT f.full_path,f.name,f.md5,f.sha256,f.signer "
                 "FROM files_fts x JOIN files f ON f.rowid = x.rowid "
                 "WHERE x.full_path LIKE ? LIMIT ?", [pattern]),
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {hash_where} LIMIT ?" if hash_where else "", hash_params),
            ]
        else:
            where, params = files_where(plan)
            queries = [
                ("SELECT full_path,name,md5,sha256,signer FROM files "
                 f"WHERE {where} LIMIT ?", params),
            ]
        for r in _union_rows(conn, queries, limit - len(out), lambda r: r["full_path"]):
            bits = [x for x in (r["signer"], r["md5"], r["sha256"]) if x]
            fp = str(r["full_path"] or r["name"] or "")
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": "info",
                "category": "文件扫描",
                "title": fp,
                "evidence": " · ".join(str(x) for x in bits[:2]) or "file_scans",
                "matcher": "files",
                "module": "file",
                "kind": "file",
                "_source": "content",
                "path": fp,
                "md5": str(r["md5"] or ""),
                "sha256": str(r["sha256"] or ""),
            })
            if len(out) >= limit:
                return out

        _ensure_event_logs_table(conn)
        # 同理：倒排只盖 message，channel / event_id 要单独补
        if plan.mode in ("segment", "glob"):
            where, params = eventlog_where(plan)
            queries = [
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 f"WHERE {where} LIMIT ?", params),
            ]
        elif pattern and _ensure_eventlog_fts(conn, key):
            queries = [
                ("SELECT e.id,e.channel,e.event_id,e.time,e.message "
                 "FROM event_logs_fts x JOIN event_logs e ON e.id = x.rowid "
                 "WHERE x.message LIKE ? LIMIT ?", [pattern]),
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 "WHERE channel LIKE ? OR CAST(event_id AS TEXT) LIKE ? LIMIT ?",
                 [pattern, pattern]),
            ]
        else:
            where, params = eventlog_where(plan)
            queries = [
                ("SELECT id,channel,event_id,time,message FROM event_logs "
                 f"WHERE {where} LIMIT ?", params),
            ]
        for r in _union_rows(conn, queries, limit - len(out), lambda r: r["id"]):
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": "info",
                "category": "系统日志",
                "title": f"{r['channel'] or 'Event'} #{int(r['event_id'] or 0)}",
                "evidence": str(r["message"] or "")[:240] or str(r["time"] or ""),
                "matcher": "eventlog",
                "module": "eventlog",
                "kind": "eventlog",
                "_source": "content",
            })
            if len(out) >= limit:
                break
    except Exception as e:
        print(f"[db_store] search content {rid}: {e}")
    finally:
        conn.close()
    return out


def search_report_content_local(
    q: str,
    hostname: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
    match_mode: str = "smart",
) -> List[Dict[str, Any]]:
    """跨报告检索 文件扫描 / 系统日志（各报告 analysis.db）。

    默认是子串包含，语义与历史实现一致，不会因为提速而少查。
    提速来自 trigram 倒排索引，见 _ensure_fts。
    """
    from .search_sql import classify

    needle = (q or "").strip()
    if not needle:
        return []
    want_hn = (hostname or "").strip()
    limit = max(1, int(size))
    try:
        rows = list_index(min(max(limit * 6, 120), 300), user=user)
    except Exception as e:
        print(f"[db_store] search content list_index: {e}")
        rows = []

    targets = []
    for row in rows:
        hn = str(row.get("hostname") or "")
        if want_hn and hn != want_hn:
            continue
        rid = str(row.get("file") or "")
        if rid:
            targets.append((rid, hn))
    if not targets:
        return []

    return _fanout_search(targets, classify(needle, match_mode), limit)


def _fanout_search(targets, plan, limit: int) -> List[Dict[str, Any]]:
    """并发查多个报告库，凑够 limit 或超出时间预算就停。"""
    from concurrent.futures import ThreadPoolExecutor

    out: List[Dict[str, Any]] = []
    deadline = time.perf_counter() + CONTENT_SEARCH_BUDGET_S
    workers = min(CONTENT_SEARCH_WORKERS, max(1, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_search_one_report, rid, hn, plan, limit): rid
            for rid, hn in targets
        }
        for fut in futures:
            if len(out) >= limit or time.perf_counter() > deadline:
                fut.cancel()
                continue
            try:
                out.extend(fut.result(timeout=max(0.1, deadline - time.perf_counter())))
            except Exception:
                continue
    return out[:limit]


def search_findings_local(
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """在本地 analysis.db / result.json 里搜告警标题、证据、分类（跨主机）。"""
    from backend.search_sql import text_matches_query

    needle = (q or "").strip()
    if not needle:
        return []
    want_hn = (hostname or "").strip()
    want_sev = (severity or "").strip().lower()
    skip = max(0, int(offset))
    need = int(size)
    out: List[Dict[str, Any]] = []
    try:
        rows = list_index(min(max((need + skip) * 4, 80), 2000), user=user)
    except Exception as e:
        print(f"[db_store] search list_index: {e}")
        rows = []
    if not rows:
        return []
    skipped = 0
    for row in rows:
        hn = str(row.get("hostname") or "")
        if want_hn and hn != want_hn:
            continue
        rid = str(row.get("file") or "")
        if not rid:
            continue
        for item in _load_findings_for_search(rid):
            sev = str(item.get("severity") or "medium").lower()
            if want_sev and sev != want_sev:
                continue
            if not text_matches_query(_finding_search_blob(item, hn, rid), needle):
                continue
            if skipped < skip:
                skipped += 1
                continue
            ev = item.get("evidence")
            if isinstance(ev, list):
                ev_s = "；".join(str(x) for x in ev[:4])
            else:
                ev_s = str(ev or "")
            out.append({
                "report_id": rid,
                "file": rid,
                "hostname": hn,
                "severity": item.get("severity") or "medium",
                "category": item.get("category") or "",
                "title": item.get("title") or item.get("name") or "",
                "evidence": ev_s or item.get("reason") or "",
                "matcher": item.get("matcher") or "",
                "rule_id": item.get("rule_id") or "",
                "_source": "local",
                "extra": item.get("extra") if isinstance(item.get("extra"), dict) else {},
                "path": str((item.get("extra") or {}).get("path") or item.get("path") or ""),
                "command": str(
                    (item.get("extra") or {}).get("command")
                    or (item.get("extra") or {}).get("image_path")
                    or item.get("command")
                    or ""
                ),
                "md5": str((item.get("extra") or {}).get("md5") or item.get("md5") or ""),
                "sha1": str((item.get("extra") or {}).get("sha1") or item.get("sha1") or ""),
                "sha256": str((item.get("extra") or {}).get("sha256") or item.get("sha256") or ""),
            })
            if len(out) >= need:
                return out
    return out


def save_report_db(report: Dict[str, Any], analysis: Dict[str, Any], fname: str) -> Path:
    """分析完成后写入独立 db（reports/<stem>/analysis.db），并更新索引。"""
    rid = P.report_id(fname)
    # 写入始终落新目录，避免继续堆在 dbs/
    dbp = P.db_path_for_write(rid)
    # 若旧库在 dbs/ 且目标还不存在内容，先迁移再写
    legacy = P.legacy_db_path(rid)
    if legacy.exists() and legacy.resolve() != dbp.resolve() and not dbp.exists():
        try:
            P.migrate_report_to_folder(rid)
            dbp = P.db_path_for_write(rid)
        except Exception:
            pass
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        conn.execute("DELETE FROM meta")
        conn.execute("DELETE FROM findings_agg")
        conn.execute("DELETE FROM blobs")
        try:
            conn.execute("DELETE FROM entity_lists")
        except sqlite3.OperationalError:
            pass
        skip_files = bool(report.get("_files_ingested"))
        if not skip_files:
            conn.execute("DELETE FROM files")

        meta = {
            "hostname": report.get("hostname") or "",
            "ip": report.get("ip") or "",
            "os": report.get("os") or "",
            "os_family": (report.get("os_family") or "").strip().lower(),
            "collect_time": report.get("collect_time") or "",
            "report_file": rid,
            "report_folder": P.report_stem(rid),
            "db_version": "2",
        }
        if meta["os_family"] not in ("linux", "windows"):
            try:
                from .os_detect import detect_os_family
                meta["os_family"] = detect_os_family(report)
                report["os_family"] = meta["os_family"]
            except Exception:
                meta["os_family"] = "windows"
        for k, v in meta.items():
            conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (k, str(v)))

        # 摘要 / 管线 / 时间线 / AI（不塞完整 rules_inventory）
        summary = analysis.get("summary") or {}
        summary_agg = analysis.get("summary_aggregated") or {}
        pipe = analysis.get("pipeline") or {}
        pipe_slim = {
            "matchers": pipe.get("matchers") or [],
            "rules_used": pipe.get("rules_used") or [],
        }
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("summary", _jdump(summary)))
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("summary_aggregated", _jdump(summary_agg)))
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("pipeline", _jdump(pipe_slim)))
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("timeline", _jdump((analysis.get("timeline") or [])[:500])))
        if analysis.get("ai"):
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("ai", _jdump(analysis["ai"])))
        if analysis.get("meta"):
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("analysis_meta", _jdump(analysis["meta"])))
        # 原始 findings 只留前 200 条兜底（界面主看聚合）
        raw = analysis.get("findings") or []
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("findings_raw_sample", _jdump(raw[:200])))
        conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", ("raw_findings_total", str(len(raw))))
        # 分模块结果（每模块最多 300 条样本；count/high 仍保留全量）
        fbm = analysis.get("findings_by_module") or {}
        fbm_slim = {}
        _mod_sample = 300
        for k, block in fbm.items():
            if not isinstance(block, dict):
                continue
            items = block.get("findings") or []
            fbm_slim[k] = {
                "matcher": block.get("matcher") or k,
                "count": block.get("count") or len(items),
                "high": block.get("high") or 0,
                "findings": items[:_mod_sample],
                "truncated": len(items) > _mod_sample,
            }
        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("findings_by_module", _jdump(fbm_slim)))

        agg_rows = []
        for item in analysis.get("findings_aggregated") or []:
            if not isinstance(item, dict):
                continue
            ex = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            if not ex:
                ex = {
                    k: item.get(k)
                    for k in ("type", "name", "reason", "kind", "path", "file_count", "file", "members_truncated")
                    if k in item and item.get(k) is not None
                }
            else:
                # findings_agg 不存成员列表（体积大），详情弹窗按 path 现查
                ex = {k: v for k, v in ex.items() if k != "members"}
            agg_rows.append(
                (
                    item.get("id") or f"{item.get('category')}|{item.get('title')}",
                    item.get("category") or "",
                    item.get("severity") or "medium",
                    item.get("title") or "",
                    int(item.get("count") or 1),
                    _jdump(item.get("evidence") or []),
                    _jdump(item.get("sources") or []),
                    item.get("rule_id") or "",
                    item.get("matcher") or "",
                    _jdump(ex),
                )
            )
        if agg_rows:
            conn.executemany(
                """INSERT OR REPLACE INTO findings_agg
                   (id,category,severity,title,count,evidence,sources,rule_id,matcher,extra)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                agg_rows,
            )

        for key in BLOB_KEYS:
            if key not in report:
                continue
            val = report.get(key)
            if key == "file_scans":
                continue  # 走 files 表
            if key == "event_logs" and isinstance(val, list):
                if bool(report.get("_event_logs_ingested")):
                    n_ev = int(report.get("_event_logs_count") or 0)
                    if n_ev <= 0:
                        try:
                            n_ev = int(conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()["c"] or 0)
                        except Exception:
                            n_ev = 0
                    conn.execute(
                        "INSERT INTO meta(key,value) VALUES(?,?)",
                        ("count_event_logs", str(n_ev)),
                    )
                    # 已入库则不重写表；补一份空样例占位（若无 blob）
                    row = conn.execute("SELECT 1 AS o FROM blobs WHERE name=? LIMIT 1", (key,)).fetchone()
                    if not row:
                        conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", (key, "[]"))
                    continue
                conn.execute("DELETE FROM event_logs")
                n_ev = _insert_event_log_rows(conn, val)
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES(?,?)",
                    ("count_event_logs", str(n_ev)),
                )
                # 样例 blob 供兼容；完整分页读 event_logs 表
                sample = [x for x in val if isinstance(x, dict)][:300]
                conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", (key, _jdump(sample)))
                continue
            if key == "browser_artifacts" and isinstance(val, list):
                # 全量入库，不再截断行
                slim = [a for a in val if isinstance(a, dict)]
                val = slim
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", (key, _jdump(val)))
            # 预写计数，摘要视图可免解析大 JSON
            if isinstance(val, list):
                conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (f"count_{key}", str(len(val))))
            elif isinstance(val, dict):
                n = len(val)
                conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (f"count_{key}", str(n)))
            elif val is not None and val != "":
                conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", (f"count_{key}", "1"))

        files = report.get("file_scans") or []
        if skip_files:
            n_files = int(report.get("_files_count") or 0)
            if n_files <= 0:
                try:
                    n_files = int(conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"] or 0)
                except Exception:
                    n_files = 0
            conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(n_files)))
            files = [{}] * n_files
        else:
            conn.execute("INSERT INTO meta(key,value) VALUES(?,?)", ("count_file_scans", str(len(files))))
            _insert_file_rows(conn, files)
        roots = report.get("file_scan_roots")
        if not isinstance(roots, dict) or not roots:
            # 已剥离数组时不要用空列表覆盖 meta；优先读库
            if skip_files:
                try:
                    row = conn.execute("SELECT value FROM meta WHERE key=?", ("file_scan_roots",)).fetchone()
                    if row and row["value"]:
                        roots = _jload(row["value"])
                except Exception:
                    roots = {}
            else:
                roots = _derive_file_scan_roots(report.get("file_scans") or [])
        if isinstance(roots, dict) and roots:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("file_scan_roots", _jdump(roots)),
            )
        # 列表投影：进程/服务/计划任务/启动项（列表 API 免解析大 blob）
        try:
            from .entity_lists import build_entity_lists_from_report

            el_counts = build_entity_lists_from_report(conn, report, rid=rid)
            if el_counts:
                print(f"[db] entity_lists rid={rid} {el_counts}")
        except Exception as e:
            print(f"[db] entity_lists build failed: {e}")
        conn.commit()
    finally:
        conn.close()

    upsert_index({
        "file": rid,
        "db_path": str(dbp.relative_to(config.REPORTS_DIR)).replace("\\", "/"),
        "hostname": report.get("hostname"),
        "collect_time": report.get("collect_time"),
        "ip": pick_primary_ip(report.get("ip") or ""),
        "issues": (summary_agg.get("total") if summary_agg else None) or summary.get("total") or 0,
        "raw_issues": summary.get("total") or len(raw),
        "analyzed": True,
        "processes": len(report.get("processes") or []),
        "services": len(report.get("services") or []),
        "files": len(files),
        "os_family": report.get("os_family") or meta.get("os_family") or "",
        "os": report.get("os") or "",
    })
    # 分析结论双写 MySQL
    try:
        from .mysql_store import save_analysis_mysql
        save_analysis_mysql(report, analysis, rid)
    except Exception as e:
        print(f"[store] save_analysis_mysql: {e}")
    return dbp


def backfill_os_family_index() -> int:
    """Fill empty/wrong os_family in SQLite index + MySQL from os / collector heuristics."""
    from .os_detect import detect_os_family

    updates: List[tuple] = []  # (file, fam, os_label)

    def _detect_for_row(file_id: str, hostname: str, os_label: str, cur_fam: str) -> tuple:
        cur = str(cur_fam or "").strip().lower()
        fake = {
            "os_family": cur,
            "os": os_label or "",
            "hostname": hostname or "",
            "file": file_id or "",
        }
        try:
            folder = P.report_dir(file_id)
            rp = folder / "report.json"
            if rp.is_file():
                data = json.loads(rp.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, dict):
                    fake.update({
                        "os_family": data.get("os_family") or cur,
                        "os": data.get("os") or fake["os"],
                        "collector": data.get("collector"),
                        "source": data.get("source"),
                        "processes": data.get("processes") or [],
                        "security_extras": data.get("security_extras"),
                    })
        except Exception:
            pass
        fam = detect_os_family(fake)
        return fam, str(fake.get("os") or os_label or "").strip()

    n = 0
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            rows = conn.execute("SELECT file, hostname, os, os_family FROM reports").fetchall()
            for r in rows:
                cur = str(r["os_family"] or "").strip().lower()
                fam, os_label = _detect_for_row(r["file"], r["hostname"] or "", r["os"] or "", cur)
                if fam and fam != cur:
                    conn.execute(
                        "UPDATE reports SET os_family=?, os=CASE WHEN ?<>'' THEN ? ELSE os END WHERE file=?",
                        (fam, os_label, os_label, r["file"]),
                    )
                    n += 1
                    updates.append((r["file"], fam, os_label))
                elif fam:
                    updates.append((r["file"], fam, os_label or (r["os"] or "")))
            conn.commit()
        finally:
            conn.close()

    # MySQL is often the live list source — must stay in sync
    try:
        from .mysql_db import mysql_ready, connect_mysql
        if mysql_ready():
            conn = connect_mysql()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT file, hostname, os, os_family FROM reports")
                    rows = cur.fetchall() or []
                    for r in rows:
                        rid = r.get("file") or ""
                        cur_fam = str(r.get("os_family") or "").strip().lower()
                        fam, os_label = _detect_for_row(
                            rid, r.get("hostname") or "", r.get("os") or "", cur_fam,
                        )
                        if not fam:
                            continue
                        if fam != cur_fam or (os_label and not str(r.get("os") or "").strip()):
                            cur.execute(
                                "UPDATE reports SET os_family=%s, os=IF(%s<>'', %s, os) WHERE file=%s",
                                (fam, os_label, os_label, rid),
                            )
                            if fam != cur_fam:
                                n += 1
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        print(f"[os_family] mysql backfill: {e}")

    try:
        invalidate_list_cache()
    except Exception:
        pass
    return n


def upsert_ai_blob(report_file: str, ai: Dict[str, Any]) -> bool:
    """仅更新 analysis.db 中的 AI 研判 blob，不重写整库。"""
    rid = P.report_id(report_file)
    dbp = db_path_for_report(rid)
    ok = False
    if dbp.exists():
        conn = _connect(dbp)
        try:
            _init_schema(conn)
            conn.execute("DELETE FROM blobs WHERE name=?", ("ai",))
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", ("ai", _jdump(ai)))
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("ai_updated_at", time.strftime("%Y-%m-%dT%H:%M:%S")),
            )
            conn.commit()
            ok = True
        finally:
            conn.close()
    try:
        from .mysql_store import upsert_ai_mysql
        hostname = ""
        try:
            meta_path = P.resolve_report_json(rid)
            if meta_path and meta_path.exists():
                with open(meta_path, encoding="utf-8") as fh:
                    hostname = (json.load(fh) or {}).get("hostname") or ""
        except Exception:
            pass
        upsert_ai_mysql(rid, ai, hostname=hostname)
    except Exception as e:
        print(f"[store] upsert_ai_mysql: {e}")
    return ok


def load_ai_blob(report_file: str) -> Optional[Dict[str, Any]]:
    """只读取 blobs.ai，避免为了一个可选结果组装整个 2GB 报告视图。"""
    dbp = db_path_for_report(report_file)
    if not dbp.exists():
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        value = _load_one_blob(conn, "ai")
        return value if isinstance(value, dict) else None
    finally:
        conn.close()


def load_view_from_db(report_file: str) -> Optional[Dict[str, Any]]:
    """从 db 组装前端所需结构，不读大 JSON。"""
    dbp = db_path_for_report(report_file)
    if not dbp.exists():
        # 兼容相对路径索引
        rel = None
        if INDEX_DB.exists():
            conn = _connect(INDEX_DB)
            try:
                _init_index(conn)
                row = conn.execute("SELECT db_path FROM reports WHERE file=?", (report_file,)).fetchone()
                if row and row["db_path"]:
                    rel = config.REPORTS_DIR / row["db_path"]
            finally:
                conn.close()
        if rel and rel.exists():
            dbp = rel
        else:
            return None

    conn = _connect(dbp)
    try:
        _init_schema(conn)
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
        blobs = {r["name"]: _jload(r["data"]) for r in conn.execute("SELECT name,data FROM blobs")}
        # 告警按 result.json / analysis.db mtime 取较新，勿死读本库旧 findings_agg
        findings = _load_fresh_findings(report_file)

        try:
            file_rows = conn.execute(
                "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files"
            ).fetchall()
            file_scans = [
                {
                    "full_path": r["full_path"], "name": r["name"], "path": r["path"],
                    "ext": r["ext"], "size": r["size"],
                    "company": r["company"] or "", "product": r["product"] or "",
                    "description": r["description"] or "", "file_version": r["file_version"] or "",
                    "signed": bool(r["signed"]), "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in r.keys() else "") or "",
                    "magic_hex": r["magic_hex"] or "",
                    "md5": (r["md5"] if "md5" in r.keys() else "") or "",
                    "sha1": (r["sha1"] if "sha1" in r.keys() else "") or "",
                    "sha256": (r["sha256"] if "sha256" in r.keys() else "") or "",
                    "hidden": bool(r["hidden"]) if "hidden" in r.keys() else False,
                    "system": bool(r["system"]) if "system" in r.keys() else False,
                }
                for r in file_rows
            ]
        except sqlite3.OperationalError:
            try:
                file_rows = conn.execute(
                    "SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,magic_hex,hidden,system FROM files"
                ).fetchall()
                file_scans = [
                    {
                        "full_path": r["full_path"], "name": r["name"], "path": r["path"],
                        "ext": r["ext"], "size": r["size"],
                        "company": r["company"] or "", "product": r["product"] or "",
                        "description": r["description"] or "", "file_version": r["file_version"] or "",
                        "signed": bool(r["signed"]), "signer": r["signer"] or "",
                        "sig_status": r["sig_status"] or "", "magic_hex": r["magic_hex"] or "",
                        "hidden": bool(r["hidden"]) if "hidden" in r.keys() else False,
                        "system": bool(r["system"]) if "system" in r.keys() else False,
                    }
                    for r in file_rows
                ]
            except sqlite3.OperationalError:
                try:
                    file_rows = conn.execute(
                        "SELECT full_path,name,path,ext,size,company,product,description,file_version,signed,signer,sig_status,magic_hex FROM files"
                    ).fetchall()
                    file_scans = [
                        {
                            "full_path": r["full_path"], "name": r["name"], "path": r["path"],
                            "ext": r["ext"], "size": r["size"],
                            "company": r["company"] or "", "product": r["product"] or "",
                            "description": r["description"] or "", "file_version": r["file_version"] or "",
                            "signed": bool(r["signed"]), "signer": r["signer"] or "",
                            "sig_status": r["sig_status"] or "", "magic_hex": r["magic_hex"] or "",
                            "hidden": False, "system": False,
                        }
                        for r in file_rows
                    ]
                except sqlite3.OperationalError:
                    file_rows = conn.execute("SELECT full_path,name,path,ext,size FROM files").fetchall()
                    file_scans = [
                        {"full_path": r["full_path"], "name": r["name"], "path": r["path"], "ext": r["ext"], "size": r["size"],
                         "hidden": False, "system": False}
                        for r in file_rows
                    ]

        out: Dict[str, Any] = {
            "hostname": meta.get("hostname"),
            "ip": meta.get("ip"),
            "os": meta.get("os"),
            "os_family": meta.get("os_family") or "",
            "collect_time": meta.get("collect_time"),
            "file_scans": file_scans,
            "_source": "db",
            "_db": str(dbp.name),
            "_report_file": meta.get("report_file") or report_file,
        }
        for k, v in blobs.items():
            if k in ("summary", "summary_aggregated", "pipeline", "timeline", "ai", "analysis_meta",
                      "findings_raw_sample", "findings_by_module"):
                continue
            if k in RETIRED_BLOB_KEYS:
                continue
            out[k] = v

        analysis = {
            "findings_aggregated": findings,
            "findings": blobs.get("findings_raw_sample") or [],
            "findings_by_module": blobs.get("findings_by_module") or {},
            "summary": blobs.get("summary") or {},
            "summary_aggregated": blobs.get("summary_aggregated") or {"total": len(findings)},
            "pipeline": blobs.get("pipeline") or {},
            "timeline": blobs.get("timeline") or [],
            "ai": blobs.get("ai"),
            "meta": blobs.get("analysis_meta") or {},
            "ioc_hits": {},
        }
        # 补齐 summary.raw_total
        if "raw_total" not in analysis["summary_aggregated"]:
            analysis["summary_aggregated"]["raw_total"] = int(meta.get("raw_findings_total") or len(analysis["findings"]))
        # MySQL 可补摘要/AI/时间线；告警列表以本地 analysis.db 为准，避免 light 重分析后仍被旧 MySQL 覆盖
        try:
            from .mysql_store import load_analysis_from_mysql
            ma = load_analysis_from_mysql(report_file)
            if ma:
                local_findings = list(findings or [])
                for key in (
                    "summary", "summary_aggregated", "pipeline", "timeline",
                    "findings_by_module", "meta", "ai",
                ):
                    if ma.get(key) is not None and ma.get(key) != {} and ma.get(key) != []:
                        # findings_by_module：本地已有非空模块结果时不覆盖
                        if key == "findings_by_module" and analysis.get("findings_by_module"):
                            continue
                        analysis[key] = ma[key]
                if local_findings:
                    analysis["findings_aggregated"] = local_findings
                    analysis["findings"] = analysis.get("findings") or local_findings
                    findings = local_findings
                elif ma.get("findings_aggregated"):
                    analysis["findings_aggregated"] = ma["findings_aggregated"]
                    analysis["findings"] = ma.get("findings") or ma["findings_aggregated"]
                    findings = analysis["findings_aggregated"]
                if ma.get("_findings_total") is not None and not local_findings:
                    analysis["_findings_total"] = ma["_findings_total"]
                analysis["_source"] = "sqlite+mysql" if local_findings else "mysql+sqlite"
                out["_source"] = analysis["_source"]
        except Exception as e:
            print("[view] mysql overlay:", e)
        try:
            from .pipeline import prune_inactive_modules
            analysis = prune_inactive_modules(analysis)
        except Exception:
            pass
        try:
            from .text_fix import fix_analysis_text
            analysis = fix_analysis_text(analysis)
        except Exception:
            pass
        out["analysis"] = analysis
        if not out.get("suspicious_items"):
            out["suspicious_items"] = [
                {
                    "type": x.get("category"), "name": x.get("title"),
                    "reason": x.get("reason") or x.get("title"),
                    "severity": x.get("severity", "medium"),
                    "count": x.get("count", 1),
                }
                for x in findings
            ]
        return out
    finally:
        conn.close()


# 重字段：摘要接口不返回，改走 section 分页
HEAVY_VIEW_KEYS = {
    "file_scans", "processes", "services", "scheduled_tasks", "startup_items",
    "installed_programs", "users", "usb_devices", "prefetch_files",
    "established_connections", "open_ports", "network", "hosts_file",
    "firewall_rules", "ps_history", "ps_artifacts", "browser_artifacts",
    "user_registry", "services_registry", "network_registry", "run_mru",
    "recycle_bin", "wmi_subscriptions", "wmi_namespaces", "environment",
    "hotfixes", "drivers", "driver_entries", "dns_cache_entries",
    "office_artifacts", "wifi_profiles", "event_log_summary", "event_logs",
    "system_info", "usn_journal", "vss_shadows", "bits_jobs", "audit_pol", "vault_creds",
    "net_sessions", "net_shares", "execution_artifacts", "remote_access", "security_extras",
    "event_log_coverage", "system_timezone", "file_scan_roots",
}

_SUMMARY_BLOB_NAMES = (
    "summary", "summary_aggregated", "pipeline", "timeline", "ai",
    "analysis_meta", "findings_raw_sample", "findings_by_module", "collection_quality",
)

# 列表/轻量视图每条告警最多带几条证据预览，完整证据走 finding-evidence 接口
_EVIDENCE_LIST_PREVIEW = 5


def _norm_evidence_list(ev: Any) -> List[str]:
    raw: List[Any] = []
    if isinstance(ev, list):
        raw = ev
    elif isinstance(ev, str) and ev.strip():
        raw = [ev.strip()]
    elif ev:
        s = str(ev).strip()
        if s:
            raw = [s]
    out: List[str] = []
    seen: Set[str] = set()
    for item in raw:
        for ln in str(item or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            key = s[:400].lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(s)
    return _coalesce_black_mod_evidence(out)


_BLACK_MOD_HDR = re.compile(r"^(?:黑模块|黑DLL|黑dll|黑文件|未签名文件|未签名模块)\s*[:：]?\s*$", re.I)
_UNSIGNED_FILE_LABEL = "未签名文件"
_BLACK_DLL_LABEL = "黑DLL"


def _coalesce_black_mod_evidence(lines: List[str]) -> List[str]:
    """把「进程行 / 未签名文件: / - dll」拆散行重新拼成一条证据（兼容旧「黑模块」）。"""
    if not lines:
        return lines
    out: List[str] = []
    i = 0
    n = len(lines)
    while i < n:
        cur = lines[i]
        nxt_hdr = i + 1 < n and bool(_BLACK_MOD_HDR.match(lines[i + 1]))
        if _BLACK_MOD_HDR.match(cur) or nxt_hdr:
            base = "" if _BLACK_MOD_HDR.match(cur) else cur
            hdr = cur if _BLACK_MOD_HDR.match(cur) else lines[i + 1]
            label = _BLACK_DLL_LABEL if re.match(r"^(?:黑DLL|黑dll|黑文件|黑模块)", str(hdr or "").strip(), re.I) else _UNSIGNED_FILE_LABEL
            if not _BLACK_MOD_HDR.match(cur):
                i += 1
            i += 1  # skip header
            mods: List[str] = []
            while i < n and (
                lines[i].startswith("-")
                or lines[i].startswith("•")
                or lines[i].startswith("*")
                or _looks_like_mod_line(lines[i])
            ):
                mods.append(lines[i].lstrip("-•* ").strip())
                i += 1
            block = (f"{label}:\n- " + "\n- ".join(mods)) if mods else f"{label}:"
            if base:
                out.append(f"{base}\n{block}")
            elif out:
                out[-1] = f"{out[-1]}\n{block}"
            else:
                out.append(block)
            continue
        if _looks_like_mod_line(cur) and out:
            prev = out[-1]
            if (
                f"\n{_UNSIGNED_FILE_LABEL}" in prev
                or "\n黑模块" in prev
                or "\n黑DLL" in prev
                or "\n黑文件" in prev
                or f"| {_UNSIGNED_FILE_LABEL}" in prev
                or "| 黑模块" in prev
                or "| 黑DLL" in prev
                or "| 黑文件" in prev
                or f"|{_UNSIGNED_FILE_LABEL}" in prev
                or "|黑模块" in prev
                or "|黑DLL" in prev
                or "|黑文件" in prev
            ):
                out[-1] = f"{prev}\n- {cur.lstrip('-•* ').strip()}"
            else:
                out[-1] = f"{prev}\n{_UNSIGNED_FILE_LABEL}:\n- {cur.lstrip('-•* ').strip()}"
            i += 1
            continue
        out.append(cur)
        i += 1
    return out


def _looks_like_mod_line(s: str) -> bool:
    t = (s or "").strip()
    if not t or _BLACK_MOD_HDR.match(t):
        return False
    if re.search(r"\[[^\]]+\]", t) and re.search(r"\.(?:dll|exe|sys|ocx)\b", t, re.I):
        return True
    if re.match(r"^[\w.-]+\.(?:dll|exe|sys|ocx)\b", t, re.I) and ("@" in t or "=>" in t or "[" in t):
        return True
    return False


_HASH_IN_EV = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_FILE_EV_PREFIX = re.compile(r"^(文件|文件哈希)[：:]\s*", re.I)


def enrich_linux_persistence_evidence(rid: str, items: List[Any]) -> List[Any]:
    """旧 Linux 告警证据常只有规则标题；按 report + rule_id 补命中上下文（仅响应侧）。"""
    if not rid or not items:
        return items
    need = False
    for it in items:
        if not isinstance(it, dict):
            continue
        mid = str(it.get("matcher") or it.get("source") or "").lower()
        if "linux" in mid or str(it.get("source") or "") == "linux_persistence":
            need = True
            break
    if not need:
        return items
    report_path = P.resolve_report_json(rid)
    if not report_path or not Path(report_path).is_file():
        return items
    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        return items
    if not isinstance(report, dict):
        return items
    try:
        from .matchers.linux_persistence import enrich_linux_finding_items
        return enrich_linux_finding_items(report, items)
    except Exception:
        return items


def _process_index_from_conn(conn) -> Dict[int, Dict[str, str]]:
    try:
        from .net_process import build_process_index
        raw = _load_one_blob(conn, "processes") or []
        return build_process_index(raw if isinstance(raw, list) else [])
    except Exception:
        return {}


def enrich_network_finding_process(rid: str, items: List[Any]) -> List[Any]:
    """旧外联/IOC 网络告警证据常只有 PID；按进程表回填进程名。"""
    if not rid or not items:
        return items
    need = False
    for it in items:
        if not isinstance(it, dict):
            continue
        extra = it.get("extra") if isinstance(it.get("extra"), dict) else {}
        if extra.get("process_name"):
            continue
        matcher = str(it.get("matcher") or "").lower()
        cat = str(it.get("category") or it.get("type") or "")
        ev = str(it.get("evidence") or it.get("reason") or "")
        if matcher == "network" or "外联" in cat or cat in ("网络外联", "网络IOC"):
            need = True
            break
        if matcher in ("ioc", "ioc_db") and ("外联" in ev or extra.get("remote")):
            need = True
            break
    if not need:
        return items
    dbp = _resolve_db_path(rid) or P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return items
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        idx = _process_index_from_conn(conn)
    finally:
        conn.close()
    if not idx:
        return items
    try:
        from .net_process import enrich_network_findings
        return enrich_network_findings(items, idx)
    except Exception:
        return items


def enrich_ioc_evidence_paths(rid: str, items: List[Any]) -> List[Any]:
    """旧报告 IOC 证据常只有文件名；按哈希从 files 表补全完整路径。"""
    if not rid or not items:
        return items
    dbp = _resolve_db_path(rid) or P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return items

    want: Set[str] = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        mid = str(it.get("matcher") or "").lower()
        cat = str(it.get("category") or it.get("type") or "")
        if mid not in ("ioc", "ioc_db") and cat.upper() != "IOC":
            continue
        for line in _norm_evidence_list(it.get("evidence")):
            if "文件" not in line and "hash" not in line.lower():
                # 仍可能含哈希
                pass
            for m in _HASH_IN_EV.finditer(line):
                want.add(m.group(1).lower())
        rid_s = str(it.get("rule_id") or "")
        for m in _HASH_IN_EV.finditer(rid_s):
            want.add(m.group(1).lower())
    if not want:
        return items

    path_by_hash: Dict[str, str] = {}
    conn = _connect(Path(dbp))
    try:
        _ensure_files_hash_indexes(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        hash_cols = [c for c in ("md5", "sha1", "sha256") if c in cols]
        if not hash_cols:
            return items
        # 分批 IN 查询
        vals = list(want)
        for i in range(0, len(vals), 400):
            chunk = vals[i: i + 400]
            ph = ",".join("?" * len(chunk))
            # 直接用列 IN，才能走 idx_files_md5 / idx_files_sha256。
            # lower(IFNULL(col,'')) 会让 117 万行 files 全表扫描，告警页首开经常 10s+。
            where = " OR ".join(f"{c} IN ({ph})" for c in hash_cols)
            args: List[Any] = []
            for _ in hash_cols:
                args.extend(chunk)
            sql = f"SELECT full_path, name, {', '.join(hash_cols)} FROM files WHERE {where} LIMIT 2000"
            for r in conn.execute(sql, args).fetchall():
                fp = (r["full_path"] or "").replace("/", "\\")
                if not fp:
                    continue
                for c in hash_cols:
                    hv = str(r[c] or "").strip().lower()
                    if hv and hv in want and hv not in path_by_hash:
                        path_by_hash[hv] = fp
    except Exception:
        return items
    finally:
        conn.close()
    if not path_by_hash:
        return items

    out: List[Any] = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        mid = str(it.get("matcher") or "").lower()
        cat = str(it.get("category") or it.get("type") or "")
        if mid not in ("ioc", "ioc_db") and cat.upper() != "IOC":
            out.append(it)
            continue
        ev = _norm_evidence_list(it.get("evidence"))
        if not ev:
            out.append(it)
            continue
        changed = False
        new_ev = []
        paths_found: List[str] = []
        for line in ev:
            nl = line
            # 已是完整路径则保留
            if re.search(r"[A-Za-z]:\\[^\\]", line) or line.startswith("\\\\"):
                new_ev.append(nl)
                mpath = re.search(r"文件[：:]\s*([^→\n]+)", line)
                if mpath:
                    paths_found.append(mpath.group(1).strip())
                continue
            hm = _HASH_IN_EV.search(line)
            fp = path_by_hash.get((hm.group(1).lower() if hm else ""), "")
            if fp:
                # 文件:Name → hash  =>  文件:full_path → hash
                if _FILE_EV_PREFIX.search(line):
                    rest = _FILE_EV_PREFIX.sub("", line, count=1)
                    # rest 可能是 "Name → hash (src)" 或 "Name"
                    if "→" in rest or "->" in rest:
                        arrow = "→" if "→" in rest else "->"
                        _name, tail = rest.split(arrow, 1)
                        nl = f"文件:{fp} {arrow}{tail}"
                    else:
                        nl = f"文件:{fp}"
                else:
                    nl = f"文件:{fp} · {line}"
                changed = True
                paths_found.append(fp)
            new_ev.append(nl)
        if not changed:
            out.append(it)
            continue
        copy = dict(it)
        copy["evidence"] = new_ev
        if new_ev and (not copy.get("reason") or "文件:" in str(copy.get("reason") or "")):
            copy["reason"] = new_ev[0]
        if paths_found:
            ex = dict(copy.get("extra") or {}) if isinstance(copy.get("extra"), dict) else {}
            if not ex.get("path"):
                ex["path"] = paths_found[0]
            copy["extra"] = ex
            if not copy.get("path"):
                copy["path"] = paths_found[0]
        out.append(copy)
    return out


def slim_finding_for_list(item: Any, preview: int = _EVIDENCE_LIST_PREVIEW) -> Dict[str, Any]:
    """压缩告警体积：列表只留证据预览，详情再按需拉取。"""
    if not isinstance(item, dict):
        return {"title": str(item or ""), "evidence": [], "evidence_total": 0}
    out = dict(item)
    out.pop("members", None)
    if isinstance(out.get("extra"), dict):
        ex = {k: v for k, v in out["extra"].items() if k != "members"}
        out["extra"] = ex
    fobj = out.get("file")
    if isinstance(fobj, dict):
        keep = ("full_path", "name", "ext", "size", "company", "product", "signed", "signer", "sig_status", "sig_type", "description")
        out["file"] = {k: fobj.get(k) for k in keep if fobj.get(k) is not None and fobj.get(k) != ""}

    ev = _norm_evidence_list(out.get("evidence"))
    # 合并后的长度为准；旧 evidence_total 常是「进程+黑模块头+dll」拆散条数
    total = len(ev)
    try:
        declared = int(out.get("evidence_total") or (out.get("extra") or {}).get("evidence_total") or 0)
    except Exception:
        declared = 0
    hit = int(out.get("count") or 0) or 0
    # 截断场景：声明总数明显大于当前列表且不像黑模块拆散（3→1）时保留
    if declared > total and not (declared <= total + 2 and any(("黑模块" in str(x) or "黑DLL" in str(x) or "黑文件" in str(x) or "未签名文件" in str(x)) for x in ev)):
        total = max(declared, total)
    if hit > total and declared <= 0:
        total = hit
    preview = max(1, int(preview or _EVIDENCE_LIST_PREVIEW))
    if len(ev) > preview:
        out["evidence"] = [x[:800] for x in ev[:preview]]
        out["evidence_lazy"] = True
    else:
        out["evidence"] = [x[:800] for x in ev]
        out["evidence_lazy"] = bool(total > len(out["evidence"]))
    out["evidence_total"] = total if total else len(out["evidence"])
    if not out.get("reason") and out["evidence"]:
        out["reason"] = out["evidence"][0]
    return out


def slim_findings_list(items: List[Any], preview: int = _EVIDENCE_LIST_PREVIEW) -> List[Dict[str, Any]]:
    return [slim_finding_for_list(x, preview=preview) for x in (items or []) if x is not None]


def slim_findings_by_module(by_mod: Any) -> Dict[str, Any]:
    """轻量视图去掉模块内 findings 样本，只保留 count/high，避免几百 KB～数 MB JSON。"""
    if not isinstance(by_mod, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, block in by_mod.items():
        if not isinstance(block, dict):
            out[k] = block
            continue
        items = block.get("findings") or []
        n = int(block.get("count") or (len(items) if isinstance(items, list) else 0) or 0)
        out[k] = {
            "matcher": block.get("matcher") or k,
            "count": n,
            "high": int(block.get("high") or 0),
            "truncated": True,
            "findings": [],
        }
    return out


def load_finding_evidence_page(
    report_file: str,
    finding_id: str,
    offset: int = 0,
    limit: int = 50,
) -> Optional[Dict[str, Any]]:
    """按告警 id 分页返回完整去重证据。"""
    rid = P.report_id(report_file)
    fid = str(finding_id or "").strip()
    if not fid:
        return None
    # 前端 expandPersistFindings 会写成 id#task
    base_id = fid.split("#", 1)[0].strip() or fid
    offset = max(0, int(offset or 0))
    limit = max(1, min(500, int(limit or 50)))

    item: Optional[Dict[str, Any]] = None
    try:
        from .mysql_store import load_finding_row_mysql
        item = load_finding_row_mysql(rid, base_id)
    except Exception:
        item = None
    if not item:
        dbp = _resolve_db_path(rid)
        if not dbp:
            return None
        conn = _connect(dbp)
        try:
            _init_schema(conn)
            row = conn.execute("SELECT * FROM findings_agg WHERE id=?", (base_id,)).fetchone()
            if not row:
                # 兼容旧 id
                for r in conn.execute("SELECT * FROM findings_agg"):
                    if str(r["id"] or "") == base_id:
                        row = r
                        break
            if row:
                item = {
                    "id": row["id"],
                    "title": row["title"],
                    "count": row["count"],
                    "evidence": _jload(row["evidence"], []),
                    "extra": _jload(row["extra"], {}) or {},
                }
        finally:
            conn.close()
    if not item:
        return None

    try:
        enriched = enrich_ioc_evidence_paths(rid, [item])
        if enriched and isinstance(enriched[0], dict):
            item = enriched[0]
    except Exception:
        pass
    try:
        enriched2 = enrich_linux_persistence_evidence(rid, [item])
        if enriched2 and isinstance(enriched2[0], dict):
            item = enriched2[0]
    except Exception:
        pass
    try:
        enriched3 = enrich_network_finding_process(rid, [item])
        if enriched3 and isinstance(enriched3[0], dict):
            item = enriched3[0]
    except Exception:
        pass

    ev = _norm_evidence_list(item.get("evidence"))
    # 多行证据拆成多条便于分页；但「黑模块」块必须再合并，否则详情会变成 3 条裸文本
    if len(ev) == 1 and "\n" in ev[0]:
        ev = [ln.strip() for ln in ev[0].splitlines() if ln.strip()] or ev
        ev = _coalesce_black_mod_evidence(ev)
    # 若前端用 #kind 拆分，尽量只返回该类型证据行
    kind_suffix = fid.split("#", 1)[1].strip() if "#" in fid else ""
    if kind_suffix and kind_suffix in ("task", "startup", "service", "registry", "wmi", "other"):
        filtered = []
        for line in ev:
            low = line.lower()
            if kind_suffix == "wmi" and ("wmi" in low or "filters=" in low):
                filtered.append(line)
            elif kind_suffix == "registry" and ("hk" in low or "ifeo" in low or "winlogon" in low or "registry" in low):
                filtered.append(line)
            elif kind_suffix == "startup" and ("startup" in low or "启动项" in line or "\\\\run" in low):
                filtered.append(line)
            elif kind_suffix == "task" and ("计划任务" in line or "schtasks" in low or line.strip().startswith("\\")):
                filtered.append(line)
            elif kind_suffix == "service" and ("服务" in line or "service" in low or "[服务]" in line):
                filtered.append(line)
            elif kind_suffix == "other":
                filtered.append(line)
        if filtered:
            ev = filtered

    total = len(ev)
    slice_ev = ev[offset: offset + limit]
    return {
        "ok": True,
        "file": rid,
        "id": fid,
        "base_id": base_id,
        "title": item.get("title") or "",
        "count": int(item.get("count") or total),
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": slice_ev,
        "evidence_total": total,
        "truncated": False,
    }


def _resolve_db_path(report_file: str) -> Optional[Path]:
    dbp = db_path_for_report(report_file)
    if dbp.exists():
        return dbp
    if INDEX_DB.exists():
        conn = _connect(INDEX_DB)
        try:
            _init_index(conn)
            row = conn.execute("SELECT db_path FROM reports WHERE file=?", (P.report_id(report_file),)).fetchone()
            if row and row["db_path"]:
                rel = config.REPORTS_DIR / row["db_path"]
                if rel.exists():
                    return rel
        finally:
            conn.close()
    return None


def _load_findings_from_conn(conn) -> List[Dict[str, Any]]:
    findings = []
    for r in conn.execute("SELECT * FROM findings_agg"):
        item = {
            "id": r["id"],
            "category": r["category"],
            "severity": r["severity"],
            "title": r["title"],
            "count": r["count"],
            "evidence": _jload(r["evidence"], []),
            "sources": _jload(r["sources"], []),
            "rule_id": r["rule_id"],
            "matcher": r["matcher"],
            "type": r["category"],
            "name": r["title"],
        }
        extra = _jload(r["extra"], {}) or {}
        item.update(extra)
        if not item.get("reason"):
            ev = item.get("evidence")
            item["reason"] = ev[0] if isinstance(ev, list) and ev else item["title"]
        findings.append(item)
    try:
        from .matchers.persistence import filter_stale_microsoft_com_task_findings
        findings = filter_stale_microsoft_com_task_findings(findings)
    except Exception:
        pass
    return findings


_FINDINGS_CACHE: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
# 每份报告一个槽（LRU）。原来是全局单槽：并发分析/浏览多份报告时
# 后一次查询会顶掉前一次的缓存，命中率趋近 0，每次都要重跑百万行证据补全。
_FINDINGS_CACHE_MAX = 16
_FINDINGS_LOCK = threading.Lock()
_FINDINGS_LOAD_LOCKS: Dict[str, threading.Lock] = {}
_FINDINGS_LOAD_GUARD = threading.Lock()


def _findings_cache_get(cache_key: str) -> Optional[List[Dict[str, Any]]]:
    with _FINDINGS_LOCK:
        items = _FINDINGS_CACHE.get(cache_key)
        if items is None:
            return None
        _FINDINGS_CACHE.move_to_end(cache_key)
        return list(items)


def _findings_cache_put(cache_key: str, items: List[Dict[str, Any]]) -> None:
    with _FINDINGS_LOCK:
        _FINDINGS_CACHE[cache_key] = list(items)
        _FINDINGS_CACHE.move_to_end(cache_key)
        while len(_FINDINGS_CACHE) > _FINDINGS_CACHE_MAX:
            _FINDINGS_CACHE.popitem(last=False)


def _findings_load_lock(rid: str) -> threading.Lock:
    with _FINDINGS_LOAD_GUARD:
        lk = _FINDINGS_LOAD_LOCKS.get(rid)
        if lk is None:
            lk = threading.Lock()
            _FINDINGS_LOAD_LOCKS[rid] = lk
        return lk


def invalidate_findings_cache(rid: str = "") -> None:
    with _FINDINGS_LOCK:
        if not rid:
            _FINDINGS_CACHE.clear()
            return
        # key 形如 "<rid>|<result_mtime>|<db_mtime>"，同一 rid 可能有多个历史 key
        for k in [k for k in _FINDINGS_CACHE if k.startswith(f"{rid}|")]:
            _FINDINGS_CACHE.pop(k, None)


def _result_findings_from_path(rp: Path) -> List[Dict[str, Any]]:
    raw = json.loads(rp.read_text(encoding="utf-8"))
    an = raw.get("analysis") if isinstance(raw, dict) else {}
    out: List[Dict[str, Any]] = []
    for x in (
        (an or {}).get("findings_aggregated")
        or (an or {}).get("findings")
        or []
    ):
        if isinstance(x, dict):
            out.append(x)
    return out


def _load_fresh_findings(report_file: str) -> List[Dict[str, Any]]:
    """告警读数：按 mtime 在 result.json 与 analysis.db 中取较新者，最后回退 MySQL。

    light 只保证更新 result.json（并可同步 findings 到 analysis.db/MySQL）；
    若仍无条件地优先读库，会继续展示上一次 full 的旧误报。
    """
    rid = P.report_id(report_file)
    rp = P.result_json_path(rid)
    result_mtime = 0.0
    dbp = _resolve_db_path(report_file)
    db_mtime = 0.0
    try:
        if rp and rp.is_file():
            result_mtime = float(rp.stat().st_mtime or 0)
    except Exception:
        result_mtime = 0.0
    try:
        if dbp and Path(dbp).is_file():
            db_mtime = float(Path(dbp).stat().st_mtime or 0)
    except Exception:
        db_mtime = 0.0

    cache_key = f"{rid}|{result_mtime}|{db_mtime}"
    hit = _findings_cache_get(cache_key)
    if hit is not None:
        try:
            from .mitre import enrich_findings_list
            return enrich_findings_list(hit)
        except Exception:
            return hit

    lk = _findings_load_lock(rid)
    with lk:
        hit = _findings_cache_get(cache_key)
        if hit is not None:
            return hit
        items = _load_fresh_findings_uncached(rid, rp, result_mtime, dbp, db_mtime)
        # 证据路径/进程名补全也很重（百万 files 表）；缓存最终结果，
        # 避免总览的统计、风险列表、分析列表重复执行同一批查询。
        try:
            items = enrich_ioc_evidence_paths(rid, items)
        except Exception:
            pass
        try:
            items = enrich_linux_persistence_evidence(rid, items)
        except Exception:
            pass
        try:
            items = enrich_network_finding_process(rid, items)
        except Exception:
            pass
        try:
            from .mitre import enrich_findings_list
            items = enrich_findings_list(items)
        except Exception:
            pass
        _findings_cache_put(cache_key, items)
        return list(items)


def _filter_known_task_fps(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """读库/读 result 时滤掉已知系统 COM 计划任务误报（无需用户白名单）。"""
    if not items:
        return items
    try:
        from .matchers.persistence import filter_stale_microsoft_com_task_findings
        return filter_stale_microsoft_com_task_findings(items)
    except Exception:
        return items


def _load_fresh_findings_uncached(
    rid: str,
    rp: Optional[Path],
    result_mtime: float,
    dbp: Any,
    db_mtime: float,
) -> List[Dict[str, Any]]:
    result_items: List[Dict[str, Any]] = []
    if rp and rp.is_file() and result_mtime:
        try:
            result_items = _result_findings_from_path(rp)
        except Exception:
            result_items = []

    # result.json 更新（light）→ 优先 result，且不要为了比 mtime 去打开 2GB analysis.db
    if result_items and result_mtime >= db_mtime:
        return _filter_known_task_fps(result_items)

    db_items: List[Dict[str, Any]] = []
    if dbp and Path(dbp).is_file():
        try:
            conn = _connect(Path(dbp))
            try:
                db_items = _load_findings_from_conn(conn)
            finally:
                conn.close()
        except Exception:
            db_items = []

    if db_items:
        return _filter_known_task_fps(db_items)
    if result_items:
        return _filter_known_task_fps(result_items)

    try:
        from .mysql_store import load_analysis_from_mysql
        ma = load_analysis_from_mysql(rid)
        if ma and ma.get("findings_aggregated"):
            return _filter_known_task_fps(
                [x for x in (ma.get("findings_aggregated") or []) if isinstance(x, dict)]
            )
    except Exception:
        pass
    return []


def sync_findings_to_analysis_db(report_file: str, analysis: Dict[str, Any]) -> bool:
    """light 阶段：只刷新 findings_agg + 分析摘要 blob，不碰 files/采集大表。

    让 analysis.db 与 result.json 告警对齐，避免界面读库仍见旧误报。
    """
    rid = P.report_id(report_file)
    dbp = _resolve_db_path(rid) or P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp:
        return False
    # 尚无库则跳过（full 会建）；勿在 light 建空库丢掉采集
    if not Path(dbp).is_file():
        return False
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        conn.execute("DELETE FROM findings_agg")
        agg_rows = []
        for item in analysis.get("findings_aggregated") or []:
            if not isinstance(item, dict):
                continue
            ex = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            if not ex:
                ex = {
                    k: item.get(k)
                    for k in ("type", "name", "reason", "kind", "path", "file_count", "file", "members_truncated")
                    if k in item and item.get(k) is not None
                }
            else:
                ex = {k: v for k, v in ex.items() if k != "members"}
            agg_rows.append(
                (
                    item.get("id") or f"{item.get('category')}|{item.get('title')}",
                    item.get("category") or "",
                    item.get("severity") or "medium",
                    item.get("title") or "",
                    int(item.get("count") or 1),
                    _jdump(item.get("evidence") or []),
                    _jdump(item.get("sources") or []),
                    item.get("rule_id") or "",
                    item.get("matcher") or "",
                    _jdump(ex),
                )
            )
        if agg_rows:
            conn.executemany(
                """INSERT OR REPLACE INTO findings_agg
                   (id,category,severity,title,count,evidence,sources,rule_id,matcher,extra)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                agg_rows,
            )

        def _upsert_blob(name: str, data: Any) -> None:
            conn.execute("DELETE FROM blobs WHERE name=?", (name,))
            conn.execute("INSERT INTO blobs(name,data) VALUES(?,?)", (name, _jdump(data)))

        summary = analysis.get("summary") or {}
        summary_agg = analysis.get("summary_aggregated") or {}
        pipe = analysis.get("pipeline") or {}
        pipe_slim = {
            "matchers": pipe.get("matchers") or [],
            "rules_used": pipe.get("rules_used") or [],
        }
        _upsert_blob("summary", summary)
        _upsert_blob("summary_aggregated", summary_agg)
        _upsert_blob("pipeline", pipe_slim)
        raw = analysis.get("findings") or []
        _upsert_blob("findings_raw_sample", raw[:200])
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
            ("raw_findings_total", str(len(raw))),
        )
        fbm = analysis.get("findings_by_module") or {}
        fbm_slim = {}
        for k, block in fbm.items():
            if not isinstance(block, dict):
                continue
            items = block.get("findings") or []
            fbm_slim[k] = {
                "matcher": block.get("matcher") or k,
                "count": block.get("count") or len(items),
                "high": block.get("high") or 0,
                "findings": items[:300],
                "truncated": len(items) > 300,
            }
        _upsert_blob("findings_by_module", fbm_slim)
        conn.commit()
        return True
    except Exception as e:
        print(f"[db_store] sync_findings_to_analysis_db: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()


def _derive_file_scan_roots(files: List[Any]) -> Dict[str, int]:
    """从路径推断分目录计数（兼容旧报告无 file_scan_roots）。"""
    st: Dict[str, int] = {}
    for f in files or []:
        if not isinstance(f, dict):
            continue
        tag = str(f.get("root") or "").strip()
        if not tag:
            p = str(f.get("full_path") or f.get("path") or "").lower().replace("/", "\\")
            if "\\users\\" in p or p.startswith("c:\\users"):
                tag = "Users"
            elif "programdata" in p:
                tag = "ProgramData"
            elif "program files (x86)" in p:
                tag = "ProgramFilesX86"
            elif "program files" in p:
                tag = "ProgramFiles"
            elif "\\windows\\" in p or p.startswith("c:\\windows"):
                tag = "Windows"
            else:
                tag = "Other"
        st[tag] = st.get(tag, 0) + 1
    return st


def _count_blob_fast(conn, name: str, meta: Dict[str, str]) -> int:
    """优先读 count_* meta；file_scans 用 files 表 COUNT；否则不解析大 JSON（返回 0）。"""
    ck = f"count_{name}"
    if ck in meta:
        try:
            return int(meta[ck] or 0)
        except ValueError:
            pass
    if name == "file_scans":
        try:
            row = conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()
            return int(row["c"] or 0) if row else 0
        except Exception:
            return 0
    if name == "event_logs":
        try:
            row = conn.execute("SELECT COUNT(1) AS c FROM event_logs").fetchone()
            n = int(row["c"] or 0) if row else 0
            if n:
                return n
        except Exception:
            pass
    # 旧库无 count_*：摘要路径绝不解析大 blob（避免热路径拖垮）
    return 0


def _nested_artifact_count(blob: Any) -> int:
    """dict 类采集块：累加列表长度 + 非空文本字段。"""
    if not isinstance(blob, dict):
        if isinstance(blob, list):
            return len(blob)
        if isinstance(blob, str) and blob.strip():
            return 1
        return 0
    n = 0
    for v in blob.values():
        if isinstance(v, list):
            n += len(v)
        elif isinstance(v, str) and v.strip():
            n += 1
        elif isinstance(v, dict) and v:
            n += 1
    return n


def _load_one_blob(conn, name: str) -> Any:
    row = conn.execute("SELECT data FROM blobs WHERE name=?", (name,)).fetchone()
    if not row:
        return None
    return _jload(row["data"])


def _conn_os_family(conn) -> str:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
        return str((row["value"] if row else "") or "").lower()
    except Exception:
        return ""


def _enrich_linux_section_sigs(conn, section: str, items: List[Any]) -> List[Any]:
    """读取侧补全 Linux 进程/服务/任务的软件包归属字段。"""
    if not isinstance(items, list) or not items:
        return items or []
    if section not in ("processes", "services", "scheduled_tasks", "startup_items"):
        return items
    fam = _conn_os_family(conn)
    looks = fam == "linux"
    if not looks:
        sample = next((x for x in items if isinstance(x, dict)), None)
        if sample:
            p = str(sample.get("path") or "")
            looks = p.startswith("/") or str(sample.get("name") or "").endswith(".service")
    if not looks:
        return items
    try:
        from .linux_sc_import import enrich_linux_entity_sigs
        svcs = items if section == "services" else (_load_one_blob(conn, "services") or [])
        key = section
        pack = {
            "os_family": "linux",
            "services": svcs if isinstance(svcs, list) else [],
            "processes": [],
            "scheduled_tasks": [],
            "startup_items": [],
        }
        pack[key] = items
        enrich_linux_entity_sigs(pack)
        return pack.get(key) or items
    except Exception:
        return items


def _annotate_persist_sideload_list(section: str, items: List[Any], rid: str = "") -> List[Any]:
    """服务/计划任务/启动项列表标注 sideload_suspect，供前端「含未签模块」筛选。"""
    try:
        from .matchers.persistence import annotate_persist_sideload_list
        return annotate_persist_sideload_list(section, items, rid=rid)
    except Exception:
        return items or []


def _slim_process_for_list(
    item: Any,
    *,
    sig_index: Optional[Dict[str, Dict[str, Any]]] = None,
    rid: str = "",
) -> Dict[str, Any]:
    """进程列表不下发 DLL/模块明细；点击详情时再按 PID 读取。预聚合白加黑计数。"""
    if not isinstance(item, dict):
        return {}
    out = dict(item)
    raw_for_count = dict(item)
    if sig_index:
        try:
            from .matchers.windows_process import enrich_process_modules_from_file_sigs
            enrich_process_modules_from_file_sigs(raw_for_count, sig_index)
        except Exception:
            pass
    out.pop("modules", None)
    out.pop("Modules", None)
    out.pop("dlls", None)
    out.pop("DLLs", None)
    try:
        from .matchers.windows_process import _iter_modules, _unsigned_modules, _process_host_signed_ok
    except Exception:
        _iter_modules = None  # type: ignore
        _unsigned_modules = None  # type: ignore
        _process_host_signed_ok = None  # type: ignore

    mods = _iter_modules(raw_for_count) if _iter_modules else []
    out["module_count"] = len(mods)
    unsigned_n = 0
    report_ctx: Optional[Dict[str, Any]] = None
    if rid:
        report_ctx = {
            "_rid": rid,
            "_files_rid": rid,
            "file_scans": [],
            "processes": [raw_for_count],
            "startup_items": [raw_for_count],
        }
    if _unsigned_modules:
        try:
            rule = {
                "moduleSameDirOnly": True,
                "moduleExcludeSystemPaths": True,
                "moduleExtAny": ["exe", "dll", "sys"],
                "moduleRequireExplicitUnsigned": True,
            }
            unsigned_n = len(_unsigned_modules(raw_for_count, rule, report_ctx))
        except Exception:
            unsigned_n = 0
    out["unsigned_module_count"] = unsigned_n
    out["dirty_unsigned_module_count"] = unsigned_n
    host_signed = False
    st = str(out.get("sig_status") or out.get("SigStatus") or "").strip().lower()
    if out.get("signed") is True or st in ("valid", "signed") or "valid" in st:
        host_signed = True
    elif _process_host_signed_ok:
        try:
            host_signed = bool(_process_host_signed_ok(
                raw_for_count,
                {"requireHostSigned": True, "requireUnsignedModule": True},
                report_ctx,
            ))
        except Exception:
            pass
    # Linux：软件包归属 ≠ Authenticode 白加黑
    path0 = str(out.get("path") or out.get("image_path") or "")
    if path0.startswith("/") or str(out.get("sig_type") or "") in ("package", "kernel"):
        out["sideload_suspect"] = False
        out["unsigned_module_count"] = 0
        out["dirty_unsigned_module_count"] = 0
    else:
        out["sideload_suspect"] = bool(host_signed and unsigned_n > 0)
    out["process_detail_lazy"] = True
    return out


def _file_sig_index_for_processes(conn, items: List[Any], rid: str = "") -> Dict[str, Dict[str, Any]]:
    """为当前页进程的未签模块路径，从 files 表批量取 Valid 签名。"""
    need: List[str] = []
    seen: Set[str] = set()
    try:
        from .matchers.windows_process import _iter_modules, _module_path
        from .matchers.persistence import _is_unsigned
    except Exception:
        return {}
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for m in _iter_modules(it):
            if not _is_unsigned(m):
                continue
            mp = _module_path(m)
            if not mp:
                continue
            low = mp.lower()
            if low in seen:
                continue
            seen.add(low)
            need.append(mp)
    if not need:
        return {}
    # 调用方通常已经持有当前报告连接；仅当当前库确实没有 files 时才走懒入库兜底。
    if rid:
        try:
            has_files = conn.execute("SELECT 1 FROM files LIMIT 1").fetchone()
        except Exception:
            has_files = None
        if not has_files:
            try:
                return lookup_file_sigs_by_paths(rid, need) or {}
            except Exception:
                pass
    out: Dict[str, Dict[str, Any]] = {}
    try:
        _ensure_files_path_norm_index(conn, create=False)
        for i in range(0, len(need), 400):
            chunk = need[i : i + 400]
            ph = ",".join("?" * len(chunk))
            lows = [x.lower().replace("/", "\\") for x in chunk]
            rows = conn.execute(
                "SELECT full_path,signed,signer,sig_status,sig_type,company "
                f"FROM files WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                lows,
            ).fetchall()
            for r in rows or []:
                fp = str(r["full_path"] or "").strip()
                if not fp:
                    continue
                keys = r.keys()
                out[fp.replace("/", "\\").lower()] = {
                    "full_path": fp,
                    "signed": bool(r["signed"]),
                    "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (r["company"] if "company" in keys else "") or "",
                }
    except Exception:
        return out
    return out


def load_process_detail(report_file: str, pid: int) -> Optional[Dict[str, Any]]:
    """按 PID 返回单个进程完整详情（含模块/DLL、父/子进程名称与路径）。"""
    rid = P.report_id(report_file)
    dbp = _resolve_db_path(rid)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        raw = _load_one_blob(conn, "processes") or []
        if not isinstance(raw, list):
            return None
        target = None
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                item_pid = int(item.get("pid") if item.get("pid") is not None else item.get("PID"))
            except (TypeError, ValueError):
                continue
            if item_pid == int(pid):
                target = item
                break
        if target is None:
            return None
        try:
            from .text_fix import sanitize_process_modules, fix_tree
            pack = sanitize_process_modules({"processes": fix_tree([target], depth=0)})
            fixed = pack.get("processes") or [target]
            target = fixed[0] if fixed else target
        except Exception:
            pass
        target = dict(target)
        try:
            sig_idx = _file_sig_index_for_processes(conn, [target], rid=str(rid or ""))
            if sig_idx:
                from .matchers.windows_process import enrich_process_modules_from_file_sigs
                enrich_process_modules_from_file_sigs(target, sig_idx)
        except Exception:
            pass
        return _enrich_process_family(target, raw)
    finally:
        conn.close()


def _proc_pid(item: Dict[str, Any]) -> int:
    try:
        return int(item.get("pid") if item.get("pid") is not None else item.get("PID") or 0)
    except (TypeError, ValueError):
        return 0


def _proc_ppid(item: Dict[str, Any]) -> int:
    try:
        return int(item.get("ppid") if item.get("ppid") is not None else item.get("PPID") or 0)
    except (TypeError, ValueError):
        return 0


def _enrich_process_family(target: Dict[str, Any], all_procs: List[Any]) -> Dict[str, Any]:
    """把 children 的纯 PID 列表解析成带 name/path 的 child_details，并补全父进程。"""
    by_pid: Dict[int, Dict[str, Any]] = {}
    for p in all_procs or []:
        if not isinstance(p, dict):
            continue
        pid = _proc_pid(p)
        if pid:
            by_pid[pid] = p

    out = dict(target)
    my_pid = _proc_pid(out)
    ppid = _proc_ppid(out)
    parent = by_pid.get(ppid) if ppid and ppid != my_pid else None
    if parent:
        out["parent_name"] = str(parent.get("name") or out.get("parent_name") or "")
        out["parent_path"] = str(parent.get("path") or "")
        out["parent_command_line"] = str(
            parent.get("command_line") or parent.get("command") or parent.get("CommandLine") or ""
        )

    kids_raw = out.get("children") if out.get("children") is not None else out.get("Children")
    if not isinstance(kids_raw, list):
        kids_raw = []
    child_details: List[Dict[str, Any]] = []
    seen: Set[int] = set()

    def _push_child(cpid: int, src: Optional[Dict[str, Any]] = None) -> None:
        if not cpid or cpid in seen or cpid == my_pid:
            return
        seen.add(cpid)
        ch = src or by_pid.get(cpid) or {}
        child_details.append({
            "pid": cpid,
            "name": str(ch.get("name") or ""),
            "path": str(ch.get("path") or ""),
            "command_line": str(ch.get("command_line") or ch.get("command") or ch.get("CommandLine") or ""),
            "user": str(ch.get("user") or ch.get("User") or ""),
        })

    for k in kids_raw:
        if isinstance(k, dict):
            _push_child(_proc_pid(k), k)
            continue
        try:
            _push_child(int(k))
        except (TypeError, ValueError):
            continue

    # 按 PPID 回扫，避免旧报告 children 为空或不全
    if my_pid:
        for p in all_procs or []:
            if not isinstance(p, dict):
                continue
            if _proc_ppid(p) == my_pid:
                _push_child(_proc_pid(p), p)

    child_details.sort(key=lambda x: int(x.get("pid") or 0))
    out["child_details"] = child_details
    out["children"] = [int(c["pid"]) for c in child_details if c.get("pid")]
    return out


def _lookup_files_by_basenames(conn, names: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    want = [str(n or "").strip().lower() for n in names if str(n or "").strip()]
    if not want:
        return out
    try:
        for nm in want[:80]:
            row = conn.execute(
                "SELECT full_path FROM files WHERE lower(name)=? AND full_path IS NOT NULL "
                "AND full_path != '' LIMIT 8",
                (nm,),
            ).fetchall()
            for r in row or []:
                fp = str(r["full_path"] or "").strip()
                if fp:
                    cur = out.get(nm, "")
                    low = fp.lower()
                    risky = any(x in low for x in (
                        "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\temp\\",
                    ))
                    if not cur or (risky and not any(x in cur.lower() for x in (
                        "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\temp\\",
                    ))):
                        out[nm] = fp
    except sqlite3.OperationalError:
        pass
    return out


def _lookup_file_meta_by_paths(conn, paths: List[str]) -> Dict[str, Dict[str, Any]]:
    """按完整路径从 files 表取签名/公司等，供列表页补字段（不读 processes blob）。"""
    out: Dict[str, Dict[str, Any]] = {}
    want = []
    seen = set()
    for p in paths or []:
        fp = str(p or "").strip().replace("/", "\\")
        if not fp:
            continue
        low = fp.lower()
        if low in seen:
            continue
        seen.add(low)
        want.append(fp)
    if not want:
        return out
    try:
        for i in range(0, len(want), 200):
            chunk = want[i : i + 200]
            ph = ",".join("?" * len(chunk))
            lows = [x.lower() for x in chunk]
            rows = conn.execute(
                "SELECT full_path,signed,signer,sig_status,sig_type,company,product,description,"
                "file_version,md5,sha1,sha256 FROM files "
                f"WHERE lower(replace(full_path,'/','\\')) IN ({ph})",
                lows,
            ).fetchall()
            for r in rows or []:
                fp = str(r["full_path"] or "").strip()
                if not fp:
                    continue
                keys = r.keys()
                out[fp.replace("/", "\\").lower()] = {
                    "signed": bool(r["signed"]),
                    "signer": r["signer"] or "",
                    "sig_status": r["sig_status"] or "",
                    "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                    "company": (r["company"] if "company" in keys else "") or "",
                    "product": (r["product"] if "product" in keys else "") or "",
                    "description": (r["description"] if "description" in keys else "") or "",
                    "file_version": (r["file_version"] if "file_version" in keys else "") or "",
                    "md5": (r["md5"] if "md5" in keys else "") or "",
                    "sha1": (r["sha1"] if "sha1" in keys else "") or "",
                    "sha256": (r["sha256"] if "sha256" in keys else "") or "",
                }
    except sqlite3.OperationalError:
        pass
    return out


def _apply_file_meta_to_items(conn, items: List[Any]) -> List[Any]:
    paths = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        p = str(it.get("resolved_path") or it.get("path") or "").strip()
        if p and ("\\" in p or "/" in p):
            paths.append(p)
    meta = _lookup_file_meta_by_paths(conn, paths)
    if not meta:
        return items
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            out.append(it)
            continue
        row = dict(it)
        p = str(row.get("resolved_path") or row.get("path") or "").replace("/", "\\").lower()
        m = meta.get(p) if p else None
        if m:
            st = str(row.get("sig_status") or "").strip().lower()
            need = (
                not st or st in ("error", "unknown", "missing", "unchecked", "n/a", "-")
                or st.startswith("error_")
                or not (row.get("md5") or row.get("sha256") or row.get("signer"))
            )
            if need:
                for k, v in m.items():
                    if v in (None, ""):
                        continue
                    if k in ("signed", "signer", "sig_status", "sig_type") or not row.get(k):
                        row[k] = v
        out.append(row)
    return out


def _resolve_task_paths_from_conn(conn, items: List[Any]) -> List[Any]:
    """列表页路径补全：只用 files 表 basename + 已知系统路径，不加载 processes 大 blob。"""
    if not items or not any(isinstance(x, dict) for x in items):
        return items
    try:
        from .ingest import resolve_scheduled_task_paths, _first_bare_exe
    except Exception:
        return items
    names = []
    for t in items:
        if not isinstance(t, dict):
            continue
        path = str(t.get("path") or t.get("resolved_path") or "")
        cmd = str(t.get("command") or "")
        if "\\" not in path and "/" not in path:
            b = _first_bare_exe(cmd) or _first_bare_exe(path)
            if b:
                names.append(b)
    extra = _lookup_files_by_basenames(conn, names) if names else {}
    pack = {
        "processes": [],
        "prefetch_files": [],
        "startup_items": [],
        "scheduled_tasks": items,
    }
    resolve_scheduled_task_paths(pack, extra)
    resolved = pack.get("scheduled_tasks") or items
    try:
        return _apply_file_meta_to_items(conn, resolved)
    except Exception:
        return resolved


def _resolve_startup_paths_from_conn(conn, items: List[Any]) -> List[Any]:
    """启动项列表路径补全：files basename + 系统已知路径，不读 processes/services blob。"""
    if not items or not any(isinstance(x, dict) for x in items):
        return items
    try:
        from .ingest import resolve_startup_item_paths, _first_bare_exe
    except Exception:
        return items
    names = []
    for it in items:
        if not isinstance(it, dict):
            continue
        path = str(it.get("path") or it.get("resolved_path") or "")
        cmd = str(it.get("command") or "")
        if "\\" not in path and "/" not in path:
            b = _first_bare_exe(cmd) or _first_bare_exe(path)
            if b:
                names.append(b)
    extra = _lookup_files_by_basenames(conn, names) if names else {}
    pack = {
        "startup_items": items,
        "processes": [],
        "prefetch_files": [],
        "services": [],
        "scheduled_tasks": [],
    }
    resolve_startup_item_paths(pack, extra)
    resolved = pack.get("startup_items") or items
    try:
        return _apply_file_meta_to_items(conn, resolved)
    except Exception:
        return resolved


def load_timeline_only(report_file: str) -> Optional[List[Dict[str, Any]]]:
    """只读 timeline blob / MySQL，不加载大段采集与全量 view。"""
    # MySQL 优先
    try:
        from .mysql_store import load_analysis_from_mysql
        ma = load_analysis_from_mysql(report_file)
        if ma and isinstance(ma.get("timeline"), list) and ma["timeline"]:
            return ma["timeline"]
    except Exception:
        pass
    dbp = _resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        tl = _load_one_blob(conn, "timeline")
        if isinstance(tl, list) and tl:
            return tl
    except Exception:
        return None
    finally:
        conn.close()
    return None


def _item_search_blob(item: Any) -> str:
    """全字段可搜文本：嵌套 dict/list 全展开；空/-/N/A 不入索引；未签名带同义词。"""
    parts: List[str] = []

    def walk(v: Any, depth: int = 0) -> None:
        if v is None or depth > 10:
            return
        if isinstance(v, bool):
            parts.append("true" if v else "false")
            return
        if isinstance(v, (int, float)):
            parts.append(str(v))
            return
        if isinstance(v, str):
            s = v.strip()
            if not s or s in ("-", "—", "–", "N/A", "n/a", "(空)", "无"):
                return
            parts.append(s)
            return
        if isinstance(v, dict):
            for k, val in v.items():
                if str(k).startswith("_"):
                    continue
                walk(val, depth + 1)
            return
        if isinstance(v, (list, tuple)):
            for x in v:
                walk(x, depth + 1)

    walk(item)
    if isinstance(item, dict):
        st = str(item.get("sig_status") or item.get("SigStatus") or "").strip().lower()
        signed_flag = item.get("signed")
        if signed_flag is None:
            signed_flag = item.get("Signed")
        empty_st = (not st) or st in ("-", "—", "n/a", "空签名")
        is_signed = False
        if not empty_st:
            if st in ("missing", "notsigned", "unsigned", "error", "unknown", "hashmismatch", "nottrusted"):
                is_signed = False
            else:
                is_signed = st == "valid" or st == "signed" or ("valid" in st)
        elif signed_flag is True:
            is_signed = True

        if is_signed:
            parts.extend(["signed", "已签名", "Valid"])
            ty = str(item.get("sig_type") or item.get("SigType") or "").strip().lower()
            if ty == "catalog":
                parts.extend(["Valid(目录)", "目录签名"])
            elif ty == "authenticode":
                parts.extend(["Valid(文件)", "文件签名"])
        elif empty_st:
            # signed=false 但无 status → 仍算空签名，不挂「未签名」
            parts.extend(["空签名", "empty", "nosig", "无状态"])
        else:
            parts.extend(["unsigned", "未签名", "无签名"])

        dll = item.get("service_dll") or item.get("ServiceDll") or item.get("serviceDll")
        if dll:
            parts.append("ServiceDll")
            parts.append(str(dll))
        mods = item.get("modules")
        if mods is None:
            mods = item.get("Modules")
        if isinstance(mods, list):
            parts.append(f"模块({len(mods)})")
            parts.append("模块")
            for m in mods:
                walk(m, 0)
        dlls = item.get("dlls")
        if dlls is None:
            dlls = item.get("DLLs")
        if isinstance(dlls, list) and dlls:
            parts.append("DLL")
            for d in dlls:
                walk(d, 0)
        pid = item.get("pid") if item.get("pid") is not None else item.get("PID")
        if pid is not None and str(pid).strip() not in ("", "-"):
            parts.extend([str(pid), "PID"])
    return " ".join(parts).lower()


_DATE_Q_RE = re.compile(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$")


def _date_q_variants(tok: str):
    """把 2026-04-20 / 2026/4/20 展开成多种日期写法。"""
    m = _DATE_Q_RE.match(str(tok or "").strip())
    if not m:
        return None
    y = m.group(1)
    try:
        mo, d = int(m.group(2)), int(m.group(3))
    except Exception:
        return None
    if not (1 <= mo <= 12 and 1 <= d <= 31):
        return None
    mm, dd = f"{mo:02d}", f"{d:02d}"
    return [
        f"{y}-{mm}-{dd}",
        f"{y}/{mm}/{dd}",
        f"{y}-{mo}-{d}",
        f"{y}/{mo}/{d}",
        f"{y}{mm}{dd}",
        f"{y}年{mm}月{dd}日",
        f"{y}年{mo}月{d}日",
    ]


def _token_in_blob(tok: str, blob: str) -> bool:
    variants = _date_q_variants(tok)
    if variants:
        return any(v.lower() in blob for v in variants)
    return tok in blob


def _item_match_q(item: Any, q: str) -> bool:
    if not q:
        return True
    tokens = [t for t in str(q).lower().split() if t and t not in ("-", "—", "–")]
    if not tokens:
        return True
    blob = _item_search_blob(item)
    return all(_token_in_blob(t, blob) for t in tokens)



def load_summary_view(report_file: str) -> Optional[Dict[str, Any]]:
    """轻量视图：只读 meta + findings + 少量摘要 blob，不加载进程/文件等大数组。"""
    dbp = _resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
        # 告警以 result.json/analysis.db 较新者为准，勿被下方 MySQL 旧数据覆盖
        findings = slim_findings_list(_load_fresh_findings(report_file))
        blobs_small = {}
        for name in _SUMMARY_BLOB_NAMES:
            row = conn.execute("SELECT data FROM blobs WHERE name=?", (name,)).fetchone()
            if row and row["data"]:
                blobs_small[name] = _jload(row["data"])

        fbm_raw = blobs_small.get("findings_by_module") or {}
        timeline = blobs_small.get("timeline") or []
        if isinstance(timeline, list) and len(timeline) > 120:
            timeline = timeline[:120]

        analysis = {
            "findings_aggregated": findings,
            "findings": slim_findings_list(blobs_small.get("findings_raw_sample") or [], preview=3),
            "findings_by_module": slim_findings_by_module(fbm_raw),
            "summary": blobs_small.get("summary") or {},
            "summary_aggregated": blobs_small.get("summary_aggregated") or {"total": len(findings)},
            "pipeline": blobs_small.get("pipeline") or {},
            "timeline": timeline,
            "ai": blobs_small.get("ai"),
            "meta": blobs_small.get("analysis_meta") or {},
            "ioc_hits": {},
        }
        if "raw_total" not in analysis["summary_aggregated"]:
            analysis["summary_aggregated"]["raw_total"] = int(meta.get("raw_findings_total") or len(analysis["findings"]))

        # MySQL 可补摘要/AI；告警列表保持本地较新结果，避免 light 重分析后仍显示旧误报
        try:
            from .mysql_store import load_analysis_from_mysql
            ma = load_analysis_from_mysql(report_file)
            if ma:
                local_findings = list(findings or [])
                for key in (
                    "summary", "summary_aggregated", "pipeline", "timeline",
                    "findings_by_module", "meta", "ai",
                ):
                    if ma.get(key) is not None and ma.get(key) != {} and ma.get(key) != []:
                        if key == "findings_by_module" and analysis.get("findings_by_module"):
                            continue
                        analysis[key] = ma[key]
                if local_findings:
                    analysis["findings_aggregated"] = local_findings
                    analysis["findings"] = slim_findings_list(
                        analysis.get("findings") or local_findings, preview=3
                    )
                    findings = local_findings
                elif ma.get("findings_aggregated"):
                    analysis["findings_aggregated"] = slim_findings_list(ma.get("findings_aggregated") or [])
                    analysis["findings"] = slim_findings_list(ma.get("findings") or [], preview=3)
                    findings = analysis["findings_aggregated"]
                if ma.get("_findings_total") is not None and not local_findings:
                    analysis["_findings_total"] = ma["_findings_total"]
                analysis["findings_by_module"] = slim_findings_by_module(
                    analysis.get("findings_by_module") or {}
                )
                tl = analysis.get("timeline") or []
                if isinstance(tl, list) and len(tl) > 120:
                    analysis["timeline"] = tl[:120]
        except Exception as e:
            print("[summary] mysql overlay:", e)

        try:
            from .pipeline import prune_inactive_modules
            analysis = prune_inactive_modules(analysis)
            findings = analysis.get("findings_aggregated") or findings
        except Exception:
            pass
        try:
            from .text_fix import fix_analysis_text
            analysis = fix_analysis_text(analysis)
            findings = analysis.get("findings_aggregated") or findings
        except Exception:
            pass

        if not findings:
            try:
                rp = P.resolve_result_json(P.report_id(report_file))
                if rp and rp.is_file():
                    with open(rp, encoding="utf-8") as fh:
                        data = json.load(fh)
                    an = data.get("analysis") if isinstance(data, dict) else None
                    if isinstance(an, dict):
                        raw = an.get("findings_aggregated") or an.get("findings") or []
                        if raw:
                            findings = slim_findings_list(raw)
                            analysis["findings_aggregated"] = findings
                            if an.get("summary_aggregated"):
                                analysis["summary_aggregated"] = an.get("summary_aggregated")
                            if an.get("pipeline"):
                                analysis["pipeline"] = an.get("pipeline")
                            analysis["summary"] = an.get("summary") or analysis.get("summary") or {}
            except Exception:
                pass

        counts: Dict[str, int] = {}
        for k in HEAVY_VIEW_KEYS:
            n = _count_blob_fast(conn, k, meta)
            if n:
                counts[k] = n
        # 嵌套 dict 采集块（执行痕迹/远程/安全）常无 count_*：轻量解析一次补计数
        for nest_name in ("execution_artifacts", "remote_access", "security_extras"):
            if counts.get(nest_name):
                continue
            try:
                nest = _load_one_blob(conn, nest_name)
                n = _nested_artifact_count(nest)
                if n:
                    counts[nest_name] = n
            except Exception:
                pass
        # 索引里常有 processes/services/files，补全旧库无 count_* 的情况
        try:
            rid0 = P.report_id(report_file)
            if INDEX_DB.exists():
                ic = _connect(INDEX_DB)
                try:
                    _init_index(ic)
                    ir = ic.execute(
                        "SELECT processes,services,files FROM reports WHERE file=?", (rid0,)
                    ).fetchone()
                    if ir:
                        if not counts.get("processes") and ir["processes"]:
                            counts["processes"] = int(ir["processes"] or 0)
                        if not counts.get("services") and ir["services"]:
                            counts["services"] = int(ir["services"] or 0)
                        if not counts.get("file_scans") and ir["files"]:
                            counts["file_scans"] = int(ir["files"] or 0)
                finally:
                    ic.close()
        except Exception:
            pass
        # 兼容旧库无 count_*：常用卡片至少给 0
        for k in ("processes", "services", "scheduled_tasks", "startup_items", "installed_programs",
                  "users", "usb_devices", "prefetch_files", "file_scans", "established_connections",
                  "wmi_namespaces", "driver_entries", "drivers", "event_logs", "browser_artifacts",
                  "office_artifacts", "ps_history"):
            counts.setdefault(k, 0)

        roots = {}
        try:
            raw_roots = meta.get("file_scan_roots") or ""
            if raw_roots:
                roots = _jload(raw_roots) or {}
        except Exception:
            roots = {}
        if not isinstance(roots, dict):
            roots = {}
        # 旧报告无分目录统计时，从 files 表快速聚合（避免全表扫 Python）
        if not roots and counts.get("file_scans"):
            try:
                row = conn.execute(
                    """
                    SELECT
                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), '\\users\\')>0
                                 OR lower(full_path) LIKE 'c:\\users%' THEN 1 ELSE 0 END) AS users,
                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'programdata')>0 THEN 1 ELSE 0 END) AS pd,
                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'program files (x86)')>0 THEN 1 ELSE 0 END) AS pfx86,
                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), 'program files')>0
                                AND instr(lower(replace(full_path,'/','\\')), 'program files (x86)')=0 THEN 1 ELSE 0 END) AS pf,
                      SUM(CASE WHEN instr(lower(replace(full_path,'/','\\')), '\\windows\\')>0
                                 OR lower(full_path) LIKE 'c:\\windows%' THEN 1 ELSE 0 END) AS win
                    FROM files
                    """
                ).fetchone()
                if row:
                    roots = {
                        "Users": int(row["users"] or 0),
                        "ProgramData": int(row["pd"] or 0),
                        "ProgramFilesX86": int(row["pfx86"] or 0),
                        "ProgramFiles": int(row["pf"] or 0),
                        "Windows": int(row["win"] or 0),
                    }
                    roots = {k: v for k, v in roots.items() if v}
            except Exception:
                pass

        out: Dict[str, Any] = {
            "hostname": meta.get("hostname"),
            "ip": meta.get("ip"),
            "os": meta.get("os"),
            "os_family": meta.get("os_family") or "",
            "collect_time": meta.get("collect_time"),
            "analysis": analysis,
            "suspicious_items": [
                {
                    "type": x.get("category"), "name": x.get("title"),
                    "reason": x.get("reason") or x.get("title"),
                    "severity": x.get("severity", "medium"),
                    "count": x.get("count", 1),
                }
                for x in findings
            ],
            "collection_quality": blobs_small.get("collection_quality") or (analysis.get("meta") or {}).get("collection_quality"),
            "file_scan_roots": roots,
            "_source": "db+summary",
            "_report_file": meta.get("report_file") or report_file,
            "_db": str(dbp.name),
            "_counts": counts,
            "_light": True,
        }
        try:
            from .quality_gate import evaluate_quality_gate
            cq = out.get("collection_quality") if isinstance(out.get("collection_quality"), dict) else None
            gate = (analysis.get("meta") or {}).get("quality_gate")
            if not isinstance(gate, dict) or not gate.get("confidence"):
                gate = evaluate_quality_gate(
                    {
                        "os_family": out.get("os_family") or "",
                        "os": out.get("os") or "",
                        "collection_quality": cq or {},
                    },
                    quality=cq,
                    counts=counts,
                    os_family=str(out.get("os_family") or ""),
                )
                analysis.setdefault("meta", {})["quality_gate"] = gate
                out["analysis"] = analysis
            out["quality_gate"] = gate
        except Exception as e:
            print("[summary] quality_gate:", e)
        try:
            from .collect_pack import load_pack_manifest
            man = load_pack_manifest(P.report_id(report_file))
            if man:
                out["_pack"] = True
                mods = man.get("modules") if isinstance(man.get("modules"), dict) else {}
                for mk, ck in (("eventlog", "event_logs"), ("files", "file_scans"),
                               ("processes", "processes"), ("network", "established_connections")):
                    n = int((mods.get(mk) or {}).get("count") or 0)
                    if n and not int(counts.get(ck) or 0):
                        counts[ck] = n
                out["_counts"] = counts
        except Exception:
            pass
        for k in ("processes", "services", "scheduled_tasks", "startup_items", "installed_programs",
                  "users", "usb_devices", "prefetch_files", "file_scans", "established_connections",
                  "wmi_namespaces", "driver_entries", "drivers", "event_logs"):
            out[k] = []
        return out
    finally:
        conn.close()


def load_section_page(
    report_file: str,
    section: str,
    offset: int = 0,
    limit: int = 100,
    q: str = "",
    channel: str = "",
    hits_only: bool = False,
) -> Optional[Dict[str, Any]]:
    """按需分页：只读对应 blob / findings，不组装整包 view。"""
    section = (section or "").strip()
    rid = P.report_id(report_file)
    offset = max(0, int(offset or 0))
    # 清单类（服务/进程/任务等）允许一次拉全量；事件日志仍按页限流
    _INVENTORY_SECTIONS = {
        "processes", "services", "scheduled_tasks", "startup_items",
        "drivers", "driver_entries", "users", "groups", "accounts",
        "installed_programs", "hotfixes", "shares", "prefetch",
        "amcache", "shimcache", "userassist", "run_mru",
        "established_connections", "open_ports", "network_adapters",
        "wmi_namespaces", "wmi_subscriptions", "browser_artifacts",
    }
    if section == "event_logs":
        cap = 2000
    elif section in _INVENTORY_SECTIONS:
        cap = 20000
    else:
        cap = 2000
    limit = max(1, min(cap, int(limit or 100)))

    if section == "findings" or section == "findings_aggregated":
        # result.json → analysis.db → MySQL（见 _load_fresh_findings）
        items: List[Any] = _load_fresh_findings(report_file)
        if q:
            ql = q.lower()
            items = [
                x for x in items
                if ql in str(x.get("title") or x.get("name") or "").lower()
                or ql in str(x.get("category") or x.get("type") or "").lower()
                or ql in str(x.get("reason") or "").lower()
                or ql in str(x.get("severity") or "").lower()
                or ql in str(x.get("evidence") or "").lower()
                or ql in str(x.get("sources") or "").lower()
                or ql in str(x.get("rule_id") or "").lower()
                or ql in str(x.get("matcher") or "").lower()
            ]
        total = len(items)
        severity_stats = {"high": 0, "medium": 0, "low": 0}
        for item in items:
            sev = str(item.get("severity") or "medium").strip().lower()
            if sev in ("critical", "high", "h", "严重", "高", "高危"):
                severity_stats["high"] += 1
            elif sev in ("low", "l", "info", "informational", "低", "低危"):
                severity_stats["low"] += 1
            else:
                severity_stats["medium"] += 1
        page_items = items[offset: offset + limit]
        return {
            "section": "findings",
            "total": total,
            "offset": offset,
            "limit": limit,
            "items": slim_findings_list(page_items),
            "severity_stats": severity_stats,
            "has_next": offset + len(page_items) < total,
            "file": rid,
        }

    dbp = _resolve_db_path(report_file)
    if not dbp:
        return None
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        # 进程/服务/计划任务/启动项：优先读瘦身投影（无 modules 大字段）
        if section in ("processes", "services", "scheduled_tasks", "startup_items"):
            try:
                from .entity_lists import query_or_build_entity_list_page

                page = query_or_build_entity_list_page(
                    conn,
                    section,
                    rid=str(rid or ""),
                    offset=offset,
                    limit=limit,
                    q=q or "",
                )
                if page is not None:
                    page["file"] = rid
                    return page
            except Exception:
                pass
        if section == "file_scans":
            # 文件走 files 表分页，避免读巨型 blob
            try:
                if q:
                    ql = f"%{q}%"
                    total = conn.execute(
                        "SELECT COUNT(1) AS c FROM files WHERE full_path LIKE ? OR name LIKE ?",
                        (ql, ql),
                    ).fetchone()["c"]
                    rows = conn.execute(
                        "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                        "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files "
                        "WHERE full_path LIKE ? OR name LIKE ? ORDER BY full_path LIMIT ? OFFSET ?",
                        (ql, ql, limit, offset),
                    ).fetchall()
                else:
                    total = None
                    try:
                        row = conn.execute(
                            "SELECT value FROM meta WHERE key='count_file_scans' LIMIT 1"
                        ).fetchone()
                        if row and str(row["value"] or "").strip().isdigit():
                            total = int(row["value"])
                    except Exception:
                        total = None
                    if total is None:
                        total = conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"]
                    rows = conn.execute(
                        "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                        "signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system FROM files "
                        "ORDER BY full_path LIMIT ? OFFSET ?",
                        (limit, offset),
                    ).fetchall()
                items = []
                for r in rows:
                    keys = r.keys()
                    items.append({
                        "full_path": r["full_path"], "name": r["name"], "path": r["path"],
                        "ext": r["ext"], "size": r["size"],
                        "company": r["company"] or "", "product": r["product"] or "",
                        "description": r["description"] or "", "file_version": r["file_version"] or "",
                        "signed": bool(r["signed"]), "signer": r["signer"] or "",
                        "sig_status": r["sig_status"] or "",
                        "sig_type": (r["sig_type"] if "sig_type" in keys else "") or "",
                        "magic_hex": r["magic_hex"] or "",
                        "md5": (r["md5"] if "md5" in keys else "") or "",
                        "sha1": (r["sha1"] if "sha1" in keys else "") or "",
                        "sha256": (r["sha256"] if "sha256" in keys else "") or "",
                        "hidden": bool(r["hidden"]) if "hidden" in keys else False,
                        "system": bool(r["system"]) if "system" in keys else False,
                    })
                return {
                    "section": section, "total": int(total or 0), "offset": offset,
                    "limit": limit, "items": items, "file": rid,
                }
            except sqlite3.OperationalError:
                pass  # fall through to blob

        if section == "event_logs":
            try:
                pack = _query_event_logs_page(
                    conn,
                    offset=offset,
                    limit=limit,
                    q=q,
                    channel=channel,
                    rid=rid,
                    hits_only=bool(hits_only),
                )
                out = {
                    "section": section,
                    "total": int(pack.get("total") or 0),
                    "total_approx": bool(pack.get("total_approx")),
                    "offset": offset,
                    "limit": limit,
                    "items": pack.get("items") or [],
                    "file": rid,
                    "hits_only": bool(hits_only or pack.get("hits_only")),
                }
                if offset == 0:
                    try:
                        out["channel_stats"] = _event_log_channel_stats(conn)
                    except Exception:
                        pass
                return out
            except sqlite3.OperationalError:
                pass

        raw = None if section in RETIRED_BLOB_KEYS else _load_one_blob(conn, section)
        if raw is None:
            return {
                "section": section, "total": 0, "offset": 0, "limit": limit,
                "items": [], "file": rid,
            }
        if isinstance(raw, list):
            items = raw
            if section == "processes":
                total = len(items)
                # 进程模块/DLL 可能很大；无搜索时先分页，再做文本修复。
                # 旧逻辑会修复完整 blob 后才切片，打开进程页容易长时间停在加载中。
                if not q:
                    items = items[offset: offset + limit]
                try:
                    from .text_fix import sanitize_process_modules, fix_tree
                    pack = sanitize_process_modules({"processes": fix_tree(items, depth=0)})
                    items = pack.get("processes") or items
                except Exception:
                    pass
                items = _enrich_linux_section_sigs(conn, "processes", items)
                if not q:
                    sig_idx = _file_sig_index_for_processes(conn, items, rid=str(rid or ""))
                    return {
                        "section": section, "total": total, "offset": offset,
                        "limit": limit,
                        "items": [_slim_process_for_list(x, sig_index=sig_idx, rid=str(rid or "")) for x in items],
                        "file": rid,
                    }
            if section == "scheduled_tasks":
                total = len(items)
                # 无搜索：先分页再路径补全，避免对全量任务 + 进程 blob 做重活
                if not q:
                    page = items[offset: offset + limit]
                    page = _resolve_task_paths_from_conn(conn, page)
                    page = _enrich_linux_section_sigs(conn, section, page)
                    page = _annotate_persist_sideload_list(section, page, rid=str(rid or ""))
                    try:
                        from .ingest import normalize_item_sig_fields
                        page = [
                            normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
                            for x in page
                        ]
                    except Exception:
                        pass
                    return {
                        "section": section, "total": total, "offset": offset,
                        "limit": limit, "items": page, "file": rid,
                        "has_next": offset + len(page) < total,
                    }
                items = _resolve_task_paths_from_conn(conn, items)
            if section == "startup_items" and isinstance(items, list) and items:
                total = len(items)
                if not q:
                    page = items[offset: offset + limit]
                    page = _resolve_startup_paths_from_conn(conn, page)
                    # Linux 启动项仍可能需要 services；仅在像 Linux 时再读
                    try:
                        from .linux_sc_import import enrich_linux_startups
                        fam = ""
                        try:
                            row = conn.execute(
                                "SELECT value FROM meta WHERE key='os_family'"
                            ).fetchone()
                            fam = str((row["value"] if row else "") or "")
                        except Exception:
                            fam = ""
                        looks_linux = fam.lower() == "linux" or any(
                            str(x.get("name") or "").endswith(".service")
                            for x in page[:20] if isinstance(x, dict)
                        )
                        if looks_linux:
                            svc_raw = _load_one_blob(conn, "services") or []
                            pack = enrich_linux_startups({
                                "os_family": "linux",
                                "collector": "linuxsc",
                                "startup_items": page,
                                "services": svc_raw if isinstance(svc_raw, list) else [],
                            })
                            page = pack.get("startup_items") or page
                    except Exception:
                        pass
                    page = _enrich_linux_section_sigs(conn, section, page)
                    page = _annotate_persist_sideload_list(section, page, rid=str(rid or ""))
                    try:
                        from .ingest import normalize_item_sig_fields
                        page = [
                            normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
                            for x in page
                        ]
                    except Exception:
                        pass
                    return {
                        "section": section, "total": total, "offset": offset,
                        "limit": limit, "items": page, "file": rid,
                        "has_next": offset + len(page) < total,
                    }
                try:
                    page_all = _resolve_startup_paths_from_conn(conn, items)
                    items = page_all
                except Exception:
                    pass
                try:
                    from .linux_sc_import import enrich_linux_startups
                    fam = ""
                    try:
                        row = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
                        fam = str((row["value"] if row else "") or "")
                    except Exception:
                        fam = ""
                    looks_linux = fam.lower() == "linux" or any(
                        str(x.get("name") or "").endswith(".service")
                        for x in items[:20] if isinstance(x, dict)
                    )
                    if looks_linux:
                        svc_raw = _load_one_blob(conn, "services") or []
                        pack = enrich_linux_startups({
                            "os_family": "linux",
                            "collector": "linuxsc",
                            "startup_items": items,
                            "services": svc_raw if isinstance(svc_raw, list) else [],
                        })
                        items = pack.get("startup_items") or items
                except Exception:
                    pass
            if section in ("established_connections", "open_ports", "listening_ports"):
                try:
                    from .net_process import enrich_conn_list
                    enrich_conn_list(items, _process_index_from_conn(conn))
                except Exception:
                    pass
        elif isinstance(raw, dict):
            # ps_artifacts 等需保留整包（history_entries/profiles/logging）
            return {
                "section": section, "total": 1, "offset": 0, "limit": 1,
                "items": [raw], "file": rid, "as_object": True,
            }
        else:
            val = "" if raw is None else raw
            return {
                "section": section,
                "total": 1 if val != "" else 0,
                "offset": 0, "limit": 1,
                "items": [val] if val != "" else [],
                "file": rid, "as_scalar": True,
            }
        if q:
            items = [x for x in items if _item_match_q(x, q)]
        # blob fallback：event_logs 支持 hits_only 过滤
        if section == "event_logs" and hits_only and isinstance(items, list) and items:
            try:
                idx = _eventlog_hit_index_for_rid(rid) if rid else {}
                from .eventlog_rules import event_hit_key
                matched = []
                seen: Set[str] = set()
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    hk = event_hit_key(it.get("channel"), it.get("event_id"), it.get("time"))
                    info = idx.get(hk) if hk else None
                    if not hk or not info or hk in seen:
                        continue
                    seen.add(hk)
                    it = dict(it)
                    it["hit_rule"] = info
                    matched.append(it)
                items = matched
            except Exception:
                pass
            total = len(items)
            return {
                "section": section, "total": total, "offset": offset,
                "limit": limit, "items": items[offset: offset + limit], "file": rid,
                "hits_only": True,
            }
        total = len(items)
        # 无筛选时回写 count_*，后续摘要无需再猜
        if not q:
            try:
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (f"count_{section}", str(total)),
                )
                conn.commit()
            except Exception:
                pass
        page_items = items[offset: offset + limit]
        if section in ("processes", "services", "scheduled_tasks", "startup_items"):
            page_items = _enrich_linux_section_sigs(conn, section, page_items)
        if section in ("services", "scheduled_tasks", "startup_items"):
            page_items = _annotate_persist_sideload_list(section, page_items, rid=str(rid or ""))
            try:
                from .ingest import normalize_item_sig_fields
                page_items = [
                    normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
                    for x in page_items
                ]
            except Exception:
                pass
        return {
            "section": section, "total": total, "offset": offset,
            "limit": limit, "items": page_items, "file": rid,
        }
    finally:
        conn.close()


def load_sections_batch(
    report_file: str,
    names: List[str],
    limit: int = 600,
) -> Dict[str, Any]:
    """一次打开 DB，批量取多个 section（减少重复连接与重复解析）。"""
    rid = P.report_id(report_file)
    # 与 /sections 的公开上限一致；否则前端请求 2000 会被静默截成 500。
    limit = max(1, min(2000, int(limit or 600)))
    want = [((n or "").strip()) for n in (names or []) if (n or "").strip()]
    out: Dict[str, Any] = {}
    if not want:
        return {"file": rid, "sections": out}

    # findings 可能走 MySQL，单独处理
    need_findings = [n for n in want if n in ("findings", "findings_aggregated")]
    blob_names = [n for n in want if n not in ("findings", "findings_aggregated")]
    for n in need_findings:
        page = load_section_page(report_file, n, offset=0, limit=limit)
        if page is not None:
            out[n if n != "findings_aggregated" else "findings"] = page

    if not blob_names:
        return {"file": rid, "sections": out}

    dbp = _resolve_db_path(report_file)
    if not dbp:
        for n in blob_names:
            page = load_section_page(report_file, n, offset=0, limit=limit)
            if page is not None:
                out[n] = page
        return {"file": rid, "sections": out}

    conn = _connect(dbp)
    try:
        _init_schema(conn)
        net_idx = None
        if any(s in ("established_connections", "open_ports", "listening_ports") for s in blob_names):
            try:
                net_idx = _process_index_from_conn(conn)
            except Exception:
                net_idx = {}
        for section in blob_names:
            if section == "file_scans":
                try:
                    total = conn.execute("SELECT COUNT(1) AS c FROM files").fetchone()["c"]
                    rows = conn.execute(
                        "SELECT full_path,name,path,ext,size,company,product,description,file_version,"
                        "signed,signer,sig_status,sig_type,magic_hex,hidden,system FROM files "
                        "ORDER BY full_path LIMIT ?",
                        (limit,),
                    ).fetchall()
                    items = [{
                        "full_path": r["full_path"], "name": r["name"], "path": r["path"],
                        "ext": r["ext"], "size": r["size"],
                        "company": r["company"] or "", "product": r["product"] or "",
                        "description": r["description"] or "", "file_version": r["file_version"] or "",
                        "signed": bool(r["signed"]), "signer": r["signer"] or "",
                        "sig_status": r["sig_status"] or "",
                        "sig_type": (r["sig_type"] if "sig_type" in r.keys() else "") or "",
                        "magic_hex": r["magic_hex"] or "",
                        "hidden": bool(r["hidden"]) if "hidden" in r.keys() else False,
                        "system": bool(r["system"]) if "system" in r.keys() else False,
                    } for r in rows]
                    out[section] = {
                        "section": section, "total": int(total or 0), "offset": 0,
                        "limit": limit, "items": items, "file": rid,
                    }
                    continue
                except sqlite3.OperationalError:
                    pass
            if section == "event_logs":
                try:
                    pack = _query_event_logs_page(conn, offset=0, limit=limit, q="")
                    out[section] = {
                        "section": section,
                        "total": int(pack.get("total") or 0),
                        "offset": 0,
                        "limit": limit,
                        "items": pack.get("items") or [],
                        "file": rid,
                    }
                    continue
                except sqlite3.OperationalError:
                    pass
            if section in ("processes", "services", "scheduled_tasks", "startup_items"):
                try:
                    from .entity_lists import query_or_build_entity_list_page

                    page = query_or_build_entity_list_page(
                        conn, section, rid=str(rid or ""), offset=0, limit=limit, q="",
                    )
                    if page is not None:
                        page["file"] = rid
                        out[section] = page
                        continue
                except Exception:
                    pass
            raw = None if section in RETIRED_BLOB_KEYS else _load_one_blob(conn, section)
            if raw is None:
                out[section] = {
                    "section": section, "total": 0, "offset": 0, "limit": limit,
                    "items": [], "file": rid,
                }
            elif isinstance(raw, list):
                if section == "processes":
                    total_raw = len(raw)
                    raw = raw[:limit]
                    try:
                        from .text_fix import sanitize_process_modules, fix_tree
                        pack = sanitize_process_modules({"processes": fix_tree(raw, depth=0)})
                        raw = pack.get("processes") or raw
                    except Exception:
                        pass
                    sig_idx = _file_sig_index_for_processes(conn, raw, rid=str(rid or ""))
                    raw = [_slim_process_for_list(x, sig_index=sig_idx, rid=str(rid or "")) for x in raw]
                else:
                    total_raw = len(raw)
                if section == "scheduled_tasks":
                    raw = _resolve_task_paths_from_conn(conn, raw[:limit])
                if section == "startup_items":
                    raw = _resolve_startup_paths_from_conn(conn, raw[:limit])
                if section in ("services", "scheduled_tasks", "startup_items"):
                    raw = _annotate_persist_sideload_list(section, raw[:limit] if section != "processes" else raw, rid=str(rid or ""))
                    try:
                        from .ingest import normalize_item_sig_fields
                        raw = [
                            normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
                            for x in raw
                        ]
                    except Exception:
                        pass
                if section in ("established_connections", "open_ports", "listening_ports") and net_idx is not None:
                    try:
                        from .net_process import enrich_conn_list
                        enrich_conn_list(raw, net_idx)
                    except Exception:
                        pass
                out[section] = {
                    "section": section, "total": total_raw, "offset": 0, "limit": limit,
                    "items": raw[:limit], "file": rid,
                }
                try:
                    conn.execute(
                        "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (f"count_{section}", str(total_raw)),
                    )
                except Exception:
                    pass
            elif isinstance(raw, dict):
                out[section] = {
                    "section": section, "total": 1, "offset": 0, "limit": 1,
                    "items": [raw], "file": rid, "as_object": True,
                }
            else:
                val = "" if raw is None else raw
                out[section] = {
                    "section": section,
                    "total": 1 if val != "" else 0,
                    "offset": 0, "limit": 1,
                    "items": [val] if val != "" else [],
                    "file": rid, "as_scalar": True,
                }
        try:
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()
    return {"file": rid, "sections": out}


_FILE_TREE_COLS = (
    "full_path,name,path,ext,size,company,product,description,"
    "file_version,signed,signer,sig_status,sig_type,magic_hex,md5,sha1,sha256,hidden,system,"
    "mtime,mode,owner,file_group"
)

# 路径推断分目录（files 表无 root 列时用）
_ROOT_SQL = {
    "Users": (
        "(instr(lower(replace(full_path,'/','\\')), '\\users\\')>0 "
        "OR lower(full_path) LIKE 'c:\\users%')"
    ),
    "ProgramData": "instr(lower(replace(full_path,'/','\\')), 'programdata')>0",
    "ProgramFilesX86": "instr(lower(replace(full_path,'/','\\')), 'program files (x86)')>0",
    "ProgramFiles": (
        "(instr(lower(replace(full_path,'/','\\')), 'program files')>0 "
        "AND instr(lower(replace(full_path,'/','\\')), 'program files (x86)')=0)"
    ),
    "Windows": (
        "(instr(lower(replace(full_path,'/','\\')), '\\windows\\')>0 "
        "OR lower(full_path) LIKE 'c:\\windows%')"
    ),
}
_ROOT_ORDER = ("Users", "ProgramData", "ProgramFiles", "ProgramFilesX86", "Windows", "Other")


def _file_row_to_tree_item(r) -> Dict[str, Any]:
    item = {
        "full_path": r["full_path"], "name": r["name"], "path": r["path"],
        "ext": r["ext"] if "ext" in r.keys() else "",
        "size": r["size"] if "size" in r.keys() else 0,
    }
    for k in ("company", "product", "description", "file_version", "signer", "sig_status", "sig_type", "magic_hex",
              "md5", "sha1", "sha256", "mtime", "mode", "owner"):
        if k in r.keys():
            item[k] = r[k] or ""
    if "file_group" in r.keys():
        item["group"] = r["file_group"] or ""
        item["file_group"] = r["file_group"] or ""
    if "signed" in r.keys():
        item["signed"] = bool(r["signed"])
    if "hidden" in r.keys():
        item["hidden"] = bool(r["hidden"])
    if "system" in r.keys():
        item["system"] = bool(r["system"])
    if "has_content" in r.keys():
        item["has_content"] = bool(r["has_content"])
    return item


# ToDesk 等 Mars xlog：正文用厂商密钥加密，平台无法解读，只能说明并指向明文缓冲
_XLOG_SUFFIX_RX = re.compile(r"_\d{4}_\d{2}_\d{2}\.xlog$", re.I)


def load_file_content(rid: str, full_path: str) -> Optional[Dict[str, Any]]:
    """按完整路径取单个文件的元数据与正文（文件树点开查看）。"""
    fp = re.sub(r"\\+", r"\\", str(full_path or "").replace("/", "\\").strip())
    if not fp:
        return None
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not Path(dbp).is_file():
        return None
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        cols = f"{_FILE_TREE_COLS},content"
        row = conn.execute(f"SELECT {cols} FROM files WHERE full_path=?", (fp,)).fetchone()
        if row is None:
            # 大小写 / 分隔符差异：按父目录索引取一批再比对
            parent = _norm_file_path(fp.rsplit("\\", 1)[0] if "\\" in fp else "")
            want = _norm_file_path(fp)
            for r in conn.execute(
                f"SELECT {cols} FROM files WHERE parent_path_norm=? LIMIT 5000", (parent,),
            ).fetchall():
                if _norm_file_path(r["full_path"]) == want:
                    row = r
                    break
        if row is None:
            return None
        item = _file_row_to_tree_item(row)
        content = str(row["content"] or "")
        item["content"] = content
        item["has_content"] = bool(content)
        name = str(item.get("name") or "")
        kind = "text" if content else "none"
        note = ""
        related = ""
        if name.lower().endswith(".xlog"):
            kind = "encrypted"
            note = (
                "Mars xlog 加密日志（ToDesk 等使用）：正文经压缩并用厂商密钥加密，平台无法解读。"
                "文件修改时间约等于该日志最后写入时间（会话日志即会话结束时间）；"
                "写盘前的明文尾部可看同目录 cache 下同名 .mmap3。"
            )
            stem = _XLOG_SUFFIX_RX.sub("", name)
            parent_disp = str(item.get("full_path") or fp).rsplit("\\", 1)[0]
            cand = f"{parent_disp}\\cache\\{stem}.mmap3"
            hit = conn.execute(
                "SELECT full_path FROM files WHERE parent_path_norm=? AND lower(name)=?",
                (_norm_file_path(f"{parent_disp}\\cache"), f"{stem}.mmap3".lower()),
            ).fetchone()
            related = str(hit["full_path"]) if hit else ""
            if not related:
                note += f"（未采到 {cand}）"
        elif not content:
            note = "采集时未保留该文件正文（非文本类型、体积超限、被占用或超出采集预算）。"
        item["content_kind"] = kind
        item["content_note"] = note
        item["related_path"] = related
        return item
    finally:
        conn.close()


def _root_where_clause(root: str) -> Optional[str]:
    tag = (root or "").strip()
    if not tag:
        return None
    if tag in _ROOT_SQL:
        return _ROOT_SQL[tag]
    if tag == "Other":
        parts = [f"NOT ({_ROOT_SQL[k]})" for k in ("Users", "ProgramData", "ProgramFiles", "ProgramFilesX86", "Windows")]
        return "(" + " AND ".join(parts) + ")"
    return None


def _patch_index_file_count(rid: str, n_files: int) -> None:
    """文件入库后回写索引 files 字段，避免列表/摘要一直显示 0。"""
    if n_files < 0:
        return
    rid0 = P.report_id(rid)
    try:
        if INDEX_DB.exists():
            conn = _connect(INDEX_DB)
            try:
                _init_index(conn)
                conn.execute(
                    "UPDATE reports SET files=?, updated_at=? WHERE file=?",
                    (int(n_files), time.time(), rid0),
                )
                conn.commit()
            finally:
                conn.close()
            invalidate_list_cache()
    except Exception as e:
        print(f"[db_store] patch index files: {e}")
    try:
        from .mysql_db import mysql_ready, connect_mysql
        if mysql_ready():
            conn = connect_mysql()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE reports SET files=%s, updated_at=%s WHERE file=%s",
                        (int(n_files), time.time(), rid0),
                    )
                conn.commit()
            finally:
                conn.close()
    except Exception:
        pass


def _build_files_tree(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """在服务端一次构树，避免浏览器下载文件后又整包 POST 回来。"""
    root: Dict[str, Any] = {"name": "", "path": "", "dir": True, "children": [], "_map": {}}

    for f in files or []:
        full = str(f.get("full_path") or "").replace("\\", "/")
        parts = [p for p in full.split("/") if p]
        if not parts:
            continue
        node = root
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            bucket = node.setdefault("_map", {})
            child = bucket.get(part)
            if child is None:
                child = {
                    "name": part,
                    "path": f"{node.get('path')}/{part}".lstrip("/") if node.get("path") else part,
                    "children": [],
                    "_map": {},
                }
                if last:
                    child["file"] = True
                    child["size"] = f.get("size", 0)
                    child["ext"] = f.get("ext", "")
                    child["full_path"] = f.get("full_path", "")
                    child["name_path"] = f.get("path", "")
                    for k in (
                        "company", "product", "description", "file_version", "signed",
                        "signer", "sig_status", "magic_hex", "hidden", "system",
                    ):
                        if f.get(k) not in (None, ""):
                            child[k] = f.get(k)
                else:
                    child["dir"] = True
                bucket[part] = child
                node["children"].append(child)
            node = child

    def finish(node: Dict[str, Any]) -> None:
        node.pop("_map", None)
        children = node.get("children") or []
        for child in children:
            finish(child)
        children.sort(key=lambda x: (0 if x.get("dir") else 1, str(x.get("name") or "").lower()))

    finish(root)
    return root["children"]


def _parse_mtime_bound(raw: str) -> str:
    """把前端 datetime-local / ISO 时间规范成 'YYYY-MM-DD HH:MM:SS'，空则返回 ''。"""
    from datetime import datetime

    s = str(raw or "").strip().replace("T", " ").replace("Z", "")
    if not s:
        return ""
    if len(s) > 19 and s[19] in "+-.":
        s = s[:19]
    for n, fmt in ((19, "%Y-%m-%d %H:%M:%S"), (16, "%Y-%m-%d %H:%M"), (10, "%Y-%m-%d")):
        if len(s) < n:
            continue
        try:
            return datetime.strptime(s[:n], fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return ""


def load_files_for_tree(
    report_file: str,
    q: str = "",
    hidden_only: bool = False,
    limit: int = 8000,
    offset: int = 0,
    root: str = "",
    include_tree: bool = False,
    recent_days: int = 0,
    mtime_from: str = "",
    mtime_to: str = "",
) -> Dict[str, Any]:
    """从 analysis.db files 表按需取文件列表（供文件树），避免整包 view。

    默认按分目录分层抽样（Users 优先），避免 Program Files 占满 LIMIT 后看不到 Users。
    传 root=Users 等可只看某一目录。
    recent_days=1/3/5：按 mtime 相对采集时间筛近 N 天（扁平列表）。
    mtime_from / mtime_to：绝对时间窗（修改时间），与 recent_days 互斥时优先绝对窗。
    """
    from datetime import datetime, timedelta

    rid = P.report_id(report_file)
    dbp = _resolve_db_path(rid)
    if not dbp or not dbp.exists():
        return {"files": [], "total": 0, "returned": 0, "truncated": False, "root": root or ""}
    lim = max(1, min(20000, int(limit or 8000)))
    off = max(0, int(offset or 0))
    root_tag = (root or "").strip()
    try:
        recent_days = int(recent_days or 0)
    except (TypeError, ValueError):
        recent_days = 0
    if recent_days not in (0, 1, 3, 5):
        recent_days = 0
    mf = _parse_mtime_bound(mtime_from)
    mt = _parse_mtime_bound(mtime_to)
    # 起止颠倒时自动纠正
    if mf and mt and mf > mt:
        mf, mt = mt, mf
    conn = _connect(dbp)
    try:
        _init_schema(conn)
        try:
            total = int(conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] or 0)
        except Exception:
            total = 0

        # 近 N 天：扁平列表（按 mtime 倒序）
        recent_counts: Dict[str, int] = {}
        collect_anchor = ""
        cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        if "mtime" in cols:
            try:
                row = conn.execute(
                    "SELECT value FROM meta WHERE key='collect_time' LIMIT 1"
                ).fetchone()
                raw_ct = row[0] if row else ""
            except Exception:
                raw_ct = ""
            if not raw_ct:
                try:
                    rp = P.report_dir(rid, create=False) / "report.json"
                    if rp.is_file():
                        import json as _json
                        data = _json.loads(rp.read_text(encoding="utf-8", errors="replace"))
                        if isinstance(data, dict):
                            raw_ct = data.get("collect_time") or data.get("time") or ""
                except Exception:
                    raw_ct = ""
            s = str(raw_ct or "").replace("T", " ").replace("Z", "")
            if len(s) > 19 and s[19] in "+-.":
                s = s[:19]
            anchor = None
            for n, fmt in ((19, "%Y-%m-%d %H:%M:%S"), (16, "%Y-%m-%d %H:%M"), (10, "%Y-%m-%d")):
                if len(s) < n:
                    continue
                try:
                    anchor = datetime.strptime(s[:n], fmt)
                    break
                except ValueError:
                    continue
            if anchor:
                collect_anchor = anchor.strftime("%Y-%m-%d %H:%M:%S")
                for d in (1, 3, 5):
                    cut = (anchor - timedelta(days=d)).strftime("%Y-%m-%d %H:%M:%S")
                    recent_counts[str(d)] = int(conn.execute(
                        "SELECT COUNT(1) FROM files WHERE IFNULL(mtime,'')!='' AND mtime>=?",
                        (cut,),
                    ).fetchone()[0] or 0)

        use_abs_range = bool(mf or mt)
        use_recent = (not use_abs_range) and recent_days > 0 and bool(collect_anchor)
        if (use_abs_range or use_recent) and "mtime" in cols:
            where = ["IFNULL(mtime,'')!=''"]
            params: List[Any] = []
            if use_abs_range:
                if mf:
                    where.append("mtime>=?")
                    params.append(mf)
                if mt:
                    where.append("mtime<=?")
                    params.append(mt)
            else:
                cut = (
                    datetime.strptime(collect_anchor, "%Y-%m-%d %H:%M:%S")
                    - timedelta(days=recent_days)
                ).strftime("%Y-%m-%d %H:%M:%S")
                where.append("mtime>=?")
                params.append(cut)
            if hidden_only:
                where.append("(hidden=1 OR system=1)")
            if q:
                ql = (q or "").strip().lower()
                from .search_sql import classify, files_where
                plan = classify(ql, "smart")
                if plan.mode in ("segment", "glob"):
                    pred, par = files_where(plan)
                    where.append(pred)
                    params.extend(par)
                else:
                    where.append("(lower(full_path) LIKE ? OR lower(name) LIKE ?)")
                    params.extend([f"%{ql}%", f"%{ql}%"])
            wh = " AND ".join(where)
            filtered_total = int(conn.execute(
                f"SELECT COUNT(1) FROM files WHERE {wh}", params,
            ).fetchone()[0] or 0)
            sel = "full_path,name,path,ext,size,company,signer,sig_status,md5,sha1,sha256,hidden,system,mtime"
            # 兼容缺列
            have = [c for c in sel.split(",") if c in cols]
            rows = conn.execute(
                f"SELECT {','.join(have)} FROM files WHERE {wh} "
                "ORDER BY mtime DESC, full_path LIMIT ? OFFSET ?",
                params + [lim, off],
            ).fetchall()
            files = []
            for r in rows:
                item = {k: r[k] for k in r.keys()}
                item["dir"] = False
                item["file"] = True
                files.append(item)
            return {
                "files": files,
                "total": total,
                "filtered_total": filtered_total,
                "returned": len(files),
                "truncated": filtered_total > off + len(files),
                "root": root_tag,
                "recent_days": 0 if use_abs_range else recent_days,
                "mtime_from": mf,
                "mtime_to": mt,
                "recent_counts": recent_counts,
                "collect_time": collect_anchor,
                "mtime_mode": True,
            }

        base_where: List[str] = []
        base_params: List[Any] = []
        if hidden_only:
            base_where.append("(hidden=1 OR system=1)")
        if q:
            ql = (q or "").strip().lower()
            tokens = [t for t in ql.split() if t and t not in ("-", "—", "–")]
            unsigned_set = {"未签名", "unsigned", "无签名"}
            empty_set = {"空签名", "empty", "nosig", "无状态"}
            signed_set = {"已签名", "signed", "valid"}
            missing_only = bool(tokens) and all(t == "missing" for t in tokens)
            empty_only = bool(tokens) and all(t in empty_set for t in tokens)
            unsigned_only = bool(tokens) and all(t in unsigned_set for t in tokens)
            signed_only = bool(tokens) and all(t in signed_set for t in tokens)
            if missing_only:
                base_where.append("LOWER(IFNULL(sig_status,'')) = 'missing'")
            elif empty_only:
                base_where.append(
                    "(IFNULL(sig_status,'')='' OR LOWER(IFNULL(sig_status,'')) IN ('-','n/a','unknown')) "
                    "AND IFNULL(signed,0)=0"
                )
            elif unsigned_only:
                # 明确未签名，不含空状态
                base_where.append(
                    "(LOWER(IFNULL(sig_status,'')) IN ('missing','notsigned','unsigned','error','hashmismatch','nottrusted') "
                    "OR (IFNULL(signed,0)=0 AND IFNULL(sig_status,'')!='' AND LOWER(IFNULL(sig_status,'')) NOT LIKE '%valid%'"
                    " AND LOWER(IFNULL(sig_status,'')) NOT IN ('-','n/a','unknown')))"
                )
            elif signed_only:
                base_where.append(
                    "(IFNULL(signed,0)=1 OR LOWER(IFNULL(sig_status,'')) LIKE '%valid%')"
                )
            else:
                from .search_sql import classify, files_where
                plan = classify(ql, "smart")
                if plan.mode in ("segment", "glob"):
                    pred, par = files_where(plan)
                    base_where.append(pred)
                    base_params.extend(par)
                else:
                    like = f"%{ql}%"
                    ext_like = f"%{ql.lstrip('.')}%"
                    base_where.append(
                        "(LOWER(full_path) LIKE ? OR LOWER(name) LIKE ? OR LOWER(IFNULL(company,'')) LIKE ? "
                        "OR LOWER(IFNULL(signer,'')) LIKE ? OR LOWER(IFNULL(sig_status,'')) LIKE ? "
                        "OR LOWER(IFNULL(product,'')) LIKE ? OR LOWER(IFNULL(description,'')) LIKE ? "
                        "OR LOWER(IFNULL(magic_hex,'')) LIKE ? OR LOWER(IFNULL(ext,'')) LIKE ? "
                        "OR LOWER(REPLACE(IFNULL(ext,''), '.', '')) LIKE ?)"
                    )
                    base_params.extend([like] * 9 + [ext_like])

        root_clause = _root_where_clause(root_tag)
        if root_clause:
            base_where.append(root_clause)

        try:
            count_sql = "SELECT COUNT(*) FROM files"
            if base_where:
                count_sql += " WHERE " + " AND ".join(base_where)
            filtered_total = int(conn.execute(count_sql, base_params).fetchone()[0] or 0)
        except Exception:
            filtered_total = total

        def _fetch(extra_where: Optional[str], lim_n: int, offset_n: int = 0) -> List[Any]:
            wh = list(base_where)
            if extra_where:
                wh.append(extra_where)
            sql = f"SELECT {_FILE_TREE_COLS} FROM files"
            if wh:
                sql += " WHERE " + " AND ".join(wh)
            sql += " ORDER BY lower(full_path) LIMIT ? OFFSET ?"
            params = list(base_params) + [max(1, lim_n), max(0, offset_n)]
            try:
                return list(conn.execute(sql, params).fetchall())
            except sqlite3.OperationalError:
                # 旧库缺列时降级：仅路径/文件名
                wh2: List[str] = []
                params2: List[Any] = []
                if hidden_only:
                    # 旧库可能无 hidden 列，忽略
                    pass
                if q:
                    wh2.append("(LOWER(full_path) LIKE ? OR LOWER(name) LIKE ?)")
                    like = f"%{str(q).lower()}%"
                    params2.extend([like, like])
                if extra_where:
                    wh2.append(extra_where)
                if root_clause:
                    wh2.append(root_clause)
                sql2 = "SELECT full_path,name,path,ext,size FROM files"
                if wh2:
                    sql2 += " WHERE " + " AND ".join(wh2)
                sql2 += " ORDER BY lower(full_path) LIMIT ? OFFSET ?"
                params2.extend([max(1, lim_n), max(0, offset_n)])
                return list(conn.execute(sql2, params2).fetchall())

        rows: List[Any] = []
        dir_rows: List[Any] = []
        dir_total = 0
        if q:
            ql = (q or "").strip().lower()
            like = f"%{ql}%"
            dir_where = ["(lower(d.name) LIKE ? OR lower(d.full_path) LIKE ?)"]
            dir_args: List[Any] = [like, like]
            if hidden_only:
                dir_where.append(
                    "EXISTS (SELECT 1 FROM files hf WHERE (hf.hidden=1 OR hf.system=1) AND "
                    "(hf.parent_path_norm=d.path_norm OR "
                    "substr(hf.parent_path_norm,1,length(d.path_norm)+1)=d.path_norm||'\\'))"
                )
            dir_sql = " AND ".join(dir_where)
            try:
                dir_total = int(conn.execute(
                    f"SELECT COUNT(1) FROM file_directories d WHERE {dir_sql}", dir_args,
                ).fetchone()[0] or 0)
            except Exception:
                dir_total = 0
            filtered_total = dir_total + filtered_total
            if off < dir_total:
                dir_rows = conn.execute(
                    "SELECT d.path_norm,d.parent_path_norm,d.name,d.full_path,"
                    "EXISTS(SELECT 1 FROM file_directories c WHERE c.parent_path_norm=d.path_norm) "
                    "OR EXISTS(SELECT 1 FROM files f WHERE f.parent_path_norm=d.path_norm) AS has_children "
                    f"FROM file_directories d WHERE {dir_sql} "
                    "ORDER BY d.name COLLATE NOCASE LIMIT ? OFFSET ?",
                    dir_args + [lim, off],
                ).fetchall()
            file_off = max(0, off - dir_total)
            file_lim = max(0, lim - len(dir_rows))
            if file_lim > 0:
                rows = _fetch(None, file_lim, file_off)
        elif root_clause or total <= lim or hidden_only or off:
            rows = _fetch(None, lim, off)
        else:
            # 分层：Users 至少一半配额，其余目录均分剩余，避免「文件数有 Users 但树里没有」
            roots_meta: Dict[str, int] = {}
            try:
                raw = conn.execute(
                    "SELECT value FROM meta WHERE key=?", ("file_scan_roots",)
                ).fetchone()
                if raw and raw["value"]:
                    roots_meta = _jload(raw["value"]) or {}
            except Exception:
                roots_meta = {}
            if not isinstance(roots_meta, dict):
                roots_meta = {}
            present = [k for k in _ROOT_ORDER if int(roots_meta.get(k) or 0) > 0]
            if not present:
                present = list(_ROOT_ORDER)
            users_quota = max(lim // 2, lim // max(1, len(present))) if "Users" in present else 0
            remain = lim - users_quota
            other = [k for k in present if k != "Users"]
            per = max(200, remain // max(1, len(other))) if other else 0
            quotas: Dict[str, int] = {}
            if "Users" in present:
                quotas["Users"] = users_quota
            for k in other:
                quotas[k] = per
            # 配额可能超额，最后截断
            seen_paths: Set[str] = set()
            for tag in _ROOT_ORDER:
                need = int(quotas.get(tag) or 0)
                if need <= 0:
                    continue
                left = lim - len(rows)
                if left <= 0:
                    break
                chunk = _fetch(_root_where_clause(tag), min(need, left))
                for r in chunk:
                    fp = r["full_path"] if "full_path" in r.keys() else ""
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)
                    rows.append(r)
                    if len(rows) >= lim:
                        break
            if len(rows) < lim:
                # 补足：任意剩余行
                left = lim - len(rows)
                for r in _fetch(None, lim * 2):
                    fp = r["full_path"] if "full_path" in r.keys() else ""
                    if fp in seen_paths:
                        continue
                    seen_paths.add(fp)
                    rows.append(r)
                    left -= 1
                    if left <= 0:
                        break

        files = [_file_row_to_tree_item(r) for r in rows]
        if dir_rows:
            dir_items = [{
                "name": r["name"] or "",
                "full_path": r["full_path"] or "",
                "path": str(r["full_path"] or "").replace("\\", "/"),
                "dir": True,
                "has_children": bool(r["has_children"]),
            } for r in dir_rows]
            files = dir_items + files
        roots_out = {}
        try:
            raw = conn.execute(
                "SELECT value FROM meta WHERE key=?", ("file_scan_roots",)
            ).fetchone()
            if raw and raw["value"]:
                roots_out = _jload(raw["value"]) or {}
        except Exception:
            roots_out = {}
        out = {
            "files": files,
            "total": total,
            "filtered_total": filtered_total,
            "returned": len(files),
            "offset": off,
            "limit": lim,
            "truncated": filtered_total > off + len(files),
            "root": root_tag,
            "file_scan_roots": roots_out if isinstance(roots_out, dict) else {},
            "recent_days": 0,
            "recent_counts": recent_counts,
            "collect_time": collect_anchor,
        }
        if include_tree:
            out["tree"] = _build_files_tree(files)
            out.pop("files", None)
        return out
    finally:
        conn.close()


def db_exists(report_file: str) -> bool:
    return P.resolve_analysis_db(report_file) is not None


def migrate_from_json_if_needed(report_file: str) -> bool:
    """若有 result 且无 db，导入一次；并尽量迁入目录。"""
    rid = P.report_id(report_file)
    try:
        P.migrate_report_to_folder(rid)
    except Exception:
        pass
    if db_exists(rid):
        return True
    rp = P.resolve_result_json(rid)
    report_path = P.resolve_report_json(rid)
    if not report_path or not rp:
        return False
    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
        with open(rp, encoding="utf-8") as f:
            analysis = (json.load(f) or {}).get("analysis") or {}
        if not analysis.get("findings_aggregated") and not analysis.get("findings"):
            return False
        save_report_db(report, analysis, rid)
        return True
    except Exception:
        return False


def rebuild_index_from_dbs() -> int:
    """扫描报告目录，清空后重建 index（与磁盘一致）。"""
    try:
        P.migrate_all_flat_reports()
    except Exception as e:
        print("[rebuild] migrate:", e)
    clear_index()
    n = 0
    for rid in P.iter_report_ids(300):
        if not P.resolve_report_json(rid) and not P.resolve_analysis_db(rid):
            continue
        if migrate_from_json_if_needed(rid) or db_exists(rid):
            view = load_view_from_db(rid)
            if not view:
                continue
            a = view.get("analysis") or {}
            sa = a.get("summary_aggregated") or {}
            s = a.get("summary") or {}
            dbp = db_path_for_report(rid)
            upsert_index({
                "file": rid,
                "db_path": str(dbp.relative_to(config.REPORTS_DIR)).replace("\\", "/") if dbp.exists() else "",
                "hostname": view.get("hostname"),
                "collect_time": view.get("collect_time"),
                "ip": pick_primary_ip(view.get("ip") or ""),
                "issues": sa.get("total") or s.get("total") or 0,
                "raw_issues": sa.get("raw_total") or s.get("total") or 0,
                "analyzed": True,
                "processes": len(view.get("processes") or []),
                "services": len(view.get("services") or []),
                "files": len(view.get("file_scans") or []),
                "os_family": view.get("os_family") or "",
                "os": view.get("os") or "",
            })
            n += 1
        else:
            rp = P.resolve_report_json(rid)
            if not rp:
                continue
            try:
                with open(rp, encoding="utf-8") as f:
                    d = json.load(f)
                upsert_index({
                    "file": rid,
                    "db_path": "",
                    "hostname": d.get("hostname"),
                    "collect_time": d.get("collect_time"),
                    "ip": pick_primary_ip(d.get("ip") or ""),
                    "issues": 0,
                    "raw_issues": 0,
                    "analyzed": False,
                    "processes": len(d.get("processes") or []),
                    "services": len(d.get("services") or []),
                    "files": len(d.get("file_scans") or []),
                    "os_family": d.get("os_family") or "",
                    "os": d.get("os") or "",
                })
                n += 1
            except Exception:
                pass
    return n
