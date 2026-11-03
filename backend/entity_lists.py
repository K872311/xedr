"""实体列表投影：进程/服务/计划任务/启动项。

分析入库时写成瘦身 JSON（无 modules 等大字段），列表 API 只读投影，
详情仍走 blobs 全量。旧库无投影时首次打开会现场生成并回写。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

ENTITY_LIST_SECTIONS = (
    "processes",
    "services",
    "scheduled_tasks",
    "startup_items",
)

# 列表页需要的字段（其余丢弃以缩小解析体积）
_PROCESS_KEEP = (
    "pid", "PID", "ppid", "PPID", "name", "path", "image_path",
    "command_line", "command", "CommandLine", "user", "User",
    "signed", "signer", "sig_status", "SigStatus", "sig_type", "SigType",
    "company", "product", "description", "file_version",
    "md5", "MD5", "sha1", "SHA1", "sha256", "SHA256",
    "mem_kb", "MemKB", "start_time", "source",
    "module_count", "unsigned_module_count", "dirty_unsigned_module_count",
    "sideload_suspect", "process_detail_lazy",
)

_PERSIST_KEEP = (
    "name", "task_name", "display_name", "location", "status", "start_type",
    "StartType", "pid", "PID", "path", "resolved_path", "command", "command_line",
    "task_to_run", "working_directory", "start_in", "author", "next_run",
    "service_dll", "ServiceDll", "image_path", "ImagePath",
    "signed", "signer", "sig_status", "SigStatus", "sig_type", "SigType",
    "company", "product", "description", "file_version",
    "md5", "sha1", "sha256", "sideload_suspect",
    "unsigned_module_count", "dirty_unsigned_module_count",
    "user", "caption", "state",
)


def ensure_entity_list_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_lists (
            section TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            count INTEGER DEFAULT 0
        )
        """
    )


def clear_entity_lists(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("DELETE FROM entity_lists")
    except sqlite3.OperationalError:
        pass


def _jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _jload(s: Optional[str], default=None):
    if s is None or s == "":
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def _pick(item: Dict[str, Any], keys: tuple) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in keys:
        if k in item and item[k] is not None:
            out[k] = item[k]
    return out


def _item_match_q(item: Any, q: str) -> bool:
    if not q:
        return True
    ql = q.lower()
    try:
        blob = json.dumps(item, ensure_ascii=False).lower()
    except Exception:
        blob = str(item).lower()
    return ql in blob


def upsert_entity_list(conn: sqlite3.Connection, section: str, items: List[Any]) -> None:
    ensure_entity_list_schema(conn)
    rows = [x for x in (items or []) if isinstance(x, dict)]
    conn.execute(
        "INSERT OR REPLACE INTO entity_lists(section,data,count) VALUES(?,?,?)",
        (section, _jdump(rows), len(rows)),
    )


def load_entity_list_raw(conn: sqlite3.Connection, section: str) -> Optional[List[Any]]:
    ensure_entity_list_schema(conn)
    try:
        row = conn.execute(
            "SELECT data, count FROM entity_lists WHERE section=?",
            (section,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    if not row:
        return None
    data = _jload(row["data"] if hasattr(row, "keys") else row[0], None)
    if not isinstance(data, list):
        return None
    return data


def query_entity_list_page(
    conn: sqlite3.Connection,
    section: str,
    *,
    offset: int = 0,
    limit: int = 100,
    q: str = "",
) -> Optional[Dict[str, Any]]:
    """有投影则分页返回；无投影返回 None（由调用方走 blob 回退）。"""
    items = load_entity_list_raw(conn, section)
    if items is None:
        return None
    if q:
        items = [x for x in items if _item_match_q(x, q)]
    total = len(items)
    offset = max(0, int(offset or 0))
    limit = max(1, int(limit or 100))
    page = items[offset: offset + limit]
    return {
        "section": section,
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": page,
        "has_next": offset + len(page) < total,
        "from_entity_list": True,
    }


def project_processes_list(conn: sqlite3.Connection, items: List[Any], rid: str = "") -> List[Dict[str, Any]]:
    from .db_store import _file_sig_index_for_processes, _slim_process_for_list

    out: List[Dict[str, Any]] = []
    batch: List[Any] = []
    for it in items or []:
        if isinstance(it, dict):
            batch.append(it)
    # 分批取签名索引，避免一次攒太多路径
    slimmed: List[Dict[str, Any]] = []
    chunk_size = 80
    for i in range(0, len(batch), chunk_size):
        chunk = batch[i : i + chunk_size]
        try:
            sig_idx = _file_sig_index_for_processes(conn, chunk, rid=str(rid or ""))
        except Exception:
            sig_idx = {}
        for it in chunk:
            try:
                slim = _slim_process_for_list(it, sig_index=sig_idx, rid=str(rid or ""))
            except Exception:
                slim = _pick(it, _PROCESS_KEEP)
                slim["process_detail_lazy"] = True
            slimmed.append(_pick(slim, _PROCESS_KEEP) if slim else {})
    return [x for x in slimmed if x]


def project_persist_list(
    conn: sqlite3.Connection,
    section: str,
    items: List[Any],
    rid: str = "",
) -> List[Dict[str, Any]]:
    from .db_store import (
        _annotate_persist_sideload_list,
        _enrich_linux_section_sigs,
        _resolve_startup_paths_from_conn,
        _resolve_task_paths_from_conn,
    )

    rows = [dict(x) for x in (items or []) if isinstance(x, dict)]
    if section == "scheduled_tasks":
        try:
            rows = _resolve_task_paths_from_conn(conn, rows)
        except Exception:
            pass
    elif section == "startup_items":
        try:
            rows = _resolve_startup_paths_from_conn(conn, rows)
        except Exception:
            pass
        # Linux 启动项
        try:
            from .linux_sc_import import enrich_linux_startups

            fam = ""
            try:
                r = conn.execute("SELECT value FROM meta WHERE key='os_family'").fetchone()
                fam = str((r["value"] if r else "") or "")
            except Exception:
                fam = ""
            looks_linux = fam.lower() == "linux" or any(
                str(x.get("name") or "").endswith(".service") for x in rows[:20]
            )
            if looks_linux:
                from .db_store import _load_one_blob

                svc_raw = _load_one_blob(conn, "services") or []
                pack = enrich_linux_startups({
                    "os_family": "linux",
                    "collector": "linuxsc",
                    "startup_items": rows,
                    "services": svc_raw if isinstance(svc_raw, list) else [],
                })
                rows = pack.get("startup_items") or rows
        except Exception:
            pass
    try:
        rows = _enrich_linux_section_sigs(conn, section, rows)
    except Exception:
        pass
    try:
        rows = _annotate_persist_sideload_list(section, rows, rid=str(rid or ""))
    except Exception:
        pass
    try:
        from .ingest import normalize_item_sig_fields

        rows = [
            normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
            for x in rows
        ]
    except Exception:
        pass
    out = []
    for it in rows:
        if not isinstance(it, dict):
            continue
        out.append(_pick(it, _PERSIST_KEEP))
    return out


def build_entity_lists_from_report(
    conn: sqlite3.Connection,
    report: Dict[str, Any],
    rid: str = "",
) -> Dict[str, int]:
    """分析入库时调用：从 report 生成四类投影。"""
    ensure_entity_list_schema(conn)
    clear_entity_lists(conn)
    counts: Dict[str, int] = {}
    rid = str(rid or report.get("_rid") or report.get("_files_rid") or "").strip()

    procs = report.get("processes")
    if isinstance(procs, list) and procs:
        slim = project_processes_list(conn, procs, rid=rid)
        upsert_entity_list(conn, "processes", slim)
        counts["processes"] = len(slim)

    for section in ("services", "scheduled_tasks", "startup_items"):
        items = report.get(section)
        if not isinstance(items, list) or not items:
            continue
        slim = project_persist_list(conn, section, items, rid=rid)
        upsert_entity_list(conn, section, slim)
        counts[section] = len(slim)
    return counts


def build_entity_list_from_blob(
    conn: sqlite3.Connection,
    section: str,
    rid: str = "",
) -> Optional[List[Dict[str, Any]]]:
    """旧库无投影：从 blobs 现场生成并回写。"""
    if section not in ENTITY_LIST_SECTIONS:
        return None
    from .db_store import _load_one_blob

    raw = _load_one_blob(conn, section)
    if not isinstance(raw, list) or not raw:
        upsert_entity_list(conn, section, [])
        return []
    if section == "processes":
        slim = project_processes_list(conn, raw, rid=rid)
    else:
        slim = project_persist_list(conn, section, raw, rid=rid)
    upsert_entity_list(conn, section, slim)
    try:
        conn.commit()
    except Exception:
        pass
    return slim


def query_or_build_entity_list_page(
    conn: sqlite3.Connection,
    section: str,
    *,
    rid: str = "",
    offset: int = 0,
    limit: int = 100,
    q: str = "",
) -> Optional[Dict[str, Any]]:
    page = query_entity_list_page(conn, section, offset=offset, limit=limit, q=q)
    if page is not None:
        return page
    # 现场构建（旧报告首次打开会慢一次）
    built = build_entity_list_from_blob(conn, section, rid=rid)
    if built is None:
        return None
    return query_entity_list_page(conn, section, offset=offset, limit=limit, q=q)
