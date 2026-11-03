"""报告内已采集哈希的全量 IOC 对照（按需扫描，带进度）。

只通过 lookup_hashes_batch 对照情报，不打开/遍历 ioc_data.db。
后续 ES 就绪时走同一入口（ioc_db 已 MySQL → ES → SQLite）。
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import ioc_db
from . import paths as P
from .matchers.ioc import (
    _norm_hash_val,
    _pe_paths_from_text,
    _pick_hashes_from_obj,
    lookup_unsigned_sidecar_hashes,
)

_STATE_NAME = "ioc_full_scan.json"
_MAX_HASHES = 100_000
_MAX_HITS_STORE = 2000
# 须 ≤ ioc_mysql.lookup_exact 单批 IN 上限（64）；过大时过去会静默丢掉后半批
_CHUNK = 64

_lock = threading.Lock()
_cancel: Set[str] = set()
_threads: Dict[str, threading.Thread] = {}

_PERSIST_BLOBS = (
    ("startup_items", "启动项"),
    ("scheduled_tasks", "计划任务"),
    ("services", "服务"),
    ("processes", "进程"),
    ("driver_entries", "驱动"),
)
_PERSIST_PATH_FIELDS = {
    "startup_items": ("path", "command", "resolved_path", "lnk_target", "lnk_arguments", "full_path", "image_path"),
    "scheduled_tasks": ("path", "command", "resolved_path", "exec_path", "full_path"),
    "services": ("path", "image_path", "resolved_path", "service_dll", "full_path"),
    "processes": ("path", "command_line", "commandline", "full_path", "image_path"),
    "driver_entries": ("path", "resolved_path", "image_path", "full_path"),
}
_NETWORK_BLOB = "established_connections"


def _state_path(rid: str) -> Path:
    return P.report_dir(rid, create=True) / _STATE_NAME


def _empty_state(rid: str) -> Dict[str, Any]:
    return {
        "ok": True,
        "rid": rid,
        "status": "idle",
        "phase": "",
        "message": "",
        "error": "",
        "total": 0,
        "scanned": 0,
        "hits": 0,
        "backend": "",
        "started_at": "",
        "finished_at": "",
        "updated_at": "",
        "items": [],
        "files_total": 0,
        "pe_total": 0,
        "signed_skipped": 0,
        "unsigned_hashed": 0,
        "unsigned_exe": 0,
        "unsigned_dll": 0,
        "no_hash": 0,
        "unchecked_pe": 0,
        "persist_hashed": 0,
        "startup_hashed": 0,
        "task_hashed": 0,
        "service_hashed": 0,
        "process_hashed": 0,
        "network_ips": 0,
    }


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    """原子写状态文件。Windows 上目标被占用/并发写同一 .tmp 时易 WinError 5，需唯一临时名+重试。"""
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False)
    tmp = path.with_name(f"{path.stem}.{os.getpid()}.{time.time_ns()}.tmp")
    tmp.write_text(payload, encoding="utf-8")
    last: Optional[BaseException] = None
    try:
        for i in range(12):
            try:
                os.replace(str(tmp), str(path))
                return
            except PermissionError as e:
                last = e
            except OSError as e:
                # WinError 5 拒绝访问；偶发文件正被前端/杀软打开
                win = getattr(e, "winerror", None)
                if win not in (5, 32) and e.errno not in (13, 11, 16):
                    raise
                last = e
            time.sleep(0.04 * (i + 1))
        # 兜底：直接覆盖写（状态文件可接受短暂非原子）
        try:
            path.write_text(payload, encoding="utf-8")
        except OSError:
            if last:
                raise last
            raise
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def load_state(rid: str, *, include_items: bool = True) -> Dict[str, Any]:
    p = _state_path(rid)
    if not p.is_file():
        return _empty_state(rid)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return _empty_state(rid)
    if not isinstance(data, dict):
        return _empty_state(rid)
    if not include_items:
        data = {**data, "items": []}
    return data


def _stat_sig(path: Optional[Path]) -> str:
    try:
        if path and Path(path).is_file():
            st = Path(path).stat()
            return f"{int(st.st_size)}@{int(getattr(st, 'st_mtime_ns', st.st_mtime * 1e9))}"
    except OSError:
        pass
    return ""


def current_fingerprint(rid: str) -> Dict[str, str]:
    """情报库文件 / 手工 IOC / 报告原始数据 三者的轻量指纹（只 stat 与小表聚合，不扫情报库）。"""
    manual = ""
    try:
        from . import ioc_manual_db
        manual = ioc_manual_db.fingerprint()
    except Exception:
        pass
    try:
        report = _stat_sig(P.resolve_report_json(rid))
    except Exception:
        report = ""
    return {"intel": _stat_sig(ioc_db.discover_ioc_db()), "manual": manual, "report": report}


_STALE_REASONS = {
    "intel": "情报库已更新",
    "manual": "手工 IOC 清单已变更",
    "report": "报告数据已重新上传或更新",
}


def with_staleness(state: Dict[str, Any]) -> Dict[str, Any]:
    """已完成的扫描若扫描时的指纹与当前不一致，标记 stale 并给出原因。"""
    out = dict(state or {})
    out["stale"] = False
    out["stale_reasons"] = []
    fp = out.get("fingerprint")
    if out.get("status") != "done" or not isinstance(fp, dict):
        return out
    now = current_fingerprint(str(out.get("rid") or ""))
    reasons = [
        _STALE_REASONS[k] for k in ("intel", "manual", "report")
        if fp.get(k) and now.get(k) and fp[k] != now[k]
    ]
    out["stale"] = bool(reasons)
    out["stale_reasons"] = reasons
    return out


def _is_trusted_signed(sig_status: str, signed: Any) -> bool:
    st = str(sig_status or "").strip().lower()
    if st in ("valid", "signed"):
        return True
    if signed in (1, True, "1") and st in ("", "valid", "signed"):
        return True
    return False


_PE_EXTS = (".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv", ".msi")
_COVERAGE_KINDS = frozenset({
    "files", "unsigned", "unsigned_exe", "unsigned_dll", "signed", "no_hash", "unchecked",
})
_RECENT_DAY_OPTS = (1, 3, 5)


def _parse_collect_dt(raw: Any) -> Optional[datetime]:
    s = str(raw or "").strip()
    if not s:
        return None
    s = s.replace("T", " ").replace("Z", "")
    if len(s) > 19 and s[19] in "+-.":
        s = s[:19]
    for n, fmt in ((19, "%Y-%m-%d %H:%M:%S"), (16, "%Y-%m-%d %H:%M"), (10, "%Y-%m-%d")):
        if len(s) < n:
            continue
        try:
            return datetime.strptime(s[:n], fmt)
        except ValueError:
            continue
    return None


def _collect_time_anchor(rid: str, conn: sqlite3.Connection) -> Optional[datetime]:
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='collect_time' LIMIT 1"
        ).fetchone()
        if row:
            dt = _parse_collect_dt(row[0] if not isinstance(row, sqlite3.Row) else row["value"])
            if dt:
                return dt
    except sqlite3.Error:
        pass
    try:
        rp = P.report_dir(rid, create=False) / "report.json"
        if rp.is_file():
            data = json.loads(rp.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                dt = _parse_collect_dt(data.get("collect_time") or data.get("time"))
                if dt:
                    return dt
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return None


def list_coverage(
    rid: str,
    kind: str,
    *,
    offset: int = 0,
    limit: int = 80,
    q: str = "",
    recent_days: int = 0,
    sort: str = "",
    sort_dir: str = "",
) -> Dict[str, Any]:
    """点开统计卡片：从 analysis.db 抽样对应文件（分页）。

    recent_days：仅 kind=files 时生效；按 mtime 相对采集时间筛选近 N 天（修改时间）。
    sort：path / mtime / status（默认 files 为 mtime，其它为 path）。
    枚举文件默认把 System32/SysWOW64/WinSxS 排到后面，优先看用户目录等。
    """
    kind = str(kind or "").strip().lower()
    if kind not in _COVERAGE_KINDS:
        return {"ok": False, "error": "未知类别", "kind": kind, "total": 0, "items": []}
    offset = max(0, int(offset or 0))
    limit = max(1, min(200, int(limit or 80)))
    needle = str(q or "").strip().lower()
    try:
        recent_days = int(recent_days or 0)
    except (TypeError, ValueError):
        recent_days = 0
    if recent_days not in (0, *_RECENT_DAY_OPTS):
        recent_days = 0
    if kind != "files":
        recent_days = 0

    sort_key = str(sort or "").strip().lower()
    if sort_key not in ("", "path", "mtime", "status"):
        sort_key = ""
    if not sort_key:
        sort_key = "mtime" if kind == "files" else "path"
    dir_asc = str(sort_dir or "").strip().lower() in ("asc", "1", "up")
    # 默认：近 N 天 / 枚举文件按 mtime 新→旧；显式 asc 才升序
    if sort_key == "mtime" and not str(sort_dir or "").strip():
        dir_asc = False
    elif sort_key == "path" and not str(sort_dir or "").strip():
        dir_asc = True
    dir_sql = "ASC" if dir_asc else "DESC"
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return {"ok": True, "kind": kind, "total": 0, "offset": offset, "limit": limit, "items": []}

    conn = sqlite3.connect(str(dbp))
    conn.row_factory = sqlite3.Row
    items: List[Dict[str, Any]] = []
    total = 0
    recent_counts: Dict[str, int] = {}
    collect_anchor = ""
    mtime_filled = 0
    labels = {
        "files": "枚举文件",
        "unsigned": "未签名已哈希",
        "unsigned_exe": "未签名 exe",
        "unsigned_dll": "未签名 dll",
        "signed": "已签名仍对照",
        "no_hash": "确认未签且无哈希",
        "unchecked": "未验签 PE",
    }
    hints = {
        "files": "含目录与各类扩展名；已签名/未签名 PE 只要有哈希都会对照 IOC。近 N 天按修改时间（mtime）相对采集时刻筛选。默认优先非 System32/SysWOW64/WinSxS，可点表头排序。",
        "unchecked": "签名字段为空：-qm 配额用尽后未再验签/哈希，不等于已确认未签名。",
        "no_hash": "已验签为 NotSigned 等，但未写入 md5/sha（超大文件或哈希失败）。",
        "signed": "已签名且已有哈希：仍参与 IOC 对照（覆盖白加黑宿主、窃签样本等）。",
    }
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        if "full_path" not in cols:
            return {"ok": True, "kind": kind, "label": labels.get(kind, kind),
                    "total": 0, "offset": offset, "limit": limit, "items": []}
        sel = ["full_path", "name"]
        for c in ("ext", "md5", "sha1", "sha256", "sig_status", "signed", "size", "mtime"):
            if c in cols:
                sel.append(c)
        where: List[str] = ["1=1"]
        args: List[Any] = []
        if needle:
            where.append("(lower(IFNULL(full_path,'')) LIKE ? OR lower(IFNULL(name,'')) LIKE ?)")
            args.extend([f"%{needle}%", f"%{needle}%"])

        pe_sql = (
            "lower(IFNULL(ext,'')) IN "
            "('.exe','.dll','.sys','.scr','.com','.ocx','.cpl','.drv','.msi')"
        )
        has_hash_sql = (
            "(IFNULL(md5,'')!='' OR IFNULL(sha1,'')!='' OR IFNULL(sha256,'')!='')"
            if {"md5", "sha1", "sha256"} & cols else "0"
        )
        no_hash_sql = (
            "(IFNULL(md5,'')='' AND IFNULL(sha1,'')='' AND IFNULL(sha256,'')='')"
            if {"md5", "sha1", "sha256"} & cols else "1"
        )
        if "sig_status" in cols:
            trusted_sql = (
                "(lower(trim(IFNULL(sig_status,''))) IN ('valid','signed') "
                "OR (IFNULL(signed,0)=1 AND lower(trim(IFNULL(sig_status,''))) "
                "IN ('','valid','signed')))"
            )
            confirmed_unsigned_sql = (
                "lower(trim(IFNULL(sig_status,''))) IN "
                "('notsigned','hashmismatch','nottrusted','invalid','error','unsigned')"
            )
            unchecked_sql = (
                "(IFNULL(trim(sig_status),'')='' OR lower(trim(sig_status))='unchecked')"
            )
        elif "signed" in cols:
            trusted_sql = "(IFNULL(signed,0)=1)"
            confirmed_unsigned_sql = "(IFNULL(signed,0)=0)"
            unchecked_sql = "0"
        else:
            trusted_sql = "0"
            confirmed_unsigned_sql = "0"
            unchecked_sql = "1"
        untrusted_sql = f"(NOT ({trusted_sql}))"

        if kind == "files":
            pass
        elif kind == "signed":
            where.append(pe_sql)
            where.append(trusted_sql)
            where.append(has_hash_sql)
        elif kind == "unsigned":
            where.append(pe_sql)
            where.append(untrusted_sql)
            where.append(f"(NOT ({unchecked_sql}))")
            where.append(has_hash_sql)
        elif kind == "unsigned_exe":
            where.append("lower(IFNULL(ext,''))='.exe'")
            where.append(untrusted_sql)
            where.append(f"(NOT ({unchecked_sql}))")
            where.append(has_hash_sql)
        elif kind == "unsigned_dll":
            where.append("lower(IFNULL(ext,''))='.dll'")
            where.append(untrusted_sql)
            where.append(f"(NOT ({unchecked_sql}))")
            where.append(has_hash_sql)
        elif kind == "no_hash":
            where.append(pe_sql)
            where.append(confirmed_unsigned_sql)
            where.append(no_hash_sql)
        elif kind == "unchecked":
            where.append(pe_sql)
            where.append(unchecked_sql)
            where.append(no_hash_sql)

        anchor = _collect_time_anchor(rid, conn)
        if anchor:
            collect_anchor = anchor.strftime("%Y-%m-%d %H:%M:%S")
        if kind == "files" and "mtime" in cols:
            mtime_filled = int(conn.execute(
                "SELECT COUNT(1) c FROM files WHERE IFNULL(mtime,'')!=''"
            ).fetchone()["c"] or 0)
            if anchor:
                for d in _RECENT_DAY_OPTS:
                    cut = (anchor - timedelta(days=d)).strftime("%Y-%m-%d %H:%M:%S")
                    n = int(conn.execute(
                        "SELECT COUNT(1) c FROM files WHERE IFNULL(mtime,'')!='' AND mtime>=?",
                        (cut,),
                    ).fetchone()["c"] or 0)
                    recent_counts[str(d)] = n
            else:
                for d in _RECENT_DAY_OPTS:
                    recent_counts[str(d)] = 0

        if recent_days > 0 and "mtime" in cols and anchor:
            cut = (anchor - timedelta(days=recent_days)).strftime("%Y-%m-%d %H:%M:%S")
            where.append("IFNULL(mtime,'')!='' AND mtime>=?")
            args.append(cut)
        elif recent_days > 0:
            # 无 mtime 列或无采集时间：筛不出近 N 天
            where.append("0")

        wh = " AND ".join(where)
        total = int(conn.execute(f"SELECT COUNT(1) c FROM files WHERE {wh}", args).fetchone()["c"] or 0)
        # System32 / SysWOW64 / WinSxS 默认沉底，优先展示用户目录、Temp、ProgramData 等
        noise_rank = (
            "CASE WHEN lower(replace(IFNULL(full_path,''),'/','\\')) LIKE '%\\system32\\%' "
            "OR lower(replace(IFNULL(full_path,''),'/','\\')) LIKE '%\\syswow64\\%' "
            "OR lower(replace(IFNULL(full_path,''),'/','\\')) LIKE '%\\winsxs\\%' "
            "THEN 1 ELSE 0 END"
        )
        if sort_key == "mtime" and "mtime" in cols:
            col_ord = f"(IFNULL(mtime,'')='') ASC, mtime {dir_sql}, full_path ASC"
        elif sort_key == "status" and "sig_status" in cols:
            col_ord = f"IFNULL(sig_status,'') {dir_sql}, full_path ASC"
        else:
            col_ord = f"full_path {dir_sql}"
        if kind == "files":
            order = f"{noise_rank} ASC, {col_ord}"
        else:
            order = col_ord
        rows = conn.execute(
            f"SELECT {', '.join(sel)} FROM files WHERE {wh} "
            f"ORDER BY {order} LIMIT ? OFFSET ?",
            [*args, limit, offset],
        ).fetchall()
        items = [_coverage_row(r) for r in rows]
    finally:
        conn.close()
    out: Dict[str, Any] = {
        "ok": True,
        "kind": kind,
        "label": labels.get(kind, kind),
        "hint": hints.get(kind, ""),
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items,
        "truncated": total > offset + len(items),
        "recent_days": recent_days,
        "sort": sort_key,
        "sort_dir": "asc" if dir_asc else "desc",
    }
    if kind == "files":
        out["recent_counts"] = recent_counts
        out["mtime_filled"] = mtime_filled
        out["collect_time"] = collect_anchor
        if mtime_filled == 0:
            out["hint"] = (
                (hints.get("files") or "")
                + " 当前报告几乎无修改时间，请用已补 mtime 的采集器重采后再筛近 N 天。"
            ).strip()
    return out


def _coverage_row(r: sqlite3.Row) -> Dict[str, Any]:
    fp = (r["full_path"] if "full_path" in r.keys() else "") or (r["name"] if "name" in r.keys() else "")
    fp = str(fp).replace("/", "\\")
    ext = str(r["ext"] if "ext" in r.keys() else "").lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    md5 = _norm_hash_val(r["md5"] if "md5" in r.keys() else "")
    sha1 = _norm_hash_val(r["sha1"] if "sha1" in r.keys() else "")
    sha256 = _norm_hash_val(r["sha256"] if "sha256" in r.keys() else "")
    hv = md5 or sha1 or sha256
    sig = str(r["sig_status"] if "sig_status" in r.keys() else "").strip()
    signed = int(r["signed"] or 0) if "signed" in r.keys() else 0
    size = int(r["size"] or 0) if "size" in r.keys() else -1
    mtime = str(r["mtime"] if "mtime" in r.keys() else "").strip()
    pe = ext in set(_PE_EXTS)
    st_low = sig.lower()
    if (not ext) and size == 0:
        status = "目录/联接"
    elif not pe:
        status = "非PE"
    elif hv:
        if _is_trusted_signed(sig, signed):
            status = "已签名已哈希"
        elif st_low in ("", "unchecked"):
            status = "已哈希"
        else:
            status = "未签名已哈希"
    elif _is_trusted_signed(sig, signed):
        status = "已签名无哈希"
    elif st_low in ("", "unchecked"):
        status = "未验签"
    elif st_low in ("notsigned", "hashmismatch", "nottrusted", "invalid", "error", "unsigned"):
        status = "未签名无哈希"
    else:
        status = sig or "无哈希"
    return {
        "path": fp[:800],
        "name": str(r["name"] if "name" in r.keys() else "")[:240],
        "ext": ext[:16],
        "sig_status": sig[:40],
        "signed": signed,
        "size": size,
        "mtime": mtime[:32],
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "hash": hv,
        "status": status,
    }


def collect_hash_rows(rid: str) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """从 analysis.db 收集哈希。

    持久化（启动项/服务/任务/进程）优先且始终收录；
    已签宿主同目录未签 PE 一并标为持久化来源（白加黑旁路）；
    文件表：已签名 PE 仍计入对照（与告警页一致），覆盖统计里单独记 signed_skipped。
    同一哈希可对应多个来源（不互相挤掉）。
    """
    rows: List[Dict[str, str]] = []
    seen: Set[str] = set()
    stats = {
        "files_total": 0,
        "pe_total": 0,
        "signed_skipped": 0,
        "unsigned_hashed": 0,
        "unsigned_exe": 0,
        "unsigned_dll": 0,
        "no_hash": 0,
        "unchecked_pe": 0,
        "persist_hashed": 0,
        "startup_hashed": 0,
        "task_hashed": 0,
        "service_hashed": 0,
        "process_hashed": 0,
        "network_ips": 0,
    }
    persist_stat_key = {
        "启动项": "startup_hashed",
        "计划任务": "task_hashed",
        "服务": "service_hashed",
        "进程": "process_hashed",
        "驱动": "persist_hashed",
        "网络": "network_ips",
    }

    def add(kind: str, hv: str, path: str, origin: str):
        hv = _norm_hash_val(hv)
        kind = kind or (ioc_db.hash_kind(hv) or "")
        if not hv or not ioc_db.hash_kind(hv):
            return
        origin = origin or "文件"
        # 同来源+同路径+同哈希去重；不同来源保留多行，命中时能看出启动项/服务
        key = f"{origin}|{kind}|{hv}|{(path or '').lower()}"
        if key in seen:
            return
        seen.add(key)
        if len(rows) >= _MAX_HASHES:
            return
        rows.append({
            "kind": kind,
            "hash": hv,
            "path": (path or "")[:320],
            "origin": origin,
        })
        sk = persist_stat_key.get(origin)
        if sk:
            stats[sk] = int(stats.get(sk) or 0) + 1
            stats["persist_hashed"] = int(stats.get("persist_hashed") or 0) + 1

    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return rows, stats
    conn = sqlite3.connect(str(dbp))
    conn.row_factory = sqlite3.Row
    pe_exts = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv", ".msi"}
    persist_hosts: List[Tuple[str, str]] = []
    try:
        blob_names = {r[0] for r in conn.execute("SELECT name FROM blobs").fetchall()}
        # 持久化优先：即使文件表因 Valid 跳过，启动项/服务仍对照
        for key, origin in _PERSIST_BLOBS:
            if key not in blob_names:
                continue
            raw = conn.execute("SELECT data FROM blobs WHERE name=?", (key,)).fetchone()
            if not raw:
                continue
            try:
                arr = json.loads(raw["data"] or "[]")
            except Exception:
                continue
            if isinstance(arr, dict):
                arr = list(arr.values())
            if not isinstance(arr, list):
                continue
            fields = _PERSIST_PATH_FIELDS.get(key) or ("path", "resolved_path", "image_path", "command")
            for item in arr:
                if not isinstance(item, dict):
                    continue
                name = item.get("name") or item.get("task_name") or item.get("display_name") or ""
                fp = str(
                    item.get("full_path")
                    or item.get("resolved_path")
                    or item.get("path")
                    or item.get("image_path")
                    or item.get("command")
                    or item.get("name")
                    or item.get("task_name")
                    or ""
                ).replace("/", "\\")[:320]
                for kind, hv in _pick_hashes_from_obj(item):
                    add(kind, hv, fp, origin)
                blob = " ".join(str(item.get(f) or "") for f in fields)
                for p in _pe_paths_from_text(blob):
                    persist_hosts.append((p, f"{origin}:{name or p}"))
                if fp and any(fp.lower().endswith(e) for e in pe_exts):
                    persist_hosts.append((fp, f"{origin}:{name or fp}"))
                if len(rows) >= _MAX_HASHES:
                    break

        cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        if "full_path" in cols:
            stats["files_total"] = int(conn.execute("SELECT COUNT(1) c FROM files").fetchone()["c"] or 0)
            if "ext" in cols:
                stats["pe_total"] = int(conn.execute(
                    "SELECT COUNT(1) c FROM files WHERE lower(IFNULL(ext,'')) IN "
                    "('.exe','.dll','.sys','.scr','.com','.ocx','.cpl','.drv','.msi')"
                ).fetchone()["c"] or 0)
        hash_cols = {"md5", "sha1", "sha256"} & cols
        # 持久化路径按路径补哈希（条目自身无哈希时）
        if hash_cols and persist_hosts and len(rows) < _MAX_HASHES:
            norms: Dict[str, Tuple[str, str]] = {}
            for p, lab in persist_hosts:
                n = str(p or "").replace("/", "\\").lower().strip()
                if n and n not in norms:
                    norms[n] = (p, lab)
            keys = list(norms.keys())
            for i in range(0, len(keys), 80):
                batch = keys[i : i + 80]
                ph = ",".join("?" * len(batch))
                sql = (
                    "SELECT full_path, md5, sha1, sha256 FROM files "
                    f"WHERE lower(replace(full_path,'/','\\')) IN ({ph})"
                )
                for r in conn.execute(sql, batch).fetchall():
                    fp = (r["full_path"] or "").replace("/", "\\")
                    lab = norms.get(fp.lower(), (fp, "文件"))[1]
                    origin = (lab.split(":")[0] if lab else "文件") or "文件"
                    for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                        add(kind, r[col] if col in r.keys() else "", fp, origin)
                    if len(rows) >= _MAX_HASHES:
                        break
                if len(rows) >= _MAX_HASHES:
                    break

        if hash_cols and len(rows) < _MAX_HASHES:
            sel = "full_path, name, md5, sha1, sha256"
            if "sig_status" in cols:
                sel += ", sig_status"
            if "signed" in cols:
                sel += ", signed"
            if "ext" in cols:
                sel += ", ext"
            for r in conn.execute(f"SELECT {sel} FROM files"):
                fp = (r["full_path"] or r["name"] or "").replace("/", "\\")
                ext = str(r["ext"] if "ext" in r.keys() else "").lower()
                if ext and not ext.startswith("."):
                    ext = "." + ext
                if not ext:
                    low = str(fp).lower()
                    for e in pe_exts:
                        if low.endswith(e):
                            ext = e
                            break
                sig = r["sig_status"] if "sig_status" in r.keys() else ""
                signed = r["signed"] if "signed" in r.keys() else 0
                has_hv = False
                for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                    hv = _norm_hash_val(r[col] if col in r.keys() else "")
                    if hv and ioc_db.hash_kind(hv):
                        has_hv = True
                if has_hv:
                    if _is_trusted_signed(sig, signed):
                        # 覆盖统计仍记「跳过已签名」，但哈希仍参与 IOC 对照
                        # （告警页会查已签名 PE；此前跳过导致「结果有命中、扫描无显示」）
                        stats["signed_skipped"] += 1
                    else:
                        stats["unsigned_hashed"] += 1
                        if ext == ".exe":
                            stats["unsigned_exe"] += 1
                        elif ext == ".dll":
                            stats["unsigned_dll"] += 1
                    for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                        add(kind, r[col] if col in r.keys() else "", fp, "文件")
                elif ext in pe_exts or any(str(fp).lower().endswith(x) for x in pe_exts):
                    st = str(sig or "").strip().lower()
                    if st in ("", "unchecked"):
                        stats["unchecked_pe"] += 1
                    else:
                        stats["no_hash"] += 1
                if len(rows) >= _MAX_HASHES:
                    break
    finally:
        conn.close()

    # 白加黑旁路：持久化宿主同目录未签 PE 标为对应持久化来源（关闭后仍可被「文件」覆盖）
    if persist_hosts and len(rows) < _MAX_HASHES:
        for kind, hv, evid in lookup_unsigned_sidecar_hashes(rid, persist_hosts):
            # evid 形如「服务同目录:C:\...\evil.dll」
            origin = "文件"
            path = ""
            if "同目录:" in evid:
                tag, path = evid.split("同目录:", 1)
                origin = (tag or "").strip() or "文件"
            else:
                path = evid
            add(kind, hv, path, origin)
            if len(rows) >= _MAX_HASHES:
                break

    return rows, stats


def collect_sideload_structure_hits(rid: str) -> List[Dict[str, Any]]:
    """把分析阶段已命中的白加黑规则挂到 IOC 扫描结果（不依赖情报库哈希）。

    典型：启动项/服务指向已签宿主，同目录未签 DLL —— IOC 情报往往没有这些哈希，
    但规则侧已检出；合并后 IOC 页能看到，避免「跳过签名 → 白加黑扫不到」的落差。
    """
    out: List[Dict[str, Any]] = []
    if not rid:
        return out
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return out

    def origin_from_rule(rule_id: str) -> str:
        rid_l = str(rule_id or "").lower()
        if rid_l.startswith("startup.") or "startup" in rid_l:
            return "启动项"
        if rid_l.startswith("task.") or "task" in rid_l:
            return "计划任务"
        if rid_l.startswith("svc.") or "service" in rid_l:
            return "服务"
        return "持久化"

    def is_sideload(rule_id: str, title: str) -> bool:
        rid_l = str(rule_id or "").lower()
        t = str(title or "")
        return "sideload" in rid_l or "白加黑" in t or "sideload" in t.lower()

    findings: List[Dict[str, Any]] = []
    conn = sqlite3.connect(str(dbp))
    conn.row_factory = sqlite3.Row
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "findings_agg" in tables:
            for r in conn.execute(
                "SELECT rule_id, title, evidence, severity FROM findings_agg"
            ):
                findings.append({
                    "rule_id": r["rule_id"],
                    "title": r["title"],
                    "evidence": r["evidence"],
                    "severity": r["severity"],
                })
        if not findings:
            raw = conn.execute(
                "SELECT data FROM blobs WHERE name=? LIMIT 1", ("findings_by_module",)
            ).fetchone()
            if raw:
                try:
                    fbm = json.loads(raw["data"] or "{}")
                except Exception:
                    fbm = {}
                if isinstance(fbm, dict):
                    for block in fbm.values():
                        if not isinstance(block, dict):
                            continue
                        for f in block.get("findings") or []:
                            if isinstance(f, dict):
                                findings.append(f)

        path_re = re.compile(
            r'(?i)[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.(?:exe|dll|sys|scr|ocx)'
        )
        seen: Set[str] = set()
        for f in findings:
            rule_id = str(f.get("rule_id") or f.get("id") or "")
            title = str(f.get("title") or f.get("name") or "")
            if not is_sideload(rule_id, title):
                continue
            ev = f.get("evidence")
            if isinstance(ev, str):
                try:
                    ev = json.loads(ev)
                except Exception:
                    ev = [ev]
            if not isinstance(ev, list):
                ev = [ev] if ev else []
            blob = " ".join(str(x) for x in ev if x)
            paths = path_re.findall(blob) or path_re.findall(title)
            # 优先未签旁路 dll，其次宿主 exe
            dlls = [p for p in paths if p.lower().endswith(".dll")]
            hosts = [p for p in paths if p.lower().endswith((".exe", ".sys", ".scr"))]
            pick = (dlls[0] if dlls else None) or (hosts[0] if hosts else None) or ""
            if not pick:
                pick = title[:200]
            key = f"{rule_id}|{pick.lower()}"
            if key in seen:
                continue
            seen.add(key)
            hv = ""
            kind = "sideload"
            if pick and "\\" in pick:
                row = conn.execute(
                    "SELECT md5, sha1, sha256 FROM files "
                    "WHERE lower(replace(full_path,'/','\\'))=? LIMIT 1",
                    (pick.replace("/", "\\").lower(),),
                ).fetchone()
                if row:
                    for col, k in (("sha256", "sha256"), ("sha1", "sha1"), ("md5", "md5")):
                        v = _norm_hash_val(row[col] if col in row.keys() else "")
                        if v and ioc_db.hash_kind(v):
                            hv = v
                            kind = k
                            break
            out.append({
                "hash": hv,
                "kind": kind,
                "path": pick[:320],
                "origin": origin_from_rule(rule_id),
                "name": (title or "白加黑旁路")[:160],
                "source": "规则·白加黑",
            })
            if len(out) >= 200:
                break
    except Exception as e:
        print(f"[ioc_full_scan] sideload merge: {e}")
    finally:
        conn.close()
    return out


def collect_network_rows(rid: str) -> Tuple[List[Dict[str, str]], int]:
    """从已建立连接提取远端 IP，供 IOC IP 对照（与告警页 network IOC 对齐）。

    路径列优先填进程真实 exe（Linux / Windows）；外联目标放 detail，避免「路径=外联说明」。
    """
    from .matchers.util import conn_remote, conn_remote_ip, is_private_ip
    from .net_process import build_process_index, conn_pid, conn_proc_label, enrich_conn_row

    def _abs_path(p: str) -> bool:
        s = str(p or "").strip()
        if not s:
            return False
        if s.startswith("/") and not s.startswith("//"):
            return True
        if len(s) >= 3 and s[1] == ":" and s[2] in "\\/":
            return True
        return False

    rows: List[Dict[str, str]] = []
    best: Dict[str, Dict[str, str]] = {}
    dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
    if not dbp or not Path(dbp).is_file():
        return rows, 0
    conn = sqlite3.connect(str(dbp))
    conn.row_factory = sqlite3.Row
    try:
        raw = conn.execute(
            "SELECT data FROM blobs WHERE name=? LIMIT 1", (_NETWORK_BLOB,)
        ).fetchone()
        if not raw:
            return rows, 0
        try:
            arr = json.loads(raw["data"] or "[]")
        except Exception:
            return rows, 0
        if isinstance(arr, dict):
            arr = list(arr.values())
        if not isinstance(arr, list):
            return rows, 0

        processes: List[Any] = []
        prow = conn.execute(
            "SELECT data FROM blobs WHERE name=? LIMIT 1", ("processes",)
        ).fetchone()
        if prow:
            try:
                processes = json.loads(prow["data"] or "[]") or []
            except Exception:
                processes = []
        proc_idx = build_process_index(processes if isinstance(processes, list) else [])

        for item in arr:
            if not isinstance(item, dict):
                continue
            ip = (conn_remote_ip(item) or "").strip().lower().strip("[]")
            if not ip:
                continue
            # 内网地址一般不在情报库；跳过可减噪音，与常见研判一致
            if is_private_ip(ip):
                continue
            enrich_conn_row(item, proc_idx)
            rm = conn_remote(item) or ip
            proc = ""
            try:
                proc = conn_proc_label(item) or ""
            except Exception:
                proc = str(item.get("process") or item.get("name") or "").strip()
            proc_path = str(item.get("process_path") or "").strip()
            if not _abs_path(proc_path):
                pid = conn_pid(item)
                proc_path = str((proc_idx.get(pid) or {}).get("path") or "").strip()
            detail = f"{proc} → {rm}".strip() if proc else f"→ {rm}"
            if _abs_path(proc_path):
                path = proc_path
            else:
                # 无 exe 时仍给出可辨识说明（兼容旧展示）
                path = f"外联:{proc} {rm}".strip() if proc else f"外联:{rm}"
            rec = {
                "kind": "ip",
                "hash": ip,
                "path": path[:500],
                "origin": "网络",
                "detail": detail[:320],
                "process_path": proc_path[:500] if _abs_path(proc_path) else "",
            }
            prev = best.get(ip)
            if not prev:
                best[ip] = rec
            elif _abs_path(rec["path"]) and not _abs_path(prev.get("path") or ""):
                best[ip] = rec
            if len(best) >= 5000:
                break
        rows = list(best.values())
    finally:
        conn.close()
    return rows, len(rows)


def _query_backend_label() -> str:
    try:
        from . import ioc_mysql
        if ioc_mysql.is_available():
            return "mysql"
    except Exception:
        pass
    try:
        from . import es_client
        if es_client.is_available():
            return "es"
    except Exception:
        pass
    return "sqlite"


def start(rid: str, *, force: bool = False) -> Dict[str, Any]:
    rid = str(rid or "").strip()
    if not rid:
        return {**_empty_state(""), "ok": False, "error": "缺少报告"}
    with _lock:
        st = load_state(rid)
        if st.get("status") in ("running", "queued") and not force:
            return st
        if rid in _threads and _threads[rid].is_alive() and not force:
            return st
        _cancel.discard(rid)
        st = {
            **_empty_state(rid),
            "status": "queued",
            "phase": "collect",
            "message": "正在收集已采集哈希…",
            "started_at": _now(),
            "updated_at": _now(),
            "backend": _query_backend_label(),
            "fingerprint": current_fingerprint(rid),
        }
        _atomic_write(_state_path(rid), st)
        t = threading.Thread(target=_run, args=(rid,), name=f"ioc-full-{rid[:24]}", daemon=True)
        _threads[rid] = t
        t.start()
    return st


def cancel(rid: str) -> Dict[str, Any]:
    rid = str(rid or "").strip()
    with _lock:
        _cancel.add(rid)
    st = load_state(rid)
    if st.get("status") in ("running", "queued"):
        st["status"] = "cancelled"
        st["message"] = "已取消"
        st["finished_at"] = _now()
        st["updated_at"] = _now()
        _atomic_write(_state_path(rid), st)
    return st


def _run(rid: str) -> None:
    try:
        # 全量扫描必须以当前情报库为准：清进程 LRU + Redis IOC 正缓存
        try:
            ioc_db.clear_local_cache()
        except Exception:
            pass
        try:
            ioc_db.clear_redis_ioc_cache()
        except Exception:
            pass
        rows, stats = collect_hash_rows(rid)
        net_rows, net_n = collect_network_rows(rid)
        stats["network_ips"] = int(net_n or 0)
        if net_n:
            # 网络 IP 计入持久化对照总量，便于前端「持久化对照」条展示
            stats["persist_hashed"] = int(stats.get("persist_hashed") or 0) + int(net_n)

        uniq: List[str] = []
        seen_h: Set[str] = set()
        for r in rows:
            hv = r["hash"]
            if hv in seen_h:
                continue
            seen_h.add(hv)
            uniq.append(hv)
        by_hash: Dict[str, List[Dict[str, str]]] = {}
        for r in rows:
            by_hash.setdefault(r["hash"], []).append(r)

        uniq_ips: List[str] = []
        seen_ip: Set[str] = set()
        by_ip: Dict[str, List[Dict[str, str]]] = {}
        for r in net_rows:
            ip = (r.get("hash") or "").strip().lower()
            if not ip or ip in seen_ip:
                continue
            seen_ip.add(ip)
            uniq_ips.append(ip)
            by_ip.setdefault(ip, []).append(r)

        cover = (
            f"枚举 {stats.get('files_total') or 0} 个文件"
            f"（PE {stats.get('pe_total') or 0}），"
            f"未签名已哈希 exe {stats.get('unsigned_exe') or 0} / dll {stats.get('unsigned_dll') or 0}，"
            f"已签名仍对照 {stats.get('signed_skipped') or 0}，"
            f"持久化 启动{stats.get('startup_hashed') or 0}"
            f"/任务{stats.get('task_hashed') or 0}"
            f"/服务{stats.get('service_hashed') or 0}"
            f"/进程{stats.get('process_hashed') or 0}"
            f"/网络IP{stats.get('network_ips') or 0}"
            f"（含同目录未签旁路）"
        )
        total_lookups = len(uniq) + len(uniq_ips)

        st = load_state(rid)
        if rid in _cancel:
            st["status"] = "cancelled"
            st["message"] = "已取消"
            st["finished_at"] = _now()
            _atomic_write(_state_path(rid), st)
            return
        st.update({
            "status": "running",
            "phase": "lookup",
            "total": total_lookups,
            "scanned": 0,
            "hits": 0,
            "items": [],
            "message": f"{cover}；对照 {len(uniq)} 哈希 + {len(uniq_ips)} IP…",
            "updated_at": _now(),
            "backend": _query_backend_label(),
            **stats,
        })
        _atomic_write(_state_path(rid), st)

        items: List[Dict[str, Any]] = []
        seen_hit: Set[str] = set()
        scanned = 0

        def _append_hit(rec: Dict[str, str], h: Dict[str, Any], value: str) -> bool:
            name = str(h.get("malware") or h.get("name") or h.get("family") or "").strip()
            src = str(h.get("source") or h.get("db_source") or "").strip()
            dk = f"{rec.get('origin')}|{rec.get('path')}|{name or value}|{value}"
            if dk in seen_hit:
                return False
            seen_hit.add(dk)
            items.append({
                "hash": value,
                "kind": rec.get("kind") or h.get("match_type") or ioc_db.hash_kind(value) or "ip",
                "path": rec.get("path") or "",
                "origin": rec.get("origin") or "文件",
                "name": name or "IOC",
                "source": src,
                "detail": rec.get("detail") or "",
                "process_path": rec.get("process_path") or "",
            })
            return True

        for i in range(0, len(uniq), _CHUNK):
            if rid in _cancel:
                st = load_state(rid)
                st["status"] = "cancelled"
                st["message"] = "已取消"
                st["scanned"] = scanned
                st["finished_at"] = _now()
                st["updated_at"] = _now()
                st["items"] = items[:_MAX_HITS_STORE]
                _atomic_write(_state_path(rid), st)
                return
            chunk = uniq[i : i + _CHUNK]
            hit_map = ioc_db.lookup_hashes_batch(chunk, chunk_size=_CHUNK, bypass_cache=True)
            for hv in chunk:
                scanned += 1
                for h in hit_map.get(hv) or []:
                    if not isinstance(h, dict):
                        continue
                    recs = by_hash.get(hv) or [{"path": "", "origin": "文件", "kind": h.get("match_type") or ""}]
                    for rec in recs:
                        _append_hit(rec, h, hv)
                        if len(items) >= _MAX_HITS_STORE:
                            break
                    if len(items) >= _MAX_HITS_STORE:
                        break
            st = {
                **load_state(rid, include_items=False),
                "status": "running",
                "phase": "lookup",
                "total": total_lookups,
                "scanned": scanned,
                "hits": len(items),
                "items": items[:80],
                "message": f"已查哈希 {scanned}/{len(uniq)}，命中 {len(items)}",
                "updated_at": _now(),
                **stats,
            }
            _atomic_write(_state_path(rid), st)

        # 网络外连 IP 对照
        for i in range(0, len(uniq_ips), _CHUNK):
            if rid in _cancel:
                st = load_state(rid)
                st["status"] = "cancelled"
                st["message"] = "已取消"
                st["scanned"] = scanned
                st["finished_at"] = _now()
                st["updated_at"] = _now()
                st["items"] = items[:_MAX_HITS_STORE]
                _atomic_write(_state_path(rid), st)
                return
            chunk = uniq_ips[i : i + _CHUNK]
            hit_map = ioc_db.lookup_ips_batch(chunk, chunk_size=_CHUNK, bypass_cache=True)
            for ip in chunk:
                scanned += 1
                for h in hit_map.get(ip) or []:
                    if not isinstance(h, dict):
                        continue
                    recs = by_ip.get(ip) or [{"path": f"外联:{ip}", "origin": "网络", "kind": "ip"}]
                    for rec in recs:
                        _append_hit(rec, h, ip)
                        if len(items) >= _MAX_HITS_STORE:
                            break
                    if len(items) >= _MAX_HITS_STORE:
                        break
            st = {
                **load_state(rid, include_items=False),
                "status": "running",
                "phase": "lookup_net",
                "total": total_lookups,
                "scanned": scanned,
                "hits": len(items),
                "items": items[:80],
                "message": f"已查 IP {min(i + _CHUNK, len(uniq_ips))}/{len(uniq_ips)}，命中 {len(items)}",
                "updated_at": _now(),
                **stats,
            }
            _atomic_write(_state_path(rid), st)

        # 白加黑：规则已检出但情报无哈希时，仍挂到 IOC 结果，避免「只跳签名 → 扫不到」
        intel_hits = len(items)
        sideload_hits = collect_sideload_structure_hits(rid)
        for rec in sideload_hits:
            dk = f"{rec.get('origin')}|{rec.get('path')}|{rec.get('name')}|sideload"
            if dk in seen_hit:
                continue
            seen_hit.add(dk)
            items.append(rec)
            if len(items) >= _MAX_HITS_STORE:
                break
        stats["sideload_hits"] = len(sideload_hits)

        st = {
            **load_state(rid, include_items=False),
            "status": "done",
            "phase": "done",
            "total": total_lookups,
            "scanned": scanned,
            "hits": len(items),
            "items": items[:_MAX_HITS_STORE],
            "message": (
                f"完成：{cover}；对照 {len(uniq)} 哈希 + {len(uniq_ips)} IP，"
                f"情报命中 {intel_hits}，白加黑旁路 {len(sideload_hits)}"
            ),
            "finished_at": _now(),
            "updated_at": _now(),
            **stats,
        }
        _atomic_write(_state_path(rid), st)
    except Exception as e:
        st = load_state(rid)
        st["status"] = "error"
        st["error"] = str(e)[:400]
        st["message"] = "扫描失败"
        st["finished_at"] = _now()
        st["updated_at"] = _now()
        try:
            _atomic_write(_state_path(rid), st)
        except Exception:
            pass
    finally:
        with _lock:
            _cancel.discard(rid)
            _threads.pop(rid, None)


def _host_slug(rid: str) -> str:
    s = str(rid or "report").strip()
    s = s.replace("report_", "")
    keep = []
    for ch in s:
        if ch.isalnum() or ch in "._-":
            keep.append(ch)
        else:
            keep.append("_")
    out = "".join(keep).strip("._") or "report"
    return out[:80]


def _esc_md(s: Any) -> str:
    return str(s or "").replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").strip()


def _esc_html(s: Any) -> str:
    return (
        str(s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def export_hits(rid: str, fmt: str = "csv") -> Tuple[bytes, str, str]:
    """导出 IOC 全量扫描命中。未扫描过则抛 ValueError。"""
    rid = str(rid or "").strip()
    fmt = str(fmt or "csv").strip().lower()
    if fmt in ("md", "markdown"):
        fmt = "markdown"
    if fmt not in ("csv", "html", "markdown"):
        raise ValueError("fmt 仅支持 csv / html / markdown")
    st = load_state(rid, include_items=True)
    status = str(st.get("status") or "idle")
    if status in ("idle", "queued", "running"):
        raise ValueError("请先完成 IOC 扫描后再导出")
    items = st.get("items") if isinstance(st.get("items"), list) else []
    slug = _host_slug(rid)
    if fmt == "csv":
        import csv
        import io

        buf = io.StringIO()
        buf.write("\ufeff")
        w = csv.writer(buf)
        w.writerow(["来源", "情报", "情报来源", "路径", "进程路径", "明细", "类型", "哈希/IP"])
        for it in items:
            if not isinstance(it, dict):
                continue
            w.writerow([
                it.get("origin") or "文件",
                it.get("name") or "",
                it.get("source") or "",
                it.get("path") or "",
                it.get("process_path") or "",
                it.get("detail") or "",
                str(it.get("kind") or "").upper(),
                it.get("hash") or "",
            ])
        body = buf.getvalue().encode("utf-8")
        return body, "text/csv; charset=utf-8", f"{slug}_ioc_scan.csv"

    hits = int(st.get("hits") or len(items) or 0)
    cover = [
        f"状态 {status}",
        f"对照 {st.get('scanned') or 0}/{st.get('total') or 0}",
        f"命中 {hits}",
        f"枚举文件 {st.get('files_total') or 0}",
        f"未签名 exe/dll {(st.get('unsigned_exe') or 0)}/{(st.get('unsigned_dll') or 0)}",
        f"已签名仍对照 {st.get('signed_skipped') or 0}",
        f"启动/任务/服务/进程 "
        f"{st.get('startup_hashed') or 0}/{st.get('task_hashed') or 0}/"
        f"{st.get('service_hashed') or 0}/{st.get('process_hashed') or 0}",
        f"外联 IP {st.get('network_ips') or 0}",
    ]
    note = (
        "对照对象是本报告已采集的文件哈希、启动项/任务/服务/进程/驱动哈希，以及已建立连接的公网 IP；"
        "不是分析页告警列表。白加黑旁路会从分析命中合并进来。未扫描到的键/无哈希文件不会出现。"
    )
    if fmt == "markdown":
        lines = [
            f"# IOC 全量扫描 · `{_esc_md(rid)}`",
            "",
            f"> {' · '.join(cover)}",
            "",
            note,
            "",
            "| 来源 | 情报 | 路径 | 类型 | 哈希/IP |",
            "| --- | --- | --- | --- | --- |",
        ]
        if not items:
            lines.append("| — | 无命中 | — | — | — |")
        else:
            for it in items:
                if not isinstance(it, dict):
                    continue
                lines.append(
                    f"| {_esc_md(it.get('origin') or '文件')} "
                    f"| {_esc_md(it.get('name') or '')} "
                    f"| `{_esc_md(it.get('path') or '')}` "
                    f"| {_esc_md(str(it.get('kind') or '').upper())} "
                    f"| `{_esc_md(it.get('hash') or '')}` |"
                )
        text = "\n".join(lines) + "\n"
        return text.encode("utf-8"), "text/markdown; charset=utf-8", f"{slug}_ioc_scan.md"

    rows_html = ""
    if not items:
        rows_html = "<tr><td colspan='5' class='empty'>没有命中</td></tr>"
    else:
        for it in items:
            if not isinstance(it, dict):
                continue
            rows_html += (
                "<tr>"
                f"<td>{_esc_html(it.get('origin') or '文件')}</td>"
                f"<td>{_esc_html(it.get('name') or '')}"
                f"<div class='src'>{_esc_html(it.get('source') or '')}</div></td>"
                f"<td class='mono'>{_esc_html(it.get('path') or '')}</td>"
                f"<td>{_esc_html(str(it.get('kind') or '').upper())}</td>"
                f"<td class='mono'>{_esc_html(it.get('hash') or '')}</td>"
                "</tr>"
            )
    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>IOC 全量扫描 · {_esc_html(rid)}</title>
<style>
body{{font-family:Segoe UI,Microsoft YaHei,sans-serif;margin:24px;color:#1f2a37;background:#f6f8fb}}
.wrap{{max-width:1180px;margin:0 auto;background:#fff;border:1px solid #e5eaf1;border-radius:10px;padding:22px 24px}}
h1{{font-size:20px;margin:0 0 8px}}
.meta{{color:#607086;font-size:13px;margin:0 0 12px}}
.note{{font-size:12px;color:#607086;line-height:1.5;margin:0 0 16px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid #eef2f7;vertical-align:top}}
th{{background:#f7f9fc;color:#5b6b7c}}
.mono{{font-family:Consolas,JetBrains Mono,monospace;word-break:break-all}}
.src{{color:#8a97a8;font-size:11px;margin-top:2px}}
.empty{{color:#8a97a8;text-align:center;padding:18px}}
</style></head>
<body><div class="wrap">
<h1>IOC 全量扫描</h1>
<p class="meta">{_esc_html(' · '.join(cover))}</p>
<p class="note">{_esc_html(note)}</p>
<table><thead><tr><th>来源</th><th>情报</th><th>路径</th><th>类型</th><th>哈希/IP</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</div></body></html>"""
    return html.encode("utf-8"), "text/html; charset=utf-8", f"{slug}_ioc_scan.html"


def markdown_section_for_report(rid: str) -> str:
    """嵌入分析报告 MD 的 IOC 扫描小节；未扫描则说明。"""
    st = load_state(rid, include_items=True)
    status = str(st.get("status") or "idle")
    items = st.get("items") if isinstance(st.get("items"), list) else []
    lines = ["## 6. IOC 全量扫描", ""]
    if status in ("idle", ""):
        lines += ["_本报告尚未在「IOC扫描」页做全量对照；下方告警里的 IOC 命中来自分析管线抽样，不是全量。_", ""]
        return "\n".join(lines)
    hits = int(st.get("hits") or len(items) or 0)
    lines.append(
        f"- 状态：`{status}` · 对照 {st.get('scanned') or 0}/{st.get('total') or 0} · 命中 **{hits}**"
    )
    lines.append(
        f"- 范围：已采集文件哈希（含已签名 PE）、启动项/任务/服务/进程/驱动哈希、已建立连接公网 IP；"
        f"白加黑旁路从分析命中合并。不是扫分析页告警列表。"
    )
    lines.append("")
    if not items:
        lines += ["_全量对照无情报命中。_", ""]
        return "\n".join(lines)
    lines += ["| 来源 | 情报 | 路径 | 类型 | 哈希/IP |", "| --- | --- | --- | --- | --- |"]
    for it in items[:800]:
        if not isinstance(it, dict):
            continue
        lines.append(
            f"| {_esc_md(it.get('origin') or '文件')} "
            f"| {_esc_md(it.get('name') or '')} "
            f"| `{_esc_md(it.get('path') or '')}` "
            f"| {_esc_md(str(it.get('kind') or '').upper())} "
            f"| `{_esc_md(it.get('hash') or '')}` |"
        )
    if len(items) > 800:
        lines.append(f"| — | _其余 {len(items) - 800} 条请用 IOC 扫描页单独导出_ | — | — | — |")
    lines.append("")
    return "\n".join(lines)


def html_section_for_report(rid: str) -> str:
    st = load_state(rid, include_items=True)
    status = str(st.get("status") or "idle")
    items = st.get("items") if isinstance(st.get("items"), list) else []
    if status in ("idle", ""):
        return (
            "<details class='sec'><summary><h2>IOC 全量扫描</h2>"
            "<span class='sec-count'>未执行</span></summary>"
            "<p class='note'>尚未在「IOC扫描」页做全量对照。分析页 IOC 告警来自管线抽样，不是全量哈希/外联对照。</p>"
            "</details>"
        )
    hits = int(st.get("hits") or len(items) or 0)
    if not items:
        body = "<div class='empty'>全量对照无情报命中</div>"
    else:
        rows = []
        for it in items[:800]:
            if not isinstance(it, dict):
                continue
            rows.append(
                "<tr>"
                f"<td class='col-src nowrap'>{_esc_html(it.get('origin') or '文件')}</td>"
                f"<td class='col-name'>{_esc_html(it.get('name') or '')}</td>"
                f"<td class='col-path mono'>{_esc_html(it.get('path') or '')}</td>"
                f"<td class='col-kind nowrap'>{_esc_html(str(it.get('kind') or '').upper())}</td>"
                f"<td class='col-hash mono'>{_esc_html(it.get('hash') or '')}</td>"
                "</tr>"
            )
        extra = ""
        if len(items) > 800:
            extra = f"<p class='note'>仅列出前 800 条，完整列表请在 IOC 扫描页导出。</p>"
        body = (
            "<div class='table-scroll'><table class='ioc-table'>"
            "<thead><tr>"
            "<th class='col-src'>来源</th><th class='col-name'>情报</th>"
            "<th class='col-path'>路径</th><th class='col-kind'>类型</th>"
            "<th class='col-hash'>哈希/IP</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>{extra}"
        )
    return (
        "<details class='sec'><summary><h2>IOC 全量扫描</h2>"
        f"<span class='sec-count'>{_esc_html(status)} · 命中 {hits}</span></summary>"
        "<p class='note'>对照已采集文件哈希、持久化（启动/任务/服务/进程）哈希、外联公网 IP；"
        "不是扫分析页告警列表。</p>"
        f"{body}</details>"
    )
