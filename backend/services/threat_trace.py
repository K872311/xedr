"""威胁溯检：以进程为中心关联报告内网络、告警等行为。"""
from __future__ import annotations

import copy
import json
import re
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.db_store import (
    _attach_eventlog_hit_rules,
    _connect,
    _ensure_directory_index,
    _ensure_event_logs_table,
    _event_log_row_to_dict,
    _init_schema,
    _load_findings_from_conn,
    _load_one_blob,
    _norm_file_path,
    _proc_pid,
    _proc_ppid,
    _resolve_db_path,
)
from backend.net_process import build_process_index, conn_pid, enrich_conn_list, enrich_report_connections

_HASH_RE = re.compile(r"^[a-f0-9]{32,64}$", re.I)
_PID_RE = re.compile(r"^\d{1,10}$")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_EXE_EXT = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".msi", ".lnk", ".cpl",
}


def _norm(s: Any) -> str:
    return str(s or "").strip()


def _norm_lower(s: Any) -> str:
    return _norm(s).lower()


def _proc_name(p: Dict[str, Any]) -> str:
    return _norm(p.get("name") or p.get("process_name") or "")


def _proc_path(p: Dict[str, Any]) -> str:
    return _norm(p.get("path") or p.get("exe") or "")


def _proc_hashes(p: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for k in ("md5", "sha1", "sha256", "MD5", "SHA1", "SHA256"):
        v = _norm_lower(p.get(k))
        if v:
            out.add(v)
    return out


def _finding_id(f: Dict[str, Any], i: int) -> str:
    return _norm(f.get("id") or f.get("rule_id") or f"finding:{i}")


def _finding_severity(f: Dict[str, Any]) -> str:
    return _norm_lower(f.get("severity") or "medium") or "medium"


def _finding_text(f: Dict[str, Any]) -> str:
    bits: List[str] = []
    for k in ("title", "name", "reason", "category"):
        v = _norm(f.get(k))
        if v:
            bits.append(v)
    ev = f.get("evidence")
    if isinstance(ev, list):
        bits.extend(_norm(x) for x in ev if _norm(x))
    elif ev:
        bits.append(_norm(ev))
    return " ".join(bits).lower()


def _finding_extra(f: Dict[str, Any]) -> Dict[str, Any]:
    extra = f.get("extra")
    return extra if isinstance(extra, dict) else {}


def _finding_pids(f: Dict[str, Any]) -> Set[int]:
    out: Set[int] = set()
    extra = _finding_extra(f)
    for k in ("pid", "PID", "process_id"):
        try:
            n = int(extra.get(k) or f.get(k) or 0)
            if n > 0:
                out.add(n)
        except (TypeError, ValueError):
            pass
    text = _finding_text(f)
    for m in re.finditer(r"\bpid\s*[:=]?\s*(\d+)\b", text, re.I):
        try:
            n = int(m.group(1))
            if n > 0:
                out.add(n)
        except (TypeError, ValueError):
            pass
    return out


def _proc_matches_query(p: Dict[str, Any], q: str) -> bool:
    if not q:
        return False
    ql = q.lower()
    if _PID_RE.match(q):
        return _proc_pid(p) == int(q)
    if _HASH_RE.match(q):
        return ql in _proc_hashes(p)
    if _IP_RE.match(q):
        return False
    if "\\" in q or ":/" in q or q.startswith("/"):
        path = _proc_path(p).lower()
        return ql in path if path else False
    name = _proc_name(p).lower()
    path = _proc_path(p).lower()
    if ql in name or (path and ql in path):
        return True
    cmd = _norm_lower(p.get("command_line") or p.get("command"))
    return ql in cmd if cmd else False


def _conn_matches_query(c: Dict[str, Any], q: str) -> bool:
    ql = q.lower()
    for k in ("remote_ip", "remote", "foreign", "dst", "destination", "hostname", "domain"):
        v = _norm_lower(c.get(k))
        if v and (v == ql or ql in v):
            return True
    return False


def _finding_matches_process(f: Dict[str, Any], p: Dict[str, Any]) -> bool:
    pid = _proc_pid(p)
    if pid and pid in _finding_pids(f):
        return True
    extra = _finding_extra(f)
    pname = _proc_name(p).lower()
    ppath = _proc_path(p).lower()
    for k in ("process_name", "process_path", "image", "path", "exe"):
        v = _norm_lower(extra.get(k) or f.get(k))
        if not v:
            continue
        if pname and (v == pname or pname in v or v in pname):
            return True
        if ppath and (v == ppath or ppath in v or v in ppath):
            return True
    text = _finding_text(f)
    if pname and len(pname) >= 3 and pname in text:
        return True
    if ppath and len(ppath) >= 8 and ppath in text:
        return True
    for hv in _proc_hashes(p):
        if hv and hv in text:
            return True
    return False


def _finding_matches_query(f: Dict[str, Any], q: str) -> bool:
    if not q:
        return False
    ql = q.lower()
    if _HASH_RE.match(q):
        return ql in _finding_text(f)
    if _IP_RE.match(q):
        return ql in _finding_text(f)
    return ql in _finding_text(f)


def _paths_from_finding(f: Dict[str, Any]) -> List[str]:
    """从单条告警抽取可作溯查锚点的绝对路径。"""
    out: List[str] = []
    extra = _finding_extra(f)
    for k in ("path", "file", "full_path", "target", "process_path", "image", "ImagePath"):
        v = _norm(extra.get(k) or f.get(k)).strip().strip('"').strip("'")
        if v and ("\\" in v or "/" in v or _WIN_PATH_RE.match(v)):
            out.append(v)
    text = _finding_text(f)
    for m in re.finditer(r"[\"']?([a-z]:\\[^\s|·\"'<>]+|/[^\s|·\"'<>]+)", text, re.I):
        v = m.group(1).strip().rstrip(",;）)】]")
        if v and ("\\" in v or v.startswith("/")):
            out.append(v)
    dedup: List[str] = []
    seen: Set[str] = set()
    for v in out:
        key = _path_key(v)
        if not key or key in seen:
            continue
        seen.add(key)
        dedup.append(v[:360])
    return dedup


def _paths_from_findings_for_name(findings: List[Dict[str, Any]], q: str, *, limit: int = 12) -> List[str]:
    """文件名检索时：从告警证据抽全路径（files 表可能已无该文件，但告警仍带路径）。"""
    base = _basename(_norm(q)).lower()
    if not base or len(base) < 3:
        return []
    stem = base.rsplit(".", 1)[0] if "." in base else base
    out: List[str] = []
    seen: Set[str] = set()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if not _finding_matches_query(f, q) and stem not in _finding_text(f):
            continue
        for fp in _paths_from_finding(f):
            bn = _basename(fp).lower()
            if bn != base and stem not in bn:
                continue
            key = _path_key(fp)
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(fp)
            if len(out) >= limit:
                return out
    return out


def _extract_file_hits(f: Dict[str, Any], p: Dict[str, Any]) -> List[str]:
    """从告警里抽可展示的文件路径（告警关联，非写盘证据）。"""
    proc_l = _proc_path(p).lower()
    out: List[str] = []
    for v in _paths_from_finding(f):
        if proc_l and v.lower() == proc_l:
            continue
        out.append(v)
    return out[:6]


def _parent_dir(path: str) -> str:
    s = _norm(path).replace("/", "\\").rstrip("\\")
    if not s or "\\" not in s:
        if s.startswith("/") and s.count("/") >= 1:
            parent = s.rsplit("/", 1)[0]
            return parent or "/"
        return ""
    parent = s.rsplit("\\", 1)[0]
    return parent.rstrip("\\")


def looks_like_path(q: str) -> bool:
    s = _norm(q)
    if not s:
        return False
    if _WIN_PATH_RE.match(s) or s.startswith("\\\\") or s.startswith("/"):
        return True
    return "\\" in s or ":/" in s


_STEM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


def looks_like_filename(q: str) -> bool:
    """纯文件名（如 ev2f79.exe / ev2f79），不含目录分隔符。"""
    s = _norm(q)
    if not s or looks_like_path(s):
        return False
    if _PID_RE.match(s) or _HASH_RE.match(s) or _IP_RE.match(s):
        return False
    if "\\" in s or "/" in s or " " in s:
        return False
    # 已知可执行/脚本扩展，或较短的 name.ext
    if _is_exec_name(s):
        return True
    if "." in s and 3 <= len(s) <= 80:
        ext = s[s.rfind("."):].lower()
        if 2 <= len(ext) <= 6 and ext[1:].isalnum():
            return True
    # 无后缀短名：ev2f79、payload123
    if _STEM_NAME_RE.fullmatch(s) and len(s) >= 4:
        return True
    return False


def _path_key(p: str) -> str:
    s = _norm(p).replace("/", "\\").strip().rstrip("\\")
    return s.lower()


def _is_exec_name(name: str) -> bool:
    n = _norm(name).lower()
    dot = n.rfind(".")
    if dot < 0:
        return False
    return n[dot:] in _EXE_EXT


def _proc_matches_file(p: Dict[str, Any], fp: str) -> bool:
    """进程镜像 / 命令行 是否对应该文件。"""
    target = _path_key(fp)
    if not target:
        return False
    path = _path_key(_proc_path(p))
    if path and path == target:
        return True
    cmd = _path_key(p.get("command_line") or p.get("command") or "")
    if target and len(target) >= 8 and target in cmd:
        return True
    bn = _basename(target).lower()
    # 纯文件名锚点：按进程名 / 路径末段匹配，不要求同目录
    if bn and "\\" not in target and "/" not in target:
        if _proc_name(p).lower() == bn:
            return True
        if path and (path.endswith("\\" + bn) or path.endswith("/" + bn)):
            return True
        if bn and len(bn) >= 5 and bn in cmd:
            return True
        return False
    if bn and _proc_name(p).lower() == bn and path and _parent_dir(path) == _parent_dir(target):
        return True
    return False


def _file_row_to_item(r: Any, *, current: bool = False) -> Dict[str, Any]:
    keys = r.keys()
    fp = r["full_path"] or ""
    name = r["name"] or _basename(fp)
    mt = ""
    if "mtime" in keys and r["mtime"]:
        mt = _normalize_time_str(r["mtime"]) or _norm(r["mtime"])[:19]
    return {
        "kind": "file",
        "name": name,
        "path": fp,
        "parent": r["path"] or "",
        "ext": r["ext"] or "",
        "size": int(r["size"] or 0),
        "signed": bool(r["signed"]) if "signed" in keys else False,
        "signer": r["signer"] or "" if "signer" in keys else "",
        "sig_status": r["sig_status"] or "" if "sig_status" in keys else "",
        "md5": r["md5"] or "" if "md5" in keys else "",
        "sha1": r["sha1"] or "" if "sha1" in keys else "",
        "sha256": r["sha256"] or "" if "sha256" in keys else "",
        "mtime": mt,
        "time": mt,
        "current": current,
    }


def _files_select_cols(conn: Any) -> Tuple[str, bool]:
    has_mtime = False
    try:
        cols_info = {str(r[1]).lower() for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        has_mtime = "mtime" in cols_info
    except Exception:
        has_mtime = False
    cols = (
        "full_path,name,path,ext,size,signed,signer,sig_status,md5,sha1,sha256"
        + (",mtime" if has_mtime else "")
    )
    return cols, has_mtime


def search_files_by_name(conn: Any, name: str, limit: int = 40) -> List[Dict[str, Any]]:
    """按纯文件名查 files 表（不要求全路径）。"""
    base = _basename(_norm(name)).lower()
    if not base or len(base) < 3 or conn is None:
        return []
    try:
        _ensure_directory_index(conn)
        cols, _ = _files_select_cols(conn)
        rows = conn.execute(
            f"SELECT {cols} FROM files WHERE lower(name)=? "
            "ORDER BY full_path COLLATE NOCASE LIMIT ?",
            (base, max(limit, 40)),
        ).fetchall()
        if not rows and len(base) >= 4:
            # 无精确命中时再试前缀（如 ev2f79 → ev2f79.exe）
            rows = conn.execute(
                f"SELECT {cols} FROM files WHERE lower(name) LIKE ? "
                "ORDER BY full_path COLLATE NOCASE LIMIT ?",
                (base + "%", max(limit, 40)),
            ).fetchall()
        if not rows and "." not in base and len(base) >= 5:
            # 仍无命中：包含匹配（目录名/改名夹带）
            rows = conn.execute(
                f"SELECT {cols} FROM files WHERE lower(name) LIKE ? "
                "ORDER BY full_path COLLATE NOCASE LIMIT ?",
                (f"%{base}%", max(limit, 40)),
            ).fetchall()
    except Exception:
        return []
    seen: Set[str] = set()
    items: List[Dict[str, Any]] = []
    for r in rows:
        fp = _path_key(r["full_path"] or "")
        if not fp or fp in seen:
            continue
        seen.add(fp)
        items.append(_file_row_to_item(r, current=True))
    return items[:limit]


def search_files_at_path(conn: Any, q: str, limit: int = 40) -> List[Dict[str, Any]]:
    """路径检索：目录下列文件，或精确文件 + 同目录兄弟。"""
    qn = _norm_file_path(q)
    if not qn or conn is None:
        return []
    try:
        _ensure_directory_index(conn)
        cols, _ = _files_select_cols(conn)
        parent_q = _norm_file_path(_parent_dir(q))
        base = _basename(q).lower()
        dir_rows = conn.execute(
            f"SELECT {cols} FROM files WHERE parent_path_norm=? "
            "ORDER BY name COLLATE NOCASE LIMIT ?",
            (qn, max(limit, 80)),
        ).fetchall()
        exact_rows = []
        sibling_rows = []
        if parent_q and base:
            exact_rows = conn.execute(
                f"SELECT {cols} FROM files WHERE parent_path_norm=? AND lower(name)=? LIMIT 8",
                (parent_q, base),
            ).fetchall()
            sibling_rows = conn.execute(
                f"SELECT {cols} FROM files WHERE parent_path_norm=? "
                "ORDER BY name COLLATE NOCASE LIMIT ?",
                (parent_q, max(limit, 80)),
            ).fetchall()
    except Exception:
        return []

    if dir_rows:
        items = [_file_row_to_item(r) for r in dir_rows]
    elif exact_rows or sibling_rows:
        seen: Set[str] = set()
        items = []
        for r in list(exact_rows) + list(sibling_rows):
            fp = _path_key(r["full_path"] or "")
            if not fp or fp in seen:
                continue
            seen.add(fp)
            items.append(_file_row_to_item(r, current=_path_key(r["full_path"] or "") == _path_key(q)))
    else:
        return []

    def rank(it: Dict[str, Any]) -> Tuple[int, int, str]:
        return (
            0 if it.get("current") else 1,
            0 if _is_exec_name(it.get("name") or "") else 1,
            str(it.get("name") or "").lower(),
        )

    items.sort(key=rank)
    return items[:limit]


def _match_slim(p: Dict[str, Any], *, via: str = "") -> Dict[str, Any]:
    row = {
        "pid": _proc_pid(p),
        "name": _proc_name(p),
        "path": _proc_path(p),
        "user": _norm(p.get("user")),
        "ppid": _proc_ppid(p),
        "md5": _norm(p.get("md5")),
        "sha256": _norm(p.get("sha256")),
        "kind": "process",
    }
    if via:
        row["via"] = via
    return row


def _elog_field(fields: Any, *keys: str) -> str:
    if not isinstance(fields, dict):
        return ""
    lower = {str(k).lower(): v for k, v in fields.items()}
    for k in keys:
        v = fields.get(k)
        if v is None:
            v = lower.get(k.lower())
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _parse_loose_time(s: Any):
    """解析进程启动时间 / 日志时间，失败返回 None。"""
    from datetime import datetime

    raw = _norm(s)
    if not raw:
        return None
    raw = raw.replace("T", " ").replace("Z", "").split("+")[0].strip()
    if "." in raw:
        raw = raw.split(".", 1)[0]
    for candidate in (raw[:19], raw[:16], raw[:10]):
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(candidate, fmt)
            except Exception:
                continue
    return None


_TIME_FIELD_KEYS = (
    "time", "Time", "utc_time", "UtcTime", "UTCTime", "CreationUtcTime",
    "created", "Created", "CreationDate", "create_time", "CreateTime",
    "start_time", "StartTime", "mtime", "modified", "Modified",
    "LastWriteTime", "timestamp", "Timestamp", "event_time", "EventTime",
)
_TIME_KEYED_RE = re.compile(
    r"(?:Time|UtcTime|CreationUtcTime|CreationDate|LastWriteTime)\s*[=:]\s*"
    r"(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)",
    re.I,
)
_ISO_TIME_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b",
)


def _normalize_time_str(s: Any) -> str:
    """归一化为 'YYYY-MM-DD HH:MM:SS'，无法解析则空串。"""
    dt = _parse_loose_time(s)
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _times_from_text(text: str) -> List[str]:
    raw = _norm(text)
    if not raw or len(raw) < 10:
        return []
    out: List[str] = []
    for m in _TIME_KEYED_RE.finditer(raw):
        n = _normalize_time_str(m.group(1))
        if n:
            out.append(n)
    if not out:
        for m in _ISO_TIME_RE.finditer(raw):
            n = _normalize_time_str(m.group(1))
            if n:
                out.append(n)
    return out


def _extract_evidence_time(*objs: Any) -> str:
    """从证据 payload / 正文 / 告警 evidence 列表抽出最早可用时间。"""
    found: List[str] = []

    def add(v: Any) -> None:
        if isinstance(v, (int, float)) and v > 1_000_000_000:
            # unix 秒/毫秒粗判
            from datetime import datetime, timezone
            try:
                sec = float(v)
                if sec > 1e12:
                    sec /= 1000.0
                n = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                found.append(n)
                return
            except Exception:
                pass
        n = _normalize_time_str(v)
        if n:
            found.append(n)
            return
        if isinstance(v, str):
            found.extend(_times_from_text(v))

    def walk(obj: Any, depth: int = 0) -> None:
        if obj is None or depth > 3:
            return
        if isinstance(obj, dict):
            for k in _TIME_FIELD_KEYS:
                if k in obj:
                    add(obj.get(k))
            fields = obj.get("fields")
            if isinstance(fields, dict):
                for k in _TIME_FIELD_KEYS:
                    if k in fields:
                        add(fields.get(k))
            ev = obj.get("evidence")
            if isinstance(ev, list):
                for x in ev[:40]:
                    if isinstance(x, str):
                        found.extend(_times_from_text(x))
                    elif isinstance(x, dict):
                        walk(x, depth + 1)
            elif isinstance(ev, str):
                found.extend(_times_from_text(ev))
            for k in ("reason", "detail", "message", "title"):
                if isinstance(obj.get(k), str):
                    found.extend(_times_from_text(obj[k]))
        elif isinstance(obj, list):
            for x in obj[:40]:
                walk(x, depth + 1)
        elif isinstance(obj, str):
            found.extend(_times_from_text(obj))

    for o in objs:
        walk(o)
    if not found:
        return ""
    return min(found)


def _lookup_file_mtime(conn: Any, path: str, cache: Optional[Dict[str, str]] = None) -> str:
    """从 files 表或预取缓存取修改时间（关联文件时间线用）。"""
    raw = _norm(path).strip().strip('"').strip("'")
    key = _path_key(raw)
    if not key:
        return ""
    if cache is not None and key in cache:
        return cache[key]
    val = ""
    if conn is not None:
        try:
            row = conn.execute(
                "SELECT mtime FROM files WHERE lower(full_path)=? LIMIT 1",
                (key,),
            ).fetchone()
            if not row:
                row = conn.execute(
                    "SELECT mtime FROM files WHERE lower(replace(full_path,'/','\\'))=? LIMIT 1",
                    (key.replace("/", "\\"),),
                ).fetchone()
            if row and row[0]:
                val = _normalize_time_str(row[0]) or _norm(row[0])[:19]
        except Exception:
            val = ""
    if cache is not None:
        cache[key] = val
    return val


_DROP_EXT_RE = re.compile(
    r"\.(exe|dll|sys|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|com|msi|lnk|dat|tmp|bin)$",
    re.I,
)


def _is_suspicious_drop_name(path: str) -> bool:
    base = _basename(path)
    return bool(_DROP_EXT_RE.search(base or path))


def _file_create_from_event(ev: Dict[str, Any], by_pid: Dict[int, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sysmon EID 11 → 写盘释放候选。"""
    try:
        eid = int(ev.get("event_id") or 0)
    except (TypeError, ValueError):
        eid = 0
    if eid != 11:
        return None
    fields = ev.get("fields") if isinstance(ev.get("fields"), dict) else {}
    target = _elog_field(fields, "TargetFilename", "TargetFileName", "targetfilename")
    if not target or not ("\\" in target or "/" in target):
        return None
    image = _elog_field(fields, "Image", "image")
    pid_raw = _elog_field(fields, "ProcessId", "ProcessID", "processid")
    try:
        pid_v = int(pid_raw) if pid_raw else 0
    except (TypeError, ValueError):
        pid_v = 0

    conf, reason = "", ""
    if pid_v > 0 and pid_v in by_pid:
        conf, reason = CONF_STRONG, "Sysmon 11 ProcessId 一致"
    elif image:
        img_l = image.lower()
        for p in by_pid.values():
            pp = _proc_path(p).lower()
            if pp and (pp == img_l or pp.endswith("\\" + _basename(img_l)) or img_l.endswith("\\" + _basename(pp))):
                pid_v = _proc_pid(p)
                conf, reason = CONF_STRONG, "Sysmon 11 Image 路径一致"
                break
            pn = _proc_name(p).lower()
            if pn and len(pn) >= 5 and pn == _basename(img_l).lower():
                pid_v = _proc_pid(p)
                conf, reason = CONF_MEDIUM, "Sysmon 11 Image 进程名一致"
                break
    if not conf or not pid_v:
        return None
    # 排除进程自身镜像
    p = by_pid.get(pid_v) or {}
    if target.lower() == _proc_path(p).lower():
        return None
    return {
        "pid": pid_v,
        "path": target[:260],
        "image": image,
        "time": _norm(ev.get("time")) or _elog_field(fields, "UtcTime", "CreationUtcTime"),
        "confidence": conf,
        "confidence_reason": reason,
        "source": "sysmon11",
        "event": ev,
    }


def _fetch_sysmon_file_creates(
    conn,
    *,
    by_pid: Dict[int, Dict[str, Any]],
    limit: int = 120,
) -> List[Dict[str, Any]]:
    """从 event_logs 拉取 Sysmon FileCreate(11) 并归因到进程。"""
    total = _ensure_event_logs_table(conn)
    if total <= 0 or not by_pid:
        return []
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    try:
        rows = conn.execute(
            "SELECT channel,event_id,provider,time,level,computer,message,fields "
            "FROM event_logs WHERE event_id=11 "
            "ORDER BY time DESC LIMIT 2500"
        ).fetchall()
    except Exception:
        return []
    for r in rows:
        if len(out) >= limit:
            break
        ev = _event_log_row_to_dict(r)
        hit = _file_create_from_event(ev, by_pid)
        if not hit:
            continue
        key = f"{hit['pid']}|{hit['path'].lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


def _network_label(c: Dict[str, Any]) -> str:
    for k in ("remote_ip", "remote", "foreign", "dst", "destination"):
        v = _norm(c.get(k))
        if v:
            return v
    for k in ("hostname", "domain"):
        v = _norm(c.get(k))
        if v:
            return v
    local = _norm(c.get("local") or c.get("local_address"))
    return local or "网络连接"


def _network_detail(c: Dict[str, Any]) -> str:
    local = _norm(c.get("local") or c.get("local_address"))
    remote = _network_label(c)
    proto = _norm(c.get("proto") or c.get("protocol"))
    bits = [x for x in (proto, local, remote) if x]
    return " · ".join(bits)


def _collect_tree_pids(
    seeds: Set[int],
    by_pid: Dict[int, Dict[str, Any]],
    *,
    up: int = 2,
    down: int = 2,
) -> Set[int]:
    out: Set[int] = set()
    for sp in seeds:
        if not sp:
            continue
        out.add(sp)
        cur = sp
        for _ in range(up):
            p = by_pid.get(cur)
            if not p:
                break
            ppid = _proc_ppid(p)
            if not ppid or ppid == cur or ppid not in by_pid:
                break
            out.add(ppid)
            cur = ppid
    queue: List[Tuple[int, int]] = [(sp, 0) for sp in seeds if sp]
    seen_bfs: Set[int] = set()
    while queue:
        cpid, depth = queue.pop(0)
        if cpid in seen_bfs:
            continue
        seen_bfs.add(cpid)
        if depth >= down:
            continue
        for pid, p in by_pid.items():
            if _proc_ppid(p) == cpid and pid not in seen_bfs:
                out.add(pid)
                queue.append((pid, depth + 1))
    return out


def _root_pid(seeds: Set[int], by_pid: Dict[int, Dict[str, Any]]) -> int:
    if not seeds:
        return 0
    primary = sorted(seeds)[0]
    cur = primary
    for _ in range(8):
        p = by_pid.get(cur)
        if not p:
            break
        ppid = _proc_ppid(p)
        if not ppid or ppid == cur or ppid not in by_pid:
            break
        cur = ppid
    return cur


def _depth_map(root: int, pids: Set[int], by_pid: Dict[int, Dict[str, Any]]) -> Dict[int, int]:
    depths: Dict[int, int] = {}
    if not root or root not in pids:
        for sp in sorted(pids):
            depths[sp] = 0
        return depths
    depths[root] = 0
    queue = [root]
    while queue:
        cpid = queue.pop(0)
        base = depths.get(cpid, 0)
        for pid, p in by_pid.items():
            if pid not in pids:
                continue
            if _proc_ppid(p) == cpid and pid not in depths:
                depths[pid] = base + 1
                queue.append(pid)
    for sp in pids:
        depths.setdefault(sp, 0)
    return depths


def search_processes(procs: List[Dict[str, Any]], q: str = "", pid: Optional[int] = None, limit: int = 20) -> List[Dict[str, Any]]:
    q = _norm(q)
    if pid and int(pid) > 0:
        out = [p for p in procs if _proc_pid(p) == int(pid)]
    elif not q:
        return []
    else:
        out = [p for p in procs if _proc_matches_query(p, q)]
        if not out and _IP_RE.match(q):
            # IP 查询时允许后续由网络反查进程；这里先返回空
            out = []
    out.sort(key=lambda p: (_proc_name(p).lower(), _proc_pid(p)))
    slim = []
    for p in out[:limit]:
        slim.append(_match_slim(p))
    return slim


def _field_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, dict):
        for k in ("path", "full_path", "command", "command_line", "executable", "exe", "name", "title", "url"):
            s = _field_str(v.get(k))
            if s:
                return s
        return ""
    if isinstance(v, (list, tuple, set)):
        return ""
    s = str(v).strip()
    if s.startswith("{") and ("'" in s or '"' in s):
        return ""
    return s


def _preview_from_item(item: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    for k in keys:
        s = _field_str(item.get(k))
        if s:
            return s[:260]
    for k in ("path", "full_path", "resolved_path", "image_path", "command", "command_line"):
        s = _field_str(item.get(k))
        if s:
            return s[:260]
    return ""


# 关联置信度：强=硬键(PID/父子) · 中=路径/哈希 · 弱=短名/文本
CONF_STRONG = "strong"
CONF_MEDIUM = "medium"
CONF_WEAK = "weak"
_CONF_RANK = {CONF_STRONG: 0, CONF_MEDIUM: 1, CONF_WEAK: 2}


def _conf_label(level: str) -> str:
    return {"strong": "强", "medium": "中", "weak": "弱"}.get(level, "")


def _best_conf(*levels: str) -> str:
    """取最强档（数值越小越强）。"""
    best = ""
    best_r = 99
    for lv in levels:
        if not lv:
            continue
        r = _CONF_RANK.get(lv, 99)
        if r < best_r:
            best, best_r = lv, r
    return best


def _evidence_row(
    *,
    module: str,
    title: str,
    detail: str,
    pid: int = 0,
    process: str = "",
    severity: str = "",
    finding_id: str = "",
    payload: Optional[Dict[str, Any]] = None,
    confidence: str = "",
    confidence_reason: str = "",
    time: str = "",
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "module": module,
        "title": title[:120],
        "detail": detail[:400],
        "pid": pid,
        "process": process,
    }
    if severity:
        row["severity"] = severity
    if finding_id:
        row["finding_id"] = finding_id
    if payload:
        row["payload"] = payload
    if confidence:
        row["confidence"] = confidence
        row["confidence_label"] = _conf_label(confidence)
    if confidence_reason:
        row["confidence_reason"] = confidence_reason[:120]
    t = _normalize_time_str(time) or _extract_evidence_time(payload, detail, title)
    if t:
        row["time"] = t
    return row


def _basename(path: str) -> str:
    s = (path or "").replace("/", "\\").strip()
    if not s:
        return ""
    return s.rsplit("\\", 1)[-1]


def _item_text(item: Dict[str, Any], keys: Tuple[str, ...]) -> str:
    bits = []
    for k in keys:
        v = _norm(item.get(k))
        if v:
            bits.append(v)
    return " ".join(bits)


def _item_command(item: Dict[str, Any]) -> str:
    return _norm(
        item.get("command")
        or item.get("command_line")
        or item.get("Command")
        or item.get("ImagePath")
        or item.get("image_path")
        or item.get("task_to_run")
        or ""
    )


def _item_exe_path(item: Dict[str, Any]) -> str:
    """从持久化条目提取可执行路径（优先显式字段，再解析 command）。"""
    for k in (
        "resolved_path", "path", "image_path", "ImagePath",
        "executable", "full_path", "exe", "lnk_target",
    ):
        v = _norm(item.get(k)).strip().strip('"').strip("'")
        if not v:
            continue
        low = v.lower()
        if "\\" in v or "/" in v or low.endswith(
            (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi")
        ):
            # 命令行带参数时截到第一个可执行后缀
            if " " in v and not low.endswith(
                (".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi")
            ):
                head = v.split(" ", 1)[0].strip().strip('"')
                if head:
                    return head
            return v
    cmd = _item_command(item)
    if not cmd:
        return ""
    try:
        from backend.startup_meta import extract_exe_path
        got = extract_exe_path(cmd)
        if got:
            return _norm(got)
    except Exception:
        pass
    low = cmd.lower()
    for ext in (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"):
        i = low.find(ext)
        if i >= 0:
            return cmd[: i + len(ext)].strip().strip('"')
    part = cmd.split()[0].strip().strip('"') if cmd.split() else ""
    return part


def _persist_subtype(module: str, item: Dict[str, Any]) -> Tuple[str, str]:
    """返回 (subtype_id, 中文标签)。"""
    mod = (module or "").lower()
    loc = _norm_lower(item.get("location") or item.get("Location") or "")
    path = _norm_lower(item.get("path") or item.get("resolved_path") or "")
    blob = f"{loc} {path} {_norm_lower(item.get('name'))}"
    linuxish = any(
        x in blob
        for x in (
            "systemd", "/etc/", "cron", "bashrc", "profile.d", "xdg", "autostart",
            "ld.so.preload", ".service", "/usr/lib/", "/lib/", ".so",
        )
    ) or bool(item.get("_linux_hunt"))
    if mod == "service":
        if linuxish or "/" in path or str(item.get("unit") or "").endswith(".service"):
            return "systemd", "systemd 服务"
        return "service", "Windows 服务"
    if mod == "task":
        if linuxish or "cron" in blob or "timer" in blob:
            return "cron", "cron/timer"
        return "task", "计划任务"
    if mod == "driver":
        return "driver", "内核模块" if linuxish or path.endswith(".ko") else "驱动"
    if mod == "program":
        return "program", "已装程序"
    if item.get("_linux_kind") == "preload":
        return "ld_preload", "ld.so.preload"
    if item.get("_linux_kind") == "unsigned_so":
        return "unsigned_so", "未签名 .so"
    if item.get("_linux_kind") == "hunt":
        return "hunt", "Hunt 痕迹"
    if item.get("_linux_kind") == "ssh_key":
        return "ssh_key", "SSH 密钥"
    if "runonce" in blob:
        return "runonce", "RunOnce"
    if re.search(r"(?:^|[\\/])run(?:$|[\\/\s])", loc) or "\\run" in loc or loc in ("run", "run key"):
        return "run", "注册表 Run"
    if "startup" in blob or "start menu" in blob or "启动" in blob:
        return "startup_folder", "启动文件夹"
    if "winlogon" in blob or "userinit" in blob:
        return "winlogon", "Winlogon"
    if "explorer" in blob and ("load" in blob or "advanced" in blob):
        return "explorer", "Explorer 加载"
    if linuxish:
        return "linux", "Linux 持久化"
    if "task" in blob or "任务" in blob:
        return "task", "计划任务"
    if "service" in blob or "服务" in blob:
        return "service", "服务"
    if loc:
        return "other", (item.get("location") or item.get("Location") or "其它")[:40]
    return "startup", "启动项"


def _linux_persist_seed_items(
    security_extras: Any,
    linuxsc_raw: Any,
    remote_access: Any = None,
) -> List[Dict[str, Any]]:
    """从 LinuxSC Hunt/preload/SSH 抽成可挂图的持久化种子项。"""
    se = security_extras if isinstance(security_extras, dict) else {}
    raw = linuxsc_raw if isinstance(linuxsc_raw, dict) else {}
    remote = remote_access if isinstance(remote_access, dict) else {}
    items: List[Dict[str, Any]] = []

    preload = _norm(raw.get("preload") or se.get("ld.so.preload") or se.get("ld_so_preload") or "")
    if preload and preload.lower() not in ("(empty)", "empty", "(null)"):
        items.append({
            "name": "ld.so.preload",
            "caption": "ld.so.preload",
            "location": "/etc/ld.so.preload",
            "path": "/etc/ld.so.preload",
            "command": preload[:2000],
            "_linux_kind": "preload",
            "_linux_hunt": True,
            "risk": True,
        })

    uso = se.get("loaded_unsigned_so") or se.get("disk_unsigned_so") or ""
    if isinstance(uso, str) and uso.strip():
        for ln in uso.splitlines()[:40]:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            path = ln.split("\t", 1)[0].strip().split()[0].strip()
            pl = path.lower()
            if not path.startswith("/") or not (pl.endswith(".so") or ".so." in pl):
                continue
            if any(n in pl for n in ("site-packages", "/snap/", ".cache/", "/usr/src/")):
                continue
            base = path.rsplit("/", 1)[-1]
            items.append({
                "name": base or path,
                "caption": base or "unsigned.so",
                "location": "Hunt/loaded_unsigned_so",
                "path": path,
                "command": path,
                "_linux_kind": "unsigned_so",
                "_linux_hunt": True,
                "risk": True,
            })

    for key, title in (
        ("ssh_symlink_backdoor", "SSH 软链后门"),
        ("ssh_symlink_runtime", "SSH 软链运行态"),
        ("sshd_wrapper", "sshd Wrapper"),
        ("path_hijack", "PATH 劫持"),
        ("prompt_command", "PROMPT_COMMAND"),
        ("cred_drop_paths", "凭据落盘路径"),
        ("systemd_sus_exec", "可疑 systemd Exec"),
        ("fake_binaries", "伪造系统二进制"),
        ("inetd_xinetd", "inetd/xinetd"),
        ("pam_d_extra", "异常 PAM 配置"),
    ):
        text = se.get(key)
        if not isinstance(text, str) or not text.strip():
            continue
        preview = "\n".join(
            ln for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )[:1200]
        if not preview.strip():
            continue
        items.append({
            "name": title,
            "caption": title,
            "location": f"Hunt/{key}",
            "path": f"Hunt/{key}",
            "command": preview,
            "_linux_kind": "hunt",
            "_linux_hunt": True,
            "risk": True,
            "source_key": key,
        })

    for key in remote.get("ssh_keys") or []:
        if not isinstance(key, dict):
            continue
        kp = _norm(key.get("path") or "")
        if not kp:
            continue
        n_lines = int(key.get("lines") or key.get("key_count") or 0)
        preview = _norm(key.get("preview") or "")[:400]
        # 仅挂「条目偏多」或路径异常的 authorized_keys，避免正常家目录刷屏
        odd = n_lines >= 8 or "/tmp/" in kp or "/dev/shm" in kp or "authorized_keys" in kp.lower() and n_lines >= 5
        if not odd and n_lines < 5:
            continue
        items.append({
            "name": kp.rsplit("/", 1)[-1] or "authorized_keys",
            "caption": f"SSH keys ({n_lines or '?'})",
            "location": kp,
            "path": kp,
            "command": preview or kp,
            "_linux_kind": "ssh_key",
            "_linux_hunt": True,
            "risk": odd,
            "key_count": n_lines,
        })

    return items[:60]


def _launch_confidence(
    proc: Dict[str, Any],
    *,
    exe_path: str,
    command: str,
) -> Tuple[str, str]:
    """启动项/服务/任务 → 进程 的拉起推断置信度。"""
    ppath = _norm_lower(proc.get("path") or "")
    pname = _norm_lower(proc.get("name") or proc.get("label") or "")
    exe = _norm_lower(exe_path)
    cmd = _norm_lower(command)
    exe_bn = _basename(exe).lower() if exe else ""
    if exe and ppath and len(exe) >= 8:
        if exe == ppath or exe in ppath or ppath in exe:
            return CONF_MEDIUM, "启动项路径匹配进程"
    if cmd and ppath and len(ppath) >= 8 and ppath in cmd:
        return CONF_MEDIUM, "启动项命令含进程路径"
    if exe_bn and pname and exe_bn == pname and len(exe_bn) >= 8:
        return CONF_WEAK, "启动项文件名匹配进程名"
    return "", ""


def _attach_launch_edges(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> int:
    """为持久化节点补 launch 边（启动项拉起进程，推断）。"""
    persist_types = {"startup", "service", "task"}
    persist_nodes = [n for n in nodes if n.get("type") in persist_types]
    proc_nodes = [n for n in nodes if n.get("type") == "process"]
    if not persist_nodes or not proc_nodes:
        return 0
    seen = {(e.get("from"), e.get("to"), e.get("kind")) for e in edges}
    added = 0
    for pn in persist_nodes:
        payload = pn.get("payload") if isinstance(pn.get("payload"), dict) else {}
        exe = _norm(pn.get("path") or _item_exe_path(payload))
        cmd = _norm(pn.get("command") or _item_command(payload))
        if not exe and not cmd:
            continue
        for proc_n in proc_nodes:
            # 构造与 _launch_confidence 兼容的进程字典
            fake = {
                "path": proc_n.get("path") or (proc_n.get("payload") or {}).get("path"),
                "name": proc_n.get("label") or (proc_n.get("payload") or {}).get("name"),
            }
            if not fake["path"] and isinstance(proc_n.get("payload"), dict):
                fake["path"] = proc_n["payload"].get("path") or proc_n["payload"].get("exe")
            conf, reason = _launch_confidence(fake, exe_path=exe, command=cmd)
            if not conf:
                continue
            if conf == CONF_WEAK and len(_basename(exe)) < 8:
                continue
            pair = (pn["id"], proc_n["id"], "launch")
            if pair in seen:
                continue
            edges.append({
                "from": pn["id"],
                "to": proc_n["id"],
                "kind": "launch",
                "confidence": conf,
                "confidence_reason": reason,
            })
            seen.add(pair)
            added += 1
    return added


def _anchor_confidence(
    item: Dict[str, Any],
    *,
    names: Set[str],
    paths: Set[str],
    hashes: Set[str],
    q: str = "",
) -> Tuple[str, str]:
    """返回 (confidence, reason)。空串表示未命中。"""
    fields = (
        "name", "path", "resolved_path", "image_path", "ImagePath", "command", "command_line",
        "exe", "executable", "file", "full_path", "service_dll", "ServiceDll", "program",
        "task_name", "display_name", "md5", "sha1", "sha256", "signer",
    )
    blob = _item_text(item, fields).lower()
    if not blob:
        return "", ""
    for h in hashes:
        if h and h in blob:
            return CONF_STRONG, "哈希一致"
    for p in paths:
        if p and len(p) >= 8 and p in blob:
            return CONF_MEDIUM, "完整路径匹配"
        if p and 6 <= len(p) < 8 and p in blob:
            return CONF_MEDIUM, "路径匹配"
    for n in names:
        if not n or len(n) < 3 or n not in blob:
            continue
        # 短通用名（如 cmd.exe）标弱；较长/非常见名标中
        if len(n) >= 10 or n.count(".") >= 1 and len(n) >= 8:
            return CONF_MEDIUM, "进程名匹配"
        return CONF_WEAK, "短进程名文本匹配"
    if q:
        ql = q.lower()
        if len(ql) >= 3 and ql in blob:
            if "\\" in ql or "/" in ql or len(ql) >= 12:
                return CONF_MEDIUM, "检索词路径/长串匹配"
            return CONF_WEAK, "检索词文本匹配"
    return "", ""


def _item_matches_anchor(item: Dict[str, Any], *, names: Set[str], paths: Set[str], hashes: Set[str], q: str) -> bool:
    """路径 / 进程名 / 哈希 / 检索词 命中。"""
    conf, _ = _anchor_confidence(item, names=names, paths=paths, hashes=hashes, q=q)
    return bool(conf)


def _finding_confidence(f: Dict[str, Any], p: Dict[str, Any]) -> Tuple[str, str]:
    pid = _proc_pid(p)
    if pid and pid in _finding_pids(f):
        return CONF_STRONG, "告警含相同 PID"
    extra = _finding_extra(f)
    pname = _proc_name(p).lower()
    ppath = _proc_path(p).lower()
    for k in ("process_name", "process_path", "image", "path", "exe"):
        v = _norm_lower(extra.get(k) or f.get(k))
        if not v:
            continue
        if ppath and (v == ppath or ppath in v or v in ppath) and len(ppath) >= 8:
            return CONF_MEDIUM, "告警字段路径匹配"
        if pname and (v == pname or pname in v or v in pname) and len(pname) >= 3:
            if len(pname) >= 8:
                return CONF_MEDIUM, "告警字段进程名匹配"
            return CONF_WEAK, "告警字段短名匹配"
    text = _finding_text(f)
    for hv in _proc_hashes(p):
        if hv and hv in text:
            return CONF_STRONG, "告警证据含哈希"
    if ppath and len(ppath) >= 8 and ppath in text:
        return CONF_MEDIUM, "告警正文含路径"
    if pname and len(pname) >= 3 and pname in text:
        if len(pname) >= 8:
            return CONF_MEDIUM, "告警正文含进程名"
        return CONF_WEAK, "告警正文短名匹配"
    return CONF_WEAK, "弱关联"


def _eventlog_confidence(ev: Dict[str, Any], p: Dict[str, Any], q: str = "") -> Tuple[str, str]:
    blob = _eventlog_blob(ev)
    if not blob:
        return "", ""
    pname = _proc_name(p).lower()
    ppath = _proc_path(p).lower()
    pid = _proc_pid(p)
    if pid > 0:
        fields = ev.get("fields") if isinstance(ev.get("fields"), dict) else {}
        for k in ("ProcessId", "NewProcessId", "ProcessID", "process_id"):
            try:
                if int(fields.get(k) or 0) == pid:
                    return CONF_STRONG, "日志字段 PID 一致"
            except Exception:
                pass
        for m in _PID_IN_EVENT_RE.finditer(blob):
            try:
                if int(m.group(1)) == pid:
                    return CONF_STRONG, "日志文本含 PID"
            except Exception:
                pass
    if ppath and len(ppath) >= 8 and ppath in blob:
        return CONF_MEDIUM, "日志含完整路径"
    if pname and len(pname) >= 3 and pname in blob:
        if len(pname) >= 8:
            return CONF_MEDIUM, "日志含进程名"
        return CONF_WEAK, "日志短名匹配"
    ql = q.strip().lower()
    if ql and len(ql) >= 3 and ql in blob:
        return CONF_WEAK, "检索词命中日志"
    return "", ""


def _as_list(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        for k in ("items", "entries", "data", "prefetch", "tasks", "services"):
            v = raw.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _exec_rows(exec_art: Any, prefetch: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    rows.extend(_as_list(prefetch))
    if isinstance(exec_art, dict):
        for k in ("prefetch", "prefetch_files", "userassist", "bam", "shimcache", "amcache", "jumplist"):
            rows.extend(_as_list(exec_art.get(k)))
    elif isinstance(exec_art, list):
        rows.extend(_as_list(exec_art))
    return rows


_PROCESS_EVENT_IDS = (4688, 4689, 4690, 1, 4103, 4104, 7045, 4698)
_PID_IN_EVENT_RE = re.compile(
    r"(?:^|[^\d])(?:processid|newprocessid|pid)\D{0,4}(\d{1,10})(?:[^\d]|$)",
    re.I,
)


def _eventlog_blob(ev: Dict[str, Any]) -> str:
    parts: List[str] = [
        _norm(ev.get("message")),
        _norm(ev.get("channel")),
        str(ev.get("event_id") or ""),
        _norm(ev.get("provider")),
    ]
    fields = ev.get("fields")
    if isinstance(fields, dict):
        for k, v in fields.items():
            parts.append(f"{k}={v}")
    elif fields:
        parts.append(str(fields))
    return " ".join(parts).lower()


def _eventlog_matches_process(ev: Dict[str, Any], p: Dict[str, Any], q: str = "") -> bool:
    conf, _ = _eventlog_confidence(ev, p, q=q)
    return bool(conf)


def _fetch_trace_eventlogs(
    conn,
    *,
    names: Set[str],
    paths: Set[str],
    pids: Set[int],
    q: str,
    rid: str,
    limit: int = 48,
) -> List[Dict[str, Any]]:
    total = _ensure_event_logs_table(conn)
    if total <= 0:
        return []

    terms: List[str] = []
    for n in sorted(names):
        nl = n.lower()
        if nl and len(nl) >= 3 and nl not in terms:
            terms.append(nl)
    for path_v in sorted(paths):
        pl = path_v.lower()
        if pl and len(pl) >= 8 and pl not in terms:
            terms.append(pl)
    ql = q.strip().lower()
    if ql and len(ql) >= 3 and ql not in terms:
        terms.append(ql)

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    sel = (
        "SELECT channel,event_id,provider,time,level,computer,message,fields "
        "FROM event_logs "
    )
    id_list = ",".join(str(x) for x in _PROCESS_EVENT_IDS)

    def _ev_key(d: Dict[str, Any]) -> str:
        return f"{d.get('channel')}|{d.get('event_id')}|{d.get('time')}"

    def _add_rows(rows) -> None:
        for r in rows:
            d = _event_log_row_to_dict(r)
            key = _ev_key(d)
            if key in seen:
                continue
            seen.add(key)
            out.append(d)

    for pid_v in sorted(pids):
        if pid_v <= 0 or len(out) >= limit:
            continue
        like = f"%{pid_v}%"
        try:
            rows = conn.execute(
                sel
                + "WHERE (lower(IFNULL(message,'')) LIKE ? OR lower(IFNULL(fields,'')) LIKE ?) "
                f"AND event_id IN ({id_list}) "
                "ORDER BY time DESC LIMIT 8",
                (like, like),
            ).fetchall()
            _add_rows(rows)
        except Exception:
            pass

    for term in terms[:12]:
        if len(out) >= limit:
            break
        like = f"%{term}%"
        try:
            rows = conn.execute(
                sel
                + "WHERE lower(IFNULL(message,'')) LIKE ? OR lower(IFNULL(fields,'')) LIKE ? "
                "ORDER BY time DESC LIMIT 10",
                (like, like),
            ).fetchall()
            _add_rows(rows)
        except Exception:
            pass

    items = out[:limit]
    if rid and items:
        _attach_eventlog_hit_rules(items, rid)
    return items


def _eventlog_label(ev: Dict[str, Any]) -> str:
    try:
        eid = int(ev.get("event_id") or 0)
    except Exception:
        eid = 0
    ch = _norm(ev.get("channel"))
    ch_short = ch.rsplit("/", 1)[-1] if ch else ""
    hit = ev.get("hit_rule") if isinstance(ev.get("hit_rule"), dict) else {}
    hit_title = _norm(hit.get("title") or "")
    if hit_title and (ch_short in ("journalctl-xe", "sshd", "last", "lastb", "auth", "secure") or not eid):
        return hit_title[:72]
    if ch_short and eid:
        return f"{ch_short} · EID {eid}"
    if eid:
        return f"EID {eid}"
    msg = _norm(ev.get("message"))
    if ch_short and msg:
        return f"{ch_short} · {msg[:48]}"
    return ch_short or "系统日志"


def _build_threat_trace_uncached(
    rid: str,
    *,
    q: str = "",
    pid: Optional[int] = None,
    file: str = "",
    limit: int = 80,
) -> Dict[str, Any]:
    q = _norm(q)
    file_anchor = _norm(file)
    name_pick = False
    path_files: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []
    seeds: Set[int] = set()
    path_hits: Dict[str, Any] = {}
    if not file_anchor and looks_like_path(q) and not (pid and int(pid) > 0):
        base = _basename(q)
        if base and "." in base:
            file_anchor = q
    dbp = _resolve_db_path(rid)
    if not dbp:
        return {"ok": False, "file": rid, "error": "报告不存在或未入库", "matches": [], "graph": {"nodes": [], "edges": []}, "evidence": []}

    conn = _connect(dbp)
    try:
        _init_schema(conn)
        procs_raw = _load_one_blob(conn, "processes") or []
        conns_raw = _load_one_blob(conn, "established_connections") or []
        services = _as_list(_load_one_blob(conn, "services"))
        tasks = _as_list(_load_one_blob(conn, "scheduled_tasks"))
        startups = _as_list(_load_one_blob(conn, "startup_items"))
        programs = _as_list(_load_one_blob(conn, "installed_programs"))
        drivers = _as_list(_load_one_blob(conn, "drivers") or _load_one_blob(conn, "driver_entries"))
        users = _as_list(_load_one_blob(conn, "users"))
        prefetch = _load_one_blob(conn, "prefetch_files")
        exec_art = _load_one_blob(conn, "execution_artifacts")
        browser = _as_list(_load_one_blob(conn, "browser_artifacts"))
        linux_seeds = _linux_persist_seed_items(
            _load_one_blob(conn, "security_extras"),
            _load_one_blob(conn, "linuxsc_raw"),
            _load_one_blob(conn, "remote_access"),
        )
        if linux_seeds:
            startups = list(startups) + linux_seeds
        findings = _load_findings_from_conn(conn)
        try:
            from backend.mitre import enrich_findings_list
            findings = enrich_findings_list(findings)
        except Exception:
            pass
        path_lookup = file_anchor or (q if looks_like_path(q) else "")
        path_files = search_files_at_path(conn, path_lookup, limit=40) if path_lookup else []
        name_pick = False
        # 纯文件名：查 files 表；唯一命中则升为全路径锚点
        if not file_anchor and q and looks_like_filename(q) and not (pid and int(pid) > 0):
            name_files = search_files_by_name(conn, q, limit=40)
            if name_files:
                path_files = name_files
                path_lookup = q
                uniq = list({_path_key(f.get("path") or ""): f for f in name_files if f.get("path")}.values())
                if len(uniq) == 1:
                    file_anchor = _norm(uniq[0].get("path") or "")
                else:
                    name_pick = True
            # files 表没有时：从告警证据抽全路径（普通检索能命中、溯查却空的常见原因）
            if not file_anchor and not name_pick:
                finding_paths = _paths_from_findings_for_name(findings, q, limit=12)
                if finding_paths:
                    path_lookup = q
                    # 合成 path_files 供点选；唯一则直接锚定
                    syn = []
                    for fp in finding_paths:
                        syn.append({
                            "kind": "file",
                            "name": _basename(fp),
                            "path": fp,
                            "parent": _parent_dir(fp),
                            "ext": (_basename(fp).rsplit(".", 1)[-1] if "." in _basename(fp) else ""),
                            "size": 0,
                            "signed": False,
                            "signer": "",
                            "sig_status": "",
                            "md5": "",
                            "sha1": "",
                            "sha256": "",
                            "mtime": "",
                            "time": "",
                            "current": True,
                            "via": "finding",
                        })
                    path_files = syn
                    if len(finding_paths) == 1:
                        file_anchor = _norm(finding_paths[0])
                    else:
                        name_pick = True

        procs = [p for p in procs_raw if isinstance(p, dict)]
        report = {"processes": procs, "established_connections": conns_raw if isinstance(conns_raw, list) else []}
        enrich_report_connections(report)
        conns = [c for c in (report.get("established_connections") or []) if isinstance(c, dict)]
        proc_idx = build_process_index(procs)
        enrich_conn_list(conns, proc_idx)
        exec_rows = _exec_rows(exec_art, prefetch)

        by_pid: Dict[int, Dict[str, Any]] = {}
        for p in procs:
            pid_v = _proc_pid(p)
            if pid_v:
                by_pid[pid_v] = p

        matches = search_processes(procs, q=q, pid=pid, limit=20)
        seeds: Set[int] = set()
        if pid and int(pid) > 0:
            seeds.add(int(pid))
        for m in matches:
            if m.get("pid"):
                seeds.add(int(m["pid"]))

        # 纯 PID 检索：只围着该 PID，不扩父子树里的系统宿主去扫服务
        pid_focus = False
        focus_pid_v = 0
        if pid and int(pid) > 0:
            pid_focus = True
            focus_pid_v = int(pid)
        elif q and _PID_RE.match(q):
            pid_focus = True
            focus_pid_v = int(q)
        if pid_focus and focus_pid_v > 0:
            seeds = {focus_pid_v} if focus_pid_v in by_pid else ({focus_pid_v} if focus_pid_v else set())
            if focus_pid_v in by_pid:
                matches = [_match_slim(by_pid[focus_pid_v], via="pid")]
            else:
                matches = [m for m in matches if int(m.get("pid") or 0) == focus_pid_v]

        # 选定文件：反查运行该文件的进程（含纯文件名锚点）
        file_needle = file_anchor or (q if looks_like_filename(q) else "")
        if file_needle and not pid_focus:
            seen_pids = {int(m["pid"]) for m in matches if m.get("pid")}
            for p in procs:
                if not _proc_matches_file(p, file_needle):
                    continue
                pid_v = _proc_pid(p)
                if not pid_v:
                    continue
                seeds.add(pid_v)
                if pid_v not in seen_pids and len(matches) < 20:
                    matches.append(_match_slim(p, via="file"))
                    seen_pids.add(pid_v)

        # IP/域名：从网络连接反查进程（排除 ev2f79.exe 这类文件名）
        if not seeds and not pid_focus and q and (
            _IP_RE.match(q) or ("." in q and not looks_like_filename(q) and not looks_like_path(q))
        ):
            for c in conns:
                if not _conn_matches_query(c, q):
                    continue
                cp = conn_pid(c)
                if cp:
                    seeds.add(cp)
                    if len(matches) < 20:
                        p = by_pid.get(cp)
                        if p:
                            matches.append(_match_slim(p, via="network"))

        # 仅在有检索词/文件锚点时，才用告警文本反查 PID（空查询不得扫全部告警）
        if not seeds and not pid_focus and (file_anchor or q):
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    continue
                needle = file_anchor or q
                if not _finding_matches_query(f, needle):
                    continue
                for fpid in _finding_pids(f):
                    seeds.add(fpid)
                    p = by_pid.get(fpid)
                    if p and len(matches) < 20:
                        matches.append(_match_slim(p, via="finding"))
                if len(seeds) >= 5:
                    break

        path_hits = {
            "processes": matches,
            "files": path_files,
            "query": path_lookup or q,
            "selected_file": file_anchor,
        }

        # 关库前预取文件 mtime，构图阶段不再访问已关闭的连接
        file_mtime_cache: Dict[str, str] = {}
        try:
            for r in conn.execute(
                "SELECT full_path, mtime FROM files WHERE IFNULL(mtime,'')!=''"
            ):
                fp = _path_key(_norm(r[0]).strip().strip('"').strip("'"))
                mt = _normalize_time_str(r[1]) or _norm(r[1])[:19]
                if fp and mt:
                    file_mtime_cache[fp] = mt
        except Exception:
            pass
    finally:
        conn.close()

    # 目录 / 同名多路径：先列出进程/文件，等用户点选后再关联
    need_pick = (
        not (pid and int(pid) > 0)
        and not file_anchor
        and (matches or path_files)
        and (
            looks_like_path(q)
            or (name_pick and path_files)
        )
    )
    if need_pick and (looks_like_path(q) or not seeds):
        msg = (
            "同名文件出现在多个路径，请点选后再溯检关联"
            if name_pick
            else "已列出该路径下的进程与文件，请点选后再溯检关联"
        )
        pick = {
            "ok": True,
            "file": rid,
            "query": q,
            "pid": 0,
            "anchor_file": "",
            "path_hits": path_hits,
            "matches": matches,
            "root_pid": 0,
            "graph": {"nodes": [], "edges": []},
            "evidence": [],
            "message": msg,
            "stats": {"confidence": {"strong": 0, "medium": 0, "weak": 0}},
        }
        pick["conclusion"] = {"system": build_system_conclusion(pick)}
        return pick

    file_only = bool(file_anchor) and not seeds
    if not seeds and not file_only:
        empty = {
            "ok": True,
            "file": rid,
            "query": q,
            "pid": pid,
            "anchor_file": file_anchor,
            "path_hits": path_hits,
            "matches": matches,
            "root_pid": 0,
            "graph": {"nodes": [], "edges": []},
            "evidence": [],
            "message": "未找到匹配的进程/文件。可试文件名、告警里的完整路径、PID 或哈希；若其它主机有同名文件会自动提示切换",
            "stats": {"confidence": {"strong": 0, "medium": 0, "weak": 0}},
        }
        empty["conclusion"] = {"system": build_system_conclusion(empty)}
        return empty

    tree_pids: Set[int] = set()
    root = 0
    depths: Dict[int, int] = {}
    if seeds:
        if pid_focus:
            # 只含种子 + 直接子进程；不向上扩到 services/svchost
            tree_pids = _collect_tree_pids(seeds, by_pid, up=0, down=1)
            root = next(iter(seeds))
        else:
            tree_pids = _collect_tree_pids(seeds, by_pid, up=2, down=2)
            root = _root_pid(seeds, by_pid)
        depths = _depth_map(root, tree_pids, by_pid)

    # 锚点：PID 聚焦只用种子进程；否则用整棵树（持久化匹配另见 attach 收紧）
    anchor_names: Set[str] = set()
    anchor_paths: Set[str] = set()
    anchor_hashes: Set[str] = set()
    anchor_pids = seeds if (pid_focus and seeds) else tree_pids
    for pid_v in anchor_pids:
        p = by_pid.get(pid_v)
        if not p:
            continue
        nm = _proc_name(p).lower()
        if nm:
            anchor_names.add(nm)
            anchor_names.add(_basename(nm).lower())
        pp = _proc_path(p).lower()
        if pp:
            anchor_paths.add(pp)
            bn = _basename(pp).lower()
            if bn:
                anchor_names.add(bn)
        anchor_hashes |= _proc_hashes(p)

    if file_anchor:
        fl = file_anchor.lower()
        anchor_paths.add(fl)
        bn = _basename(file_anchor).lower()
        if bn:
            anchor_names.add(bn)
        for it in path_files:
            if _path_key(it.get("path") or "") != _path_key(file_anchor):
                continue
            for hk in ("md5", "sha1", "sha256"):
                hv = _norm_lower(it.get(hk))
                if hv:
                    anchor_hashes.add(hv)

    conn_ev = _connect(dbp)
    try:
        _init_schema(conn_ev)
        all_eventlogs = _fetch_trace_eventlogs(
            conn_ev,
            names=anchor_names,
            paths=anchor_paths,
            pids=tree_pids if not pid_focus else seeds,
            q=("" if pid_focus else (file_anchor or q)),
            rid=rid,
            limit=24 if pid_focus else 48,
        )
        sysmon_drops = _fetch_sysmon_file_creates(conn_ev, by_pid=by_pid, limit=120)
    finally:
        conn_ev.close()

    # pid → drop hits（Sysmon 11）
    drops_by_pid: Dict[int, List[Dict[str, Any]]] = {}
    drop_path_seen: Set[str] = set()
    for hit in sysmon_drops:
        pid_h = int(hit.get("pid") or 0)
        path_h = _norm(hit.get("path"))
        if not pid_h or not path_h:
            continue
        key = f"{pid_h}|{path_h.lower()}"
        if key in drop_path_seen:
            continue
        drop_path_seen.add(key)
        drops_by_pid.setdefault(pid_h, []).append(hit)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    node_ids: Set[str] = set()
    row_by_col: Dict[int, int] = {}

    def next_row(col: int) -> int:
        row_by_col[col] = row_by_col.get(col, 0) + 1
        return row_by_col[col]

    def add_node(n: Dict[str, Any]) -> str:
        nid = n["id"]
        if nid in node_ids:
            # 已有占位节点时合并字段（保留更完整的 payload / 置信度）
            for existing in nodes:
                if existing.get("id") == nid:
                    for k, v in n.items():
                        if k == "id":
                            continue
                        if v is None or v == "":
                            continue
                        if k not in existing or existing.get(k) in (None, "", 0, False):
                            existing[k] = v
                        elif k in ("confidence", "confidence_label", "confidence_reason", "payload", "detail", "module"):
                            existing[k] = v
                    break
            return nid
        node_ids.add(nid)
        nodes.append(n)
        return nid

    spawn_count: Dict[int, int] = {pid_v: 0 for pid_v in tree_pids}
    for pid_v in tree_pids:
        p = by_pid.get(pid_v)
        if not p:
            continue
        ppid = _proc_ppid(p)
        if ppid and ppid in tree_pids and ppid != pid_v:
            spawn_count[ppid] = spawn_count.get(ppid, 0) + 1
            edges.append({
                "from": f"proc:{ppid}",
                "to": f"proc:{pid_v}",
                "kind": "spawn",
                "confidence": CONF_STRONG,
            })

    risk_pids: Set[int] = set()
    for pid_v in tree_pids:
        p = by_pid.get(pid_v)
        if not p:
            continue
        col = depths.get(pid_v, 0)
        is_seed = pid_v in seeds
        related_findings = [f for f in findings if isinstance(f, dict) and _finding_matches_process(f, p)]
        has_high = any(_finding_severity(f) == "high" for f in related_findings)
        if has_high:
            risk_pids.add(pid_v)
        add_node({
            "id": f"proc:{pid_v}",
            "type": "process",
            "label": _proc_name(p) or f"PID {pid_v}",
            "pid": pid_v,
            "ppid": _proc_ppid(p) or 0,
            "path": _proc_path(p),
            "column": col,
            "row": next_row(col),
            "risk": has_high or (is_seed and bool(related_findings)),
            "spawn_count": spawn_count.get(pid_v, 0),
            "detail": _preview_from_item(p, ("command_line", "command", "path")) or _proc_path(p),
            "command_line": _norm(p.get("command_line") or p.get("command") or p.get("cmdline")),
            "user": _norm(p.get("user")),
            "md5": _norm(p.get("md5")),
            "sha256": _norm(p.get("sha256") or p.get("SHA256")),
            "sig_status": _norm(p.get("sig_status") or p.get("signature") or ""),
            "signer": _norm(p.get("signer") or p.get("Signer") or p.get("company") or ""),
            "start_time": _norm(p.get("start_time") or p.get("create_time") or p.get("CreationDate") or ""),
            "module": "process",
            "payload": dict(p),
            "confidence": CONF_STRONG if is_seed else CONF_MEDIUM,
            "confidence_label": _conf_label(CONF_STRONG if is_seed else CONF_MEDIUM),
            "confidence_reason": "检索命中进程" if is_seed else "进程树父子关联",
        })

    file_nid = ""
    file_col = 0
    if file_anchor:
        base = _basename(file_anchor) or file_anchor
        meta = next((it for it in path_files if _path_key(it.get("path") or "") == _path_key(file_anchor)), None) or {}
        file_nid = f"file:anchor:{abs(hash(_path_key(file_anchor))) % 10_000_000}"
        file_payload = {
            "path": file_anchor,
            "full_path": file_anchor,
            "name": base,
            **({k: meta[k] for k in ("size", "signed", "sig_status", "md5", "sha256", "ext", "mtime", "time") if meta.get(k) not in (None, "")}),
            "_dropSource": "anchor",
        }
        if not file_payload.get("mtime"):
            mt = _lookup_file_mtime(None, file_anchor, file_mtime_cache)
            if mt:
                file_payload["mtime"] = mt
                file_payload["time"] = mt
        add_node({
            "id": file_nid,
            "type": "file",
            "label": base[:80],
            "column": 0 if file_only else 1,
            "row": next_row(0 if file_only else 1),
            "risk": False,
            "detail": file_anchor,
            "module": "file",
            "payload": file_payload,
            "confidence": CONF_STRONG,
            "confidence_label": _conf_label(CONF_STRONG),
            "confidence_reason": "选定文件锚点",
            "drop_source": "anchor",
        })
        for pid_v in seeds:
            p = by_pid.get(pid_v)
            if p and _proc_matches_file(p, file_anchor):
                edges.append({
                    "from": f"proc:{pid_v}",
                    "to": file_nid,
                    "kind": "related",
                    "confidence": CONF_STRONG,
                })
        evidence.append(_evidence_row(
            module="file",
            title=base[:120],
            detail=file_anchor[:400],
            payload=file_payload,
            confidence=CONF_STRONG,
            confidence_reason="选定文件锚点",
        ))
        file_col = 0 if file_only else 1

    net_seen: Set[str] = set()
    file_seen: Set[str] = set()
    if file_anchor:
        file_seen.add(_path_key(file_anchor))
    finding_seen: Set[str] = set()
    persist_seen: Set[str] = set()
    exec_seen: Set[str] = set()
    eventlog_seen: Set[str] = set()

    def attach_related(
        *,
        items: List[Dict[str, Any]],
        module: str,
        ntype: str,
        edge_kind: str,
        label_keys: Tuple[str, ...],
        detail_keys: Tuple[str, ...],
        per_proc: int = 4,
        pid_v: int = 0,
        proc_nid: str = "",
        col: int = 0,
        pname: str = "",
        min_conf: str = CONF_WEAK,
        use_query: bool = True,
    ) -> None:
        hit_n = 0
        # 持久化匹配：有 PID 时只用该进程锚点；文件锚点模式用全局 anchor_*
        if pid_v:
            p_obj = by_pid.get(pid_v) or {}
            p_names = {_proc_name(p_obj).lower(), _basename(_proc_path(p_obj)).lower()}
            p_names = {x for x in p_names if x}
            p_paths = {x for x in {_proc_path(p_obj).lower()} if x}
            p_hashes = _proc_hashes(p_obj)
        else:
            p_names = set(anchor_names)
            p_paths = set(anchor_paths)
            p_hashes = set(anchor_hashes)
        q_use = q if use_query and not pid_focus else ""
        min_rank = _CONF_RANK.get(min_conf, 99)
        for i, it in enumerate(items):
            if hit_n >= per_proc or len(nodes) >= limit:
                break
            conf, conf_reason = _anchor_confidence(
                it, names=p_names, paths=p_paths, hashes=p_hashes, q=q_use,
            )
            # Linux Hunt/preload：锚点对不上时，用命令正文含进程名/路径，或 preload 挂种子进程
            if not conf and it.get("_linux_hunt"):
                blob = _norm_lower(
                    f"{it.get('command') or ''} {it.get('path') or ''} {it.get('location') or ''}"
                )
                for pp in p_paths:
                    if pp and len(pp) >= 6 and pp in blob:
                        conf, conf_reason = CONF_MEDIUM, "Hunt 痕迹含进程路径"
                        break
                if not conf:
                    for nm in p_names:
                        if nm and len(nm) >= 3 and nm in blob:
                            conf, conf_reason = (
                                CONF_MEDIUM if len(nm) >= 6 else CONF_WEAK,
                                "Hunt 痕迹含进程名",
                            )
                            break
                if not conf and it.get("_linux_kind") == "preload" and pid_v and pid_v in seeds:
                    conf, conf_reason = CONF_MEDIUM, "主机存在 ld.so.preload（挂种子进程）"
                if not conf and it.get("_linux_kind") == "hunt" and pid_v and pid_v in seeds and not pid_focus:
                    # 全局 Hunt 线索：仅挂在种子进程，避免整树刷屏
                    conf, conf_reason = CONF_WEAK, "主机 Hunt 痕迹（弱关联种子）"
            if not conf:
                continue
            if _CONF_RANK.get(conf, 99) > min_rank:
                continue
            label = _item_text(it, label_keys) or module
            detail = _preview_from_item(it, detail_keys) or _item_text(it, label_keys)
            key = f"{module}|{label}|{detail}".lower()
            if key in persist_seen or key in exec_seen:
                continue
            if edge_kind == "exec":
                exec_seen.add(key)
            else:
                persist_seen.add(key)
            item_payload = dict(it)
            subtype_id, subtype_label = _persist_subtype(module, it)
            exe_path = _item_exe_path(it)
            cmd = _item_command(it)
            loc = _norm(it.get("location") or it.get("Location") or "")
            item_payload["_persist_subtype"] = subtype_id
            item_payload["_persist_subtype_label"] = subtype_label
            if exe_path and not _norm(item_payload.get("resolved_path") or item_payload.get("path")):
                item_payload["resolved_path"] = exe_path
            if cmd and not item_payload.get("command"):
                item_payload["command"] = cmd
            if loc and not item_payload.get("location"):
                item_payload["location"] = loc
            item_time = _extract_evidence_time(it, detail, label)
            if not item_time and module in ("service", "task", "startup", "driver", "program", "file", "exec"):
                for pk in ("path", "resolved_path", "image_path", "ImagePath", "full_path", "command", "executable"):
                    pv = _norm(it.get(pk)).strip().strip('"').strip("'")
                    if not pv or ("\\" not in pv and "/" not in pv):
                        continue
                    # 命令行取第一个路径片段
                    if " " in pv and not pv.lower().endswith((".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1")):
                        pv = pv.split(" ", 1)[0].strip().strip('"')
                    item_time = _lookup_file_mtime(None, pv, file_mtime_cache)
                    if item_time:
                        item_payload["mtime"] = item_time
                        item_payload["time"] = item_time
                        item_payload["_timeSource"] = "file_mtime"
                        break
            if item_time and "time" not in item_payload:
                item_payload["time"] = item_time
            # 详情优先拼 location / command / path，便于图上与证据侧阅读
            detail_bits = [x for x in (subtype_label, loc, cmd or exe_path or detail) if x]
            rich_detail = " · ".join(detail_bits) if detail_bits else detail
            nid = f"{ntype}:{pid_v}:{i}:{abs(hash(key)) % 10_000_000}"
            add_node({
                "id": nid,
                "type": ntype,
                "label": label[:80],
                "column": col + 1,
                "row": next_row(col + 1),
                "risk": False,
                "detail": rich_detail[:260],
                "pid": pid_v,
                "module": module,
                "subtype": subtype_id,
                "subtype_label": subtype_label,
                "location": loc,
                "command": cmd,
                "path": exe_path or _norm(it.get("path") or ""),
                "payload": item_payload,
                "confidence": conf,
                "confidence_label": _conf_label(conf),
                "confidence_reason": conf_reason,
            })
            use_kind = "persist_write" if edge_kind == "persist" else edge_kind
            edges.append({"from": proc_nid, "to": nid, "kind": use_kind, "confidence": conf})
            evidence.append(_evidence_row(
                module=module,
                title=label[:120],
                detail=rich_detail[:400],
                pid=pid_v,
                process=pname,
                payload=item_payload,
                confidence=conf,
                confidence_reason=conf_reason,
                time=item_time,
            ))
            hit_n += 1

    for pid_v in sorted(tree_pids):
        p = by_pid.get(pid_v)
        if not p:
            continue
        col = depths.get(pid_v, 0)
        proc_nid = f"proc:{pid_v}"
        pname = _proc_name(p)
        is_seed = pid_v in seeds
        # PID 聚焦：子进程只保留进程节点与 spawn，不做持久化/浏览器等广扫
        if pid_focus and not is_seed:
            continue

        related_conns = [c for c in conns if conn_pid(c) == pid_v]
        if q and _IP_RE.match(q):
            related_conns = [c for c in related_conns if _conn_matches_query(c, q)] or related_conns
        for i, c in enumerate(related_conns[:12]):
            remote = _network_label(c)
            key = f"{pid_v}|{remote}|{_norm(c.get('local'))}"
            if key in net_seen:
                continue
            net_seen.add(key)
            nid = f"net:{pid_v}:{i}"
            proc_start = _normalize_time_str(
                p.get("start_time") or p.get("create_time") or p.get("CreationDate") or ""
            )
            own_time = _extract_evidence_time(c)
            conn_time = own_time or proc_start
            net_payload = {**dict(c), "_neKind": "conn"}
            if conn_time:
                net_payload["time"] = conn_time
                if not own_time and proc_start:
                    net_payload["_timeSource"] = "process_start"
            add_node({
                "id": nid,
                "type": "network",
                "label": remote,
                "column": col + 1,
                "row": next_row(col + 1),
                "risk": False,
                "detail": _network_detail(c),
                "pid": pid_v,
                "module": "network",
                "payload": net_payload,
                "confidence": CONF_STRONG,
                "confidence_label": _conf_label(CONF_STRONG),
                "confidence_reason": "连接记录 PID 一致",
            })
            edges.append({"from": proc_nid, "to": nid, "kind": "connect", "confidence": CONF_STRONG})
            evidence.append(_evidence_row(
                module="network",
                title=remote,
                detail=_network_detail(c),
                pid=pid_v,
                process=pname,
                payload=net_payload,
                confidence=CONF_STRONG,
                confidence_reason="连接记录 PID 一致",
                time=conn_time,
            ))

        # 真·释放文件：Sysmon 11
        for di, hit in enumerate(drops_by_pid.get(pid_v, [])[:10]):
            if len(nodes) >= limit:
                break
            fp = _norm(hit.get("path"))
            fkey = fp.lower()
            if not fp or fkey in file_seen:
                continue
            file_seen.add(fkey)
            base = _basename(fp) or fp
            src = _norm(hit.get("source") or "drop")
            dconf = hit.get("confidence") or CONF_MEDIUM
            dreason = _norm(hit.get("confidence_reason") or "写盘关联")
            payload = hit.get("payload") if isinstance(hit.get("payload"), dict) else {
                "path": fp,
                "full_path": fp,
                "name": base,
                "_dropSource": src,
                "image": hit.get("image") or "",
                "time": hit.get("time") or "",
            }
            if "_dropSource" not in payload:
                payload = {**payload, "_dropSource": src}
            if not _extract_evidence_time(payload):
                mt = _lookup_file_mtime(None, fp, file_mtime_cache)
                if mt:
                    payload = {**payload, "mtime": mt, "time": mt}
            fnid = f"drop:{pid_v}:{di}:{abs(hash(fkey)) % 10_000_000}"
            add_node({
                "id": fnid,
                "type": "file",
                "label": base[:80],
                "column": col + 1,
                "row": next_row(col + 1),
                "risk": dconf == CONF_STRONG,
                "detail": fp,
                "pid": pid_v,
                "module": "file",
                "payload": payload,
                "confidence": dconf,
                "confidence_label": _conf_label(dconf),
                "confidence_reason": dreason,
                "drop_source": src,
            })
            edges.append({"from": proc_nid, "to": fnid, "kind": "drop", "confidence": dconf})
            evidence.append(_evidence_row(
                module="file",
                title=base[:120],
                detail=fp[:400],
                pid=pid_v,
                process=pname,
                payload=payload,
                confidence=dconf,
                confidence_reason=dreason,
            ))

        related_findings = [f for f in findings if isinstance(f, dict) and _finding_matches_process(f, p)]
        for i, f in enumerate(related_findings[:16]):
            fid = _finding_id(f, i)
            if fid in finding_seen:
                continue
            finding_seen.add(fid)
            sev = _finding_severity(f)
            fconf, freason = _finding_confidence(f, p)
            ftime = _extract_evidence_time(f)
            ftime_source = ""
            if not ftime:
                for fp0 in _extract_file_hits(f, p):
                    ftime = _lookup_file_mtime(None, fp0, file_mtime_cache)
                    if ftime:
                        ftime_source = "file_mtime"
                        break
            if not ftime:
                ftime = _normalize_time_str(
                    p.get("start_time") or p.get("create_time") or p.get("CreationDate") or ""
                )
                if ftime:
                    ftime_source = "process_start"
            f_payload = dict(f)
            if ftime:
                f_payload["time"] = ftime
                if ftime_source:
                    f_payload["_timeSource"] = ftime_source
            nid = f"finding:{fid}"
            add_node({
                "id": nid,
                "type": "finding",
                "label": _norm(f.get("title") or f.get("name") or "告警")[:80],
                "column": col + 1,
                "row": next_row(col + 1),
                "risk": sev == "high",
                "severity": sev,
                "detail": _preview_from_item(f, ("reason", "title")) or _norm(f.get("title") or ""),
                "pid": pid_v,
                "module": "finding",
                "finding_id": fid,
                "payload": f_payload,
                "confidence": fconf,
                "confidence_label": _conf_label(fconf),
                "confidence_reason": freason,
            })
            edges.append({"from": proc_nid, "to": nid, "kind": "alert", "confidence": fconf})
            evidence.append(_evidence_row(
                module="finding",
                title=_norm(f.get("title") or f.get("name") or "告警"),
                detail=_norm(f.get("reason") or ""),
                severity=sev,
                pid=pid_v,
                process=pname,
                finding_id=fid,
                payload=f_payload,
                confidence=fconf,
                confidence_reason=freason,
                time=ftime,
            ))

            # 告警抽路径 = 关联文件（非写盘证据）
            for j, fp in enumerate(_extract_file_hits(f, p)):
                fkey = fp.lower()
                if fkey in file_seen:
                    continue
                file_seen.add(fkey)
                fnid = f"related:{pid_v}:{j}:{abs(hash(fkey)) % 10_000_000}"
                base = fp.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                fp_payload = {
                    "path": fp,
                    "full_path": fp,
                    "name": base or fp,
                    "_dropSource": "finding",
                }
                mt = _lookup_file_mtime(None, fp, file_mtime_cache)
                if mt:
                    fp_payload["mtime"] = mt
                    fp_payload["time"] = mt
                file_conf = CONF_MEDIUM if ("\\" in fp or "/" in fp) else CONF_WEAK
                file_reason = "告警关联路径（非写盘证据）" if file_conf == CONF_MEDIUM else "告警文本提取路径"
                add_node({
                    "id": fnid,
                    "type": "file",
                    "label": base or fp,
                    "column": col + 1,
                    "row": next_row(col + 1),
                    "risk": sev == "high",
                    "detail": fp,
                    "pid": pid_v,
                    "module": "file",
                    "payload": fp_payload,
                    "confidence": file_conf,
                    "confidence_label": _conf_label(file_conf),
                    "confidence_reason": file_reason,
                    "drop_source": "finding",
                })
                edges.append({"from": proc_nid, "to": fnid, "kind": "related", "confidence": file_conf})
                evidence.append(_evidence_row(
                    module="file",
                    title=base or fp,
                    detail=fp,
                    pid=pid_v,
                    process=pname,
                    payload=fp_payload,
                    confidence=file_conf,
                    confidence_reason=file_reason,
                    time=mt,
                ))

        persist_min = CONF_MEDIUM if pid_focus else CONF_WEAK
        attach_related(
            items=services, module="service", ntype="service", edge_kind="persist_write",
            label_keys=("name", "display_name", "DisplayName"),
            detail_keys=("path", "resolved_path", "image_path", "ImagePath", "command", "service_dll"),
            pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            min_conf=persist_min, use_query=not pid_focus,
        )
        attach_related(
            items=tasks, module="task", ntype="task", edge_kind="persist_write",
            label_keys=("name", "task_name", "path"),
            detail_keys=("command", "command_line", "exec", "actions", "path"),
            pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            min_conf=persist_min, use_query=not pid_focus,
        )
        attach_related(
            items=startups, module="startup", ntype="startup", edge_kind="persist_write",
            label_keys=("name", "caption"),
            detail_keys=("command", "path", "location"),
            pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            min_conf=persist_min, use_query=not pid_focus,
        )
        attach_related(
            items=exec_rows, module="exec", ntype="exec", edge_kind="exec",
            label_keys=("name", "executable", "exe", "file"),
            detail_keys=("path", "full_path", "executed", "last_run", "run_count"),
            per_proc=5, pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            min_conf=persist_min, use_query=not pid_focus,
        )
        if not pid_focus:
            attach_related(
                items=drivers, module="driver", ntype="driver", edge_kind="persist_write",
                label_keys=("name", "display_name"),
                detail_keys=("path", "image_path", "ImagePath"),
                per_proc=3, pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            )
            attach_related(
                items=programs, module="program", ntype="program", edge_kind="persist_write",
                label_keys=("name", "display_name", "DisplayName"),
                detail_keys=("publisher", "install_location", "version"),
                per_proc=2, pid_v=pid_v, proc_nid=proc_nid, col=col, pname=pname,
            )

        # 用户：同账号侧栏证据（不强行画边，避免图过乱）
        puser = _norm_lower(p.get("user"))
        if puser and not pid_focus:
            for u in users[:200]:
                uname = _norm_lower(u.get("name") or u.get("user") or u.get("account"))
                if uname and (uname in puser or puser.endswith("\\" + uname) or uname == puser):
                    evidence.append(_evidence_row(
                        module="user",
                        title=_norm(u.get("name") or u.get("user") or "用户"),
                        detail=_preview_from_item(u, ("sid", "description", "groups", "home")) or _item_text(u, ("sid", "description")),
                        pid=pid_v,
                        process=pname,
                        payload=dict(u),
                        confidence=CONF_WEAK,
                        confidence_reason="同用户名弱关联",
                    ))
                    break

        # 浏览器：路径/进程名弱关联 → 证据列表
        if not pid_focus:
            for b in browser[:300]:
                bconf, breason = _anchor_confidence(
                    b, names={_proc_name(p).lower()}, paths={_proc_path(p).lower()}, hashes=set(), q="",
                )
                if not bconf:
                    continue
                # 浏览器默认最多中档；无路径则弱
                if bconf == CONF_STRONG:
                    bconf, breason = CONF_MEDIUM, "浏览器路径匹配"
                evidence.append(_evidence_row(
                    module="browser",
                    title=_norm(b.get("title") or b.get("url") or b.get("name") or "浏览器")[:120],
                    detail=_preview_from_item(b, ("url", "path", "profile", "browser"))[:400],
                    pid=pid_v,
                    process=pname,
                    payload=dict(b),
                    confidence=bconf,
                    confidence_reason=breason or "浏览器弱关联",
                ))
                if sum(1 for e in evidence if e.get("module") == "browser") >= 8:
                    break

        ev_hits = 0
        for ev in all_eventlogs:
            if ev_hits >= 6 or len(nodes) >= limit:
                break
            econf, ereason = _eventlog_confidence(ev, p, q=q)
            if not econf:
                continue
            ekey = f"{ev.get('channel')}|{ev.get('event_id')}|{ev.get('time')}"
            if ekey in eventlog_seen:
                continue
            eventlog_seen.add(ekey)
            label = _eventlog_label(ev)
            detail = _preview_from_item(ev, ("message",)) or _norm(ev.get("time"))
            hit = ev.get("hit_rule") if isinstance(ev.get("hit_rule"), dict) else {}
            sev = _norm_lower(hit.get("level") or ev.get("level") or "info") or "info"
            is_high = sev in ("high", "critical")
            nid = f"eventlog:{pid_v}:{abs(hash(ekey)) % 10_000_000}"
            add_node({
                "id": nid,
                "type": "eventlog",
                "label": label[:80],
                "column": col + 1,
                "row": next_row(col + 1),
                "risk": is_high,
                "detail": detail[:260],
                "pid": pid_v,
                "module": "eventlog",
                "payload": dict(ev),
                "confidence": econf,
                "confidence_label": _conf_label(econf),
                "confidence_reason": ereason,
            })
            edges.append({"from": proc_nid, "to": nid, "kind": "log", "confidence": econf})
            evidence.append(_evidence_row(
                module="eventlog",
                title=label[:120],
                detail=detail[:400],
                severity=sev if sev in ("high", "medium", "low", "critical") else "",
                pid=pid_v,
                process=pname,
                payload=dict(ev),
                confidence=econf,
                confidence_reason=ereason,
            ))
            ev_hits += 1

        if len(nodes) >= limit:
            break

    if file_only and file_nid:
        fake_p = {"pid": 0, "name": _basename(file_anchor), "path": file_anchor}
        for i, f in enumerate(findings):
            if not isinstance(f, dict) or len(nodes) >= limit:
                continue
            if not (
                _finding_matches_query(f, file_anchor)
                or _item_matches_anchor(f, names=anchor_names, paths=anchor_paths, hashes=anchor_hashes, q=file_anchor)
            ):
                continue
            fid = _finding_id(f, i)
            if fid in finding_seen:
                continue
            finding_seen.add(fid)
            sev = _finding_severity(f)
            fconf, freason = _finding_confidence(f, fake_p)
            if not fconf:
                fconf, freason = CONF_MEDIUM, "告警命中选定文件"
            nid = f"finding:{fid}"
            add_node({
                "id": nid,
                "type": "finding",
                "label": _norm(f.get("title") or f.get("name") or "告警")[:80],
                "column": 1,
                "row": next_row(1),
                "risk": sev == "high",
                "severity": sev,
                "detail": _preview_from_item(f, ("reason", "title")) or _norm(f.get("title") or ""),
                "module": "finding",
                "finding_id": fid,
                "payload": dict(f),
                "confidence": fconf,
                "confidence_label": _conf_label(fconf),
                "confidence_reason": freason,
            })
            edges.append({"from": file_nid, "to": nid, "kind": "alert", "confidence": fconf})
            evidence.append(_evidence_row(
                module="finding",
                title=_norm(f.get("title") or f.get("name") or "告警"),
                detail=_norm(f.get("reason") or ""),
                severity=sev,
                finding_id=fid,
                payload=dict(f),
                confidence=fconf,
                confidence_reason=freason,
            ))
        attach_related(
            items=services, module="service", ntype="service", edge_kind="persist_write",
            label_keys=("name", "display_name", "DisplayName"),
            detail_keys=("path", "resolved_path", "image_path", "ImagePath", "command", "service_dll"),
            pid_v=0, proc_nid=file_nid, col=file_col, pname=_basename(file_anchor),
        )
        attach_related(
            items=tasks, module="task", ntype="task", edge_kind="persist_write",
            label_keys=("name", "task_name", "path"),
            detail_keys=("command", "command_line", "exec", "actions", "path"),
            pid_v=0, proc_nid=file_nid, col=file_col, pname=_basename(file_anchor),
        )
        attach_related(
            items=startups, module="startup", ntype="startup", edge_kind="persist_write",
            label_keys=("name", "caption"),
            detail_keys=("command", "path", "location"),
            pid_v=0, proc_nid=file_nid, col=file_col, pname=_basename(file_anchor),
        )
        attach_related(
            items=exec_rows, module="exec", ntype="exec", edge_kind="exec",
            label_keys=("name", "executable", "exe", "file"),
            detail_keys=("path", "full_path", "executed", "last_run", "run_count"),
            per_proc=6, pid_v=0, proc_nid=file_nid, col=file_col, pname=_basename(file_anchor),
        )
        ev_hits = 0
        for ev in all_eventlogs:
            if ev_hits >= 8 or len(nodes) >= limit:
                break
            econf, ereason = _eventlog_confidence(ev, fake_p, q=file_anchor)
            if not econf:
                continue
            ekey = f"{ev.get('channel')}|{ev.get('event_id')}|{ev.get('time')}"
            if ekey in eventlog_seen:
                continue
            eventlog_seen.add(ekey)
            label = _eventlog_label(ev)
            detail = _preview_from_item(ev, ("message",)) or _norm(ev.get("time"))
            nid = f"eventlog:file:{abs(hash(ekey)) % 10_000_000}"
            add_node({
                "id": nid,
                "type": "eventlog",
                "label": label[:80],
                "column": 1,
                "row": next_row(1),
                "risk": False,
                "detail": detail[:260],
                "module": "eventlog",
                "payload": dict(ev),
                "confidence": econf,
                "confidence_label": _conf_label(econf),
                "confidence_reason": ereason,
            })
            edges.append({"from": file_nid, "to": nid, "kind": "log", "confidence": econf})
            evidence.append(_evidence_row(
                module="eventlog",
                title=label[:120],
                detail=detail[:400],
                payload=dict(ev),
                confidence=econf,
                confidence_reason=ereason,
            ))
            ev_hits += 1

    for n in nodes:
        if n.get("type") != "process":
            continue
        pid_v = int(n.get("pid") or 0)
        n["spawn_count"] = spawn_count.get(pid_v, 0)
        if pid_v in risk_pids:
            n["risk"] = True

    # 启动项/服务/任务 → 进程 的拉起边（路径/命令推断，弱置信度需人工复核）
    launch_n = _attach_launch_edges(nodes, edges)

    nodes.sort(key=lambda n: (int(n.get("column") or 0), int(n.get("row") or 0), n.get("id") or ""))
    evidence.sort(
        key=lambda e: (
            _CONF_RANK.get(str(e.get("confidence") or ""), 9),
            str(e.get("module") or ""),
            str(e.get("title") or ""),
        ),
    )
    evidence = evidence[:160]

    conf_stats = {
        "strong": sum(1 for e in evidence if e.get("confidence") == CONF_STRONG),
        "medium": sum(1 for e in evidence if e.get("confidence") == CONF_MEDIUM),
        "weak": sum(1 for e in evidence if e.get("confidence") == CONF_WEAK),
    }

    persist_edge_n = sum(1 for e in edges if e.get("kind") in ("persist_write", "persist"))
    stats = {
        "processes": sum(1 for n in nodes if n.get("type") == "process"),
        "network": sum(1 for n in nodes if n.get("type") == "network"),
        "findings": sum(1 for n in nodes if n.get("type") == "finding"),
        "files": sum(1 for n in nodes if n.get("type") == "file"),
        "drops": sum(1 for e in edges if e.get("kind") == "drop"),
        "related_files": sum(1 for e in edges if e.get("kind") == "related"),
        "persist": sum(1 for n in nodes if n.get("type") in ("service", "task", "startup", "driver", "program")),
        "persist_write": persist_edge_n,
        "launches": launch_n or sum(1 for e in edges if e.get("kind") == "launch"),
        "exec": sum(1 for n in nodes if n.get("type") == "exec"),
        "eventlog": sum(1 for n in nodes if n.get("type") == "eventlog"),
        "confidence": conf_stats,
    }

    result = {
        "ok": True,
        "file": rid,
        "query": q,
        "pid": (focus_pid_v if pid_focus and focus_pid_v else None) or pid or (matches[0]["pid"] if matches else 0),
        "pid_focus": bool(pid_focus),
        "anchor_file": file_anchor,
        "path_hits": path_hits,
        "matches": matches,
        "root_pid": root,
        "graph": {"nodes": nodes[:limit], "edges": edges[:limit * 3]},
        "evidence": evidence,
        "stats": stats,
        "modules_covered": [
            "process", "network", "finding", "file", "service", "task", "startup",
            "exec", "driver", "program", "user", "browser", "eventlog",
            "linux_hunt",
        ],
        "linux_hunt_seeds": len(linux_seeds),
    }
    result["conclusion"] = {
        "system": build_system_conclusion(result),
    }
    return result


_TRACE_CACHE: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
_TRACE_CACHE_LOCK = threading.RLock()
_TRACE_LOAD_LOCKS: Dict[Tuple[Any, ...], threading.Lock] = {}
_TRACE_CACHE_CAP = 24


def locate_threat_trace_targets(
    q: str,
    *,
    os_family: str = "",
    exclude_file: str = "",
    limit_hosts: int = 40,
    limit_hits: int = 12,
) -> Dict[str, Any]:
    """跨报告定位：按文件名/哈希在近期报告中找命中，供「全部主机」溯查切换。"""
    from backend.os_detect import detect_os_family
    from backend import config as cfg

    qn = _norm(q)
    want = str(os_family or "").strip().lower()
    if want not in ("windows", "linux"):
        want = ""
    exclude = _norm(exclude_file)
    out: List[Dict[str, Any]] = []
    if not qn or _PID_RE.match(qn) or _IP_RE.match(qn):
        return {"ok": True, "query": qn, "hits": [], "scanned": 0}

    is_hash = bool(_HASH_RE.match(qn))
    is_name = looks_like_filename(qn) or (not looks_like_path(qn) and len(qn) >= 4)
    if not is_hash and not is_name and not looks_like_path(qn):
        return {"ok": True, "query": qn, "hits": [], "scanned": 0}

    root = cfg.REPORTS_DIR
    dirs = []
    if root.is_dir():
        dirs = [d for d in root.iterdir() if d.is_dir() and not d.name.startswith("_")]
        dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    scanned = 0
    base = _basename(qn).lower()
    for d in dirs:
        if len(out) >= limit_hits:
            break
        if scanned >= limit_hosts:
            break
        rid = d.name
        if exclude and rid == exclude:
            continue
        meta_j: Dict[str, Any] = {}
        host = rid.split("_")[0]
        meta = d / "report.json"
        if meta.is_file():
            try:
                j = json.loads(meta.read_text(encoding="utf-8"))
                if isinstance(j, dict):
                    meta_j = j
                    host = str(j.get("hostname") or host)
            except Exception:
                pass
        if want:
            fam = detect_os_family(meta_j) if meta_j else detect_os_family(
                {"collector": "linuxsc"} if "linux" in rid.lower() else {}
            )
            # 与战役一致：无 meta 时再看目录名
            if not meta_j:
                low = rid.lower()
                if "linuxsc" in low or "_linux_" in low:
                    fam = "linux"
                else:
                    fam = detect_os_family({"hostname": host})
            if fam != want:
                continue

        scanned += 1
        dbp = _resolve_db_path(rid)
        if not dbp:
            continue
        try:
            conn = _connect(dbp)
        except Exception:
            continue
        try:
            _init_schema(conn)
            paths: List[str] = []
            if is_hash:
                hv = qn.lower()
                try:
                    rows = conn.execute(
                        "SELECT full_path FROM files WHERE lower(md5)=? OR lower(sha1)=? OR lower(sha256)=? LIMIT 5",
                        (hv, hv, hv),
                    ).fetchall()
                    paths = [str(r[0] or "") for r in rows if r[0]]
                except Exception:
                    paths = []
            else:
                files = search_files_by_name(conn, base or qn, limit=5)
                paths = [str(f.get("path") or "") for f in files if f.get("path")]
                if not paths and looks_like_path(qn):
                    files = search_files_at_path(conn, qn, limit=5)
                    paths = [str(f.get("path") or "") for f in files if f.get("path") and f.get("current")]

            # 进程名兜底
            proc_hit = False
            via = "file" if paths else ""
            if not paths and is_name:
                procs = _load_one_blob(conn, "processes") or []
                for p in procs:
                    if isinstance(p, dict) and _proc_matches_query(p, qn):
                        proc_hit = True
                        via = "process"
                        pp = _proc_path(p)
                        if pp:
                            paths.append(pp)
                        break

            # 告警证据路径兜底（files 表无文件但告警带全路径）
            if not paths and is_name:
                try:
                    findings = _load_findings_from_conn(conn) or []
                except Exception:
                    findings = []
                fpaths = _paths_from_findings_for_name(findings, qn, limit=5)
                if fpaths:
                    paths = fpaths
                    via = "finding"

            if not paths and not proc_hit:
                continue
            out.append({
                "file": rid,
                "hostname": host,
                "path": paths[0] if paths else "",
                "paths": paths[:5],
                "via": via or ("file" if paths else "process"),
            })
        except Exception:
            continue
        finally:
            try:
                conn.close()
            except Exception:
                pass

    return {
        "ok": True,
        "query": qn,
        "hits": out,
        "scanned": scanned,
        "os_family": want or "all",
    }


def build_threat_trace(
    rid: str,
    *,
    q: str = "",
    pid: Optional[int] = None,
    file: str = "",
    limit: int = 80,
) -> Dict[str, Any]:
    """按报告 DB 版本缓存结果，并合并同参数并发计算。"""
    dbp = _resolve_db_path(rid)
    try:
        db_mtime = int(dbp.stat().st_mtime_ns) if dbp else 0
    except OSError:
        db_mtime = 0
    limit_v = max(1, min(int(limit or 80), 500))
    key = (str(rid), db_mtime, _norm_lower(q), int(pid or 0), _norm_lower(file), limit_v)
    with _TRACE_CACHE_LOCK:
        hit = _TRACE_CACHE.get(key)
        if hit is not None:
            return copy.deepcopy(hit)
        load_lock = _TRACE_LOAD_LOCKS.setdefault(key, threading.Lock())
    with load_lock:
        with _TRACE_CACHE_LOCK:
            hit = _TRACE_CACHE.get(key)
            if hit is not None:
                return copy.deepcopy(hit)
        out = _build_threat_trace_uncached(rid, q=q, pid=pid, file=file, limit=limit_v)
        with _TRACE_CACHE_LOCK:
            _TRACE_CACHE[key] = copy.deepcopy(out)
            while len(_TRACE_CACHE) > _TRACE_CACHE_CAP:
                _TRACE_CACHE.pop(next(iter(_TRACE_CACHE)))
            _TRACE_LOAD_LOCKS.pop(key, None)
        return out


def build_system_conclusion(trace: Dict[str, Any]) -> Dict[str, Any]:
    """基于关联结果生成确定性系统结论（无大模型）。"""
    evidence = [e for e in (trace.get("evidence") or []) if isinstance(e, dict)]
    stats = trace.get("stats") if isinstance(trace.get("stats"), dict) else {}
    conf = stats.get("confidence") if isinstance(stats.get("confidence"), dict) else {}
    matches = [m for m in (trace.get("matches") or []) if isinstance(m, dict)]
    nodes = ((trace.get("graph") or {}).get("nodes") or []) if isinstance(trace.get("graph"), dict) else []

    seed = matches[0] if matches else {}
    seed_name = _norm(seed.get("name") or "")
    seed_pid = int(seed.get("pid") or trace.get("pid") or 0)
    seed_path = _norm(seed.get("path") or "")

    strong = [e for e in evidence if e.get("confidence") == CONF_STRONG]
    medium = [e for e in evidence if e.get("confidence") == CONF_MEDIUM]
    weak = [e for e in evidence if e.get("confidence") == CONF_WEAK]
    high_findings = [
        e for e in evidence
        if e.get("module") == "finding" and str(e.get("severity") or "").lower() in ("high", "critical")
    ]
    net_n = int(stats.get("network") or 0)
    persist_n = int(stats.get("persist") or 0)
    eventlog_n = int(stats.get("eventlog") or 0)
    finding_n = int(stats.get("findings") or 0)
    drop_n = int(stats.get("drops") or 0)
    related_n = int(stats.get("related_files") or 0)
    launch_n = int(stats.get("launches") or 0)
    persist_write_n = int(stats.get("persist_write") or 0)

    risk, score = "低", 20
    if high_findings or (finding_n >= 8 and len(strong) >= 3) or drop_n >= 3:
        risk, score = "高", 78
    elif finding_n >= 3 or net_n >= 2 or persist_n >= 2 or drop_n >= 1:
        risk, score = "中", 48
    if any("mimikatz" in _norm_lower(e.get("title")) for e in evidence):
        risk, score = "严重", 95

    highlights: List[str] = []
    for e in (high_findings or strong)[:8]:
        tag = e.get("confidence_label") or _conf_label(str(e.get("confidence") or ""))
        mod = e.get("module") or ""
        title = _norm(e.get("title"))[:100]
        reason = _norm(e.get("confidence_reason"))
        bit = f"[{tag or '?'}·{mod}] {title}"
        if reason:
            bit += f"（{reason}）"
        highlights.append(bit)

    lines: List[str] = []
    anchor = seed_name or (f"PID {seed_pid}" if seed_pid else (trace.get("query") or "目标"))
    lines.append(f"锚点进程：{anchor}" + (f"（PID {seed_pid}）" if seed_pid else ""))
    if seed_path:
        lines.append(f"路径：{seed_path}")
    lines.append(
        f"关联规模：进程 {stats.get('processes') or 0} · 告警 {finding_n} · 网络 {net_n} · "
        f"释放文件 {drop_n} · 关联文件 {related_n} · 持久化 {persist_n} · 日志 {eventlog_n} · "
        f"执行痕迹 {stats.get('exec') or 0}"
    )
    if drop_n or persist_write_n or launch_n:
        chain_bits = []
        if drop_n:
            chain_bits.append(f"释放 {drop_n}")
        if persist_write_n:
            chain_bits.append(f"写入启动项关联 {persist_write_n}")
        if launch_n:
            chain_bits.append(f"拉起推断 {launch_n}")
        lines.append(
            "自启动串链线索：" + " → ".join(chain_bits)
            + "（拉起为路径/命令推断，弱关联需人工复核）。"
        )
    if drop_n:
        lines.append(
            f"写盘释放：{drop_n} 条（依据 Sysmon 11）；"
            f"告警抽路径 {related_n} 条仅作关联线索。"
        )
    lines.append(
        f"置信度分布：强 {conf.get('strong') or len(strong)} · "
        f"中 {conf.get('medium') or len(medium)} · 弱 {conf.get('weak') or len(weak)}"
    )
    lines.append(f"系统研判风险：**{risk}**（启发式 {score}/100）。")
    if strong:
        lines.append(f"硬关联（建议优先采信）{len(strong)} 条，含 PID/哈希/进程树等。")
    if weak:
        lines.append(f"弱关联 {len(weak)} 条为短名/文本匹配，**需人工复核**，勿单独作为结论依据。")
    if not evidence and not nodes:
        lines.append("暂无关联证据；可换 PID / 完整路径 / 哈希再试。")

    recommendations = [
        "优先核验「强」关联证据（网络 PID、4688、哈希一致等）",
        "对高危告警打开详情核对原始路径与命令行",
        "弱关联条目仅作线索，结合同目录文件 / 系统日志交叉验证",
        "若需攻击链叙事，可点击「AI 分析」（需已配置大模型）",
    ]
    if net_n:
        recommendations.insert(1, "核对外联 IP/域名是否业务授权，并对照威胁情报")
    if persist_n:
        recommendations.insert(1, "检查关联服务 / 计划任务 / 启动项的 location/command/path 是否被植入")
    if launch_n:
        recommendations.insert(1, "核对「拉起」边：启动项命令是否确实对应图中进程（推断边，非时序实证）")

    return {
        "mode": "system",
        "risk_level": risk,
        "risk_score": score,
        "summary": "\n".join(lines),
        "highlights": highlights,
        "recommendations": recommendations[:6],
        "anchor": {
            "name": seed_name,
            "pid": seed_pid,
            "path": seed_path,
            "query": _norm(trace.get("query")),
        },
        "note": "系统结论仅陈述本报告内已关联事实，不含大模型推断。",
    }


def slim_trace_for_ai(trace: Dict[str, Any], *, max_evidence: int = 40) -> Dict[str, Any]:
    """压缩溯检结果供大模型窗口，避免塞入 payload 全文。"""
    evidence = []
    for e in (trace.get("evidence") or [])[:max_evidence]:
        if not isinstance(e, dict):
            continue
        evidence.append({
            "module": e.get("module"),
            "title": _norm(e.get("title"))[:120],
            "detail": _norm(e.get("detail"))[:220],
            "confidence": e.get("confidence"),
            "confidence_reason": _norm(e.get("confidence_reason"))[:80],
            "severity": e.get("severity") or "",
            "pid": e.get("pid") or 0,
            "process": _norm(e.get("process"))[:80],
        })
    matches = []
    for m in (trace.get("matches") or [])[:8]:
        if not isinstance(m, dict):
            continue
        matches.append({
            "pid": m.get("pid"),
            "name": _norm(m.get("name"))[:80],
            "path": _norm(m.get("path"))[:200],
            "via": m.get("via") or "",
        })
    return {
        "query": _norm(trace.get("query")),
        "pid": trace.get("pid") or 0,
        "matches": matches,
        "stats": trace.get("stats") or {},
        "system_conclusion": (trace.get("conclusion") or {}).get("system") or {},
        "evidence_windows": evidence,
        "note": "仅根据威胁溯检关联窗口研判；禁止编造窗口外的文件、进程或日志。弱关联需标注待复核。",
    }

