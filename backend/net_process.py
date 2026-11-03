"""用进程表把网络连接 / 监听端口的 PID 回填成进程名与路径。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_SS_USERS = re.compile(r'"([^"]+)"\s*,\s*pid\s*=\s*(\d+)', re.I)
_SS_PID = re.compile(r"pid\s*=\s*(\d+)", re.I)
_NETSTAT_PROG = re.compile(r"^(\d+)\s*/\s*(.+)$")
_PID_IN_TEXT = re.compile(r"\bPID\s*[:=]?\s*(\d+)\b", re.I)


def conn_pid(row: Any) -> int:
    if not isinstance(row, dict):
        return 0
    v = row.get("pid")
    if v is None or str(v).strip() == "":
        v = row.get("PID")
    try:
        n = int(v)
        return n if n > 0 else 0
    except (TypeError, ValueError):
        return 0


def _basename(path: str) -> str:
    s = (path or "").replace("\\", "/").strip()
    if not s:
        return ""
    return s.rsplit("/", 1)[-1]


def _clean_name(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s or s in ("-", "—", "n/a", "N/A", "null"):
        return ""
    if _is_ss_blob(s):
        name, _ = parse_ss_process(s)
        return name
    m = _NETSTAT_PROG.match(s)
    if m:
        return m.group(2).strip().strip('"')[:200]
    return s[:200]


def _is_ss_blob(s: str) -> bool:
    low = (s or "").lower()
    return "users:(" in low or ("pid=" in low and "(" in low)


def parse_ss_process(raw: str) -> Tuple[str, int]:
    """从 ss/netstat 进程字段解析 (name, pid)。"""
    s = str(raw or "").strip()
    if not s:
        return "", 0
    m = _SS_USERS.search(s)
    if m:
        try:
            return m.group(1).strip()[:200], int(m.group(2))
        except (TypeError, ValueError):
            return m.group(1).strip()[:200], 0
    m = _NETSTAT_PROG.match(s)
    if m:
        try:
            return m.group(2).strip().strip('"')[:200], int(m.group(1))
        except (TypeError, ValueError):
            return m.group(2).strip()[:200], 0
    m = _SS_PID.search(s)
    pid = 0
    if m:
        try:
            pid = int(m.group(1))
        except (TypeError, ValueError):
            pid = 0
    if _is_ss_blob(s):
        return "", pid
    return s[:200], pid


def _proc_fields(p: Dict[str, Any]) -> Dict[str, str]:
    name = str(
        p.get("name") or p.get("process_name") or p.get("image_name")
        or p.get("ImageFileName") or p.get("comm") or p.get("image") or ""
    ).strip()
    path = str(
        p.get("path") or p.get("exe") or p.get("image_path")
        or p.get("ImagePath") or p.get("full_path") or p.get("executable") or ""
    ).strip()
    if not name and path:
        name = _basename(path)
    cmd = str(
        p.get("command_line") or p.get("command") or p.get("cmdline") or ""
    ).strip()
    return {"name": name[:200], "path": path[:500], "command": cmd[:500]}


def build_process_index(processes: Any) -> Dict[int, Dict[str, str]]:
    """pid -> {name, path, command}。忽略模块列表。"""
    idx: Dict[int, Dict[str, str]] = {}

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for p in items:
            if not isinstance(p, dict):
                continue
            pid = conn_pid(p)
            if pid:
                info = _proc_fields(p)
                prev = idx.get(pid)
                if not prev or (info.get("path") and not prev.get("path")):
                    idx[pid] = info
                elif prev and not prev.get("name") and info.get("name"):
                    idx[pid] = info
            kids = p.get("children")
            if isinstance(kids, list) and kids and isinstance(kids[0], dict):
                walk(kids)

    walk(processes)
    return idx


def _row_name_hint(row: Dict[str, Any]) -> str:
    for k in ("process_name", "image", "image_name", "owner", "process"):
        v = _clean_name(row.get(k))
        if v:
            return v
    # 内存 netscan 用 name 表示 Owner
    n = str(row.get("name") or "").strip()
    if n and ":" not in n and not n.replace(".", "").isdigit():
        return _clean_name(n)
    return ""


def enrich_conn_row(row: Any, proc_idx: Optional[Dict[int, Dict[str, str]]] = None) -> Any:
    """就地回填 process_name / process_path / process。"""
    if not isinstance(row, dict):
        return row
    idx = proc_idx or {}
    pid = conn_pid(row)
    raw_proc = str(row.get("process") or "")
    parsed_name, parsed_pid = parse_ss_process(raw_proc) if raw_proc else ("", 0)
    if not pid and parsed_pid:
        pid = parsed_pid
        row["pid"] = parsed_pid

    hint = _row_name_hint(row)
    info = idx.get(pid) or {}
    name = (info.get("name") or hint or parsed_name or "").strip()
    path = str(row.get("process_path") or "").strip() or (info.get("path") or "")
    cmd = str(row.get("process_command") or "").strip() or (info.get("command") or "")
    if not name and path:
        name = _basename(path)

    if name:
        row["process_name"] = name
        row["process"] = name
        if raw_proc and raw_proc != name and _is_ss_blob(raw_proc):
            row["process_raw"] = raw_proc
    if path:
        row["process_path"] = path
    if cmd:
        row["process_command"] = cmd
    return row


def enrich_conn_list(rows: Any, proc_idx: Optional[Dict[int, Dict[str, str]]] = None) -> List[Any]:
    if not isinstance(rows, list):
        return []
    idx = proc_idx or {}
    for row in rows:
        enrich_conn_row(row, idx)
    return rows


def enrich_report_connections(report: Dict[str, Any]) -> Dict[str, Any]:
    """回填 established_connections 与 open_ports。可重复调用。"""
    if not isinstance(report, dict):
        return report
    idx = build_process_index(report.get("processes"))
    for key in ("established_connections", "open_ports", "listening_ports"):
        rows = report.get(key)
        if isinstance(rows, list) and rows:
            enrich_conn_list(rows, idx)
    return report


def conn_proc_name(row: Any) -> str:
    if not isinstance(row, dict):
        return ""
    return str(
        row.get("process_name") or row.get("process") or row.get("image") or row.get("name") or ""
    ).strip()


def conn_proc_label(row: Any) -> str:
    """告警证据用：chrome.exe (PID 1234)。"""
    if not isinstance(row, dict):
        return ""
    name = conn_proc_name(row)
    if _is_ss_blob(name):
        name, _ = parse_ss_process(name)
    pid = conn_pid(row)
    if name and pid:
        return f"{name} (PID {pid})"
    if name:
        return name
    if pid:
        return f"PID {pid}"
    return ""


def _inject_label(text: Any, label: str) -> Any:
    if not label:
        return text
    if isinstance(text, list):
        if not text:
            return [label]
        first = str(text[0] or "")
        if label in first:
            return text
        out = list(text)
        out[0] = f"{label}  {first}".strip()
        return out
    s = str(text or "")
    if not s:
        return label
    if label in s:
        return s
    return f"{label}  {s}"


def enrich_network_findings(items: List[Any], proc_idx: Dict[int, Dict[str, str]]) -> List[Any]:
    """读取旧告警时按 PID 补进程名（不写回库）。"""
    if not items or not proc_idx:
        return items
    out: List[Any] = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        matcher = str(it.get("matcher") or "").lower()
        cat = str(it.get("category") or it.get("type") or "")
        extra = it.get("extra") if isinstance(it.get("extra"), dict) else {}
        ev_s = str(it.get("evidence") or it.get("reason") or "")
        is_net = matcher == "network" or "外联" in cat or cat in ("网络外联", "网络IOC")
        is_ioc_net = matcher in ("ioc", "ioc_db") and ("外联" in ev_s or extra.get("remote"))
        if not is_net and not is_ioc_net:
            out.append(it)
            continue
        if extra.get("process_name"):
            out.append(it)
            continue
        pid = 0
        try:
            pid = int(extra.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if not pid:
            m = _PID_IN_TEXT.search(ev_s)
            if m:
                try:
                    pid = int(m.group(1))
                except (TypeError, ValueError):
                    pid = 0
        info = proc_idx.get(pid) or {}
        name = (info.get("name") or "").strip()
        if not name:
            out.append(it)
            continue
        it = dict(it)
        extra = dict(extra)
        extra["pid"] = pid
        extra["process_name"] = name
        if info.get("path"):
            extra["process_path"] = info["path"]
        if info.get("command"):
            extra["process_command"] = info["command"]
        it["extra"] = extra
        label = f"{name} (PID {pid})" if pid else name
        it["evidence"] = _inject_label(it.get("evidence"), label)
        if it.get("reason"):
            it["reason"] = _inject_label(it.get("reason"), label)
        out.append(it)
    return out
