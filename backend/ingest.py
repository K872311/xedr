"""入库瘦身：大字段截断、环境脱敏、采集质量评估、兼容旧报告字段"""
from __future__ import annotations
import os
import re
from typing import Any, Dict, List, Optional

from .lnk_parse import resolve_lnk_target
from .normalize import normalize_report

SENSITIVE_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL|PRIVATE|AUTH)", re.I)
USN_MAX = 8000
_PATH_ABS = re.compile(r"(?i)^(?:[a-z]:\\|\\\\)")
_PATH_IN_CMD = re.compile(
    r"(?i)(?:^|[\s\"'=])(([a-z]:\\|\\\\)[^\"'\r\n]*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|scr|msi|com))\b"
)
_RISKY_DIR = (
    "\\appdata\\", "\\programdata\\", "\\users\\public\\",
    "\\temp\\", "\\tmp\\", "\\downloads\\",
)


def _norm_win_path(p: str) -> str:
    s = (p or "").strip().strip('"').strip("'")
    s = s.replace("/", "\\")
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    if s.startswith("\\??\\"):
        s = s[4:]
    return s


def _is_abs_win(p: str) -> bool:
    return bool(_PATH_ABS.match(_norm_win_path(p)))


def _first_bare_exe(text: str) -> str:
    s = (text or "").strip().strip('"').strip("'")
    if not s or "\\" in s or "/" in s:
        return ""
    m = re.match(r"(?i)^([^\s]+\.(?:exe|dll|bat|cmd|scr|ps1|vbs|js))\b", s)
    return m.group(1) if m else ""


def _better_exe_path(old: str, new: str) -> str:
    if not new:
        return old
    if not old:
        return new
    nl, ol = new.lower(), old.lower()
    n_risk = any(x in nl for x in _RISKY_DIR)
    o_risk = any(x in ol for x in _RISKY_DIR)
    if n_risk and not o_risk:
        return new
    return old


def exe_basename_index(report: Dict[str, Any], extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """exe 名 -> 完整路径（进程 / 启动项 / 服务 / Prefetch / 文件扫描）。"""
    idx: Dict[str, str] = {}

    def consider(raw: str) -> None:
        if not raw:
            return
        for m in _PATH_IN_CMD.finditer(" " + raw):
            full = _norm_win_path(m.group(1))
            if _is_abs_win(full):
                base = full.rsplit("\\", 1)[-1].lower()
                idx[base] = _better_exe_path(idx.get(base, ""), full)
        n = _norm_win_path(raw.split(" /", 1)[0].split(" -", 1)[0])
        if _is_abs_win(n):
            base = n.rsplit("\\", 1)[-1].lower()
            idx[base] = _better_exe_path(idx.get(base, ""), n)

    sources = [
        report.get("processes") or [],
        report.get("startup_items") or [],
        report.get("services") or [],
        report.get("prefetch_files") or [],
        report.get("scheduled_tasks") or [],
    ]
    files = report.get("file_scans")
    # 几十万文件扫描不能在上传热路径上扫一遍；计划任务路径用进程/服务即可。
    if isinstance(files, list) and 0 < len(files) <= 8000:
        sources.append(files)
    for src in sources:
        if not isinstance(src, list):
            continue
        for row in src:
            if not isinstance(row, dict):
                continue
            for field in (
                "path", "original_path", "full_path", "resolved_path", "command", "command_line",
                "task_to_run", "image_path", "ImagePath", "exe",
            ):
                consider(str(row.get(field) or ""))
    if extra:
        for k, v in extra.items():
            if k and v:
                idx[str(k).lower()] = _better_exe_path(idx.get(str(k).lower(), ""), _norm_win_path(str(v)))
    return idx


def _is_com_handler(path: str, cmd: str = "") -> bool:
    p = (path or "").strip()
    c = (cmd or "").strip()
    if p.upper() in ("COM", "N/A", "NA"):
        return True
    if not c:
        return False
    if c.startswith("{"):
        return True
    cu = c.upper()
    if cu == "COM" or cu.startswith("COM "):
        return True
    if "COM 处理" in c or "com handler" in c.lower():
        return True
    return False


def _is_non_pe_sig_target(path: str, cmd: str = "", name: str = "") -> bool:
    p = (path or "").strip()
    c = (cmd or "").strip()
    n = (name or "").strip()
    if _is_com_handler(p, c):
        return True
    blob = f"{n}\n{p}\n{c}".lower()
    if n.lower() == "desktop.ini" or p.lower().endswith("\\desktop.ini") or p.lower().endswith("/desktop.ini"):
        return True
    if "多项操作" in (c + p + n):
        return True
    # 非可执行扩展
    for s in (p, c, n):
        m = re.search(r"\.([a-z0-9]{1,8})$", s.strip().strip('"'), re.I)
        if not m:
            continue
        ext = "." + m.group(1).lower()
        if ext in (".ini", ".txt", ".xml", ".json", ".log", ".mof", ".lnk", ".url", ".cfg", ".dat"):
            return True
    return False


def normalize_item_sig_fields(row: Dict[str, Any]) -> Dict[str, Any]:
    """旧报告自愈：COM / desktop.ini / Error_0x80092003 不当未签名。"""
    if not isinstance(row, dict):
        return row
    path = str(row.get("path") or row.get("resolved_path") or "")
    cmd = str(row.get("command") or row.get("task_to_run") or row.get("command_line") or "")
    name = str(row.get("name") or row.get("task_name") or "")
    st = str(row.get("sig_status") or row.get("SigStatus") or "").strip()
    stl = st.lower()
    if _is_non_pe_sig_target(path, cmd, name):
        out = dict(row)
        if _is_com_handler(path, cmd) and not _is_abs_win(str(out.get("path") or "")):
            out["path"] = "COM"
        out["signed"] = False
        out["sig_status"] = "N/A"
        out["sig_type"] = "None"
        return out
    if stl.startswith("error_") or stl in ("error", "fileerror") or stl.startswith("0x8009"):
        out = dict(row)
        out["signed"] = False
        if "80092003" in stl or stl == "fileerror":
            out["sig_status"] = "FileError"
        return out
    return row


def resolve_scheduled_task_paths(
    report: Dict[str, Any],
    extra_index: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """裸 exe 计划任务补全 resolved_path / path（工作目录 + 进程/文件索引）。"""
    tasks = report.get("scheduled_tasks")
    if not isinstance(tasks, list) or not tasks:
        return report
    idx = exe_basename_index(report, extra_index)
    out = []
    for t in tasks:
        if not isinstance(t, dict):
            out.append(t)
            continue
        row = dict(t)
        cmd = str(row.get("command") or row.get("task_to_run") or "")
        path = _norm_win_path(str(row.get("path") or ""))
        if _is_com_handler(path, cmd):
            row["path"] = "COM"
            row["signed"] = False
            row["sig_status"] = "N/A"
            row["sig_type"] = "None"
            out.append(row)
            continue
        resolved = _norm_win_path(str(row.get("resolved_path") or ""))
        wd = _norm_win_path(str(row.get("working_directory") or row.get("start_in") or ""))
        if not _is_abs_win(resolved):
            resolved = ""
        if not resolved and _is_abs_win(path):
            resolved = path
        if not resolved:
            m = _PATH_IN_CMD.search(" " + cmd)
            if m:
                resolved = _norm_win_path(m.group(1))
        if not resolved:
            bare = _first_bare_exe(cmd) or _first_bare_exe(path)
            if bare and wd:
                joined = _norm_win_path(wd.rstrip("\\") + "\\" + bare)
                if _is_abs_win(joined):
                    resolved = joined
            if not resolved and bare:
                resolved = idx.get(bare.lower(), "")
        if resolved:
            row["resolved_path"] = resolved
            if not _is_abs_win(path):
                row["path"] = resolved
        out.append(normalize_item_sig_fields(row))
    report["scheduled_tasks"] = out
    return report


_KNOWN_SYSTEM_EXE = {
    "explorer.exe": r"C:\Windows\explorer.exe",
    "userinit.exe": r"C:\Windows\System32\userinit.exe",
    "winlogon.exe": r"C:\Windows\System32\winlogon.exe",
    "csrss.exe": r"C:\Windows\System32\csrss.exe",
    "services.exe": r"C:\Windows\System32\services.exe",
    "lsass.exe": r"C:\Windows\System32\lsass.exe",
    "svchost.exe": r"C:\Windows\System32\svchost.exe",
    "smss.exe": r"C:\Windows\System32\smss.exe",
    "wininit.exe": r"C:\Windows\System32\wininit.exe",
}


def _copy_meta_from_process(report: Dict[str, Any], full_path: str) -> Dict[str, Any]:
    """从已采集进程里抄签名/哈希（旧启动项只有裸名时用）。"""
    want = _norm_win_path(full_path).lower()
    base = want.rsplit("\\", 1)[-1] if want else ""
    best: Dict[str, Any] = {}
    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        pp = _norm_win_path(str(p.get("path") or "")).lower()
        if not pp:
            continue
        if pp != want and pp.rsplit("\\", 1)[-1] != base:
            continue
        if p.get("sig_status") or p.get("md5") or p.get("signer"):
            best = p
            if pp == want:
                break
    if not best:
        return {}
    out = {}
    for k in (
        "signed", "signer", "sig_status", "sig_type", "company", "product",
        "description", "file_version", "md5", "sha1", "sha256",
    ):
        if best.get(k) not in (None, ""):
            out[k] = best.get(k)
    return out


def resolve_startup_item_paths(
    report: Dict[str, Any],
    extra_index: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """裸 exe 启动项（如 Winlogon Shell=explorer.exe）补全 path，并尽量抄进程签名。"""
    items = report.get("startup_items")
    if not isinstance(items, list) or not items:
        return report
    idx = exe_basename_index(report, extra_index)
    out = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        row = dict(it)
        cmd = str(row.get("command") or "")
        # Startup .lnk 补全 resolved_path（旧报告 / 未重采集）
        lnk = str(row.get("shortcut_path") or "").strip()
        if not lnk and " -> " in cmd:
            head = cmd.split(" -> ", 1)[0].strip().strip('"')
            if head.lower().endswith(".lnk"):
                lnk = head
        elif not lnk and cmd.lower().endswith(".lnk"):
            lnk = cmd.strip().strip('"')
        if lnk.lower().endswith(".lnk") and not row.get("resolved_path"):
            target = resolve_lnk_target(lnk)
            if target:
                row["resolved_path"] = os.path.normpath(target)
                row["shortcut_path"] = lnk
                if not row.get("path"):
                    row["path"] = row["resolved_path"]
        path = _norm_win_path(str(row.get("resolved_path") or row.get("path") or ""))
        if not _is_abs_win(path):
            path = ""
        if not path:
            m = _PATH_IN_CMD.search(" " + cmd)
            if m:
                path = _norm_win_path(m.group(1))
        if not _is_abs_win(path):
            bare = _first_bare_exe(cmd) or _first_bare_exe(str(row.get("path") or ""))
            if bare:
                bl = bare.lower()
                path = idx.get(bl) or _KNOWN_SYSTEM_EXE.get(bl) or ""
                if path:
                    path = _norm_win_path(path)
        if _is_abs_win(path):
            row["path"] = path
            row["resolved_path"] = path
            # 签名失败 / 缺哈希时从进程抄一份
            st = str(row.get("sig_status") or "").strip().lower()
            need = (
                not st or st in ("error", "unknown", "missing", "unchecked")
                or st.startswith("error_")
                or not (row.get("md5") or row.get("sha256") or row.get("signer"))
            )
            if need:
                meta = _copy_meta_from_process(report, path)
                for k, v in meta.items():
                    if v not in (None, "") and not row.get(k):
                        row[k] = v
                    elif k in ("signed", "sig_status", "sig_type", "signer") and meta.get(k) not in (None, ""):
                        # 覆盖失败态
                        if need:
                            row[k] = meta[k]
        out.append(row)
    report["startup_items"] = out
    return report


def redact_environment(env: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(env, dict):
        return {}
    out = {}
    for k, v in env.items():
        if SENSITIVE_ENV.search(str(k)):
            out[k] = "***REDACTED***"
        else:
            out[k] = v
    return out


def slim_report(report: Dict[str, Any]) -> Dict[str, Any]:
    r = normalize_report(report)
    # 内存 / $MFT 取证已移出平台：旧采集器上传的这两块直接丢弃
    r.pop("memory_artifacts", None)
    r.pop("mft_artifacts", None)
    # USN
    usn = r.get("usn_journal") or ""
    if isinstance(usn, str) and len(usn) > USN_MAX:
        r["usn_journal"] = usn[:USN_MAX] + f"\n...[服务端截断, 原长度 {len(usn)}]"
    # env
    if r.get("environment"):
        r["environment"] = redact_environment(r["environment"])
    # 浏览器 SQL：全量保留（不再截断行）
    ba = r.get("browser_artifacts")
    if isinstance(ba, list):
        r["browser_artifacts"] = [a for a in ba if isinstance(a, dict)]
    # 兼容旧 prefetch: string[] -> {name,exe}
    pf = r.get("prefetch_files") or []
    if pf and isinstance(pf[0], str):
        r["prefetch_files"] = [
            {"name": x, "exe": (x.split("-")[0] + ".exe") if "-" in x else x, "path": ""}
            for x in pf
        ]
    elif isinstance(pf, list):
        norm_pf = []
        for x in pf:
            if not isinstance(x, dict):
                continue
            item = dict(x)
            orig = str(item.get("original_path") or "").strip()
            pth = str(item.get("path") or "").strip()
            pfpath = str(item.get("prefetch_path") or "").strip()
            low = pth.lower()
            if "\\prefetch\\" in low.replace("/", "\\") and orig:
                item["path"] = orig
            elif not orig and pth and "\\prefetch\\" not in low.replace("/", "\\"):
                item["original_path"] = pth
            if not pfpath and "\\prefetch\\" in low.replace("/", "\\"):
                item["prefetch_path"] = pth
            norm_pf.append(item)
        r["prefetch_files"] = norm_pf
    # 兼容旧 wmi 字符串
    wmi = r.get("wmi_subscriptions")
    if isinstance(wmi, str):
        status = "empty"
        if wmi.strip() and "No Instance" not in wmi and len(wmi.strip()) > 40:
            status = "degraded"
        elif not wmi.strip() or wmi.strip().startswith("---"):
            status = "empty"
        r["wmi_subscriptions"] = {
            "status": status, "filters": [], "consumers": [], "bindings": [], "raw": wmi[:2000],
        }
    # 计划任务字段自愈：若 task_name 不像路径而 next_run 像，则交换
    fixed = []
    for t in r.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        name = t.get("task_name") or ""
        nxt = t.get("next_run") or ""
        if name and "\\" not in name and nxt.startswith("\\"):
            t = dict(t)
            t["task_name"], t["next_run"] = nxt, name
        fixed.append(t)
    r["scheduled_tasks"] = fixed
    resolve_scheduled_task_paths(r)
    resolve_startup_item_paths(r)
    for key in ("services", "startup_items", "processes"):
        items = r.get(key)
        if not isinstance(items, list):
            continue
        r[key] = [
            normalize_item_sig_fields(dict(x)) if isinstance(x, dict) else x
            for x in items
        ]
    try:
        from .net_process import enrich_report_connections
        enrich_report_connections(r)
    except Exception:
        pass
    r["collection_quality"] = assess_quality(r)
    try:
        from .os_detect import apply_os_family
        apply_os_family(r)
    except Exception:
        r.setdefault("os_family", "windows")
    return r


def assess_quality(r: Dict[str, Any]) -> Dict[str, str]:
    q = dict(r.get("collection_quality") or {})

    def mark(key, n, rich):
        if key in q and q[key] in ("ok", "empty", "degraded"):
            return
        if n == 0:
            q[key] = "empty"
        elif rich:
            q[key] = "ok"
        else:
            q[key] = "degraded"

    procs = r.get("processes") or []
    mark("processes", len(procs), any(p.get("path") for p in procs))
    svcs = r.get("services") or []
    mark("services", len(svcs), any(s.get("path") for s in svcs))
    tasks = r.get("scheduled_tasks") or []
    mark("scheduled_tasks", len(tasks), any(t.get("command") for t in tasks) or any("\\" in (t.get("task_name") or "") for t in tasks))
    wmi = r.get("wmi_subscriptions") or {}
    if isinstance(wmi, dict):
        q["wmi"] = wmi.get("status") or "empty"
    pf = r.get("prefetch_files") or []
    mark("prefetch", len(pf), True)
    ps = r.get("ps_history") or []
    mark("ps_history", len(ps), any(len(str(x)) > 20 for x in ps))
    reg = r.get("user_registry") or {}
    mark("user_registry", sum(len(v or []) for v in reg.values() if isinstance(v, list)), bool(reg.get("IETypedURLs")))
    ba = r.get("browser_artifacts") or []
    mark("browser_artifacts", len(ba), any(
        isinstance(x, dict) and x.get("status") == "ok" and (x.get("row_count") or 0) > 0 for x in ba
    ))
    users = r.get("users") or []
    mark("users", len(users), any(isinstance(u, dict) and (u.get("sid") or u.get("name")) for u in users))
    files = r.get("file_scans") or []
    mark("file_scans", len(files), len(files) > 0)
    evs = r.get("event_logs") or []
    mark("event_logs", len(evs) if isinstance(evs, list) else 0, isinstance(evs, list) and len(evs) > 0)
    q.pop("memory", None)
    q.pop("mft", None)
    oa = r.get("office_artifacts") or {}
    if isinstance(oa, dict):
        on = (
            len(oa.get("addins") or [])
            + len(oa.get("trust_records") or [])
            + len(oa.get("recent_files") or [])
            + len(oa.get("special_perf") or [])
        )
        mark("office", on, on > 0)
    return q
