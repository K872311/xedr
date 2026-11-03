"""远控软件分析：从报告的服务/进程/文件/事件日志汇总实例，并解析会话记录。

解析规则放在 rules/remote_tools.json，格式变更后改 JSON 即可对已有报告重跑。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import paths as P

_lock = threading.RLock()
_CACHE: Optional[Dict[str, Any]] = None
_CACHE_MTIME = 0.0

_PATH_SEP = re.compile(r"[/\\]+")


def _catalog_path() -> Path:
    return Path(__file__).resolve().parents[1] / "rules" / "remote_tools.json"


def load_catalog(force: bool = False) -> Dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    path = _catalog_path()
    with _lock:
        mtime = 0.0
        try:
            mtime = path.stat().st_mtime
        except OSError:
            pass
        if not force and _CACHE is not None and mtime == _CACHE_MTIME:
            return _CACHE
        doc: Dict[str, Any] = {"tools": []}
        if path.is_file():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                doc = {"tools": []}
        if not isinstance(doc, dict):
            doc = {"tools": []}
        for t in doc.get("tools") or []:
            if isinstance(t, dict):
                _normalize_tool(t)
        _CACHE = doc
        _CACHE_MTIME = mtime
        return _CACHE


_PRIORITY_RANK = {"high": 0, "medium_high": 1, "medium": 2}
_PRIORITY_LABEL = {"high": "高", "medium_high": "中高", "medium": "中"}


def _normalize_tool(tool: Dict[str, Any]) -> None:
    """路径标记统一为小写单反斜杠；进程/服务名小写。"""
    markers = []
    for m in tool.get("path_markers") or []:
        s = re.sub(r"[\\/]+", r"\\", str(m or "").lower())
        if s.strip("\\"):
            markers.append(s)
    tool["path_markers"] = markers
    for key in ("exe_names", "service_names", "signer_markers", "product_markers", "file_name_patterns"):
        tool[key] = [str(x or "").strip().lower() for x in (tool.get(key) or []) if str(x or "").strip()]
    pri = str(tool.get("priority") or "medium").strip().lower()
    tool["priority"] = pri if pri in _PRIORITY_RANK else "medium"


def _has_token(low: str, needle: str) -> bool:
    """整词匹配：避免 client32.exe / level.exe 之类短名被子串误命中。"""
    if not needle:
        return False
    return re.search(r"(?<![a-z0-9_.-])" + re.escape(needle) + r"(?![a-z0-9_-])", low) is not None


def _norm(p: Any) -> str:
    s = str(p or "").strip().strip('"').replace("/", "\\")
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s.rstrip("\\")


def _norm_l(p: Any) -> str:
    return _norm(p).lower()


def _parent(p: str) -> str:
    s = _norm(p)
    return s.rsplit("\\", 1)[0] if "\\" in s else s


def _basename(p: str) -> str:
    return _norm(p).rsplit("\\", 1)[-1]


def _parse_dt(s: Any) -> Optional[datetime]:
    t = str(s or "").strip().replace("T", " ").replace(",", " ")
    t = re.sub(r"\s+", " ", t)
    # 去掉时区尾巴
    t = re.sub(r"[Zz]$", "", t)
    t = re.sub(r"[+-]\d{2}:?\d{2}$", "", t).strip()
    for fmt, n in (
        ("%Y-%m-%d %H:%M:%S.%f", 26),
        ("%Y-%m-%d %H:%M:%S", 19),
        ("%Y-%m-%d %H:%M", 16),
        ("%Y/%m/%d %H:%M:%S", 19),
        ("%Y-%m-%d", 10),
    ):
        try:
            return datetime.strptime(t[:n], fmt)
        except ValueError:
            continue
    return None


def _fmt_dt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""


def _match_tool(blob: str, tool: Dict[str, Any]) -> bool:
    low = re.sub(r"[\\/]+", r"\\", blob.lower())
    for m in tool.get("path_markers") or []:
        if m in low:
            return True
    for m in tool.get("exe_names") or []:
        if _has_token(low, m):
            return True
    for m in tool.get("service_names") or []:
        if _has_token(low, m):
            return True
    for m in tool.get("signer_markers") or []:
        if m in low:
            return True
    for m in tool.get("product_markers") or []:
        if m in low:
            return True
    return False


def _tool_by_id(catalog: Dict[str, Any], tid: str) -> Optional[Dict[str, Any]]:
    for t in catalog.get("tools") or []:
        if str(t.get("id") or "") == tid:
            return t
    return None


def _identify(blob: str, catalog: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for t in catalog.get("tools") or []:
        if _match_tool(blob, t):
            return t
    return None


def _install_root_from_path(path: str, tool: Dict[str, Any]) -> str:
    """从任意远控相关路径推断安装根目录。"""
    p = _norm(path)
    low = p.lower()
    markers = [m.lower().replace("/", "\\").strip("\\") for m in (tool.get("path_markers") or [])]
    markers = [m for m in markers if m]
    # 长标记优先：Oray\AweSun 优于 Oray，避免根目录停在厂商目录
    markers.sort(key=lambda m: (-len(m.split("\\")), -len(m)))
    for m in markers:
        # 找到 ...\Oray\AweSun\... → 取到 AweSun；...\ToDesk\... → ToDesk
        parts = low.split("\\")
        marker_parts = m.split("\\")
        for i in range(len(parts)):
            if parts[i : i + len(marker_parts)] == marker_parts:
                end = i + len(marker_parts)
                return "\\".join(_norm(path).split("\\")[:end])
    # 前缀型目录（如「ScreenConnect Client (随机标识)」）：截到标记所在目录末尾
    for m in markers:
        idx = low.find("\\" + m)
        if idx < 0:
            continue
        end = low.find("\\", idx + 1 + len(m))
        if end < 0:
            return p if not low.endswith(".exe") else _parent(p)
        return p[:end]
    # 回退：exe 的父目录
    if p.lower().endswith(".exe"):
        return _parent(p)
    return _parent(p)


# ─── 数据装载 ───────────────────────────────────────────────────────────────

def _load_blob_list(rid: str, name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pack = P.report_dir(rid) / "pack"
    # persistence / processes 在不同文件
    candidates = {
        "services": ("persistence.json", "services"),
        "startup_items": ("persistence.json", "startup_items"),
        "scheduled_tasks": ("persistence.json", "scheduled_tasks"),
        "installed_programs": ("persistence.json", "installed_programs"),
        "drivers": ("persistence.json", "drivers"),
        "processes": ("processes.json", "processes"),
        "established_connections": ("network.json", "established_connections"),
    }
    if name in candidates:
        fn, key = candidates[name]
        fp = pack / fn
        if fp.is_file():
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
                raw = data.get(key) if isinstance(data, dict) else None
                if isinstance(raw, list):
                    out = [x for x in raw if isinstance(x, dict)]
            except Exception:
                out = []
    if out:
        return out
    try:
        from .db_store import _connect, _load_one_blob
        dbp = P.resolve_analysis_db(rid)
        if dbp and Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                raw = _load_one_blob(conn, name) or []
                if isinstance(raw, list):
                    out = [x for x in raw if isinstance(x, dict)]
            finally:
                conn.close()
    except Exception:
        pass
    return out


def _load_files_rows(rid: str, like_patterns: List[str]) -> List[Dict[str, Any]]:
    dbp = P.resolve_analysis_db(rid)
    if not dbp or not Path(dbp).is_file():
        return []
    from .db_store import _connect, _init_schema
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        out: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for pat in like_patterns:
            # parent_path_norm / full_path LIKE
            rows = conn.execute(
                "SELECT full_path,name,path,ext,size,mtime,company,signer,sig_status,signed,content "
                "FROM files WHERE lower(replace(full_path,'/','\\')) LIKE ? LIMIT 2000",
                (pat.lower().replace("/", "\\"),),
            ).fetchall()
            for r in rows:
                fp = r["full_path"] or ""
                if fp in seen:
                    continue
                seen.add(fp)
                out.append({k: r[k] for k in r.keys()})
        return out
    except Exception:
        return []
    finally:
        conn.close()


def _name_like_any(name: str, patterns: List[str]) -> bool:
    """SQL LIKE 风格（% 通配）的文件名匹配。"""
    for pat in patterns:
        rx = "^" + ".*".join(re.escape(x) for x in pat.split("%")) + "$"
        if re.match(rx, name):
            return True
    return False


def _load_remote_files(rid: str, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """一次扫描 files 表：路径含远控标记，或文件名命中远控程序名，归到对应工具。"""
    dbp = P.resolve_analysis_db(rid)
    if not dbp or not Path(dbp).is_file():
        return []
    path_likes: List[str] = []
    names: Set[str] = set()
    name_likes: List[str] = []
    for t in tools:
        path_likes.extend(f"%{m}%" for m in t.get("path_markers") or [])
        names.update(t.get("exe_names") or [])
        name_likes.extend(t.get("file_name_patterns") or [])
    # SQLite LIKE 对 ASCII 不区分大小写，无需 lower()；逐条 lower() 会让大表慢一个数量级
    clauses = ["full_path LIKE ?"] * len(path_likes)
    params: List[Any] = list(path_likes)
    if names:
        clauses.append("lower(name) IN (" + ",".join("?" * len(names)) + ")")
        params.extend(sorted(names))
    for pat in name_likes:
        clauses.append("lower(name) LIKE ?")
        params.append(pat)
    if not clauses:
        return []
    from .db_store import _connect, _init_schema
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        rows = conn.execute(
            "SELECT full_path,name,path,ext,size,mtime,company,signer,sig_status,signed,content "
            "FROM files WHERE " + " OR ".join(clauses) + " LIMIT 8000",
            params,
        ).fetchall()
    except Exception:
        return []
    finally:
        conn.close()

    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for r in rows:
        fp = r["full_path"] or ""
        if not fp or fp in seen:
            continue
        seen.add(fp)
        low = re.sub(r"[\\/]+", r"\\", fp.lower())
        name = str(r["name"] or "").lower()
        # 标记只比对所在目录，避免「SunloginClient_123.log」这类同名文件被当成安装痕迹
        parent = low.rsplit("\\", 1)[0] + "\\" if "\\" in low else ""
        hit = None
        # 路径标记优先（长标记先比），其次文件名
        best = -1
        for t in tools:
            for m in t.get("path_markers") or []:
                if m in parent and len(m) > best:
                    hit, best = t, len(m)
        if hit is None:
            for t in tools:
                if name in (t.get("exe_names") or []) or _name_like_any(name, t.get("file_name_patterns") or []):
                    hit = t
                    break
        if hit is None:
            continue
        row = {k: r[k] for k in r.keys()}
        row["_tool"] = hit
        out.append(row)
    return out


def _load_service_install_events(rid: str) -> List[Dict[str, Any]]:
    dbp = P.resolve_analysis_db(rid)
    if not dbp or not Path(dbp).is_file():
        return []
    from .db_store import _connect, _init_schema
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        rows = conn.execute(
            "SELECT time,channel,event_id,provider,message FROM event_logs "
            "WHERE event_id = 7045 ORDER BY time LIMIT 5000"
        ).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _load_event_hits(rid: str, needles: List[str]) -> List[Dict[str, Any]]:
    dbp = P.resolve_analysis_db(rid)
    if not dbp or not Path(dbp).is_file():
        return []
    from .db_store import _connect, _init_schema
    conn = _connect(Path(dbp))
    try:
        _init_schema(conn)
        out: List[Dict[str, Any]] = []
        for n in needles:
            rows = conn.execute(
                "SELECT time,channel,event_id,provider,message FROM event_logs "
                "WHERE lower(message) LIKE ? OR lower(provider) LIKE ? "
                "ORDER BY time LIMIT 200",
                (f"%{n.lower()}%", f"%{n.lower()}%"),
            ).fetchall()
            for r in rows:
                out.append({k: r[k] for k in r.keys()})
        return out
    except Exception:
        return []
    finally:
        conn.close()


# ─── 实例汇总 ───────────────────────────────────────────────────────────────

def _new_instance(tool: Dict[str, Any], root: str) -> Dict[str, Any]:
    pri = str(tool.get("priority") or "medium")
    return {
        "tool_id": tool.get("id"),
        "name": tool.get("name"),
        "vendor": tool.get("vendor") or "",
        "priority": pri,
        "priority_label": _PRIORITY_LABEL.get(pri, "中"),
        "binaries": [],
        "install_path": root,
        "version": "",
        "client_id": "",
        "install_time": "",
        "first_seen": "",
        "last_seen": "",
        "unattended": False,
        "portable": False,
        "running": False,
        "services": [],
        "processes": [],
        "sources": [],
        "config_files": [],
        "log_files": [],
        "drivers": [],
        "notes": list(tool.get("notes") or []),
    }


def _add_source(inst: Dict[str, Any], src: str) -> None:
    if src and src not in inst["sources"]:
        inst["sources"].append(src)


def _touch_time(inst: Dict[str, Any], when: Any) -> None:
    dt = _parse_dt(when) if not isinstance(when, datetime) else when
    if not dt:
        return
    s = _fmt_dt(dt)
    if not inst["first_seen"] or s < inst["first_seen"]:
        inst["first_seen"] = s
    if not inst["last_seen"] or s > inst["last_seen"]:
        inst["last_seen"] = s


def _get_or_create(
    buckets: Dict[Tuple[str, str], Dict[str, Any]],
    tool: Dict[str, Any],
    path_hint: str,
) -> Dict[str, Any]:
    root = _install_root_from_path(path_hint, tool) or path_hint
    key = (str(tool.get("id")), _norm_l(root))
    if key not in buckets:
        buckets[key] = _new_instance(tool, root)
    return buckets[key]


def build_instances(rid: str) -> List[Dict[str, Any]]:
    catalog = load_catalog()
    buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for svc in _load_blob_list(rid, "services"):
        blob = " ".join(str(svc.get(k) or "") for k in (
            "name", "display_name", "path", "resolved_path", "company", "signer", "product",
        ))
        tool = _identify(blob, catalog)
        if not tool:
            continue
        path = _norm(svc.get("resolved_path") or svc.get("path") or "")
        inst = _get_or_create(buckets, tool, path or str(tool.get("id")))
        _add_source(inst, "服务")
        start = str(svc.get("start_type") or "")
        auto = "auto" in start.lower() or "自动" in start
        inst["services"].append({
            "name": svc.get("name") or "",
            "display_name": svc.get("display_name") or "",
            "path": path,
            "start_type": start,
            "status": svc.get("status") or "",
            "auto": auto,
        })
        if auto or "run" in str(svc.get("status") or "").lower():
            inst["unattended"] = True

    for pr in _load_blob_list(rid, "processes"):
        blob = " ".join(str(pr.get(k) or "") for k in (
            "name", "path", "command_line", "command", "company", "product", "signer",
        ))
        tool = _identify(blob, catalog)
        if not tool:
            continue
        path = _norm(pr.get("path") or "")
        inst = _get_or_create(buckets, tool, path or str(tool.get("id")))
        _add_source(inst, "进程")
        inst["running"] = True
        inst["processes"].append({
            "pid": pr.get("pid") or pr.get("PID") or 0,
            "name": pr.get("name") or "",
            "path": path,
            "command_line": str(pr.get("command_line") or pr.get("command") or "")[:300],
        })
        ver = str(pr.get("file_version") or "")
        if ver and not inst["version"]:
            inst["version"] = ver

    for st in _load_blob_list(rid, "startup_items"):
        blob = " ".join(str(st.get(k) or "") for k in ("name", "command", "path", "resolved_path"))
        tool = _identify(blob, catalog)
        if not tool:
            continue
        path = _norm(st.get("resolved_path") or st.get("path") or "")
        inst = _get_or_create(buckets, tool, path or str(tool.get("id")))
        _add_source(inst, "启动项")

    for prog in _load_blob_list(rid, "installed_programs"):
        blob = " ".join(str(prog.get(k) or "") for k in ("name", "vendor", "version"))
        tool = _identify(blob, catalog)
        if not tool:
            continue
        # 卸载信息通常没有安装路径，挂到已有实例或占位
        existing = [b for k, b in buckets.items() if k[0] == tool.get("id")]
        inst = existing[0] if existing else _get_or_create(buckets, tool, str(tool.get("id")))
        _add_source(inst, "已装程序")
        if prog.get("version") and not inst["version"]:
            inst["version"] = str(prog.get("version"))
        if prog.get("install_date"):
            # YYYYMMDD
            d = str(prog.get("install_date"))
            if re.fullmatch(r"\d{8}", d):
                inst["install_time"] = f"{d[:4]}-{d[4:6]}-{d[6:8]}"
            else:
                inst["install_time"] = d

    for drv in _load_blob_list(rid, "drivers"):
        blob = " ".join(str(drv.get(k) or "") for k in ("name", "display_name", "path", "company"))
        tool = _identify(blob, catalog)
        if not tool:
            continue
        existing = [b for k, b in buckets.items() if k[0] == tool.get("id")]
        if not existing:
            continue
        existing[0]["drivers"].append({
            "name": drv.get("name") or "",
            "path": drv.get("path") or "",
        })
        _add_source(existing[0], "驱动")

    # 事件日志：7045 新服务 = 精确安装时间（只取一次 7045，再逐条识别）
    for ev in _load_service_install_events(rid):
        msg = str(ev.get("message") or "")
        tool2 = _identify(msg, catalog)
        if not tool2:
            continue
        # ImagePath
        m = re.search(r'(?i)ImagePath[=:]\s*"?([^"\r\n]+)', msg)
        path = _norm(m.group(1)) if m else str(tool2.get("id"))
        inst = _get_or_create(buckets, tool2, path)
        _add_source(inst, "事件7045")
        t = _fmt_dt(_parse_dt(ev.get("time")))
        if t:
            if not inst["install_time"] or t < inst["install_time"]:
                inst["install_time"] = t
            _touch_time(inst, t)

    # 文件：配置 / 日志 / 程序本体（一次扫描 files 表，按路径标记或文件名归到工具）
    tools_list = [t for t in (catalog.get("tools") or []) if isinstance(t, dict)]
    files_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for f in _load_remote_files(rid, tools_list):
        files_by_tool.setdefault(str(f["_tool"].get("id")), []).append(f)
    for tool in tools_list:
        for f in files_by_tool.get(str(tool.get("id")), []):
            fp = _norm(f.get("full_path") or "")
            if not fp:
                continue
            inst = _get_or_create(buckets, tool, fp)
            _touch_time(inst, f.get("mtime"))
            name = str(f.get("name") or "").lower()
            ext = str(f.get("ext") or "").lower()
            content = str(f.get("content") or "")
            low = fp.lower()
            if ext in (".exe", ".msi") and (
                name in (tool.get("exe_names") or [])
                or _name_like_any(name, tool.get("file_name_patterns") or [])
            ):
                inst["binaries"].append({
                    "path": fp,
                    "name": f.get("name") or "",
                    "size": int(f.get("size") or 0),
                    "mtime": f.get("mtime") or "",
                    "signer": f.get("signer") or f.get("company") or "",
                    "sig_status": f.get("sig_status") or "",
                })
                _add_source(inst, "程序文件")
            if ext in (".ini", ".conf", ".cfg", ".toml") or name in ("config.ini", "system.conf", "service.conf", "sys_config.ini"):
                inst["config_files"].append({
                    "path": fp, "mtime": f.get("mtime") or "", "has_content": bool(content),
                })
                # clientId：向日葵/ToDesk ini、AnyDesk system.conf、RustDesk toml
                if not inst["client_id"]:
                    for rx in (
                        r"(?im)^\s*clientId\s*=\s*(\S+)",
                        r"(?im)^\s*fastcode\s*=\s*(\S+)",  # 向日葵识别码
                        r"(?im)^\s*ad\.anynet\.id\s*=\s*(\S+)",
                        r"(?im)^\s*id\s*=\s*['\"]?(\d+)['\"]?",
                    ):
                        m = re.search(rx, content)
                        if m:
                            val = m.group(1).strip().strip("'\"")
                            if val and val.lower() not in ("0", "null", "none"):
                                inst["client_id"] = val
                                break
                m = re.search(r"(?im)^\s*Version\s*=\s*(\S+)", content)
                if m and not inst["version"]:
                    inst["version"] = m.group(1).strip()
                # RustDesk / AnyDesk 自定义中继
                for key, label in (
                    ("rendezvous_server", "自定义 ID 服务器"),
                    ("relay_server", "自定义中继"),
                    ("api_server", "自定义 API"),
                    ("ad.anynet.relay", "AnyDesk 中继"),
                ):
                    m = re.search(rf"(?im)^\s*{re.escape(key)}\s*=\s*['\"]?([^'\"\r\n#]+)", content)
                    if m:
                        val = m.group(1).strip()
                        note = f"{label}: {val}"
                        if val and note not in inst["notes"]:
                            inst["notes"].append(note)
                if "pass" in content.lower() or "pwd" in content.lower() or "******" in content:
                    if "已设置访问密码/凭据" not in inst["notes"]:
                        inst["notes"].append("已设置访问密码/凭据（采集端已打码）")
            if ext in (".log", ".txt", ".xlog", ".mmap3") or "\\log\\" in low or "\\logs\\" in low:
                inst["log_files"].append({
                    "path": fp,
                    "name": f.get("name") or "",
                    "size": int(f.get("size") or 0),
                    "mtime": f.get("mtime") or "",
                    "has_content": bool(content),
                    "encrypted": ext == ".xlog",
                })
            # Sentry session did ≈ ToDesk clientId
            if name == "session.json" and content:
                try:
                    js = json.loads(content)
                    did = str(js.get("did") or "")
                    if did and not inst["client_id"]:
                        inst["client_id"] = did
                    rel = str((js.get("attrs") or {}).get("release") or "")
                    if rel and not inst["version"]:
                        inst["version"] = rel
                except Exception:
                    pass

    # 便携版判定 + 字段去重
    user_dirs = ("\\users\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\appdata\\")
    for inst in buckets.values():
        low = _norm_l(inst["install_path"])
        if any(u in low for u in user_dirs) and "已装程序" not in inst["sources"]:
            inst["portable"] = True
            if "便携版/非标准安装路径" not in inst["notes"]:
                inst["notes"].append("便携版/非标准安装路径")
        for k in ("services", "processes", "config_files", "log_files", "drivers", "binaries"):
            seen: Set[str] = set()
            uniq = []
            for row in inst[k]:
                key = json.dumps(row, ensure_ascii=False, sort_keys=True)
                if key in seen:
                    continue
                seen.add(key)
                uniq.append(row)
            inst[k] = uniq

    return _consolidate_instances(list(buckets.values()))


def _inst_score(inst: Dict[str, Any]) -> int:
    """主安装目录打分：服务/进程/配置优先于零星相关路径。"""
    score = 0
    low = _norm_l(inst.get("install_path"))
    if inst.get("services"):
        score += 50
    if inst.get("processes"):
        score += 30
    if "已装程序" in (inst.get("sources") or []):
        score += 20
    if inst.get("config_files"):
        score += 15
    if inst.get("client_id"):
        score += 10
    if inst.get("unattended"):
        score += 10
    if "\\program files" in low:
        score += 25
    if any(x in low for x in ("\\windows\\", "\\system32", "\\syswow64", "\\drivers")):
        score -= 40
    if any(x in low for x in ("\\desktop", "\\downloads", "\\public\\")) and not inst.get("services"):
        score -= 20
    if inst.get("binaries"):
        score += 15
    # 空/占位路径（无路径时用 tool_id 占位）
    if not low or low == str(inst.get("tool_id") or "").lower():
        score -= 30
    return score


def _merge_inst_into(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k in ("version", "client_id", "install_time", "first_seen", "last_seen"):
        if src.get(k) and not dst.get(k):
            dst[k] = src[k]
    if src.get("first_seen") and (not dst.get("first_seen") or src["first_seen"] < dst["first_seen"]):
        dst["first_seen"] = src["first_seen"]
    if src.get("last_seen") and (not dst.get("last_seen") or src["last_seen"] > dst["last_seen"]):
        dst["last_seen"] = src["last_seen"]
    if src.get("unattended"):
        dst["unattended"] = True
    if src.get("running"):
        dst["running"] = True
    if src.get("portable") and not dst.get("services"):
        dst["portable"] = True
    for src_key, dst_key in (
        ("services", "services"),
        ("processes", "processes"),
        ("config_files", "config_files"),
        ("log_files", "log_files"),
        ("drivers", "drivers"),
        ("binaries", "binaries"),
        ("sources", "sources"),
        ("notes", "notes"),
    ):
        for row in src.get(src_key) or []:
            if row not in dst[dst_key]:
                dst[dst_key].append(row)
    rel = dst.setdefault("related_paths", [])
    sp = _norm(src.get("install_path") or "")
    if sp and _norm_l(sp) != _norm_l(dst.get("install_path")) and sp not in rel:
        rel.append(sp)


def _consolidate_instances(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """同一工具多路径合并：Program Files 主装为主，其余进 related_paths。"""
    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for inst in raw:
        tid = str(inst.get("tool_id") or "")
        if not tid:
            continue
        # 丢弃纯噪声：无服务/进程/配置/日志/已装，且路径在系统目录或桌面快捷
        low = _norm_l(inst.get("install_path"))
        has_signal = bool(
            inst.get("services") or inst.get("processes") or inst.get("config_files")
            or inst.get("log_files") or inst.get("client_id") or inst.get("binaries")
            or "已装程序" in (inst.get("sources") or [])
            or "事件7045" in (inst.get("sources") or [])
        )
        if not has_signal:
            continue
        if (
            any(x in low for x in ("\\windows\\system32", "\\windows\\syswow64", "\\systemroot"))
            and not inst.get("services") and not inst.get("config_files")
        ):
            continue
        by_tool.setdefault(tid, []).append(inst)

    out: List[Dict[str, Any]] = []
    for tid, group in by_tool.items():
        group.sort(key=_inst_score, reverse=True)
        if not group:
            continue
        primary = group[0]
        primary.setdefault("related_paths", [])
        # 第一名仍很弱：有进程/程序本体的各自独立（便携版），零星痕迹并成一条
        if _inst_score(primary) < 20:
            strong = [g for g in group if g.get("processes") or g.get("binaries") or g.get("services")]
            weak = [g for g in group if g not in strong]
            out.extend(strong)
            if weak:
                if strong:
                    for w in weak:
                        _merge_inst_into(strong[0], w)
                else:
                    head = weak[0]
                    head.setdefault("related_paths", [])
                    for w in weak[1:]:
                        _merge_inst_into(head, w)
                    if "仅零星文件痕迹（无服务/进程/程序本体），可能已卸载或为同名残留" not in head["notes"]:
                        head["notes"].append("仅零星文件痕迹（无服务/进程/程序本体），可能已卸载或为同名残留")
                    out.append(head)
            continue
        for other in group[1:]:
            # 独立便携安装：用户目录且有自己的配置/进程
            o_low = _norm_l(other.get("install_path"))
            if (
                other.get("portable")
                and (other.get("config_files") or other.get("processes"))
                and "\\program files" not in o_low
                and _inst_score(other) >= 20
            ):
                out.append(other)
                continue
            _merge_inst_into(primary, other)
        out.append(primary)

    out.sort(key=lambda x: (
        _PRIORITY_RANK.get(str(x.get("priority") or "medium"), 2),
        0 if x.get("unattended") else 1,
        x.get("name") or "",
        x.get("install_path") or "",
    ))
    return out


# ─── 会话解析 ───────────────────────────────────────────────────────────────

def _read_file_content(rid: str, full_path: str) -> str:
    try:
        from .db_store import load_file_content
        item = load_file_content(rid, full_path)
        return str((item or {}).get("content") or "")
    except Exception:
        return ""


def _list_files_by_glob(rid: str, patterns: List[str]) -> List[Dict[str, Any]]:
    """用简单通配（* 与 **）在 files 表里找路径。"""
    likes = []
    for pat in patterns or []:
        # **/Oray/AweSun/log/history.log → %\oray\awesun\log\history.log
        p = str(pat or "").replace("/", "\\")
        while "**\\" in p:
            p = p.replace("**\\", "%\\")
        p = p.replace("**", "%")
        if p.startswith("*\\"):
            p = "%" + p[1:]
        elif p.startswith("*"):
            p = "%" + p[1:]
        p = p.replace("*", "%")
        if not p.startswith("%"):
            p = "%" + p
        likes.append(p.lower())
    return _load_files_rows(rid, likes) if likes else []


def _parse_sunlogin_sessions(rid: str, tool: Dict[str, Any], inst: Dict[str, Any]) -> List[Dict[str, Any]]:
    parsers = (tool.get("parsers") or {})
    hist_cfg = parsers.get("history") or {}
    line_rx = re.compile(hist_cfg.get("line_regex") or r"^$", re.I)
    sessions: List[Dict[str, Any]] = []

    # 1) history.log：成对的 开始/结束
    open_map: Dict[str, Dict[str, Any]] = {}
    for f in _list_files_by_glob(rid, tool.get("history_globs") or []):
        content = str(f.get("content") or "") or _read_file_content(rid, f.get("full_path") or "")
        for ln in content.splitlines():
            m = line_rx.search(ln.strip())
            if not m:
                continue
            g = m.groupdict()
            peer = g.get("peer") or ""
            action = g.get("action") or ""
            when = _parse_dt(g.get("time"))
            kind = g.get("kind") or "桌面控制"
            method = g.get("method") or ""
            key = f"{peer}|{kind}"
            if action == (hist_cfg.get("start_action") or "开始"):
                open_map[key] = {
                    "tool_id": "sunlogin",
                    "tool_name": tool.get("name"),
                    "direction": "inbound",
                    "peer_id": peer,
                    "peer_ip": "",
                    "method": method,
                    "kind": kind,
                    "start": _fmt_dt(when),
                    "end": "",
                    "account": "",
                    "relay": "",
                    "evidence": [f.get("full_path") or ""],
                    "confidence": "high",
                    "summary": f"{peer} {action}{kind}" + (f"（{method}）" if method else ""),
                }
            elif action == (hist_cfg.get("end_action") or "结束") and key in open_map:
                s = open_map.pop(key)
                s["end"] = _fmt_dt(when)
                sessions.append(s)
            elif action == (hist_cfg.get("end_action") or "结束"):
                sessions.append({
                    "tool_id": "sunlogin",
                    "tool_name": tool.get("name"),
                    "direction": "inbound",
                    "peer_id": peer,
                    "peer_ip": "",
                    "method": method,
                    "kind": kind,
                    "start": "",
                    "end": _fmt_dt(when),
                    "account": "",
                    "relay": "",
                    "evidence": [f.get("full_path") or ""],
                    "confidence": "medium",
                    "summary": f"{peer} {action}{kind}" + (f"（{method}）" if method else ""),
                })
    for s in open_map.values():
        sessions.append(s)

    # 2) 服务日志：补充 IP / 中继 / 账号
    svc_cfg = parsers.get("service_session") or {}
    start_rx = re.compile(svc_cfg.get("start_regex") or r"^$", re.I)
    p2p_rx = re.compile(svc_cfg.get("p2p_regex") or r"^$", re.I)
    peer_rx = re.compile(svc_cfg.get("peer_regex") or r"^$", re.I)
    account_rx = re.compile(svc_cfg.get("account_regex") or r"^$", re.I)
    stop_rx = re.compile(svc_cfg.get("stop_regex") or r"^$", re.I)

    for f in _list_files_by_glob(rid, tool.get("session_log_globs") or []):
        content = str(f.get("content") or "") or _read_file_content(rid, f.get("full_path") or "")
        if not content:
            continue
        cur: Optional[Dict[str, Any]] = None
        for ln in content.splitlines():
            tm = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", ln)
            when = _parse_dt(tm.group(1)) if tm else None
            if start_rx.search(ln):
                cur = {
                    "tool_id": "sunlogin",
                    "tool_name": tool.get("name"),
                    "direction": "inbound",
                    "peer_id": "",
                    "peer_ip": "",
                    "method": "",
                    "kind": "桌面控制",
                    "start": _fmt_dt(when),
                    "end": "",
                    "account": "",
                    "relay": "",
                    "evidence": [f.get("full_path") or ""],
                    "confidence": "high",
                    "summary": "接受远程控制请求",
                }
            if not cur:
                continue
            m = p2p_rx.search(ln)
            if m:
                cur["relay"] = m.groupdict().get("relay") or cur["relay"]
                pub = m.groupdict().get("public_ip") or ""
                if pub and not cur["peer_ip"]:
                    # public_ip 是本机出口，先记在 note 里；对端 IP 用 peer_regex
                    cur.setdefault("local_public_ip", pub.split(":")[0])
            m = peer_rx.search(ln)
            if m:
                pip = (m.groupdict().get("peer_public") or "").split(":")[0]
                if pip:
                    cur["peer_ip"] = pip
            m = account_rx.search(ln)
            if m:
                cur["account"] = m.groupdict().get("account") or cur["account"]
            if stop_rx.search(ln) and cur.get("start"):
                cur["end"] = _fmt_dt(when)
                # 补全 summary
                bits = ["被控会话"]
                if cur.get("peer_ip"):
                    bits.append(f"对端 {cur['peer_ip']}")
                if cur.get("account"):
                    bits.append(f"账号 {cur['account']}")
                if cur.get("relay"):
                    bits.append(f"中继 {cur['relay']}")
                cur["summary"] = " · ".join(bits)
                sessions.append(cur)
                cur = None
        if cur and cur.get("start"):
            sessions.append(cur)

    # 合并 history 与 service：同一时间窗口的合成一条
    sessions = _merge_sessions(sessions, window_sec=120)
    return sessions


def _merge_sessions(sessions: List[Dict[str, Any]], window_sec: int = 120) -> List[Dict[str, Any]]:
    if not sessions:
        return []
    sessions = sorted(sessions, key=lambda s: s.get("start") or s.get("end") or "")
    out: List[Dict[str, Any]] = []
    for s in sessions:
        st = _parse_dt(s.get("start") or s.get("end"))
        merged = False
        for o in out:
            ot = _parse_dt(o.get("start") or o.get("end"))
            if not st or not ot:
                continue
            if abs((st - ot).total_seconds()) <= window_sec and o.get("tool_id") == s.get("tool_id"):
                # 合并字段
                for k in ("peer_id", "peer_ip", "method", "account", "relay", "kind", "end", "start"):
                    if not o.get(k) and s.get(k):
                        o[k] = s[k]
                for e in s.get("evidence") or []:
                    if e and e not in o["evidence"]:
                        o["evidence"].append(e)
                if s.get("confidence") == "high":
                    o["confidence"] = "high"
                # 重写摘要
                bits = []
                if o.get("peer_id"):
                    bits.append(str(o["peer_id"]))
                bits.append("被控" if o.get("direction") == "inbound" else "主控")
                if o.get("kind"):
                    bits.append(str(o["kind"]))
                if o.get("method"):
                    bits.append(f"（{o['method']}）")
                if o.get("peer_ip"):
                    bits.append(f"对端 {o['peer_ip']}")
                if o.get("account"):
                    bits.append(f"账号 {o['account']}")
                o["summary"] = " ".join(bits)
                merged = True
                break
        if not merged:
            out.append(s)
    return out


def _parse_todesk_sessions(rid: str, tool: Dict[str, Any], inst: Dict[str, Any]) -> List[Dict[str, Any]]:
    """ToDesk xlog 加密：用 session_*.xlog 的 mtime 推断会话结束时间，mmap3 作旁证。"""
    sessions: List[Dict[str, Any]] = []
    xlogs = [
        f for f in (inst.get("log_files") or [])
        if str(f.get("name") or "").lower().startswith("session_")
        and str(f.get("name") or "").lower().endswith(".xlog")
        and "webrtc" not in str(f.get("name") or "").lower()
        and "zrtc" not in str(f.get("name") or "").lower()
    ]
    # 按会话 stem 去重（同一会话可能有 webrtc/zrtc 附属日志）
    seen_stem: Set[str] = set()
    for f in xlogs:
        name = str(f.get("name") or "")
        stem = re.sub(r"_\d{4}_\d{2}_\d{2}\.xlog$", "", name, flags=re.I)
        if stem in seen_stem:
            continue
        seen_stem.add(stem)
        end = _parse_dt(f.get("mtime"))
        # 找同名 mmap3
        mmap_name = stem + ".mmap3"
        mmap_path = ""
        mmap_snippet = ""
        for lf in inst.get("log_files") or []:
            if str(lf.get("name") or "").lower() == mmap_name.lower():
                mmap_path = lf.get("path") or ""
                mmap_snippet = _read_file_content(rid, mmap_path)[:500]
                break
        # 没有独立 session_ 主日志时，用附属 webrtc 的 mtime 也算
        sessions.append({
            "tool_id": "todesk",
            "tool_name": tool.get("name"),
            "direction": "inbound",  # session_* 在服务端 Logs 下，偏向被控
            "peer_id": "",
            "peer_ip": "",
            "method": "",
            "kind": "远程会话",
            "start": "",
            "end": _fmt_dt(end),
            "account": "",
            "relay": "",
            "evidence": [f.get("path") or ""] + ([mmap_path] if mmap_path else []),
            "confidence": "low",
            "summary": (
                f"ToDesk 会话日志（加密），文件时间 {_fmt_dt(end)} ≈ 会话结束；"
                f"本机 ID {inst.get('client_id') or '未知'}"
                + ("；已关联明文缓冲" if mmap_snippet else "（无明文缓冲）")
            ),
        })

    # 若只有 webrtc/zrtc session 日志、没有主 session_ 日志，按时间聚成一场
    if not sessions:
        affiliates = [
            f for f in (inst.get("log_files") or [])
            if str(f.get("name") or "").lower().startswith("session")
            and str(f.get("name") or "").lower().endswith(".xlog")
        ]
        times = [_parse_dt(f.get("mtime")) for f in affiliates]
        times = [t for t in times if t]
        if times:
            end = max(times)
            sessions.append({
                "tool_id": "todesk",
                "tool_name": tool.get("name"),
                "direction": "inbound",
                "peer_id": "",
                "peer_ip": "",
                "method": "",
                "kind": "远程会话",
                "start": "",
                "end": _fmt_dt(end),
                "account": "",
                "relay": "",
                "evidence": [f.get("path") or "" for f in affiliates[:6]],
                "confidence": "low",
                "summary": (
                    f"ToDesk 会话痕迹（xlog 加密），最近文件时间 {_fmt_dt(end)}；"
                    f"本机 ID {inst.get('client_id') or '未知'}"
                ),
            })
    return sessions


def _parse_anydesk_sessions(rid: str, tool: Dict[str, Any], inst: Dict[str, Any]) -> List[Dict[str, Any]]:
    """AnyDesk connection_trace.txt。"""
    parsers = (tool.get("parsers") or {})
    cfg = parsers.get("connection_trace") or {}
    line_rx = re.compile(
        cfg.get("line_regex")
        or r"(?P<time>\d{4}-\d{2}-\d{2},\s*\d{2}:\d{2})\s+(?P<status>\w+)\s+(?P<peer>\S+)\s+(?P<user>.*)",
        re.I,
    )
    sessions: List[Dict[str, Any]] = []
    for f in _list_files_by_glob(rid, tool.get("history_globs") or []):
        content = str(f.get("content") or "") or _read_file_content(rid, f.get("full_path") or "")
        for ln in content.splitlines():
            m = line_rx.search(ln.strip())
            if not m:
                continue
            g = m.groupdict()
            when = _parse_dt(g.get("time"))
            status = (g.get("status") or "").lower()
            peer = (g.get("peer") or "").strip()
            user = (g.get("user") or "").strip()
            direction = "inbound" if "in" in status else ("outbound" if "out" in status else "")
            sessions.append({
                "tool_id": "anydesk",
                "tool_name": tool.get("name"),
                "direction": direction or "inbound",
                "peer_id": peer,
                "peer_ip": "",
                "method": status,
                "kind": "远程会话",
                "start": _fmt_dt(when),
                "end": "",
                "account": user,
                "relay": "",
                "evidence": [f.get("full_path") or f.get("path") or ""],
                "confidence": "medium",
                "summary": (
                    f"AnyDesk {status or '连接'} 对端 {peer or '未知'}"
                    + (f" 用户 {user}" if user else "")
                    + f"；本机 ID {inst.get('client_id') or '未知'}"
                ),
            })
    return sessions


def _parse_teamviewer_sessions(rid: str, tool: Dict[str, Any], inst: Dict[str, Any]) -> List[Dict[str, Any]]:
    """TeamViewer Connections*.txt：PartnerID / 本机用户 / 起止时间。"""
    # 典型行：234567890\thost\tuser\t2024-01-15 14:30:00\t2024-01-15 14:45:00\t900\tRemoteControl\t{guid}
    line_rx = re.compile(
        r"^(?P<peer>\d{6,})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<user>\S+)\s+"
        r"(?P<start>\d{2,4}[-./]\d{1,2}[-./]\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2})?)\s+"
        r"(?P<end>\d{2,4}[-./]\d{1,2}[-./]\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2})?)"
        r"(?:\s+(?P<duration>\d+))?"
        r"(?:\s+(?P<kind>\S+))?",
        re.I,
    )
    sessions: List[Dict[str, Any]] = []
    for f in _list_files_by_glob(rid, tool.get("history_globs") or []):
        content = str(f.get("content") or "") or _read_file_content(rid, f.get("full_path") or "")
        path = f.get("full_path") or f.get("path") or ""
        incoming = "incoming" in str(path).lower()
        for ln in content.splitlines():
            s = ln.strip()
            if not s or s.lower().startswith("partner") or s.lower().startswith("#"):
                continue
            # 兼容制表符
            s = re.sub(r"\t+", " ", s)
            m = line_rx.search(s)
            if not m:
                continue
            g = m.groupdict()
            sessions.append({
                "tool_id": "teamviewer",
                "tool_name": tool.get("name"),
                "direction": "inbound" if incoming else "outbound",
                "peer_id": g.get("peer") or "",
                "peer_ip": "",
                "method": "",
                "kind": g.get("kind") or "RemoteControl",
                "start": _fmt_dt(_parse_dt(g.get("start"))),
                "end": _fmt_dt(_parse_dt(g.get("end"))),
                "account": g.get("user") or "",
                "relay": "",
                "evidence": [path],
                "confidence": "medium",
                "summary": (
                    f"TeamViewer {'呼入' if incoming else '呼出'} "
                    f"对端 {g.get('peer') or '?'}@{g.get('host') or '?'}"
                    + (f" 本机用户 {g.get('user')}" if g.get("user") else "")
                ),
            })
    return sessions


def _parse_rustdesk_sessions(rid: str, tool: Dict[str, Any], inst: Dict[str, Any]) -> List[Dict[str, Any]]:
    """RustDesk 无标准明文会话日志时，用配置侧写一条「自定义服务器」摘要会话。"""
    del rid  # 配置已在实例 notes / config_files
    notes = [n for n in (inst.get("notes") or []) if "自定义" in str(n)]
    if not notes and not inst.get("client_id"):
        return []
    # 仅在有自定义服务器或本机 ID 时给出一条配置侧写，避免空噪声
    if not notes:
        return []
    conf_paths = [c.get("path") for c in (inst.get("config_files") or []) if c.get("path")]
    return [{
        "tool_id": "rustdesk",
        "tool_name": tool.get("name"),
        "direction": "",
        "peer_id": "",
        "peer_ip": "",
        "method": "自定义服务器",
        "kind": "配置痕迹",
        "start": "",
        "end": "",
        "account": "",
        "relay": "; ".join(notes)[:200],
        "evidence": conf_paths[:4],
        "confidence": "low",
        "summary": (
            f"RustDesk 本机 ID {inst.get('client_id') or '未知'}；"
            + "；".join(notes[:3])
        ),
    }]


def build_sessions(rid: str, instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """每种工具只解析一次（避免多实例重复扫同一批日志）。"""
    catalog = load_catalog()
    sessions: List[Dict[str, Any]] = []
    done: Set[str] = set()
    # 优先用主装（有服务）的实例上下文（client_id 等）
    ordered = sorted(instances, key=_inst_score, reverse=True)
    for inst in ordered:
        tid = str(inst.get("tool_id") or "")
        if not tid or tid in done:
            continue
        tool = _tool_by_id(catalog, tid)
        if not tool:
            continue
        done.add(tid)
        if tid == "sunlogin":
            sessions.extend(_parse_sunlogin_sessions(rid, tool, inst))
        elif tid == "todesk":
            sessions.extend(_parse_todesk_sessions(rid, tool, inst))
        elif tid == "anydesk":
            sessions.extend(_parse_anydesk_sessions(rid, tool, inst))
        elif tid == "teamviewer":
            sessions.extend(_parse_teamviewer_sessions(rid, tool, inst))
        elif tid == "rustdesk":
            sessions.extend(_parse_rustdesk_sessions(rid, tool, inst))
    sessions = _merge_sessions(sessions, window_sec=180)
    # 二次去重：同工具+同开始+同对端
    uniq: List[Dict[str, Any]] = []
    seen_k: Set[str] = set()
    for s in sessions:
        k = "|".join([
            str(s.get("tool_id") or ""),
            str(s.get("start") or ""),
            str(s.get("end") or ""),
            str(s.get("peer_id") or ""),
            str(s.get("peer_ip") or ""),
        ])
        if k in seen_k:
            continue
        seen_k.add(k)
        uniq.append(s)
    uniq.sort(key=lambda s: s.get("start") or s.get("end") or "", reverse=True)
    return uniq


# ─── IP 痕迹：是否有境外 IP 连过 ─────────────────────────────────────────────

_IP = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
_IP_RX = re.compile(r"(?<![\d.])(" + _IP + r")(?![\d.])")

# 对端（控制端）：向日葵 P2P 请求 / remoteip / 打洞；AnyDesk「Logged in from」；通用 peer/remote ip
_PEER_RX = [re.compile(p, re.I) for p in (
    r"receive P2P request[^\n]*?\(public\s+(?P<ip>" + _IP + r")",
    r"remote_?ip\s*[=:]\s*\(?(?P<ip>" + _IP + r")",
    r"P2PHolePunch\s+(?P<ip>" + _IP + r")",
    r"logged in from\s+(?P<ip>" + _IP + r")",
    r"\b(?:peer|remote|client|visitor|controller)[ _-]?(?:ip|addr(?:ess)?)\s*[:=]\s*\(?(?P<ip>" + _IP + r")",
)]
# 本机出口
_SELF_RX = [re.compile(p, re.I) for p in (
    r"public address:?\s*(?P<ip>" + _IP + r")",
    r"received public ip\s+(?P<ip>" + _IP + r")",
)]
# 厂商服务器 / 中继
_SERVER_RX = re.compile(r"\b(?:server|relay|turn|stun|forward|p2p)\b", re.I)
_NET_WORD_RX = re.compile(r"\b(?:connect\w*|ip|addr\w*|host|peer|remote|socket|tcp|udp|login|session)\b", re.I)
_VERSION_RX = re.compile(r"\b(?:ver(?:sion)?|build|appiconversion)\b", re.I)
_LINE_TS_RX = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"), None),
    (re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"), None),
    (re.compile(r"\[(\d{4})(\d{2})(\d{2})-(\d{2}:\d{2}:\d{2})"), "todesk"),
]

_ROLE_LABEL = {
    "peer": "对端（控制方）",
    "conn": "采集时连接",
    "server": "厂商服务器/中继",
    "self": "本机出口",
    "unknown": "日志中出现",
}
_ROLE_RANK = {"peer": 0, "conn": 1, "unknown": 2, "server": 3, "self": 4}


def _line_time(line: str) -> str:
    for rx, kind in _LINE_TS_RX:
        m = rx.search(line)
        if not m:
            continue
        if kind == "todesk":
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}"
        return _fmt_dt(_parse_dt(m.group(1)))
    return ""


def _line_ip_roles(line: str) -> List[Tuple[str, str]]:
    """一行日志里的公网候选 IP 及其角色。版本号行只认明确的对端/出口写法。"""
    roles: Dict[str, str] = {}
    for rx in _PEER_RX:
        for m in rx.finditer(line):
            roles.setdefault(m.group("ip"), "peer")
    for rx in _SELF_RX:
        for m in rx.finditer(line):
            roles.setdefault(m.group("ip"), "self")
    rest = [ip for ip in _IP_RX.findall(line) if ip not in roles]
    if rest and not _VERSION_RX.search(line):
        if _SERVER_RX.search(line):
            for ip in rest:
                roles.setdefault(ip, "server")
        elif _NET_WORD_RX.search(line):
            for ip in rest:
                roles.setdefault(ip, "unknown")
    return list(roles.items())


def build_ip_hits(rid: str, instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """远控日志 / 配置里的 IP + 采集时远控进程的网络连接，标注境内/境外。"""
    from .ip_catalog import locate_ip

    agg: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def add(inst: Dict[str, Any], ip: str, role: str, when: str, evidence: str, line: str) -> None:
        geo = locate_ip(ip)
        if geo["scope"] in ("nonpublic", "invalid"):
            return
        key = (str(inst.get("tool_id") or ""), ip, role)
        row = agg.get(key)
        if row is None:
            row = agg[key] = {
                "ip": ip,
                "scope": geo["scope"],
                "overseas": geo["scope"] == "overseas",
                "cloud": geo.get("cloud") or "",
                "role": role,
                "role_label": _ROLE_LABEL.get(role, role),
                "tool_id": inst.get("tool_id"),
                "tool_name": inst.get("name"),
                "count": 0,
                "first_seen": "",
                "last_seen": "",
                "evidence": [],
                "sample": line.strip()[:240],
            }
        row["count"] += 1
        if when:
            if not row["first_seen"] or when < row["first_seen"]:
                row["first_seen"] = when
            if not row["last_seen"] or when > row["last_seen"]:
                row["last_seen"] = when
        if evidence and evidence not in row["evidence"] and len(row["evidence"]) < 5:
            row["evidence"].append(evidence)

    for inst in instances:
        paths = [f.get("path") for f in (inst.get("log_files") or []) if not f.get("encrypted")]
        paths += [f.get("path") for f in (inst.get("config_files") or [])]
        for path in dict.fromkeys(p for p in paths if p):
            content = _read_file_content(rid, path)
            if not content:
                continue
            for line in content.splitlines():
                if "." not in line or not _IP_RX.search(line):
                    continue
                for ip, role in _line_ip_roles(line):
                    add(inst, ip, role, _line_time(line), path, line)

    # 采集那一刻远控进程的 TCP 连接（ToDesk 会话日志加密，主要靠这个）
    pid_inst: Dict[int, Dict[str, Any]] = {}
    for inst in instances:
        for pr in inst.get("processes") or []:
            try:
                pid = int(pr.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid:
                pid_inst[pid] = inst
    if pid_inst:
        for c in _load_blob_list(rid, "established_connections"):
            try:
                pid = int(c.get("pid") or 0)
            except (TypeError, ValueError):
                continue
            inst = pid_inst.get(pid)
            if not inst:
                continue
            remote = str(c.get("remote_addr") or c.get("RemoteAddr") or "")
            m = _IP_RX.search(remote)
            if not m:
                continue
            proc = next((p.get("name") for p in inst.get("processes") or [] if int(p.get("pid") or 0) == pid), "")
            add(inst, m.group(1), "conn", "", f"{proc or '进程'} PID {pid}",
                f"{c.get('proto') or 'TCP'} {c.get('local_addr') or ''} -> {remote} {c.get('status') or ''}")

    # 已确认为厂商服务器/本机出口的 IP，不再重复列「日志中出现」
    known = {(r["tool_id"], r["ip"]) for r in agg.values() if r["role"] in ("server", "self", "peer")}
    rows = [r for r in agg.values() if not (r["role"] == "unknown" and (r["tool_id"], r["ip"]) in known)]
    rows.sort(key=lambda r: (
        0 if r["overseas"] else 1,
        _ROLE_RANK.get(r["role"], 9),
        str(r.get("tool_id") or ""),
        r["last_seen"] or "",
    ))
    return rows


def _attach_session_geo(sessions: List[Dict[str, Any]]) -> None:
    from .ip_catalog import locate_ip
    for s in sessions:
        m = _IP_RX.search(str(s.get("peer_ip") or ""))
        if not m:
            continue
        geo = locate_ip(m.group(1))
        if geo["scope"] in ("domestic", "overseas"):
            s["peer_scope"] = geo["scope"]
            s["peer_overseas"] = geo["scope"] == "overseas"
            if geo.get("cloud"):
                s["peer_cloud"] = geo["cloud"]


def analyze_remote_tools(rid: str) -> Dict[str, Any]:
    rid = P.report_id(rid)
    instances = build_instances(rid)
    sessions = build_sessions(rid, instances)
    _attach_session_geo(sessions)
    ip_hits = build_ip_hits(rid, instances)
    overseas = [r for r in ip_hits if r["overseas"]]
    overseas_peer = [r for r in overseas if r["role"] in ("peer", "conn", "unknown")]
    return {
        "ok": True,
        "file": rid,
        "instances": instances,
        "sessions": sessions,
        "stats": {
            "instance_count": len(instances),
            "unattended": sum(1 for i in instances if i.get("unattended")),
            "portable": sum(1 for i in instances if i.get("portable")),
            "running": sum(1 for i in instances if i.get("running")),
            "session_count": len(sessions),
            "high_priority": sum(1 for i in instances if i.get("priority") == "high"),
            "tools": sorted({i.get("name") for i in instances if i.get("name")}),
            "ip_count": len({r["ip"] for r in ip_hits}),
            "overseas_ip_count": len({r["ip"] for r in overseas}),
            "overseas_peer_count": len({r["ip"] for r in overseas_peer}),
        },
        "ip_hits": ip_hits,
        "catalog_size": len(load_catalog().get("tools") or []),
        "catalog_note": str(load_catalog().get("note") or ""),
    }
