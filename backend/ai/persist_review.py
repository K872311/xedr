"""持久化与落点审视：不依赖规则命中，对计划任务 / 服务 / 启动项与用户可写目录落点做确定性预筛，
再交给大模型找规则漏报与关联链条（无 Key 时只出预筛结果）。

预筛只剔除基线噪声（COM 系统任务、Windows 目录内已签名载荷、svchost 系统 DLL 服务），
厂商白名单只降分不剔除——否则又退回到「只看规则认识的东西」。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import config
from .. import paths as P
from .citations import CITATION_RULE, attach_refs, cited_completion, citation_note

MAX_PERSIST = 70
MAX_FILES = 50
MIN_PERSIST_SCORE = 30
MIN_FILE_SCORE = 40

_USER_DIR_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\users\\public\\", "\\programdata\\",
    "\\downloads\\", "\\perflogs\\", "\\$recycle.bin\\", "\\windows\\tasks\\",
)
_LINUX_USER_DIR_MARKERS = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
    "/home/", "/root/", "/etc/cron", "/var/spool/cron",
    "/etc/systemd/", "/usr/lib/systemd/", "/.config/systemd/",
    "/.ssh/", "/etc/profile", "/etc/ld.so.preload",
)
_LINUX_HIGH_MARKERS = (
    "authorized_keys", "id_rsa", "id_ed25519", "ld.so.preload",
    "/etc/cron.d/", "/etc/cron.hourly/", "/var/spool/cron/",
    ".config/systemd/user/", "/etc/systemd/system/",
    "/etc/rc.local", "/etc/init.d/",
)
# 这些目录下的文件量大且几乎都是开发/包管理产物，不进文件候选
_FILE_NOISE_MARKERS = (
    "\\node_modules\\", "\\site-packages\\", "\\.vscode\\extensions\\", "\\.nuget\\",
    "\\appdata\\local\\programs\\python\\", "\\go\\pkg\\", "\\appdata\\local\\jetbrains\\",
    "\\windowsapps\\", "\\appdata\\local\\packages\\", "\\appdata\\local\\microsoft\\",
    "\\appdata\\roaming\\microsoft\\", "\\.cargo\\", "\\.rustup\\", "\\anaconda3\\",
    "\\miniconda3\\", "\\appdata\\local\\pip\\", "\\appdata\\local\\yarn\\",
    "\\programdata\\package cache\\", "\\programdata\\microsoft\\",
)
_ROOT_DIRS = (
    "c:\\programdata", "c:\\users\\public", "c:\\program files", "c:\\program files (x86)",
)
_PE_EXTS = (".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx")
_SCRIPT_EXTS = (".ps1", ".vbs", ".js", ".jse", ".vbe", ".bat", ".cmd", ".hta", ".wsf")
_LOLBIN_RX = re.compile(
    r"(?i)\b(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|"
    r"msiexec|cmstp|installutil|regasm|regsvcs|odbcconf|forfiles|conhost\s+--headless)\b"
)
_CMD_C_RX = re.compile(r"(?i)\bcmd(?:\.exe)?\s+/[ck]\b")
_ENCODED_RX = re.compile(
    r"(?i)(-e(?:nc(?:odedcommand)?)?\s+[a-z0-9+/=]{16,}|frombase64string|\biex\b|"
    r"invoke-expression|downloadstring|downloadfile|invoke-webrequest|net\.webclient|"
    r"https?://|\\\\[0-9]{1,3}\.[0-9]{1,3}\.)"
)
_DOUBLE_EXT_RX = re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png|rar|zip)\.(exe|scr|com|bat|cmd|js|vbs)$")
_PATH_RX = re.compile(
    r'(?i)(?:^|[\s"\'=,])(([a-z]:\\|\\\\)[^"\'\r\n,]*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|scr|msi|com|hta|cpl))\b'
)
_LINUX_PATH_RX = re.compile(r"(?:^|[\s\"'=;|])(/[^\s\"';|]+)")


def _norm(p: Any) -> str:
    s = str(p or "").strip().strip('"').strip("'").replace("/", "\\")
    if s.startswith("\\\\?\\"):
        s = s[4:]
    s = re.sub(r"\\+", r"\\", s)
    return s.rstrip("\\")


def _parent(p: str) -> str:
    s = _norm(p)
    return s.rsplit("\\", 1)[0] if "\\" in s else ""


def _is_signed(item: Dict[str, Any]) -> bool:
    st = str(item.get("sig_status") or item.get("SigStatus") or "").strip().lower()
    if item.get("signed") is True:
        return st not in ("invalid", "hashmismatch", "notsigned")
    return st == "valid"


def _sig_bad(item: Dict[str, Any]) -> bool:
    st = str(item.get("sig_status") or "").strip().lower()
    return st in ("invalid", "hashmismatch", "nottrusted", "untrusted", "expired", "bad")


def _sig_label(item: Dict[str, Any]) -> str:
    if _is_signed(item):
        return "已签名" + (f"（{item.get('signer')}）" if item.get("signer") else "")
    st = str(item.get("sig_status") or "").strip()
    if _sig_bad(item):
        return f"签名无效（{st}）"
    if st.lower() in ("", "missing", "unchecked", "unknown", "n/a", "na"):
        return "未校验"
    return "未签名"


def _parse_dt(s: Any) -> Optional[datetime]:
    t = str(s or "").strip().replace("T", " ")[:19]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(t[: len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
    return None


def _payload_path(item: Dict[str, Any], kind: str) -> str:
    for k in ("resolved_path", "image_path"):
        v = _norm(item.get(k))
        if v and ("\\" in v or v.startswith("/")):
            return v
    blob = " ".join(str(item.get(k) or "") for k in ("path", "command", "command_line"))
    m = _PATH_RX.search(" " + blob)
    if m:
        return _norm(m.group(1))
    m = _LINUX_PATH_RX.search(" " + blob)
    if m:
        return str(m.group(1)).strip()
    v = str(item.get("path") or "").strip()
    return _norm(v) if ("\\" in v) else v


def _randomish(name: str) -> bool:
    base = os.path.splitext(str(name or "").lower())[0]
    if len(base) < 5 or len(base) > 16:
        return False
    if not re.fullmatch(r"[a-z0-9]+", base):
        return False
    if not re.search(r"\d", base) or not re.search(r"[a-z]", base):
        return False
    # 版本号 / 常见产品缩写（v2、x64 等）不算随机
    return not re.fullmatch(r"[a-z]+(?:v?\d{1,3}|x(?:64|86)|32|64)", base)


def _in_user_dir(path_l: str, linux: bool) -> bool:
    if linux:
        return any(m in path_l for m in _LINUX_USER_DIR_MARKERS) or "/." in path_l
    return any(m in path_l for m in _USER_DIR_MARKERS)


def _dir_root_file(path_l: str) -> bool:
    par = path_l.rsplit("\\", 1)[0] if "\\" in path_l else ""
    if par in _ROOT_DIRS:
        return True
    return bool(re.fullmatch(r"[a-z]:\\users\\[^\\]+\\appdata\\(roaming|local|locallow)", par))


def _vendor_benign(blob: str) -> bool:
    try:
        from ..matchers.persistence import _is_known_benign_persist
        return bool(_is_known_benign_persist(blob))
    except Exception:
        return False


def _is_com(item: Dict[str, Any]) -> bool:
    try:
        from ..matchers.persistence import _is_com_handler
        return bool(_is_com_handler(item))
    except Exception:
        return str(item.get("path") or "").strip().upper() == "COM"


# ─── 数据装载 ───────────────────────────────────────────────────────────────

def _load_persist(rid: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    from ..search_hunt import _load_persist_pack
    return _load_persist_pack(rid)


def _db_path(rid: str) -> Optional[Path]:
    dbp = P.resolve_analysis_db(rid)
    return Path(dbp) if dbp and Path(dbp).is_file() else None


def _file_row(r: sqlite3.Row) -> Dict[str, Any]:
    keys = r.keys()
    return {k: r[k] for k in keys}


def _files_by_parent(conn: sqlite3.Connection, parents: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    """parent_path_norm（小写归一）→ 该目录下文件；走 idx_files_parent_norm。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    uniq = sorted({p.lower() for p in parents if p})
    cols = "full_path,name,parent_path_norm,ext,size,company,signed,signer,sig_status,hidden,mtime,md5,sha256"
    for i in range(0, len(uniq), 200):
        part = uniq[i:i + 200]
        ph = ",".join("?" * len(part))
        try:
            rows = conn.execute(
                f"SELECT {cols} FROM files WHERE parent_path_norm IN ({ph})", part,
            ).fetchall()
        except sqlite3.OperationalError:
            return out
        for r in rows:
            d = _file_row(r)
            out.setdefault(str(d.get("parent_path_norm") or ""), []).append(d)
    return out


def _file_candidates_sql(conn: sqlite3.Connection, linux: bool, limit: int = 4000) -> List[Dict[str, Any]]:
    cols = "full_path,name,parent_path_norm,ext,size,company,product,description,signed,signer,sig_status,hidden,mtime,md5,sha256"
    try:
        if linux:
            conds = " OR ".join("instr(lower(full_path), ?) > 0" for _ in _LINUX_USER_DIR_MARKERS)
            rows = conn.execute(
                f"SELECT {cols} FROM files WHERE ({conds}) LIMIT ?",
                [*_LINUX_USER_DIR_MARKERS, limit],
            ).fetchall()
        else:
            exts = list(_PE_EXTS + _SCRIPT_EXTS)
            ph = ",".join("?" * len(exts))
            conds = " OR ".join("instr(parent_path_norm || '\\', ?) > 0" for _ in _USER_DIR_MARKERS)
            rows = conn.execute(
                f"SELECT {cols} FROM files WHERE ext IN ({ph}) AND ({conds}) "
                "AND (IFNULL(signed,0)=0 OR lower(IFNULL(sig_status,'')) NOT IN ('valid')) LIMIT ?",
                [*exts, *_USER_DIR_MARKERS, limit],
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [_file_row(r) for r in rows]


def _rule_hit_blob(rid: str) -> str:
    """规则告警的标题/证据/路径拼成小写大串，用于判断某条目是否已被规则覆盖。"""
    try:
        from ..db_store import _load_fresh_findings
        findings = _load_fresh_findings(rid) or []
    except Exception:
        findings = []
    parts: List[str] = []
    for f in findings[:3000]:
        if not isinstance(f, dict):
            continue
        if str(f.get("review_status") or f.get("review") or "").lower() == "rejected":
            continue
        ex = f.get("extra") if isinstance(f.get("extra"), dict) else {}
        fl = ex.get("file") if isinstance(ex.get("file"), dict) else {}
        ev = f.get("evidence")
        if isinstance(ev, list):
            ev = " ".join(str(x) for x in ev)
        parts.extend([
            str(f.get("title") or ""), str(ev or "")[:600],
            str(ex.get("path") or ""), str(fl.get("full_path") or ""),
        ])
    return _norm(" \n ".join(parts)).lower() if parts else ""


def _rule_hit(blob: str, *needles: str) -> bool:
    if not blob:
        return False
    for n in needles:
        s = _norm(n).lower()
        if len(s) >= 6 and s in blob:
            return True
    return False


# ─── 预筛打分 ───────────────────────────────────────────────────────────────

def _score_persist(
    kind: str,
    item: Dict[str, Any],
    payload: str,
    pfile: Optional[Dict[str, Any]],
    siblings: List[Dict[str, Any]],
    collect_dt: Optional[datetime],
    linux: bool,
) -> Tuple[int, List[str], bool]:
    """返回 (score, reasons, is_baseline)。"""
    name = str(item.get("task_name") or item.get("name") or "")
    cmd = str(item.get("command") or item.get("command_line") or item.get("path") or "")
    pl = payload.lower()
    if kind == "task" and _is_com(item):
        return 0, [], True
    sig_src = pfile or item
    signed = _is_signed(sig_src) or _is_signed(item)
    lol = bool(_LOLBIN_RX.search(cmd)) or bool(_CMD_C_RX.search(cmd))
    enc = bool(_ENCODED_RX.search(cmd))

    svc_dll = _norm(item.get("service_dll")).lower() if kind == "service" else ""
    foreign_dll = bool(svc_dll) and "\\windows\\" not in svc_dll
    if kind == "service" and pl.endswith("\\svchost.exe") and "\\windows\\" in pl and not foreign_dll:
        return 0, [], True
    if not linux and "\\windows\\" in pl and signed and not lol and not enc and not foreign_dll:
        return 0, [], True
    if not linux and ("\\program files\\" in pl or "\\program files (x86)\\" in pl) and signed and not lol and not enc:
        return 0, [], True

    score = 0
    reasons: List[str] = []
    if not linux:
        if _sig_bad(sig_src):
            score += 50
            reasons.append("签名无效")
        elif not signed and payload and str(sig_src.get("sig_status") or "").lower() not in ("", "missing", "unchecked", "n/a"):
            score += 40
            reasons.append("未签名")
        elif not signed and payload:
            score += 15
            reasons.append("签名未校验")
    if payload and _in_user_dir(pl, linux):
        score += 35
        reasons.append("载荷在用户可写目录")
    if payload and not linux and _dir_root_file(pl):
        score += 20
        reasons.append("载荷直接放在 ProgramData/Program Files/AppData 根目录")
    base = os.path.basename(payload.replace("/", "\\")) if payload else ""
    if base and _randomish(base):
        score += 20
        reasons.append("随机文件名")
    if lol:
        score += 25
        reasons.append("脚本宿主/LOLBin 执行")
    if enc:
        score += 40
        reasons.append("编码或远程下载特征")
    if foreign_dll:
        score += 45
        reasons.append("svchost 加载非系统目录 DLL")
    if kind == "task" and "\\microsoft\\" in name.lower() and payload and not any(
        m in pl for m in ("\\windows\\", "\\microsoft\\")
    ):
        score += 30
        reasons.append("任务名伪装 Microsoft，载荷不在官方目录")
    if pfile:
        if pfile.get("hidden"):
            score += 15
            reasons.append("载荷隐藏属性")
        mdt = _parse_dt(pfile.get("mtime"))
        if collect_dt and mdt:
            days = (collect_dt - mdt).total_seconds() / 86400
            if -1 <= days <= 7:
                score += 20
                reasons.append("载荷近 7 天内修改")
            elif days <= 30:
                score += 8
                reasons.append("载荷近 30 天内修改")
        if not linux and not str(pfile.get("company") or "").strip() and not signed:
            score += 10
            reasons.append("无公司信息")
    if not linux and siblings and payload and not _in_windows(pl):
        bad = [
            s for s in siblings
            if str(s.get("ext") or "").lower() in (".dll", ".ocx", ".cpl")
            and not _is_signed(s)
        ]
        if bad and signed:
            score += 35
            reasons.append(f"已签名宿主同目录有 {len(bad)} 个未签名 DLL（白加黑候选）")
        elif bad:
            score += 10
            reasons.append(f"同目录有 {len(bad)} 个未签名 DLL")
    if _vendor_benign(f"{name} {cmd} {payload}"):
        score -= 30
        reasons.append("已知厂商路径（降分）")
    return score, reasons, False


def _in_windows(pl: str) -> bool:
    return "\\windows\\" in pl


def _score_file(f: Dict[str, Any], collect_dt: Optional[datetime], linux: bool) -> Tuple[int, List[str]]:
    full = str(f.get("full_path") or "")
    pl = _norm(full).lower() if not linux else full.lower()
    if not linux and any(m in pl + "\\" for m in _FILE_NOISE_MARKERS):
        return 0, []
    ext = str(f.get("ext") or "").lower()
    name = str(f.get("name") or os.path.basename(full))
    # Electron/网页应用目录里的前端库，研判价值低
    if ext == ".js" and (name.lower().endswith(".min.js") or name.lower().startswith("jquery")):
        return 0, []
    score = 0
    reasons: List[str] = []
    if linux:
        if any(m in pl for m in ("/tmp/", "/var/tmp/", "/dev/shm/")):
            score += 30
            reasons.append("位于临时/内存目录")
        elif any(m in pl for m in _LINUX_HIGH_MARKERS) or any(
            pl.endswith(s) for s in ("/authorized_keys", "/ld.so.preload", "/rc.local")
        ):
            score += 45
            reasons.append("Linux 高价值持久化路径")
        elif "/home/" in pl or pl.startswith("/root/"):
            score += 20
            reasons.append("用户主目录落点")
        else:
            score += 15
            reasons.append("Linux 可写/配置目录")
        if name in ("authorized_keys", "known_hosts", "ld.so.preload", "crontab"):
            score += 15
            reasons.append(f"敏感文件名 {name}")
    elif ext in _PE_EXTS:
        if _sig_bad(f):
            score += 45
            reasons.append("签名无效 PE")
        else:
            score += 30
            reasons.append("用户可写目录未签名 PE")
    else:
        score += 15
        reasons.append("用户可写目录脚本")
    if _randomish(name):
        score += 20
        reasons.append("随机文件名")
    if _DOUBLE_EXT_RX.search(name):
        score += 40
        reasons.append("双扩展名伪装")
    if f.get("hidden"):
        score += 15
        reasons.append("隐藏属性")
    if not linux and _dir_root_file(pl):
        score += 20
        reasons.append("直接放在 ProgramData/AppData 根目录")
    mdt = _parse_dt(f.get("mtime"))
    if collect_dt and mdt:
        days = (collect_dt - mdt).total_seconds() / 86400
        if -1 <= days <= 7:
            score += 20
            reasons.append("近 7 天内修改")
        elif days <= 30:
            score += 8
            reasons.append("近 30 天内修改")
    if not linux and ext in _PE_EXTS and not str(f.get("company") or "").strip():
        score += 10
        reasons.append("无公司信息")
    if _vendor_benign(full):
        score -= 30
        reasons.append("已知厂商路径（降分）")
    return score, reasons


_KIND_LABEL = {"task": "计划任务", "service": "服务", "startup": "启动项", "file": "文件"}


def build_review_pack(rid: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rid = P.report_id(rid)
    meta = meta or {}
    linux = str(meta.get("os_family") or "").lower() == "linux"
    collect_dt = _parse_dt(meta.get("collect_time"))
    su, tk, sv = _load_persist(rid)
    rule_blob = _rule_hit_blob(rid)

    raw: List[Tuple[str, Dict[str, Any], str]] = []
    for kind, lst in (("task", tk), ("service", sv), ("startup", su)):
        for it in lst:
            if isinstance(it, dict):
                raw.append((kind, it, _payload_path(it, kind)))

    dbp = _db_path(rid)
    by_parent: Dict[str, List[Dict[str, Any]]] = {}
    file_rows: List[Dict[str, Any]] = []
    files_total = 0
    if dbp:
        from ..db_store import _connect
        conn = _connect(dbp)
        try:
            parents = [_parent(p).lower() for _, _, p in raw if p and "\\" in p]
            by_parent = _files_by_parent(conn, parents)
            file_rows = _file_candidates_sql(conn, linux)
            try:
                files_total = int(conn.execute("SELECT COUNT(1) FROM files").fetchone()[0] or 0)
            except sqlite3.OperationalError:
                files_total = 0
        finally:
            conn.close()

    persist: List[Dict[str, Any]] = []
    baseline = 0
    referenced: Set[str] = set()
    # 可疑持久化载荷所在目录 → 载荷文件名；用于给同目录落点文件补「关联」理由
    payload_dirs: Dict[str, str] = {}
    seen_keys: Set[Tuple[str, str, str]] = set()
    for kind, it, payload in raw:
        name = str(it.get("task_name") or it.get("name") or it.get("display_name") or "")
        dkey = (kind, name.lower(), _norm(payload).lower())
        if dkey in seen_keys:
            continue
        seen_keys.add(dkey)
        par = _parent(payload).lower() if payload else ""
        sibs = by_parent.get(par) or []
        pfile = next((s for s in sibs if _norm(s.get("full_path")).lower() == _norm(payload).lower()), None)
        score, reasons, is_base = _score_persist(kind, it, payload, pfile, sibs, collect_dt, linux)
        if is_base:
            baseline += 1
            continue
        if payload:
            referenced.add(_norm(payload).lower())
        if score < MIN_PERSIST_SCORE:
            continue
        if par:
            payload_dirs.setdefault(par, os.path.basename(_norm(payload)))
        unsigned_sibs = [
            str(s.get("name") or "") for s in sibs
            if str(s.get("ext") or "").lower() in (".dll", ".ocx", ".cpl", ".exe")
            and not _is_signed(s)
            and _norm(s.get("full_path")).lower() != _norm(payload).lower()
        ][:6]
        row: Dict[str, Any] = {
            "kind": _KIND_LABEL[kind],
            "name": name[:160],
            "command": str(it.get("command") or it.get("command_line") or it.get("path") or "")[:300],
            "path": payload[:260],
            "signature": _sig_label(pfile or it),
            "company": str((pfile or {}).get("company") or it.get("company") or "")[:80],
            "score": score,
            "reasons": reasons,
            "rule_hit": _rule_hit(rule_blob, payload, name),
        }
        for k in ("start_type", "status", "location", "next_run", "working_directory"):
            v = str(it.get(k) or "").strip()
            if v:
                row[k] = v[:120]
        if pfile:
            row["payload_mtime"] = str(pfile.get("mtime") or "")[:19]
            row["payload_size"] = int(pfile.get("size") or 0)
            row["sha256"] = str(pfile.get("sha256") or pfile.get("md5") or "")[:64]
        if unsigned_sibs:
            row["unsigned_siblings"] = unsigned_sibs
        persist.append(row)

    files: List[Dict[str, Any]] = []
    for f in file_rows:
        full = str(f.get("full_path") or "")
        if _norm(full).lower() in referenced:
            continue
        score, reasons = _score_file(f, collect_dt, linux)
        host_exe = payload_dirs.get(_parent(full).lower())
        if host_exe and score > 0:
            score += 25 if str(f.get("ext") or "").lower() in _PE_EXTS else 10
            reasons = reasons + [f"与可疑持久化载荷 {host_exe} 同目录"]
        if score < MIN_FILE_SCORE:
            continue
        files.append({
            "kind": "文件",
            "name": str(f.get("name") or "")[:120],
            "path": full[:260],
            "signature": _sig_label(f),
            "company": str(f.get("company") or "")[:80],
            "mtime": str(f.get("mtime") or "")[:19],
            "size": int(f.get("size") or 0),
            "hidden": bool(f.get("hidden")),
            "sha256": str(f.get("sha256") or f.get("md5") or "")[:64],
            "score": score,
            "reasons": reasons,
            "rule_hit": _rule_hit(rule_blob, full),
        })

    # 规则未命中优先，其次分数
    persist.sort(key=lambda x: (x["rule_hit"], -x["score"]))
    files.sort(key=lambda x: (x["rule_hit"], -x["score"]))
    persist_n, files_n = len(persist), len(files)
    persist = persist[:MAX_PERSIST]
    files = files[:MAX_FILES]
    return {
        "persist": persist,
        "files": files,
        "stats": {
            "tasks": len(tk),
            "services": len(sv),
            "startup": len(su),
            "files_total": files_total,
            "file_rows_scanned": len(file_rows),
            "baseline_dropped": baseline,
            "persist_candidates": persist_n,
            "file_candidates": files_n,
            "persist_sent": len(persist),
            "files_sent": len(files),
            "rule_hit_blob": bool(rule_blob),
        },
    }


# ─── 研判 ───────────────────────────────────────────────────────────────────

_SYSTEM = (
    "你是资深应急响应与主机取证分析师。下面是一台主机经过确定性预筛的持久化项（计划任务/服务/启动项）"
    "与用户可写目录落点文件候选，已剔除 COM 系统任务、Windows/Program Files 目录内已签名载荷等基线项。"
    "每条带 reasons（预筛理由，只是线索）与 rule_hit（是否已被规则引擎告警）。\n"
    "任务：独立于规则结果审视这些条目，重点找出 rule_hit=false 但可疑的项，"
    "并识别条目之间的关联（例如计划任务 → 用户目录未签名 exe → 同目录未签名 DLL 的白加黑链条）。\n"
    "注意：知名厂商签名软件、浏览器/IM 自动更新器、开发工具等常见良性情况请排除，"
    "不要仅因路径在 AppData 或未签名就判为可疑。\n"
    "输出简洁中文 Markdown，结构固定：\n"
    "1) 风险等级（严重/高/中/低）与一句话理由；\n"
    "2) 规则漏报候选：Markdown 表格「名称|类型|位置/路径|原因」，只列 rule_hit=false 且确实可疑的条目，没有写「无」；\n"
    "3) 关联链条（候选）：无序列表描述串联起来的可疑条目，没有写「无」；\n"
    "4) 已命中项补充：rule_hit=true 的条目如有额外发现（如关联落点）简述，否则写「无」。\n"
    "一律用「候选」，禁止写「确认」恶意/入侵；不要输出处置建议或操作步骤；禁止编造输入外的证据；"
    "预筛已剔除基线项且有数量上限，不能据此断言主机干净。"
)


def _heuristic(pack: Dict[str, Any], hostname: str) -> Dict[str, Any]:
    persist = pack.get("persist") or []
    files = pack.get("files") or []
    st = pack.get("stats") or {}
    allc = persist + files
    top = max((int(x.get("score") or 0) for x in allc), default=0)
    miss = [x for x in allc if not x.get("rule_hit")]
    if top >= 100 and miss:
        risk, score = "高", 70
    elif top >= 70 and miss:
        risk, score = "中", 45
    else:
        risk, score = "低", 15
    lines = [
        "1) 风险等级（预筛评分）",
        f"{risk}：主机 {hostname or '未知'} 共审视计划任务 {st.get('tasks', 0)}、服务 {st.get('services', 0)}、"
        f"启动项 {st.get('startup', 0)}，剔除基线 {st.get('baseline_dropped', 0)} 条；"
        f"预筛出持久化候选 {st.get('persist_candidates', 0)}、落点文件候选 {st.get('file_candidates', 0)}，"
        f"其中规则未命中 {len(miss)} 条。以下为确定性打分，未经大模型研判。",
        "",
        "2) 规则漏报候选（预筛）",
    ]
    if miss:
        lines.append("| 名称 | 类型 | 位置/路径 | 预筛理由 |")
        lines.append("| --- | --- | --- | --- |")
        for x in sorted(miss, key=lambda r: -int(r.get("score") or 0))[:20]:
            nm = str(x.get("name") or "").replace("|", "/")
            pth = str(x.get("path") or "").replace("|", "/")
            why = "、".join(x.get("reasons") or []).replace("|", "/")
            lines.append(f"| {nm} | {x.get('kind')} | {pth} | {why}（{x.get('score')}） |")
    else:
        lines.append("无")
    return {
        "mode": "heuristic",
        "risk_level": risk,
        "risk_score": score,
        "summary": "\n".join(lines),
        "highlights": [],
        "recommendations": [],
        "model": None,
    }


def analyze_persist_review(
    rid: str,
    *,
    use_llm: bool = True,
    user: Optional[Dict[str, Any]] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from .analyzer import (
        _chat_completions_url,
        _chat_sender,
        _http_error_detail,
        _normalize_model,
        load_inputs_for_ai,
    )

    meta, _ = load_inputs_for_ai(rid)
    hostname = str((meta or {}).get("hostname") or "")
    pack = build_review_pack(rid, meta)
    base = _heuristic(pack, hostname)
    candidates = [
        {k: v for k, v in x.items() if k != "command" or x.get("kind") != "文件"}
        for x in (pack["persist"] + pack["files"])
    ]
    base["stats"] = pack["stats"]
    base["candidates"] = candidates
    if not use_llm:
        base["note"] = "仅确定性预筛（未调用大模型）。"
        return base
    if not candidates:
        base["note"] = "预筛后没有候选条目，未调用大模型。这只说明没有命中预筛特征，不代表主机干净。"
        return base
    if creds is None:
        try:
            from ..user_ai import resolve_ai_creds
            creds = resolve_ai_creds(user)
        except Exception:
            creds = {"api_key": "", "base_url": "", "model": "", "timeout": 60, "source": "none"}
    if not (creds.get("api_key") or "").strip():
        base["mode"] = "need_config"
        base["note"] = "未配置个人 API Key，仅展示预筛结果。请到「我的大模型」填写并保存。"
        return base

    send_items = []
    for x in candidates:
        row = {k: v for k, v in x.items() if k not in ("sha256", "payload_size", "size")}
        send_items.append(row)
    compact, refs = attach_refs(send_items)
    payload_user = {
        "hostname": hostname,
        "os": str(meta.get("os") or ""),
        "collect_time": str(meta.get("collect_time") or ""),
        "stats": pack["stats"],
        "candidates": compact,
        "note": (
            f"持久化候选送入 {pack['stats']['persist_sent']}/{pack['stats']['persist_candidates']}，"
            f"落点文件候选送入 {pack['stats']['files_sent']}/{pack['stats']['file_candidates']}；"
            "规则未命中的优先送入。"
        ),
    }
    base_url = (creds.get("base_url") or config.AI_BASE_URL or "").strip()
    model = _normalize_model(creds.get("model") or config.AI_MODEL or "", base_url)
    timeout = max(float(creds.get("timeout") or config.AI_TIMEOUT or 60), 120.0)
    url = _chat_completions_url(base_url)
    try:
        send = _chat_sender(url, creds["api_key"].strip(), model, timeout)
        text, cite = cited_completion(send, [
            {"role": "system", "content": _SYSTEM + CITATION_RULE},
            {"role": "user", "content": json.dumps(payload_user, ensure_ascii=False)},
        ], list(refs))
    except Exception as e:
        detail = _http_error_detail(e)
        base["mode"] = "heuristic_fallback"
        base["error"] = str(detail)[:400]
        base["note"] = f"大模型调用失败，已回退预筛结果。原因：{str(detail)[:200]}"
        base["model"] = model
        return base
    if not text:
        base["mode"] = "heuristic_fallback"
        base["note"] = "模型返回空内容，已回退预筛结果。"
        return base
    risk = "中"
    for lv in ("严重", "高", "中", "低"):
        if lv in text[:160]:
            risk = lv
            break
    # 候选 ref 与送模型时一致，前端可按 ref 对照
    for c, r in zip(candidates, compact):
        c["ref"] = r["ref"]
    return {
        "mode": "llm",
        "risk_level": risk,
        "risk_score": {"严重": 95, "高": 75, "中": 45, "低": 15}.get(risk, 45),
        "summary": text,
        "highlights": [],
        "recommendations": [],
        "model": model,
        "request_url": url,
        "config_source": creds.get("source") or "user",
        "citations": cite,
        "evidence_refs": refs,
        "citation_note": citation_note(cite),
        "stats": pack["stats"],
        "candidates": candidates,
        "heuristic": {"risk_level": base["risk_level"], "risk_score": base["risk_score"]},
    }
