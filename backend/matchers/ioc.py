"""IOC 匹配 — rules-ioc.json + ioc/*.db（SQLite 情报库）"""
from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import ioc_db
from ..models import Finding
from ..rules_loader import RuleStore


def ioc_match(store: RuleStore, value: str, ioc_type: Optional[str] = None) -> List[Dict]:
    """合并 JSON 规则库 + SQLite/ES IOC 库命中。"""
    results = []
    v = (value or "").strip().lower()
    if not v:
        return results
    type_map = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "domain": "domains", "ip": "ips", "url": "urls"}
    types = [ioc_type] if ioc_type else ["md5", "sha1", "sha256", "domain", "ip", "url"]
    host = ioc_db.extract_host(v)
    hk = ioc_db.hash_kind(v)

    for t in types:
        # 哈希：情报库统一 type=file_hash，按长度识别 md5/sha1/sha256
        if t in ("md5", "sha1", "sha256", "file_hash") or (t is None and hk):
            continue  # 下面统一处理，避免重复
        bucket = store.ioc.get(t, []) or store.ioc.get(type_map.get(t, t), [])
        for item in bucket:
            if not isinstance(item, dict) or item.get("enabled") is False:
                continue
            target = (item.get(t) or item.get("hash") or item.get("domain") or item.get("ip") or item.get("url") or "").lower()
            if not target:
                continue
            if t in ("domain", "url") and ioc_db.is_generic_benign_ioc(target):
                continue
            hit = False
            if t == "domain":
                h = host or v
                hit = h == target or h.endswith("." + target)
            elif t == "ip":
                hit = v == target
            elif t == "url":
                nv = ioc_db.normalize_url(v)
                nt = ioc_db.normalize_url(target)
                hit = nv == nt or v.rstrip("/") == target.rstrip("/")
            else:
                hit = v == target
            if hit:
                results.append({**item, "match_type": t, "matched": target, "from_db": False, "source": item.get("source") or "rules-ioc.json"})

        for h in ioc_db.lookup(v, t):
            results.append(h)

    # —— 哈希：JSON 规则 + IOC(file_hash) ——
    want_hash = any(t in ("md5", "sha1", "sha256", "file_hash", None) for t in types) or bool(hk)
    if want_hash and (hk or (ioc_type in ("md5", "sha1", "sha256", "file_hash"))):
        mtype = hk or (ioc_type if ioc_type in ("md5", "sha1", "sha256") else "md5")
        bucket = store.ioc.get(mtype, []) or store.ioc.get("md5", []) or store.ioc.get("hashes", [])
        for item in bucket:
            if not isinstance(item, dict) or item.get("enabled") is False:
                continue
            target = (item.get(mtype) or item.get("hash") or item.get("md5") or item.get("sha1") or item.get("sha256") or "").lower()
            if target and v == target:
                results.append({**item, "match_type": mtype, "matched": target, "from_db": False, "source": item.get("source") or "rules-ioc.json"})
        # ES/SQLite：一律按 file_hash 精确查（长度已由 hash_kind 校验）
        for h in ioc_db.lookup(v, "file_hash"):
            if not h.get("match_type"):
                h = {**h, "match_type": mtype}
            results.append(h)
        # 兼容 Redis 里按 md5/sha1/sha256 键缓存的条目
        if mtype != "file_hash":
            for h in ioc_db.lookup(v, mtype):
                results.append(h)
    return results


_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_DOM_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")

# 文件名被当成「域名」：rc.local / readme.md / foo.sh → 误撞情报
_FILELIKE_TLD = frozenset({
    "7z", "a", "apk", "asm", "asp", "aspx", "bak", "bash", "bat", "bin", "bmp", "bz2",
    "c", "cfg", "class", "conf", "config", "cpp", "cs", "css", "csv", "dat", "db", "deb",
    "desk", "desktop", "dll", "doc", "docx", "el", "elf", "exe", "gif", "go", "gz", "h",
    "hpp", "htm", "html", "ico", "ini", "jar", "java", "jpeg", "jpg", "js", "json", "jsp",
    "key", "ko", "kt", "less", "list", "lock", "log", "lua", "map", "md", "msi", "o",
    "old", "orig", "out", "pas", "patch", "pdf", "pem", "php", "pid", "pl", "plist", "png",
    "policy", "ps1", "py", "pyc", "pyo", "rb", "reg", "rpm", "rs", "rst", "rtf", "rules",
    "sample", "sass", "scss", "service", "sh", "so", "socket", "sock", "sql", "sqlite",
    "src", "svg", "swp", "sys", "tar", "tbz", "tgz", "timer", "tmp", "toml", "ts", "tsx",
    "txt", "unit", "vb", "vbs", "vue", "war", "wasm", "webp", "xml", "xz", "yaml", "yml",
    "zsh", "zip", "zshrc", "bashrc", "profile",
})
# 两段名且像 Unix 配置/脚本文件（即便 TLD 像 local）
_FILELIKE_BASENAME = frozenset({
    "rc.local", "readme.md", "readme.txt", "license.md", "license.txt", "changelog.md",
    "hosts.allow", "hosts.deny", "resolv.conf", "nsswitch.conf", "sysctl.conf",
    "ld.so.conf", "pam.conf", "sudoers", "crontab", "fstab", "passwd", "shadow",
    "group", "gshadow", "motd", "issue", "bashrc", "bash_profile", "profile",
    "zshrc", "zprofile", "vimrc", "gitconfig", "dockerignore", "gitignore",
    "makefile", "dockerfile", "procmailrc", "mailrc",
})


def _is_plausible_domain(dom: str) -> bool:
    """过滤文件名/扩展名伪域名，避免 rc.local、readme.md 等撞 IOC。"""
    d = (dom or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return False
    if d in _FILELIKE_BASENAME:
        return False
    if ioc_db.is_generic_benign_ioc(d) or ioc_db.is_benign_host(d):
        return False
    parts = d.split(".")
    if len(parts) < 2 or any(not p or p.startswith("-") or p.endswith("-") for p in parts):
        return False
    tld = parts[-1]
    if tld in _FILELIKE_TLD or tld.isdigit() or len(tld) > 24:
        return False
    # 两段 + .local：几乎都是 rc.local / foo.local 文件或局域网尾巴，不作域名 IOC 证据源
    if len(parts) == 2 and tld == "local":
        return False
    return True


def _extract_domains(text: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for d in _DOM_RE.findall(str(text or "")):
        low = d.lower()
        if low in seen or not _is_plausible_domain(low):
            continue
        seen.add(low)
        out.append(low)
    return out

_HASH_FIELD_KEYS = (
    "md5", "sha1", "sha256", "MD5", "SHA1", "SHA256",
    "hash", "file_hash", "file_md5", "file_sha1", "file_sha256",
    "md5_hash", "sha1_hash", "sha256_hash", "Hash", "FileHash",
)
_PE_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv", ".msi"}
_PF_ROOT_RE = re.compile(r"(?i)^[a-z]:\\program files(?: \(x86\))?$")
_LOCAL_ROOT_RE = re.compile(r"(?i)^[a-z]:\\users\\[^\\]+\\appdata\\local$")
_LOCAL_ONE_RE = re.compile(r"(?i)^[a-z]:\\users\\[^\\]+\\appdata\\local\\[^\\]+$")
_ABS_PE_IN_CMD = re.compile(
    r'(?i)[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.(?:exe|dll|sys|scr|com|ocx|cpl|drv|msi)'
)


def _parent_dir(path: str) -> str:
    p = str(path or "").replace("/", "\\").rstrip("\\")
    if "\\" not in p:
        return ""
    return p.rsplit("\\", 1)[0].lower()


def _is_program_files_root_pe(path: str) -> bool:
    """仅 C:\\Program Files\\a.exe 这一层，不含子目录里的正常安装树。"""
    return bool(_PF_ROOT_RE.match(_parent_dir(path)))


def _is_user_desktop_or_docs(path: str) -> bool:
    lp = str(path or "").lower().replace("/", "\\")
    if "\\users\\" not in lp:
        return False
    return "\\desktop\\" in lp or "\\documents\\" in lp


def _is_users_public_pe(path: str) -> bool:
    lp = str(path or "").lower().replace("/", "\\")
    return "\\users\\public\\" in lp


def _is_appdata_local_root_pe(path: str) -> bool:
    return bool(_LOCAL_ROOT_RE.match(_parent_dir(path)))


def _is_appdata_local_one_level_pe(path: str) -> bool:
    """C:\\Users\\x\\AppData\\Local\\rand\\a.exe，不含 Microsoft\\Windows\\... 深树。"""
    return bool(_LOCAL_ONE_RE.match(_parent_dir(path)))


def _pe_paths_from_text(blob: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for m in _ABS_PE_IN_CMD.findall(str(blob or "")):
        p = m.replace("/", "\\")
        lp = p.lower()
        if lp in seen:
            continue
        seen.add(lp)
        out.append(p)
    return out


def _norm_hash_val(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    # 去掉常见分隔
    s = s.replace(" ", "").replace("-", "")
    return s


def _pick_hashes_from_obj(obj: dict) -> List[Tuple[str, str]]:
    """从对象提取 (kind, hex)。"""
    out: List[Tuple[str, str]] = []
    if not isinstance(obj, dict):
        return out
    # nested hashes dict
    nested = obj.get("hashes") or obj.get("Hashes") or obj.get("file_hashes")
    if isinstance(nested, dict):
        for k, v in nested.items():
            hv = _norm_hash_val(str(v or ""))
            kind = ioc_db.hash_kind(hv)
            if kind:
                out.append((kind, hv))
    for k in _HASH_FIELD_KEYS:
        if k not in obj or obj.get(k) in (None, "", "-", "—"):
            continue
        hv = _norm_hash_val(str(obj.get(k)))
        kind = ioc_db.hash_kind(hv)
        if kind:
            out.append((kind, hv))
    return out


_PERSIST_HASH_SECTIONS = (
    ("processes", "进程"),
    ("services", "服务"),
    ("startup_items", "启动项"),
    ("scheduled_tasks", "计划任务"),
    ("driver_entries", "驱动"),
)
_FILEISH_HASH_SECTIONS = (
    ("file_scans", "文件"),
    ("interesting_files", "兴趣文件"),
    ("hashed_files", "哈希清单"),
    ("file_hashes", "哈希清单"),
    ("prefetch_files", "Prefetch"),
)


def _harvest_embedded_hashes(
    report: Dict,
    *,
    persist_only: bool = False,
    files_only: bool = False,
) -> List[Tuple[str, str, str]]:
    """收集报告内已有哈希 → (kind, hex, evidence)。"""
    found: List[Tuple[str, str, str]] = []
    seen: Set[str] = set()

    def add(kind: str, hv: str, evidence: str):
        key = f"{kind}|{hv}"
        if key in seen:
            return
        seen.add(key)
        found.append((kind, hv, evidence))

    if persist_only:
        sections = _PERSIST_HASH_SECTIONS
    elif files_only:
        sections = _FILEISH_HASH_SECTIONS
    else:
        sections = _PERSIST_HASH_SECTIONS + _FILEISH_HASH_SECTIONS
    for key, label in sections:
        arr = report.get(key) or []
        if isinstance(arr, dict):
            arr = list(arr.values()) if arr else []
        if not isinstance(arr, list):
            continue
        for item in arr:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("task_name") or item.get("display_name") or item.get("full_path") or item.get("path") or ""
            fp = str(
                item.get("full_path")
                or item.get("resolved_path")
                or item.get("path")
                or item.get("image_path")
                or ""
            ).replace("/", "\\")
            lab = f"{label}:{fp}" if fp else f"{label}:{name}"
            for kind, hv in _pick_hashes_from_obj(item):
                add(kind, hv, lab[:240])
            dll = str(item.get("service_dll") or item.get("ServiceDll") or "")
            if dll:
                for kind, hv in _pick_hashes_from_obj({
                    "md5": item.get("dll_md5"),
                    "sha1": item.get("dll_sha1"),
                    "sha256": item.get("dll_sha256"),
                }):
                    add(kind, hv, f"{label}DLL:{dll}"[:240])
            for m in item.get("modules") or item.get("Modules") or []:
                if not isinstance(m, dict):
                    continue
                mp = str(m.get("path") or m.get("name") or "").replace("/", "\\")
                for kind, hv in _pick_hashes_from_obj(m):
                    add(kind, hv, f"{label}模块:{mp}"[:240])
    if persist_only:
        return found
    # 顶层扁平哈希列表
    for key in ("hashes", "ioc_hashes", "malware_hashes"):
        arr = report.get(key) or []
        if not isinstance(arr, list):
            continue
        for item in arr:
            if isinstance(item, str):
                hv = _norm_hash_val(item)
                kind = ioc_db.hash_kind(hv)
                if kind:
                    add(kind, hv, f"清单:{key}")
            elif isinstance(item, dict):
                for kind, hv in _pick_hashes_from_obj(item):
                    add(kind, hv, f"清单:{key}")
    return found


def _harvest_hashes_from_files_db(rid: str, limit: int = 20000) -> List[Tuple[str, str, str]]:
    """从 analysis.db files 表读取采集端写入的 md5/sha*（file_scans 已被掏空）。"""
    out: List[Tuple[str, str, str]] = []
    if not rid:
        return out
    try:
        from .. import paths as P
        import sqlite3

        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if not dbp or not Path(dbp).is_file():
            return out
        conn = sqlite3.connect(str(dbp))
        conn.row_factory = sqlite3.Row
        try:
            # 旧库可能无哈希列
            cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
            if not ({"md5", "sha1", "sha256"} & cols):
                return out
            lim = max(1, min(int(limit or 20000), 100000))
            # 持久化实体已单独入队；这里优先非系统 PE，避免 8000 条被 System32 占满
            sql = """
                SELECT full_path, name, md5, sha1, sha256 FROM files
                WHERE IFNULL(md5,'')!='' OR IFNULL(sha1,'')!='' OR IFNULL(sha256,'')!=''
                ORDER BY
                  CASE
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\windows\\system32\\')>0 THEN 5
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\windows\\syswow64\\')>0 THEN 5
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\windows\\winsxs\\')>0 THEN 5
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\local\\temp\\')>0 THEN 0
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\users\\public\\')>0 THEN 0
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\local\\microsoft\\')>0 THEN 4
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\local\\google\\')>0 THEN 4
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\local\\packages\\')>0 THEN 4
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\local\\')>0 THEN 0
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\desktop\\')>0
                         AND instr(lower(replace(full_path,'/','\\')), '\\users\\')>0 THEN 0
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\documents\\')>0
                         AND instr(lower(replace(full_path,'/','\\')), '\\users\\')>0 THEN 0
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\appdata\\roaming\\')>0 THEN 1
                    WHEN instr(lower(replace(full_path,'/','\\')), '\\programdata\\')>0 THEN 2
                    ELSE 3
                  END
                LIMIT ?
            """
            for r in conn.execute(sql, (lim,)).fetchall():
                fp = (r["full_path"] or "").replace("/", "\\")
                name = r["name"] or Path(fp).name
                # 证据带完整路径，便于分析页定位文件
                evid = (f"文件:{fp}" if fp else f"文件:{name}")[:240]
                for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                    hv = _norm_hash_val(r[col] if col in r.keys() else "")
                    if hv and ioc_db.hash_kind(hv):
                        out.append((kind, hv, evid))
        finally:
            conn.close()
    except Exception as e:
        print(f"[ioc] harvest hashes from files db: {e}")
    return out


def _persist_pe_paths(report: Dict) -> List[Tuple[str, str]]:
    """启动项/任务/服务命令行里的盘符 PE 路径（cmd /c start 包一层也能抠出来）。"""
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    keys = (
        ("startup_items", "启动项", ("path", "command", "resolved_path", "lnk_target", "lnk_arguments")),
        ("scheduled_tasks", "计划任务", ("path", "command", "resolved_path", "exec_path")),
        ("services", "服务", ("path", "image_path", "resolved_path", "service_dll")),
        ("processes", "进程", ("path", "command_line", "commandline")),
        ("driver_entries", "驱动", ("path", "resolved_path", "image_path")),
    )
    for section, label, fields in keys:
        for item in report.get(section) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("task_name") or ""
            blob = " ".join(str(item.get(f) or "") for f in fields)
            for p in _pe_paths_from_text(blob):
                lp = p.lower()
                if lp in seen:
                    continue
                seen.add(lp)
                out.append((p, f"{label}:{name or p}"))
    return out


def _lookup_hashes_for_paths(rid: str, paths: List[str]) -> List[Tuple[str, str, str]]:
    """用采集 files 表按路径补哈希，不打开情报库。"""
    out: List[Tuple[str, str, str]] = []
    if not rid or not paths:
        return out
    try:
        from .. import paths as P
        import sqlite3

        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if not dbp or not Path(dbp).is_file():
            return out
        norms = []
        seen: Set[str] = set()
        for p in paths:
            n = str(p or "").replace("/", "\\").lower().strip()
            if not n or n in seen:
                continue
            seen.add(n)
            norms.append(n)
        if not norms:
            return out
        conn = sqlite3.connect(str(dbp))
        conn.row_factory = sqlite3.Row
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
            if not ({"md5", "sha1", "sha256"} & cols):
                return out
            # 分批 IN，避免过长 SQL
            for i in range(0, len(norms), 80):
                batch = norms[i : i + 80]
                ph = ",".join("?" * len(batch))
                sql = (
                    "SELECT full_path, md5, sha1, sha256 FROM files "
                    f"WHERE lower(replace(full_path,'/','\\')) IN ({ph})"
                )
                for r in conn.execute(sql, batch).fetchall():
                    fp = (r["full_path"] or "").replace("/", "\\")
                    evid = f"文件:{fp}"[:240]
                    for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                        hv = _norm_hash_val(r[col] if col in r.keys() else "")
                        if hv and ioc_db.hash_kind(hv):
                            out.append((kind, hv, evid))
        finally:
            conn.close()
    except Exception as e:
        print(f"[ioc] lookup hashes by path: {e}")
    return out


def _row_is_trusted_signed(sig_status: Any, signed: Any) -> bool:
    st = str(sig_status or "").strip().lower()
    if st in ("valid", "signed"):
        return True
    if signed in (1, True, "1") and st in ("", "valid", "signed"):
        return True
    return False


def _is_systemish_parent_dir(parent: str) -> bool:
    """持久化同目录旁路：排除系统目录，避免扫进 System32 海量 PE。"""
    lp = str(parent or "").lower().replace("/", "\\").rstrip("\\") + "\\"
    return any(
        n in lp
        for n in (
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\windows\\winsxs\\",
            "\\windows\\servicing\\",
            "\\windows\\softwaredistribution\\",
            "\\windows\\assembly\\",
        )
    )


def lookup_unsigned_sidecar_hashes(
    rid: str,
    host_paths: List[Tuple[str, str]],
    *,
    per_dir_limit: int = 24,
    max_total: int = 500,
) -> List[Tuple[str, str, str]]:
    """持久化宿主同目录的未签 PE 哈希（白加黑旁路）。

    host_paths: (宿主路径, 证据前缀如「启动项:xxx」)
    返回 (kind, hex, evidence)；跳过 System32/SysWOW64/WinSxS，只收直接子文件。
    """
    out: List[Tuple[str, str, str]] = []
    if not rid or not host_paths:
        return out
    # dir_lower -> 证据前缀（首个宿主的标签）
    dirs: Dict[str, str] = {}
    host_set: Set[str] = set()
    for path, label in host_paths:
        fp = str(path or "").replace("/", "\\").strip().strip('"')
        if not fp:
            continue
        lp = fp.lower()
        host_set.add(lp)
        parent = _parent_dir(fp)
        if not parent or _is_systemish_parent_dir(parent):
            continue
        if parent not in dirs:
            dirs[parent] = (label or "持久化").split(":")[0] or "持久化"
    if not dirs:
        return out
    try:
        from .. import paths as P
        import sqlite3

        dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
        if not dbp or not Path(dbp).is_file():
            return out
        conn = sqlite3.connect(str(dbp))
        conn.row_factory = sqlite3.Row
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
            if "full_path" not in cols or not ({"md5", "sha1", "sha256"} & cols):
                return out
            sel = "full_path, md5, sha1, sha256"
            if "sig_status" in cols:
                sel += ", sig_status"
            if "signed" in cols:
                sel += ", signed"
            if "ext" in cols:
                sel += ", ext"
            per_dir: Dict[str, int] = {d: 0 for d in dirs}
            seen_hv: Set[str] = set()
            for parent, tag in dirs.items():
                if len(out) >= max_total:
                    break
                prefix = parent.rstrip("\\") + "\\"
                sql = (
                    f"SELECT {sel} FROM files "
                    "WHERE lower(replace(full_path,'/','\\')) LIKE ? || '%' "
                    "AND (IFNULL(md5,'')!='' OR IFNULL(sha1,'')!='' OR IFNULL(sha256,'')!='')"
                )
                for r in conn.execute(sql, (prefix,)).fetchall():
                    if len(out) >= max_total or per_dir[parent] >= per_dir_limit:
                        break
                    fp = (r["full_path"] or "").replace("/", "\\")
                    fl = fp.lower()
                    if fl in host_set:
                        continue
                    if not fl.startswith(prefix):
                        continue
                    rest = fl[len(prefix):]
                    if not rest or "\\" in rest:
                        continue  # 只要同目录直接子文件
                    ext = ""
                    if "ext" in r.keys():
                        ext = str(r["ext"] or "").lower()
                        if ext and not ext.startswith("."):
                            ext = "." + ext
                    if not ext:
                        for e in _PE_EXTS:
                            if fl.endswith(e):
                                ext = e
                                break
                    if ext not in _PE_EXTS:
                        continue
                    sig = r["sig_status"] if "sig_status" in r.keys() else ""
                    signed = r["signed"] if "signed" in r.keys() else 0
                    if _row_is_trusted_signed(sig, signed):
                        continue
                    evid = f"{tag}同目录:{fp}"[:240]
                    added = False
                    for kind, col in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                        hv = _norm_hash_val(r[col] if col in r.keys() else "")
                        if not hv or not ioc_db.hash_kind(hv):
                            continue
                        key = f"{kind}|{hv}"
                        if key in seen_hv:
                            continue
                        seen_hv.add(key)
                        out.append((kind, hv, evid))
                        added = True
                    if added:
                        per_dir[parent] = per_dir.get(parent, 0) + 1
        finally:
            conn.close()
    except Exception as e:
        print(f"[ioc] unsigned sidecar hashes: {e}")
    return out


def _collect_paths_for_hash(report: Dict) -> List[Tuple[str, str]]:
    """收集待本地哈希的路径（进程/模块/启动项/服务/任务/文件扫描）。"""
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()

    def add(path: str, label: str):
        p = str(path or "").strip().strip('"')
        if not p or p in ("-", "—"):
            return
        lp = p.lower()
        if lp in seen:
            return
        seen.add(lp)
        out.append((p, label))

    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        if p.get("path"):
            add(p["path"], f"进程:{p.get('name') or ''}")
        for m in p.get("modules") or []:
            if isinstance(m, dict) and m.get("path"):
                add(m["path"], f"模块:{m.get('name') or m.get('path')}")
    for s in report.get("services") or []:
        if isinstance(s, dict):
            add(s.get("path") or s.get("image_path") or s.get("resolved_path") or "", f"服务:{s.get('name') or ''}")
            add(s.get("service_dll") or "", f"服务DLL:{s.get('name') or ''}")
            blob = " ".join(str(s.get(k) or "") for k in ("path", "image_path", "resolved_path", "service_dll"))
            for p in _pe_paths_from_text(blob):
                add(p, f"服务:{s.get('name') or ''}")
    for si in report.get("startup_items") or []:
        if isinstance(si, dict):
            add(si.get("path") or "", f"启动项:{si.get('name') or ''}")
            blob = " ".join(str(si.get(k) or "") for k in ("command", "path", "resolved_path", "lnk_arguments"))
            for p in _pe_paths_from_text(blob):
                add(p, f"启动项:{si.get('name') or ''}")
    for t in report.get("scheduled_tasks") or []:
        if isinstance(t, dict):
            add(t.get("path") or "", f"计划任务:{t.get('task_name') or t.get('name') or ''}")
            blob = " ".join(str(t.get(k) or "") for k in ("command", "path", "resolved_path"))
            for p in _pe_paths_from_text(blob):
                add(p, f"计划任务:{t.get('task_name') or ''}")
    for f in report.get("file_scans") or []:
        if not isinstance(f, dict):
            continue
        ext = str(f.get("ext") or "").lower()
        if ext and not ext.startswith("."):
            ext = "." + ext
        name = str(f.get("name") or "").lower()
        if ext in _PE_EXTS or any(name.endswith(x) for x in _PE_EXTS):
            add(f.get("full_path") or f.get("path") or "", f"文件:{f.get('name') or ''}")
    return out


def _pe_paths_from_files_db(rid: str, limit: int = 400) -> List[Tuple[str, str]]:
    """从已入库的 files 表取 PE 路径（file_scans 分析时已被掏空）。

    优先：未签名 + 高危路径；避免预算被 System32 正常文件占满导致 IOC 哈希全未命中。
    """
    if not rid:
        return []
    try:
        from ..db_store import query_files
        from .. import paths as P
        import sqlite3

        limit = max(1, min(int(limit or 400), 2000))
        out: List[Tuple[str, str]] = []
        seen: Set[str] = set()

        def add_row(fp: str, name: str = ""):
            fp = str(fp or "").strip()
            if not fp:
                return
            lp = fp.lower()
            if lp in seen:
                return
            seen.add(lp)
            out.append((fp, f"文件:{fp}" if fp else f"文件:{name or Path(fp).name}"))

        # 1) 高危路径片段优先（与 High risk_rules 对齐）
        hot_parts = (
            "AppData\\Roaming",
            "AppData\\Local\\Temp",
            "\\Temp\\",
            "Users\\Public",
            "ProgramData\\User",
            "Downloads",
            "\\Desktop\\",
            "\\Documents\\",
        )
        for part in hot_parts:
            if len(out) >= limit:
                break
            for r in query_files(rid, exts=list(_PE_EXTS), path_contains=part, limit=min(120, limit - len(out))):
                fp = r.get("full_path") or ""
                if part.lower() in ("\\desktop\\", "\\documents\\") and not _is_user_desktop_or_docs(fp):
                    continue
                st = str(r.get("sig_status") or "").lower()
                if st in ("valid", "signed") or r.get("signed") is True:
                    continue
                add_row(fp, r.get("name") or "")

        if len(out) < limit:
            for r in query_files(rid, exts=list(_PE_EXTS), path_contains="AppData\\Local", limit=min(250, limit - len(out))):
                fp = r.get("full_path") or ""
                if not (_is_appdata_local_root_pe(fp) or _is_appdata_local_one_level_pe(fp)):
                    continue
                st = str(r.get("sig_status") or "").lower()
                if st in ("valid", "signed") or r.get("signed") is True:
                    continue
                add_row(fp, r.get("name") or "")

        # Program Files / (x86) 只收根目录下一层 PE（C:\Program Files\evil.exe），不扫整棵安装树
        if len(out) < limit:
            from ..db_store import query_files_under_dir
            for root in (
                r"C:\Program Files",
                r"C:\Program Files (x86)",
            ):
                if len(out) >= limit:
                    break
                pack = query_files_under_dir(rid, root, limit=min(80, limit - len(out)))
                for r in pack.get("items") or []:
                    if not isinstance(r, dict):
                        continue
                    fp = r.get("full_path") or ""
                    ext = str(r.get("ext") or "").lower()
                    if ext and not ext.startswith("."):
                        ext = "." + ext
                    name = str(r.get("name") or "").lower()
                    if ext not in _PE_EXTS and not any(name.endswith(x) for x in _PE_EXTS):
                        continue
                    if not _is_program_files_root_pe(fp):
                        continue
                    st = str(r.get("sig_status") or "").lower()
                    if st in ("valid", "signed") or r.get("signed") is True:
                        continue
                    add_row(fp, r.get("name") or "")

        # 2) 库内未签名 / Missing / NotSigned / Unchecked PE（排除 System32）
        if len(out) < limit:
            dbp = P.resolve_analysis_db(rid) or P.db_path_for_write(rid)
            if dbp and Path(dbp).is_file():
                conn = sqlite3.connect(str(dbp))
                conn.row_factory = sqlite3.Row
                try:
                    ext_ph = ",".join("?" * len(_PE_EXTS))
                    ext_args = [e.lower() if str(e).startswith(".") else ("." + str(e).lower()) for e in _PE_EXTS]
                    sql = f"""
                        SELECT full_path, name, sig_status, signed FROM files
                        WHERE lower(ext) IN ({ext_ph})
                          AND IFNULL(signed,0)=0
                          AND lower(IFNULL(sig_status,'')) NOT IN ('valid','signed')
                          AND instr(lower(replace(full_path,'/','\\')), '\\windows\\system32\\')=0
                          AND instr(lower(replace(full_path,'/','\\')), '\\windows\\syswow64\\')=0
                          AND instr(lower(replace(full_path,'/','\\')), '\\windows\\winsxs\\')=0
                        LIMIT ?
                    """
                    need = limit - len(out)
                    for r in conn.execute(sql, [*ext_args, need]).fetchall():
                        add_row(r["full_path"] or "", r["name"] or "")
                finally:
                    conn.close()

        # 3) 不足再补普通 PE（仍尽量避开 system32）
        if len(out) < limit:
            for r in query_files(rid, exts=list(_PE_EXTS), limit=min(limit * 2, 800)):
                if len(out) >= limit:
                    break
                fp = r.get("full_path") or ""
                if _is_systemish_path(fp):
                    continue
                add_row(fp, r.get("name") or "")

        return out[:limit]
    except Exception as e:
        print(f"[ioc] files db pe paths: {e}")
        return []


def _is_systemish_path(path: str) -> bool:
    lp = str(path or "").lower().replace("/", "\\")
    needles = (
        r"\windows\system32\\",
        r"\windows\syswow64\\",
        r"\windows\winsxs\\",
        r"\windows\servicing\\",
        r"\windows\softwaredistribution\\",
        r"\windows\assembly\\",
    )
    return any(n in lp for n in needles)


def _hash_budget() -> int:
    """默认同机应急可哈希；分析服务器上路径不存在会快速跳过。FORENSIC_LOCAL_FILE_HASH=0 可关闭。"""
    raw = (os.environ.get("FORENSIC_LOCAL_FILE_HASH") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return 0
    try:
        return max(0, int(os.environ.get("FORENSIC_LOCAL_FILE_HASH_BUDGET") or "300"))
    except ValueError:
        return 300


def _hash_file(path: str, limit: int = 64 * 1024 * 1024) -> Dict[str, str]:
    """本地可读文件时计算哈希（同机分析场景）。"""
    out = {}
    try:
        p = Path(path)
        if not p.is_file():
            return out
        if p.stat().st_size > limit:
            return out
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        out["md5"] = md5.hexdigest()
        out["sha1"] = sha1.hexdigest()
        out["sha256"] = sha256.hexdigest()
    except OSError:
        pass
    return out


def _json_rules_hits(store: RuleStore, value: str, ioc_type: str) -> List[Dict]:
    """仅匹配 rules-ioc.json，不访问情报库（批量路径里与 DB 分开）。"""
    results: List[Dict] = []
    v = (value or "").strip().lower()
    if not v:
        return results
    t = (ioc_type or "").strip().lower()
    type_map = {"domain": "domains", "ip": "ips", "url": "urls"}
    host = ioc_db.extract_host(v)
    bucket = store.ioc.get(t, []) or store.ioc.get(type_map.get(t, t), [])
    for item in bucket:
        if not isinstance(item, dict) or item.get("enabled") is False:
            continue
        target = (item.get(t) or item.get("hash") or item.get("domain") or item.get("ip") or item.get("url") or "").lower()
        if not target:
            continue
        if t in ("domain", "url") and ioc_db.is_generic_benign_ioc(target):
            continue
        hit = False
        if t == "domain":
            h = host or v
            hit = h == target or h.endswith("." + target)
        elif t == "ip":
            hit = v == target
        elif t == "url":
            nv = ioc_db.normalize_url(v)
            nt = ioc_db.normalize_url(target)
            hit = nv == nt or v.rstrip("/") == target.rstrip("/")
        else:
            hit = v == target
        if hit:
            results.append({
                **item,
                "match_type": t,
                "matched": target,
                "from_db": False,
                "source": item.get("source") or "rules-ioc.json",
            })
    return results


def _ioc_hash_limit() -> int:
    try:
        return max(500, min(int(os.environ.get("FORENSIC_IOC_HASH_LIMIT") or "8000"), 100000))
    except ValueError:
        return 8000


def _ioc_browser_row_cap() -> int:
    try:
        return max(200, min(int(os.environ.get("FORENSIC_IOC_BROWSER_ROWS") or "2500"), 50000))
    except ValueError:
        return 2500


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    import time
    from .. import applog

    t0 = time.perf_counter()
    findings: List[Finding] = []
    ioc_hits = {"md5": [], "sha1": [], "sha256": [], "domain": [], "ip": [], "url": []}
    db_stats = ioc_db.stats()
    scanned_ips: Set[str] = set()
    scanned_domains: Set[str] = set()
    scanned_urls: Set[str] = set()
    # (kind, value, evidence, source)
    pending_net: List[Tuple[str, str, str, str]] = []

    def add_hit(cat: str, h: dict, evidence: str, source: str):
        matched = str(h.get("matched") or "")
        if cat in ("domain", "url"):
            if ioc_db.is_generic_benign_ioc(matched):
                return
            mhost = ioc_db.extract_host(matched) or matched.lower()
            # 整站级良性域名（含其子域）一律不报，避免 VT/IBM 等安全站被 IOC 库误收录
            if ioc_db.is_benign_host(mhost):
                return
        cat_list = ioc_hits.setdefault(cat, [])
        cat_list.append({**h, "evidence": evidence, "source_field": source})
        # name 可能是情报库占位符 unknown，或误填的报告 URL
        src = h.get("source") or source
        raw_name = str(h.get("name") or "").strip()
        raw_low = raw_name.lower()
        if (
            raw_low in {"", "unknown", "n/a", "na", "none", "null", "-", "ioc", "ioc 命中", "ioc命中"}
            or raw_low.startswith(("http://", "https://", "www."))
            or "://" in raw_name
        ):
            title = ioc_db._ioc_hit_title(
                str(h.get("malware") or ""),
                str(h.get("matched") or ""),
                str(h.get("match_type") or cat or ""),
                str(src or ""),
            )
        else:
            title = raw_name
        if not title or title.lower() == "unknown":
            title = ioc_db._ioc_hit_title(
                str(h.get("malware") or ""),
                str(h.get("matched") or ""),
                str(h.get("match_type") or cat or ""),
                str(src or ""),
            ) or "IOC 命中"
        key = f"IOC|{title}|{h.get('matched')}|{evidence}|{src}"
        if key in seen:
            return
        seen.add(key)
        sev = h.get("severity") or "high"
        # matcher 统一为 ioc，避免前端按模块分栏时 ioc / ioc_db 拆开导致「有命中无数」
        rid = h.get("matched") or ""
        if h.get("from_db"):
            rid = (rid + "|ioc_db").strip("|")
        findings.append(Finding(
            "IOC", sev, title,
            f"{evidence} → {h.get('matched')} ({src})",
            source, rid, "ioc",
            extra={"from_db": bool(h.get("from_db")), "malware": h.get("malware") or ""},
        ))

    def queue_net(kind: str, value: str, evidence: str, source: str):
        v = (value or "").strip().lower()
        if not v:
            return
        if kind == "ip":
            scanned_ips.add(v)
        elif kind == "domain":
            if not _is_plausible_domain(v):
                return
            scanned_domains.add(v)
        elif kind == "url":
            v = ioc_db.normalize_url(v).lower() or v
            scanned_urls.add(v[:200])
        pending_net.append((kind, v, evidence, source))

    # —— 先收集 IP / Domain / URL，再批量查情报库（避免逐条 Redis/MySQL）——
    try:
        from ..net_process import enrich_report_connections
        enrich_report_connections(report)
    except Exception:
        pass
    for c in report.get("established_connections") or []:
        if not isinstance(c, dict):
            continue
        from .util import conn_remote, conn_remote_ip
        from ..net_process import conn_proc_label
        ip = conn_remote_ip(c)
        rm = conn_remote(c)
        if ip:
            proc = conn_proc_label(c)
            ppath = str(c.get("process_path") or "").strip()
            if ppath.startswith("/") or (len(ppath) >= 3 and ppath[1] == ":"):
                ev = f"{ppath} | 外联:{proc} {rm or ip}" if proc else f"{ppath} | 外联:{rm or ip}"
            else:
                ev = f"外联:{proc} {rm or ip}" if proc else f"外联:{rm or ip}"
            queue_net("ip", ip, ev, "network")

    for line in (report.get("hosts_file") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for ip in _IP_RE.findall(line):
            queue_net("ip", ip, f"hosts:{line[:80]}", "hosts")

    dns_entries = report.get("dns_cache_entries") or []
    for ent in dns_entries:
        if not isinstance(ent, dict):
            continue
        for field in ("name", "entry", "data"):
            val = ent.get(field) or ""
            if not val:
                continue
            for dom in _extract_domains(str(val)):
                queue_net("domain", dom, "DNS缓存", "dns")
            for ip in _IP_RE.findall(str(val)):
                queue_net("ip", ip, "DNS缓存", "dns")

    dns = (report.get("network") or {}).get("dns_cache", "") or ""
    for line in dns.split("\n"):
        line = line.strip()
        if not line or "----" in line:
            continue
        for dom in _extract_domains(line):
            queue_net("domain", dom, "DNS缓存", "dns")

    browser_cap = _ioc_browser_row_cap()
    browser_rows = 0
    for art in report.get("browser_artifacts") or []:
        if not isinstance(art, dict):
            continue
        if browser_rows >= browser_cap:
            break
        for row in art.get("rows") or []:
            if browser_rows >= browser_cap:
                break
            if not isinstance(row, dict):
                continue
            browser_rows += 1
            blob = " ".join(str(x) for x in row.values() if x)
            for dom in _extract_domains(blob):
                queue_net("domain", dom, f"浏览器:{art.get('kind') or art.get('db_path') or ''}", "browser")
            for url_m in re.findall(r"https?://[^\s\"'<>]+", blob, re.I):
                queue_net("url", url_m[:200], "浏览器URL", "browser")

    for p in report.get("processes") or []:
        path = (p.get("path") or "") + " " + (p.get("name") or "")
        for dom in _extract_domains(path):
            queue_net("domain", dom, f"进程:{p.get('name')}", "process")

    for t in report.get("scheduled_tasks") or []:
        cmd = t.get("command") or ""
        for dom in _extract_domains(cmd):
            queue_net("domain", dom, f"计划任务:{t.get('task_name')}", "task")
        for ip in _IP_RE.findall(cmd):
            queue_net("ip", ip, f"计划任务:{t.get('task_name')}", "task")

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        blob = " ".join(str(si.get(k) or "") for k in ("command", "path", "resolved_path", "lnk_arguments"))
        name = si.get("name") or ""
        for dom in _extract_domains(blob):
            queue_net("domain", dom, f"启动项:{name}", "startup")
        for ip in _IP_RE.findall(blob):
            queue_net("ip", ip, f"启动项:{name}", "startup")

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        blob = " ".join(str(s.get(k) or "") for k in ("path", "resolved_path", "image_path", "service_dll"))
        name = s.get("name") or ""
        for ip in _IP_RE.findall(blob):
            queue_net("ip", ip, f"服务:{name}", "service")

    t_collect = time.perf_counter()
    uniq_ips = sorted(scanned_ips)
    uniq_doms = sorted(scanned_domains)
    uniq_urls = sorted(scanned_urls)
    ip_map = ioc_db.lookup_ips_batch(uniq_ips) if uniq_ips else {}
    dom_map = ioc_db.lookup_domains_batch(uniq_doms) if uniq_doms else {}
    url_map = ioc_db.lookup_urls_batch(uniq_urls) if uniq_urls else {}
    t_net = time.perf_counter()

    for kind, val, evidence, source in pending_net:
        for h in _json_rules_hits(store, val, kind):
            add_hit(kind, h, evidence, source)
        if kind == "ip":
            rows = ip_map.get(val) or []
        elif kind == "domain":
            rows = dom_map.get(val) or []
        else:
            key = ioc_db.normalize_url(val).lower() or val
            rows = url_map.get(key) or url_map.get(val) or []
        for h in rows:
            add_hit(kind, h, evidence, source)

    # 报告里的进程路径属于被采集终端；仅当本机存在同名文件时才哈希（分析服务器会自然跳过）。
    # FORENSIC_LOCAL_FILE_HASH=0 可关闭；预算默认 300，可用 FORENSIC_LOCAL_FILE_HASH_BUDGET 调整。
    hash_budget = _hash_budget()
    hashed = 0
    scanned_hashes: Set[str] = set()
    # 待批量查询：(kind, hex, evidence, source)
    pending_hashes: List[Tuple[str, str, str, str]] = []

    def queue_hash(kind: str, hv: str, evidence: str, source: str):
        hv = _norm_hash_val(hv)
        kind = kind or ioc_db.hash_kind(hv) or "md5"
        if not hv or not ioc_db.hash_kind(hv):
            return
        key = f"{kind}|{hv}"
        if key in scanned_hashes:
            return
        scanned_hashes.add(key)
        pending_hashes.append((kind, hv, evidence, source))

    # 1) 持久化实体哈希（启动项/任务/服务/进程/驱动）不受 files 上限挤掉
    for kind, hv, evidence in _harvest_embedded_hashes(report, persist_only=True):
        queue_hash(kind, hv, evidence, "hash")

    rid = str(report.get("_rid") or report.get("_files_rid") or "").strip()
    persist_hosts = _persist_pe_paths(report) if rid else []
    if rid:
        for kind, hv, evidence in _lookup_hashes_for_paths(rid, [p for p, _ in persist_hosts]):
            queue_hash(kind, hv, evidence, "hash")
        # 白加黑：持久化宿主（常已签名）同目录未签 PE 优先入队，避免被 files 上限挤掉
        for kind, hv, evidence in lookup_unsigned_sidecar_hashes(rid, persist_hosts):
            queue_hash(kind, hv, evidence, "hash")

    # 1b) Prefetch / file_scans 等报告内哈希
    for kind, hv, evidence in _harvest_embedded_hashes(report, files_only=True):
        queue_hash(kind, hv, evidence, "hash")

    # 1c) files 表：非系统路径优先，剩余额度
    hash_limit = _ioc_hash_limit()
    remain = max(0, hash_limit - len(scanned_hashes))
    if rid and remain > 0:
        for kind, hv, evidence in _harvest_hashes_from_files_db(rid, limit=remain):
            queue_hash(kind, hv, evidence, "hash")

    # 2) 本机可读文件 → 计算哈希再对 IOC
    # 顺序：高危/未签名 PE（files 库）→ 非系统实体路径 → 系统路径（预算剩余才用）
    entity_paths = _collect_paths_for_hash(report)
    pe_paths: List[Tuple[str, str]] = []
    if hash_budget > 0 and rid and not report.get("file_scans"):
        pe_paths = _pe_paths_from_files_db(rid, limit=max(80, hash_budget))

    non_sys: List[Tuple[str, str]] = []
    sys_paths: List[Tuple[str, str]] = []
    for pth, lab in entity_paths:
        if _is_systemish_path(pth):
            sys_paths.append((pth, lab))
        else:
            non_sys.append((pth, lab))

    ordered: List[Tuple[str, str]] = []
    ordered.extend(non_sys)
    ordered.extend(pe_paths)
    ordered.extend(sys_paths)

    seen_p: Set[str] = set()
    uniq_paths: List[Tuple[str, str]] = []
    for pth, lab in ordered:
        lp = str(pth).lower()
        if lp in seen_p:
            continue
        seen_p.add(lp)
        uniq_paths.append((pth, lab))

    for path, label in uniq_paths:
        if hashed >= hash_budget:
            break
        norm = str(path).strip().replace("/", "\\")
        if norm.startswith("\\\\") or norm.startswith("\\?\\") or norm.startswith("\\.\\"):
            continue
        if not os.path.isfile(path):
            continue
        digests = _hash_file(path)
        if not digests:
            continue
        hashed += 1
        for kind in ("md5", "sha1", "sha256"):
            hv = digests.get(kind)
            if not hv:
                continue
            queue_hash(kind, hv, f"文件哈希:{label or path}", "hash")

    # 3) 批量查情报：命中即出告警（ES terms / SQLite IN）
    t_hash0 = time.perf_counter()
    if pending_hashes:
        uniq_vals: List[str] = []
        seen_v: Set[str] = set()
        for _k, hv, _e, _s in pending_hashes:
            if hv not in seen_v:
                seen_v.add(hv)
                uniq_vals.append(hv)
        hit_map = ioc_db.lookup_hashes_batch(uniq_vals)
        for kind, hv, evidence, source in pending_hashes:
            for h in hit_map.get(hv) or []:
                row = dict(h)
                row["match_type"] = kind
                row["matched"] = row.get("matched") or hv
                if not row.get("hash"):
                    row["hash"] = hv
                add_hit(kind, row, evidence, source)
    t_end = time.perf_counter()

    net_ms = int((t_net - t_collect) * 1000)
    hash_ms = int((t_end - t_hash0) * 1000)
    total_ms = int((t_end - t0) * 1000)
    applog.info(
        "ioc",
        f"scan ips={len(uniq_ips)} domains={len(uniq_doms)} urls={len(uniq_urls)} "
        f"hashes={len(scanned_hashes)} hits={len(findings)} "
        f"net_ms={net_ms} hash_ms={hash_ms} total_ms={total_ms}",
        ips=len(uniq_ips),
        domains=len(uniq_doms),
        urls=len(uniq_urls),
        hashes=len(scanned_hashes),
        hits=len(findings),
        net_ms=net_ms,
        hash_ms=hash_ms,
        total_ms=total_ms,
    )

    return findings, {
        "ioc_hits": ioc_hits,
        "ioc_db": db_stats,
        "hashed_files": hashed,
        "ioc_scan": {
            "ips": len(scanned_ips),
            "domains": len(scanned_domains),
            "urls": len(scanned_urls),
            "hashes": len(scanned_hashes),
            "hashed_files": hashed,
            "hash_budget": hash_budget,
            "hash_limit": hash_limit,
            "browser_rows": browser_rows,
            "browser_cap": browser_cap,
            "hits": len(findings),
            "db_total": db_stats.get("total") or 0,
            "db_path": db_stats.get("path") or "",
            "es_count": (db_stats.get("es_count") if isinstance(db_stats, dict) else None),
            "query_backend": (db_stats.get("query_backend") if isinstance(db_stats, dict) else ""),
            "rules_md5": len(store.ioc.get("md5") or []),
            "rules_ip": len(store.ioc.get("ips") or []),
            "rules_domain": len(store.ioc.get("domains") or []),
            "hash_batch": True,
            "net_batch": True,
            "net_ms": net_ms,
            "hash_ms": hash_ms,
            "total_ms": total_ms,
        },
    }
