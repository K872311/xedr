"""Convert LinuxSC.sh collection directory into platform report.json shape."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_MAX_TEXT = 2_000_000
_MAX_PROC = 8000
_MAX_CONN = 5000
_MAX_USERS = 2000


def _read_text(path: Path, limit: int = _MAX_TEXT) -> str:
    if not path.is_file():
        return ""
    try:
        raw = path.read_bytes()[: limit + 1]
        if len(raw) > limit:
            raw = raw[:limit]
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _first_existing(*paths: Path) -> Optional[Path]:
    for p in paths:
        if p and p.is_file():
            return p
    return None


_FOOTPRINT_VER_RE = re.compile(r"Footprint\s+v(\d+\.\d+(?:\.\d+)?)", re.I)
_CQ_VER_RE = re.compile(r"[\"']version[\"']\s*:\s*[\"'](\d+\.\d+(?:\.\d+)?)[\"']", re.I)


def _detect_linuxsc_version(root: Path, footprint: str = "", report_hint: Optional[Dict[str, Any]] = None) -> str:
    """从 footprint / 旁路 JSON / 已有 collection_quality 解析采集脚本版本。"""
    for blob in (footprint or "",):
        m = _FOOTPRINT_VER_RE.search(blob)
        if m:
            return m.group(1)
    cq = (report_hint or {}).get("collection_quality") if isinstance(report_hint, dict) else None
    if isinstance(cq, dict):
        v = str(cq.get("version") or "").strip()
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", v):
            return v
    # 目录旁 collect_*.json / report.json（KEEP_RAW 或二次导入）
    for pat in ("collect_*.json", "report.json", "*.json"):
        for p in sorted(root.glob(pat))[:8]:
            if not p.is_file() or p.stat().st_size > 8_000_000:
                continue
            head = _read_text(p, 12_000)
            m = _CQ_VER_RE.search(head) or _FOOTPRINT_VER_RE.search(head)
            if m:
                return m.group(1)
    return ""


def find_linuxsc_root(path: Path) -> Path:
    """Locate LinuxSC root (has SystemInfo/ or _COLLECTION_TIME.txt)."""
    p = path.resolve()
    if p.is_file():
        p = p.parent
    markers = ("_COLLECTION_TIME.txt", "SystemInfo", "ProcInfo")
    if any((p / m).exists() for m in markers):
        return p
    # zip often wraps one top folder
    if p.is_dir():
        kids = [c for c in p.iterdir() if c.is_dir() and not c.name.startswith(".")]
        for c in kids[:20]:
            if any((c / m).exists() for m in markers):
                return c
        # shallow walk
        for c in p.rglob("_COLLECTION_TIME.txt"):
            return c.parent
        for c in p.rglob("SystemInfo"):
            if c.is_dir():
                return c.parent
    raise ValueError("未识别为 LinuxSC 采集目录（缺少 _COLLECTION_TIME.txt / SystemInfo）")


def _parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _parse_collection_time(text: str) -> Tuple[str, str]:
    collect = ""
    tz = ""
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if s.lower().startswith("timezone="):
            tz = s.split("=", 1)[1].strip()
            continue
        # Prefer explicit datetime inside LinuxSC banner line
        m = re.search(
            r"(\d{4})[/-](\d{1,2})[/-](\d{1,2}).*?(\d{1,2}:\d{2}:\d{2})",
            s,
        )
        if m and not collect:
            y, mo, d, t = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
            collect = f"{y}-{mo:02d}-{d:02d} {t}"
            continue
        if not collect and re.search(r"\d{4}", s) and "Collection Started" not in s:
            collect = s
    return collect, tz


def _hostname_from_ctl(text: str) -> str:
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        if k.strip().lower() in ("static hostname", "hostname", "pretty hostname"):
            hn = v.strip()
            if hn and hn.lower() not in ("n/a", "(none)"):
                return hn.split(".")[0][:128]
    return ""


def _hostname_from_outdir(root: Path) -> str:
    # LinuxSC_<IP>_<hostname>
    name = root.name
    m = re.match(r"^LinuxSC_(.+?)_(.+)$", name, re.I)
    if m:
        return m.group(2)[:128]
    return ""


def _ip_from_outdir(root: Path) -> str:
    m = re.match(r"^LinuxSC_([^_]+)_", root.name, re.I)
    if not m:
        return ""
    cand = m.group(1).replace("-", ".")
    try:
        ipaddress.ip_address(cand)
        return cand
    except Exception:
        return m.group(1)[:64]


def _strip_ps_forest(cmd: str) -> str:
    s = str(cmd or "")
    # ps auxwwf tree art: "\_", "|", "`-", spaces
    while True:
        ns = re.sub(r"^(?:\\_|\\||\|_|\||`-|[\s|_\\-])+", "", s)
        if ns == s:
            break
        s = ns
    return s.strip()


def _parse_ps_aux(text: str) -> List[Dict[str, Any]]:
    """Parse ps listing. Prefer flat USER PID PPID … CMD; strip forest names."""
    rows: List[Dict[str, Any]] = []
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return rows
    header = lines[0]
    has_ppid = bool(re.search(r"\bPPID\b", header, re.I))
    start = 1 if re.search(r"\bPID\b", header, re.I) and re.search(
        r"USER|UID|CMD|COMMAND", header, re.I
    ) else 0
    for ln in lines[start:_MAX_PROC + start]:
        if has_ppid:
            parts = ln.split(None, 10)
            if len(parts) < 11:
                continue
            user, pid, ppid, cpu, mem, vsz, rss, tty, stat, etime, cmd = parts[:11]
            start_t = etime
            time_s = etime
        else:
            parts = ln.split(None, 10)
            if len(parts) < 11:
                parts = ln.split(None, 9)
                if len(parts) < 10:
                    continue
                user, pid, cpu, mem, vsz, rss, tty, stat, start_t, cmd = parts[:10]
                time_s = ""
                ppid = "0"
            else:
                user, pid, cpu, mem, vsz, rss, tty, stat, start_t, time_s, cmd = parts[:11]
                ppid = "0"
        try:
            pid_i = int(pid)
        except Exception:
            continue
        try:
            ppid_i = int(ppid)
        except Exception:
            ppid_i = 0
        cmd = _strip_ps_forest(cmd)
        if not cmd or cmd in ("_", "\\_"):
            continue
        name = (cmd.split()[0] if cmd else "").rsplit("/", 1)[-1] or f"pid-{pid_i}"
        if name in ("_", "\\_"):
            name = f"pid-{pid_i}"
        rows.append({
            "pid": pid_i,
            "ppid": ppid_i,
            "name": name[:200],
            "user": user,
            "path": cmd.split()[0] if cmd.startswith("/") else "",
            "command_line": cmd[:2000],
            "start_time": start_t,
            "cpu": cpu,
            "mem": mem,
            "tty": tty,
            "stat": stat,
            "vsz": vsz,
            "rss": rss,
            "time": time_s,
            "children": [],
        })
    _attach_process_tree(rows)
    return rows


def _attach_process_tree(processes: List[Dict[str, Any]]) -> None:
    by_pid: Dict[int, Dict[str, Any]] = {}
    for p in processes:
        try:
            by_pid[int(p.get("pid") or 0)] = p
        except Exception:
            continue
    for p in processes:
        p.setdefault("children", [])
        try:
            ppid = int(p.get("ppid") or 0)
            pid = int(p.get("pid") or 0)
        except Exception:
            continue
        parent = by_pid.get(ppid)
        if parent and ppid != pid:
            kids = parent.setdefault("children", [])
            if pid not in kids:
                kids.append(pid)
            p["parent_name"] = parent.get("name") or ""


def _parse_passwd(text: str, group_text: str = "", birth_text: str = "") -> List[Dict[str, Any]]:
    gid_name: Dict[str, str] = {}
    user_groups: Dict[str, List[str]] = {}
    for ln in (group_text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(":")
        if len(parts) < 4:
            continue
        gname, _x, ggid, members = parts[0], parts[1], parts[2], parts[3]
        gid_name[ggid] = gname
        for m in members.split(","):
            m = m.strip()
            if not m:
                continue
            user_groups.setdefault(m, []).append(gname)

    birth_map: Dict[str, Tuple[str, str]] = {}
    for ln in (birth_text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        if len(parts) < 3:
            continue
        uname = parts[0].strip()
        created = parts[2].strip()
        source = parts[3].strip() if len(parts) > 3 else ""
        if uname:
            birth_map[uname] = (created, source)

    users: List[Dict[str, Any]] = []
    for ln in (text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(":")
        if len(parts) < 7:
            continue
        name, _x, uid, gid, gecos, home, shell = parts[:7]
        if not name:
            continue
        gprim = gid_name.get(gid, gid)
        extras = [g for g in user_groups.get(name, []) if g != gprim]
        groups = ",".join([gprim] + extras) if gprim or extras else gprim
        created, csrc = birth_map.get(name, ("", ""))
        users.append({
            "name": name,
            # Samba/Windows 约定的 Unix User SID（S-1-22-1-UID），非 AD SID；真实身份以 uid/gid 为准
            "sid": f"S-1-22-1-{uid}",
            "sid_kind": "samba-unix",
            "uid": uid,
            "gid": gid,
            "description": gecos,
            "profile_path": home,
            "shell": shell,
            "account_type": "local",
            "disabled": shell.endswith("nologin") or shell.endswith("/false") or shell.endswith("/sync"),
            "local_account": True,
            "logged_on": False,
            "groups": groups,
            "last_logon": "",
            "domain": "",
            "created_at": created,
            "created_source": csrc,
        })
        if len(users) >= _MAX_USERS:
            break
    return users


def _strip_journal_decor(text: str) -> str:
    """去掉 journalctl --catalog 等前缀装饰符（░░ 等）。"""
    s = str(text or "")
    # 行首常见 catalog / 进度装饰
    s = re.sub(r"^[\s░▒▓█■●◆◇○◎※›»·]+", "", s)
    s = s.replace("░░", "").replace("▒▒", "").replace("▓▓", "")
    return s.strip()


def _parse_proc_modules(text: str) -> Dict[int, List[Dict[str, Any]]]:
    out: Dict[int, List[Dict[str, Any]]] = {}
    for ln in (text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        if len(parts) < 2:
            parts = ln.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except Exception:
            continue
        path = parts[1].strip()
        if not path:
            continue
        name = path.rsplit("/", 1)[-1]
        company = ""
        if "/lib" in path:
            company = "system-lib"
        elif path.startswith("/usr/local"):
            company = "local"
        elif any(path.startswith(p) for p in ("/tmp", "/dev/shm", "/var/tmp")):
            company = "tmp-volatile"
        lst = out.setdefault(pid, [])
        if len(lst) >= 200:
            continue
        lst.append({
            "name": name[:200],
            "path": path[:1000],
            "signed": None,
            "signer": "",
            "company": company,
            "sig_status": "unchecked",
        })
    return out


def _parse_bin_pkg(text: str) -> Dict[str, Tuple[str, str]]:
    """Parse Persistence/bin_pkg.txt or service_bin_pkg.txt → path -> (pkg, vendor)."""
    out: Dict[str, Tuple[str, str]] = {}
    for ln in (text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        path = (parts[0] or "").strip()
        if not path.startswith("/"):
            continue
        pkg = (parts[1] if len(parts) > 1 else "").strip()
        vend = (parts[2] if len(parts) > 2 else "").strip()
        out[path] = (pkg, vend)
    return out


def _pkg_sig_fields(path: str, pkgmap: Dict[str, Tuple[str, str]]) -> Dict[str, Any]:
    """Map rpm/dpkg ownership to Windows-like signature fields."""
    path = str(path or "").strip()
    if not path:
        return {
            "signed": None,
            "signer": "",
            "company": "",
            "sig_status": "unchecked",
            "sig_type": "",
        }
    pkg, vend = pkgmap.get(path, ("", ""))
    if not pkg:
        # 尝试去参数后的裸路径
        bare = path.split()[0] if " " in path else path
        if bare != path:
            pkg, vend = pkgmap.get(bare, ("", ""))
            if pkg:
                path = bare
    if pkg and not pkg.startswith("file "):
        signer = vend or f"package:{pkg}"
        return {
            "signed": True,
            "signer": signer[:300],
            "company": (pkg or vend.split("|")[0])[:200],
            "sig_status": "signed",
            "sig_type": "package",
        }
    if path.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
        return {
            "signed": False,
            "signer": "",
            "company": "tmp-volatile",
            "sig_status": "unsigned",
            "sig_type": "",
        }
    return {
        "signed": False,
        "signer": "",
        "company": "",
        "sig_status": "unsigned",
        "sig_type": "",
    }


def _kernel_thread_sig(name: str) -> Optional[Dict[str, Any]]:
    n = str(name or "").strip()
    if n.startswith("[") and n.endswith("]") and len(n) > 2:
        return {
            "signed": None,
            "signer": "kernel",
            "company": "kernel",
            "sig_status": "n/a",
            "sig_type": "kernel",
        }
    return None


def enrich_linux_entity_sigs(report: Dict[str, Any]) -> Dict[str, Any]:
    """就地补全 Linux 进程/任务/启动项的软件包归属（签名列）。

    采集包常只有服务侧 bin_pkg；进程用同一路径可从服务反填。
    """
    if not isinstance(report, dict):
        return report
    if str(report.get("os_family") or "").lower() != "linux":
        return report

    pkg_text = ""
    raw = report.get("linuxsc_raw") if isinstance(report.get("linuxsc_raw"), dict) else {}
    # 优先已有 pkgmap 字段
    pkgmap: Dict[str, Tuple[str, str]] = {}
    if isinstance(report.get("_bin_pkg_map"), dict):
        for k, v in report["_bin_pkg_map"].items():
            if isinstance(v, (list, tuple)) and len(v) >= 1:
                pkgmap[str(k)] = (str(v[0] or ""), str(v[1] if len(v) > 1 else "") or "")
    # 从服务反填 path → package
    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        path = str(s.get("path") or s.get("resolved_path") or "").split()[0]
        if not path.startswith("/"):
            continue
        if s.get("signed") is True or str(s.get("sig_status") or "").lower() == "signed":
            pkg = str(s.get("company") or "")
            vend = str(s.get("signer") or "")
            if pkg or vend:
                pkgmap.setdefault(path, (pkg, vend))

    def apply_one(ent: Dict[str, Any]) -> None:
        if not isinstance(ent, dict):
            return
        name = str(ent.get("name") or ent.get("image") or ent.get("task_name") or "")
        ks = _kernel_thread_sig(name)
        if ks:
            for k, v in ks.items():
                ent[k] = v
            return
        st = str(ent.get("sig_status") or "").strip().lower()
        if ent.get("signed") is True and st in ("signed", "valid"):
            if not ent.get("sig_type"):
                ent["sig_type"] = "package"
            return
        path = str(ent.get("path") or ent.get("resolved_path") or ent.get("image_path") or "").strip()
        if not path:
            cl = str(ent.get("command_line") or ent.get("command") or ent.get("cmdline") or "")
            if cl.startswith("/"):
                path = cl.split()[0]
                ent["path"] = path
        if not path:
            if ent.get("signed") is None and not st:
                ent["sig_status"] = "unchecked"
            return
        sig = _pkg_sig_fields(path, pkgmap)
        # 仅在未采集或 unchecked 时覆盖；已有包签名保留
        if ent.get("signed") is None or st in ("", "unchecked", "unknown", "n/a") or not st:
            ent["signed"] = sig["signed"]
            ent["signer"] = sig["signer"] or ent.get("signer") or ""
            ent["company"] = sig["company"] or ent.get("company") or ""
            ent["sig_status"] = sig["sig_status"]
            ent["sig_type"] = sig["sig_type"] or ent.get("sig_type") or ""

    for key in ("processes", "services", "scheduled_tasks", "startup_items", "tasks"):
        for ent in report.get(key) or []:
            if isinstance(ent, dict):
                apply_one(ent)
    return report


def _first_abs_path(cmd: str) -> str:
    for tok in re.split(r"[\s;|&<>]+", str(cmd or "")):
        if tok.startswith("/"):
            return tok
    return ""


def _attach_process_modules(processes: List[Dict[str, Any]], mods: Dict[int, List[Dict[str, Any]]],
                            pkgmap: Optional[Dict[str, Tuple[str, str]]] = None) -> None:
    pkgmap = pkgmap or {}
    for p in processes:
        try:
            pid = int(p.get("pid") or 0)
        except Exception:
            continue
        mlist = mods.get(pid) or []
        # enrich module sig from pkg map
        for m in mlist:
            if not isinstance(m, dict):
                continue
            if m.get("sig_status") in (None, "", "unchecked") or m.get("signed") is None:
                m.update(_pkg_sig_fields(str(m.get("path") or ""), pkgmap))
        p["modules"] = mlist
        p["module_count"] = len(mlist)
        path = str(p.get("path") or "").strip()
        if not path:
            cl = str(p.get("command_line") or "")
            if cl.startswith("/"):
                path = cl.split()[0]
                p["path"] = path
        # maps 首条常是 /proc/pid/exe；cmdline 仅进程名时回填绝对路径
        if (not path or not path.startswith("/")) and mlist:
            picked = ""
            for m in mlist:
                mp = re.sub(r"\s*\(deleted\)\s*$", "", str(m.get("path") or "").strip(), flags=re.I)
                if not mp.startswith("/"):
                    continue
                if re.search(r"(?i)\.so(?:\.[0-9]+)*$", mp.rsplit("/", 1)[-1]):
                    continue
                picked = mp
                break
            if not picked:
                mp0 = re.sub(
                    r"\s*\(deleted\)\s*$",
                    "",
                    str((mlist[0] or {}).get("path") or "").strip(),
                    flags=re.I,
                )
                if mp0.startswith("/"):
                    picked = mp0
            if picked:
                path = picked
                p["path"] = path
                if not p.get("exe"):
                    p["exe"] = path
        sig = _pkg_sig_fields(path, pkgmap)
        p["signed"] = sig["signed"]
        p["signer"] = sig["signer"]
        p["company"] = sig["company"]
        p["sig_status"] = sig["sig_status"]
        p["sig_type"] = sig["sig_type"]


def _parse_modinfo(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    cur: Dict[str, str] = {}

    def flush() -> None:
        nonlocal cur
        if not cur.get("name"):
            cur = {}
            return
        signer = cur.get("signer") or ""
        signed: Any = True if signer else (False if cur.get("filename") else None)
        rows.append({
            "name": cur["name"],
            "path": cur.get("filename") or "",
            "size": "",
            "used_by": cur.get("depends") or "",
            "ref_count": "",
            "signed": signed,
            "signer": signer[:300],
            "company": (signer or cur.get("license") or "")[:200],
            "description": (cur.get("description") or "kernel module")[:400],
            "sig_status": "signed" if signed is True else ("unsigned" if signed is False else "unchecked"),
        })
        cur = {}

    for ln in (text or "").splitlines():
        if ln.startswith("===== "):
            flush()
            cur["name"] = ln.strip().strip("=").strip()
            continue
        if ":" not in ln:
            continue
        k, _, v = ln.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "filename":
            cur["filename"] = v
        elif k == "description":
            cur["description"] = v
        elif k == "signer":
            cur["signer"] = v
        elif k == "license":
            cur["license"] = v
        elif k == "depends":
            cur["depends"] = v
    flush()
    return rows[:3000]


def _parse_service_details(text: str, pkg_text: str = "") -> List[Dict[str, Any]]:
    pkgmap = _parse_bin_pkg(pkg_text)

    services: List[Dict[str, Any]] = []
    cur: Dict[str, str] = {}

    def flush() -> None:
        nonlocal cur
        name = cur.get("name") or ""
        if not name:
            cur = {}
            return
        path = cur.get("exec") or cur.get("frag") or ""
        cmd = cur.get("exec_cmd") or path
        if path:
            sig = _pkg_sig_fields(path, pkgmap)
        else:
            sig = {
                "signed": None,
                "signer": "",
                "company": "",
                "sig_status": "unchecked",
                "sig_type": "",
            }
        services.append({
            "name": name,
            "status": cur.get("active") or cur.get("unit_state") or "",
            "start_type": cur.get("unit_state") or cur.get("sub") or "",
            "path": path[:1000],
            "command": (cmd or "")[:2000],
            "fragment_path": (cur.get("frag") or "")[:1000],
            "description": (cur.get("desc") or "")[:400],
            "pid": cur.get("pid") or "",
            "signed": sig["signed"],
            "signer": sig["signer"],
            "company": sig["company"],
            "sig_status": sig["sig_status"],
            "sig_type": sig["sig_type"],
        })
        cur = {}

    for ln in (text or "").splitlines():
        if ln.startswith("===== "):
            flush()
            cur["name"] = ln.strip().strip("=").strip()
            continue
        if ln.startswith("FragmentPath="):
            cur["frag"] = ln.split("=", 1)[1].strip()
        elif ln.startswith("ExecStart="):
            body = ln.split("=", 1)[1]
            m = re.search(r"path=([^ ;]+)", body)
            if m:
                cur["exec"] = m.group(1)
            else:
                for tok in re.split(r"[\s=;{}]+", body):
                    if tok.startswith("/"):
                        cur["exec"] = tok
                        break
            # argv[]= 完整命令行（含参数）
            am = re.search(r"argv\[\]=([^;]+)", body)
            if am:
                cur["exec_cmd"] = am.group(1).strip()
            elif cur.get("exec"):
                # 退化：取 = 后第一个绝对路径起的片段
                cur["exec_cmd"] = cur["exec"]
        elif ln.startswith("MainPID="):
            cur["pid"] = ln.split("=", 1)[1].strip()
        elif ln.startswith("ActiveState="):
            cur["active"] = ln.split("=", 1)[1].strip()
        elif ln.startswith("SubState="):
            cur["sub"] = ln.split("=", 1)[1].strip()
        elif ln.startswith("UnitFileState="):
            cur["unit_state"] = ln.split("=", 1)[1].strip()
        elif ln.startswith("Description="):
            cur["desc"] = ln.split("=", 1)[1].strip()
        if len(services) >= 3000:
            break
    flush()
    return services[:3000]


def _parse_file_inventory(text: str, pkgmap: Optional[Dict[str, Tuple[str, str]]] = None) -> List[Dict[str, Any]]:
    """Parse Files/file_inventory.tsv；pkgmap 来自 Files/file_bin_pkg.txt（仅已查路径）。"""
    pkgmap = pkgmap or {}
    rows: List[Dict[str, Any]] = []
    for ln in (text or "").splitlines():
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split("\t")
        if len(parts) < 1:
            continue
        full = parts[0].strip()
        if not full.startswith("/"):
            continue
        size = 0
        try:
            size = int(parts[1]) if len(parts) > 1 and parts[1] else 0
        except Exception:
            size = 0
        # 新格式: path size mtime mode owner group type flags
        # 旧格式: path size mtime flags
        if len(parts) >= 7:
            mtime = parts[2] if len(parts) > 2 else ""
            mode = parts[3] if len(parts) > 3 else ""
            owner = parts[4] if len(parts) > 4 else ""
            group = parts[5] if len(parts) > 5 else ""
            file_type = parts[6] if len(parts) > 6 else "f"
            flags = parts[7] if len(parts) > 7 else ""
        else:
            mtime = parts[2] if len(parts) > 2 else ""
            mode = ""
            owner = ""
            group = ""
            file_type = "f"
            flags = parts[3] if len(parts) > 3 else ""
        name = full.rsplit("/", 1)[-1]
        parent = full.rsplit("/", 1)[0] if "/" in full else ""
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        row: Dict[str, Any] = {
            "full_path": full[:1000],
            "name": name[:260],
            "path": parent[:1000],
            "ext": ext[:32],
            "size": size,
            "mtime": str(mtime or "")[:40],
            "mode": str(mode or "")[:32],
            "owner": str(owner or "")[:64],
            "group": str(group or "")[:64],
            "file_type": str(file_type or "f")[:8],
            "signed": None,
            "signer": "",
            "company": "",
            "description": flags[:200],
            "product": "",
            "file_version": "",
            "sig_status": "unchecked",
            "sig_type": "",
            "hidden": name.startswith("."),
            "system": False,
            "root": "linuxsc",
        }
        if full in pkgmap:
            sig = _pkg_sig_fields(full, pkgmap)
            row["signed"] = sig["signed"]
            row["signer"] = sig["signer"]
            row["company"] = sig["company"]
            row["sig_status"] = sig["sig_status"]
            row["sig_type"] = sig["sig_type"]
        rows.append(row)
        if len(rows) >= 100_000:
            break
    return rows


def _is_private_or_local(addr: str) -> bool:
    host = (addr or "").rsplit("%", 1)[0].strip()
    if host in ("*", "0.0.0.0", "::", "::1", "127.0.0.1", ""):
        return True
    if host.startswith("["):
        host = host.strip("[]")
    else:
        if host.count(":") == 1 and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", host):
            host = host.rsplit(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host.split("/")[0])
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)
    except Exception:
        return False  # 主机名等：不当作内网过滤掉


def _split_addr_port(token: str) -> Tuple[str, str]:
    t = (token or "").strip()
    if not t:
        return "", ""
    if t.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", t)
        if m:
            return m.group(1), m.group(2)
        return t.strip("[]"), ""
    if t.count(":") == 1:
        h, p = t.rsplit(":", 1)
        return h, p
    # ipv6 with :port at end
    m = re.match(r"^(.+):(\d+)$", t)
    if m and t.count(":") > 1:
        return m.group(1), m.group(2)
    return t, ""


def _pid_from_ss_proc(proc: str) -> str:
    """从 ss 进程字段解析 pid=N。"""
    m = re.search(r"pid\s*=\s*(\d+)", str(proc or ""), re.I)
    return m.group(1) if m else ""


def _parse_ss(text: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return (established_connections, open_ports)."""
    conns: List[Dict[str, Any]] = []
    ports: List[Dict[str, Any]] = []
    seen_port = set()
    for ln in (text or "").splitlines():
        if not ln.strip() or ln.lower().startswith("netid") or ln.lower().startswith("proto"):
            continue
        parts = ln.split()
        if len(parts) < 5:
            continue
        # ss: Netid State Recv-Q Send-Q Local Peer [Process]
        # netstat: Proto Recv-Q Send-Q Local Foreign State PID/Program
        proto = parts[0]
        if proto in ("tcp", "tcp6", "udp", "udp6", "u_str", "u_dgr", "u_seq"):
            state = parts[1] if len(parts) > 1 else ""
            local = parts[4] if len(parts) > 4 else ""
            peer = parts[5] if len(parts) > 5 else ""
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
        elif re.match(r"(?i)tcp|udp", proto):
            # netstat style
            local = parts[3] if len(parts) > 3 else ""
            peer = parts[4] if len(parts) > 4 else ""
            state = parts[5] if len(parts) > 5 else ""
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
        else:
            continue
        lhost, lport = _split_addr_port(local)
        rhost, rport = _split_addr_port(peer)
        if lport and lport not in seen_port:
            seen_port.add(lport)
            ports.append({
                "protocol": proto,
                "local_addr": f"{lhost}:{lport}" if lport else local,
                "local_address": lhost,
                "local_port": lport,
                "state": state,
                "process": proc[:300],
                "pid": _pid_from_ss_proc(proc),
            })
        st = (state or "").upper()
        # 已建立连接：保留公网与内网横向；仅丢弃未指定/本机回环对端
        if st in ("ESTAB", "ESTABLISHED") and rhost and rhost not in ("*", "0.0.0.0", "::", ""):
            try:
                rip = ipaddress.ip_address(rhost.split("%")[0])
                skip = bool(rip.is_loopback or rip.is_unspecified)
            except Exception:
                skip = False
            if not skip:
                conns.append({
                    "protocol": proto,
                    "local_addr": local,
                    "local_address": local,
                    "remote_addr": peer,
                    "remote_address": peer,
                    "remote_ip": rhost,
                    "remote_port": rport,
                    "state": state,
                    "process": proc[:300],
                    "pid": _pid_from_ss_proc(proc),
                    "remote_is_private": _is_private_or_local(rhost),
                })
        if len(conns) >= _MAX_CONN:
            break
    return conns[:_MAX_CONN], ports[:2000]


def _parse_lsmod(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    start = 1 if lines and re.search(r"Module", lines[0], re.I) else 0
    for ln in lines[start:3000]:
        parts = ln.split()
        if not parts:
            continue
        name = parts[0]
        size = parts[1] if len(parts) > 1 else ""
        used = parts[2] if len(parts) > 2 else ""
        by = " ".join(parts[3:]) if len(parts) > 3 else ""
        rows.append({
            "name": name,
            "path": "",
            "size": size,
            "used_by": by,
            "ref_count": used,
            "signed": None,
            "company": "",
            "description": f"kernel module · refs={used}",
        })
    return rows


def _parse_systemctl_units(text: str) -> List[Dict[str, Any]]:
    services: List[Dict[str, Any]] = []
    for ln in (text or "").splitlines():
        if not ln.strip() or ln.startswith("UNIT") or ln.startswith("UNIT FILE"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        if not (name.endswith(".service") or name.endswith(".timer") or name.endswith(".socket")):
            continue
        state = parts[1] if len(parts) > 1 else ""
        sub = parts[2] if len(parts) > 2 else ""
        desc = " ".join(parts[4:]) if len(parts) > 4 else " ".join(parts[1:])
        services.append({
            "name": name,
            "status": state,
            "start_type": sub,
            "path": "",
            "description": desc[:400],
            "pid": "",
            "signed": None,
            "company": "",
        })
        if len(services) >= 3000:
            break
    return services


def _cron_tasks(root: Path, pkgmap: Optional[Dict[str, Tuple[str, str]]] = None) -> List[Dict[str, Any]]:
    pkgmap = pkgmap or {}
    tasks: List[Dict[str, Any]] = []
    p = root / "Persistence"
    candidates = [
        p / "crontab_all_users.txt",
        p / "etc" / "crontab",
    ]
    cron_d = p / "etc" / "cron.d"
    if cron_d.is_dir():
        for f in sorted(cron_d.iterdir())[:200]:
            if f.is_file():
                candidates.append(f)
    for f in candidates:
        text = _read_text(f, 200_000)
        if not text.strip():
            continue
        for ln in text.splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or s.startswith("====="):
                continue
            if s.startswith("no crontab") or s.startswith("(crontab"):
                continue
            path = _first_abs_path(s)
            sig = _pkg_sig_fields(path, pkgmap) if path else {
                "signed": None, "signer": "", "company": "", "sig_status": "unchecked", "sig_type": "",
            }
            tasks.append({
                "task_name": f"cron:{f.name}",
                "name": f"cron:{f.name}",
                "command": s[:1500],
                "status": "enabled",
                "path": path or str(f.relative_to(root)).replace("\\", "/"),
                "resolved_path": path,
                "next_run": "",
                "author": "",
                "signed": sig["signed"],
                "signer": sig["signer"],
                "company": sig["company"],
                "sig_status": sig["sig_status"],
                "sig_type": sig["sig_type"],
            })
            if len(tasks) >= 2000:
                return tasks
    timers = p / "systemctl_list_timers.txt"
    if timers.is_file():
        for ln in _read_text(timers, 200_000).splitlines()[1:500]:
            parts = ln.split()
            if not parts:
                continue
            unit = parts[-1]
            if not unit.endswith(".timer"):
                continue
            tasks.append({
                "task_name": unit,
                "name": unit,
                "command": ln.strip()[:1500],
                "status": "timer",
                "path": "systemd",
                "next_run": "",
                "author": "",
                "signed": None,
                "signer": "",
                "company": "",
                "sig_status": "unchecked",
                "sig_type": "",
            })
            if len(tasks) >= 2000:
                return tasks
    return tasks


def _startup_items(
    root: Path,
    pkgmap: Optional[Dict[str, Tuple[str, str]]] = None,
    services: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Linux 启动项：真实路径 + 包归属签名（对齐进程/服务字段）。"""
    pkgmap = pkgmap or {}
    items: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _add(
        *,
        name: str,
        path: str,
        command: str = "",
        location: str,
        user: str = "root",
        enabled: bool = True,
        bin_path: str = "",
    ) -> None:
        key = f"{location}|{name}|{path}"
        if key in seen:
            return
        seen.add(key)
        lookup = (bin_path or path or "").strip()
        # 命令行里抽出第一个绝对路径作签名查询
        if not lookup.startswith("/") and command:
            for tok in re.split(r"[\s;|&]+", command):
                t = tok.strip().strip("\"'")
                if t.startswith("/"):
                    lookup = t
                    break
        sig = _pkg_sig_fields(lookup, pkgmap) if lookup.startswith("/") else {
            "signed": None, "signer": "", "company": "", "sig_status": "unchecked", "sig_type": "",
        }
        items.append({
            "name": name[:260],
            "command": (command or path or "")[:2000],
            "path": (path or lookup or "")[:1000],
            "location": location,
            "user": user,
            "enabled": enabled,
            "signed": sig["signed"],
            "signer": sig["signer"],
            "company": sig["company"],
            "sig_status": sig["sig_status"],
            "sig_type": sig["sig_type"],
        })

    p = root / "Persistence"
    preload = _first_existing(p / "etc" / "ld.so.preload")
    if preload:
        body = _read_text(preload, 50_000).strip()
        # preload 内容常是 .so 路径；签名取第一个绝对路径
        first_so = ""
        for tok in re.split(r"\s+", body):
            if tok.startswith("/"):
                first_so = tok
                break
        _add(
            name="ld.so.preload",
            path="/etc/ld.so.preload",
            command=body[:2000] or "(empty)",
            location="ld.so.preload",
            bin_path=first_so or "/etc/ld.so.preload",
        )

    for cand, real in (
        (p / "etc" / "rc.local", "/etc/rc.local"),
        (p / "etc" / "rc.d" / "rc.local", "/etc/rc.d/rc.local"),
    ):
        if cand.is_file():
            _add(
                name="rc.local",
                path=real,
                command=_read_text(cand, 50_000)[:2000],
                location="rc.local",
                bin_path=real,
            )
            break

    # profile.d / bashrc（用真实系统路径）
    for rel, loc in (
        ("etc/profile.d", "profile.d"),
        ("etc/bash.bashrc", "bash.bashrc"),
        ("etc/bashrc", "bashrc"),
        ("etc/profile", "profile"),
    ):
        target = p / rel
        if target.is_file():
            real = f"/{rel.replace(chr(92), '/')}"
            _add(
                name=target.name,
                path=real,
                command=_read_text(target, 20_000)[:800],
                location=loc,
                bin_path=real,
            )
        elif target.is_dir():
            for f in sorted(target.glob("*"))[:80]:
                if not f.is_file():
                    continue
                real = f"/etc/profile.d/{f.name}" if "profile.d" in rel else f"/{rel}/{f.name}"
                _add(
                    name=f.name,
                    path=real,
                    command=_read_text(f, 20_000)[:800],
                    location=loc,
                    bin_path=real,
                )
                if len(items) >= 400:
                    break

    # 用户级 shell rc（采集镜像）：LinuxSC v1.40 起按 /etc/passwd 家目录复制，
    # 服务账号家目录可能在 /var/lib/*、/opt/* 等，不能只看 home/* 与 root/
    rc_names = {
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
        ".profile", ".zshrc", ".zprofile", ".zshenv",
    }
    rc_files = sorted(
        f for f in p.rglob(".*")
        if f.name in rc_names and f.is_file()
    ) if p.is_dir() else []
    for f in rc_files:
        try:
            rel = f.relative_to(p).as_posix()
        except Exception:
            continue
        if rel.startswith("etc/"):
            continue
        # Persistence/var/lib/postgres/.bashrc → /var/lib/postgres/.bashrc
        real = "/" + rel
        parent = real.rsplit("/", 2)
        user = parent[-2] if len(parent) >= 2 and parent[-2] else "root"
        body = _read_text(f, 60_000)
        # 去注释/空行后取尾部：后门通常追加在 rc 末尾
        eff = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        _add(
            name=f"{user}/{f.name}",
            path=real,
            command=" ".join(eff)[-1500:],
            location="user_shell_rc",
            user=user,
            bin_path=real,
        )
        if len(items) >= 500:
            break

    # systemd enabled：仅 UnitFileState 含 enabled（不用 ActiveState 冒充开机自启）
    svc_by_name: Dict[str, Dict[str, Any]] = {}
    for svc in services or []:
        if isinstance(svc, dict) and svc.get("name"):
            svc_by_name[str(svc["name"])] = svc

    for svc in services or []:
        if not isinstance(svc, dict):
            continue
        name = str(svc.get("name") or "")
        if not name.endswith(".service"):
            continue
        st = str(svc.get("start_type") or "").lower()
        if "enabled" not in st:
            continue
        if "disabled" in st or "masked" in st:
            continue
        path = str(svc.get("path") or "")
        cmd = str(svc.get("command") or path or "")
        frag = str(svc.get("fragment_path") or "")
        display_path = path or frag or name
        _add(
            name=name,
            path=display_path,
            command=cmd or f"systemctl:{st}",
            location="systemd-unit",
            bin_path=path or frag,
            enabled=True,
        )
        if len(items) >= 800:
            break

    # 若无 services 详情，退回 unit-files 列表；有同名服务则回填路径/签名
    if not any(x.get("location") == "systemd-unit" for x in items):
        uf = _read_text(p / "systemctl_list_unit_files.txt")
        for ln in uf.splitlines():
            parts = ln.split()
            if len(parts) < 2:
                continue
            name, st = parts[0], parts[1]
            if not name.endswith(".service") or "enabled" not in st.lower():
                continue
            svc = svc_by_name.get(name) or {}
            path = str(svc.get("path") or "")
            cmd = str(svc.get("command") or path or "")
            frag = str(svc.get("fragment_path") or "")
            _add(
                name=name,
                path=path or frag or name,
                command=cmd or f"systemctl:{st}",
                location="systemd-unit",
                bin_path=path or frag,
                enabled=True,
            )
            if len(items) >= 400:
                break

    return items[:800]


def enrich_linux_startups(report: Dict[str, Any]) -> Dict[str, Any]:
    """用 services 回填 startup_items 的真实路径/命令/签名（兼容旧报告占位符）。"""
    if not isinstance(report, dict):
        return report
    if str(report.get("os_family") or "").lower() != "linux" and report.get("collector") != "linuxsc":
        return report
    startups = report.get("startup_items")
    services = report.get("services")
    if not isinstance(startups, list) or not isinstance(services, list):
        return report
    by_name: Dict[str, Dict[str, Any]] = {}
    for svc in services:
        if isinstance(svc, dict) and svc.get("name"):
            by_name[str(svc["name"])] = svc
    if not by_name:
        return report
    out: List[Dict[str, Any]] = []
    for si in startups:
        if not isinstance(si, dict):
            out.append(si)
            continue
        row = dict(si)
        name = str(row.get("name") or "")
        loc = str(row.get("location") or "")
        path = str(row.get("path") or "")
        cmd = str(row.get("command") or "")
        need = (
            loc == "systemd-unit"
            or name.endswith(".service")
            or (not path.startswith("/") and name.endswith(".service"))
            or cmd.startswith("systemctl:")
            or path == name
        )
        svc = by_name.get(name) if need else None
        if svc:
            sp = str(svc.get("path") or "")
            sc = str(svc.get("command") or sp or "")
            frag = str(svc.get("fragment_path") or "")
            if sp.startswith("/") or frag.startswith("/"):
                row["path"] = sp or frag
            if sc and (not cmd or cmd.startswith("systemctl:") or cmd == path or cmd == name):
                row["command"] = sc
            for k in ("signed", "signer", "company", "sig_status", "sig_type"):
                if svc.get(k) is not None and svc.get(k) != "" and (
                    row.get(k) in (None, "", "unchecked") or k not in row
                ):
                    row[k] = svc.get(k)
            if row.get("location") in ("", None) and name.endswith(".service"):
                row["location"] = "systemd-unit"
        out.append(row)
    report["startup_items"] = out
    return report


def _remote_access(root: Path) -> Dict[str, Any]:
    ssh = root / "SSH"
    keys: List[Dict[str, Any]] = []
    for f in ssh.rglob("authorized_keys*"):
        if not f.is_file():
            continue
        text = _read_text(f, 100_000)
        n = sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))
        keys.append({
            "path": str(f.relative_to(root)).replace("\\", "/"),
            "count": n,
            "preview": "\n".join(
                ln.strip()[:120] for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )[:800],
        })
    cfg = _read_text(_first_existing(ssh / "sshd_T_effective_config.txt", ssh / "etc" / "ssh" / "sshd_config") or Path(), 100_000)
    return {
        "ssh_keys": keys,
        "sshd_config": cfg[:8000],
        "rdp_files": [],
        "remote_tools": [],
        "cred_stores": [],
    }


def _parse_shell_history(root: Path) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    hist_dir = root / "Hunt" / "shell_history"
    if hist_dir.is_dir():
        for f in sorted(hist_dir.glob("*.txt"))[:80]:
            text = _read_text(f, 600_000)
            user = f.stem[:120]
            # 每个文件取最近 1500 条：历史文件尾部才是最新活动
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()][-1500:]
            for s in lines:
                entries.append({
                    "user": user,
                    "command": s[:800],
                    "source": f.name,
                })
            if len(entries) >= 12000:
                break
    return {"history_entries": entries, "profiles": [], "logging": []}


def _security_extras(root: Path) -> Dict[str, Any]:
    rk = root / "RootkitHunt"
    sec = root / "Security"
    hunt = root / "Hunt"
    extras: Dict[str, Any] = {"linuxsc": True}
    for f in [
        rk / "proc_stack_packet_recvmsg.txt",
        rk / "proc_net_packet.txt",
        rk / "packet_socket_fd.txt",
        root / "Kernel" / "module_source_diff.txt",
        root / "Kernel" / "modules_builtin_names.txt",
        root / "Persistence" / "etc" / "ld.so.preload",
        sec / "sysctl_security.txt",
        sec / "selinux_status.txt",
        sec / "apparmor_status.txt",
        sec / "sshd_security_keys.txt",
        sec / "pwquality.txt",
        sec / "firewall_summary.txt",
        sec / "audit_rules.txt",
        sec / "audit_pol.txt",
        hunt / "hacker_tools.txt",
        hunt / "webshell_hits.txt",
        hunt / "miner_procs.txt",
        hunt / "risk_ports.txt",
        hunt / "redis_bind.txt",
        hunt / "ssh_symlink_backdoor.txt",
        hunt / "ssh_symlink_runtime.txt",
        hunt / "ssh_symlink_find.txt",
        hunt / "sshd_wrapper.txt",
        hunt / "inetd_xinetd.txt",
        hunt / "ssh_client_config.txt",
        hunt / "pam_security_sos.txt",
        hunt / "prompt_command.txt",
        hunt / "pam_d_extra.txt",
        hunt / "path_hijack.txt",
        hunt / "vimrc_shell.txt",
        hunt / "ld_library_path.txt",
        hunt / "authorized_keys_file.txt",
        hunt / "loaded_unsigned_so.txt",
        hunt / "disk_unsigned_so.txt",
        hunt / "cred_drop_paths.txt",
        hunt / "systemd_sus_exec.txt",
        hunt / "fake_binaries.txt",
        hunt / "services_high_ports.txt",
        root / "SystemInfo" / "alias.txt",
        root / "SystemInfo" / "uid0_accounts.txt",
        root / "SystemInfo" / "empty_password_users.txt",
        root / "SSH" / "sshd_bin_meta.txt",
        root / "RootkitHunt" / "rpm_Va_keypkgs.txt",
        root / "RootkitHunt" / "debsums_keypkgs.txt",
        root / "RootkitHunt" / "dpkg_V_keypkgs.txt",
        root / "Security" / "suid_sgid_files.txt",
        root / "Files" / "suid_sgid.txt",
        root / "Security" / "etc" / "sudoers",
    ]:
        if f.is_file():
            key = f.stem if f.name != "ld.so.preload" else "ld_so_preload"
            if f.name == "alias.txt":
                key = "alias"
            if f.name in ("suid_sgid_files.txt", "suid_sgid.txt"):
                key = "suid_sgid_files"
            if f.name == "sudoers":
                key = "sudoers"
            # 与 LinuxSC JSON security_extras 键名对齐
            if key == "rpm_Va_keypkgs":
                key = "rpm_va_keypkgs"
            # 不覆盖已有更完整的同名键
            if key == "suid_sgid_files" and str(extras.get(key) or "").strip():
                continue
            extras[key] = _read_text(f, 100_000)[:50_000]
    # sudoers.d 片段合并
    sudod = root / "Security" / "etc" / "sudoers.d"
    if sudod.is_dir():
        bits: List[str] = []
        for sf in sorted(sudod.iterdir())[:40]:
            if sf.is_file() and not sf.name.startswith("."):
                body = _read_text(sf, 20_000)[:8_000]
                if body.strip():
                    bits.append(f"# --- {sf.name} ---\n{body}")
        if bits:
            extras["sudoers"] = (
                (str(extras.get("sudoers") or "") + "\n" + "\n".join(bits))
            )[:50_000]
    # deb/dpkg 校验并入 rpm_va_keypkgs 供启发式统一消费（不覆盖已有 rpm 结果）
    if not str(extras.get("rpm_va_keypkgs") or "").strip():
        for alt in ("debsums_keypkgs", "dpkg_V_keypkgs"):
            if str(extras.get(alt) or "").strip():
                extras["rpm_va_keypkgs"] = extras[alt]
                break
    extras["rootkit_hunt"] = {
        "files": [str(x.relative_to(root)).replace("\\", "/") for x in rk.rglob("*") if x.is_file()][:200]
    } if rk.is_dir() else {}
    err = _read_text(root / "_COLLECT_ERRORS.log", 200_000)
    if err:
        extras["collect_errors"] = err[:100_000]
    return extras


def _event_logs_from_journal(root: Path) -> List[Dict[str, Any]]:
    """Map journal snippets into a light event_logs list for UI."""
    logs: List[Dict[str, Any]] = []
    for name, channel in (
        ("journalctl_xe.txt", "journalctl-xe"),
        ("journalctl_sshd_unit.txt", "sshd"),
        ("last.txt", "last"),
        ("lastb.txt", "lastb"),
    ):
        text = _read_text(root / "Logs" / name, 300_000)
        if not text.strip():
            continue
        for i, ln in enumerate(text.splitlines()[:400]):
            msg = _strip_journal_decor(ln)
            if not msg:
                continue
            logs.append({
                "channel": channel,
                "provider": "linuxsc",
                "event_id": "",
                "level": "info",
                "time": "",
                "message": msg[:1000],
                "record_id": f"{channel}-{i}",
            })
    return logs[:2000]


def convert_linuxsc_dir(path: Path) -> Dict[str, Any]:
    root = find_linuxsc_root(Path(path))
    errors: List[str] = []

    collect_time, tz = _parse_collection_time(_read_text(root / "_COLLECTION_TIME.txt"))
    os_rel = _parse_os_release(_read_text(root / "SystemInfo" / "os_release.txt"))
    uname = _read_text(root / "SystemInfo" / "uname_a.txt").strip()
    hostctl = _read_text(root / "SystemInfo" / "hostnamectl.txt")
    hostname = (
        _hostname_from_ctl(hostctl)
        or os_rel.get("HOSTNAME")
        or _hostname_from_outdir(root)
        or "linux-host"
    )
    hostname = re.sub(r"[\\/:*?\"<>|\s]+", "-", hostname).strip("-")[:128] or "linux-host"
    ip = _ip_from_outdir(root)

    passwd_path = _first_existing(
        root / "SystemInfo" / "etc" / "passwd",
        root / "SystemInfo" / "passwd",
    )
    group_path = _first_existing(
        root / "SystemInfo" / "etc" / "group",
        root / "SystemInfo" / "group",
        root / "SystemInfo" / "getent_group.txt",
    )
    birth_path = _first_existing(
        root / "SystemInfo" / "user_home_birth.tsv",
        root / "SystemInfo" / "user_home_birth.txt",
    )
    users = _parse_passwd(
        _read_text(passwd_path or Path()),
        _read_text(group_path or Path()),
        _read_text(birth_path or Path()),
    )
    if not users:
        errors.append("MISS users: passwd not found")

    ps_text = _read_text(root / "ProcInfo" / "ps_eo_ppid.txt")
    if not ps_text.strip():
        ps_text = _read_text(root / "ProcInfo" / "ps_auxwwf.txt")
    processes = _parse_ps_aux(ps_text)
    pkg_text = _read_text(root / "Persistence" / "bin_pkg.txt")
    if not pkg_text.strip():
        pkg_text = _read_text(root / "Persistence" / "service_bin_pkg.txt")
    pkgmap = _parse_bin_pkg(pkg_text)
    _attach_process_modules(
        processes,
        _parse_proc_modules(_read_text(root / "ProcInfo" / "proc_loaded_modules.tsv")),
        pkgmap,
    )
    if not processes:
        errors.append("MISS processes: ps_eo_ppid.txt / ps_auxwwf.txt empty")

    ss_text = _read_text(root / "Network" / "ss_tuanp.txt") or _read_text(root / "Network" / "netstat_tuanp.txt")
    conns, ports = _parse_ss(ss_text)

    svc_details = _read_text(root / "Persistence" / "systemd_service_details.txt")
    svc_pkg = pkg_text or _read_text(root / "Persistence" / "service_bin_pkg.txt")
    if svc_details.strip():
        services = _parse_service_details(svc_details, svc_pkg)
    else:
        services = _parse_systemctl_units(
            _read_text(root / "Persistence" / "systemctl_list_units_all.txt")
            or _read_text(root / "Persistence" / "systemctl_list_unit_files.txt")
        )
    tasks = _cron_tasks(root, pkgmap)
    startups = _startup_items(root, pkgmap, services)
    modinfo = _read_text(root / "Kernel" / "modinfo_all.txt")
    drivers = _parse_modinfo(modinfo) if modinfo.strip() else _parse_lsmod(_read_text(root / "Kernel" / "lsmod.txt"))
    file_pkg = _parse_bin_pkg(
        _read_text(root / "Files" / "file_bin_pkg.txt")
        or _read_text(root / "Persistence" / "bin_pkg.txt")
    )
    # 合并进程/服务包表，便于清单命中同一路径
    for k, v in pkgmap.items():
        file_pkg.setdefault(k, v)
    file_scans = _parse_file_inventory(_read_text(root / "Files" / "file_inventory.tsv"), file_pkg)
    remote = _remote_access(root)
    security = _security_extras(root)
    event_logs = _event_logs_from_journal(root)

    firewall = _read_text(root / "Network" / "iptables_save.txt") or _read_text(root / "Network" / "nft_ruleset.txt")
    resolv = _read_text(
        _first_existing(root / "Network" / "etc" / "resolv.conf", root / "Network" / "resolv.conf") or Path()
    )
    audit_pol = _read_text(root / "Security" / "audit_pol.txt", 200_000)

    pretty = os_rel.get("PRETTY_NAME") or os_rel.get("NAME") or "Linux"
    if uname and pretty == "Linux":
        pretty = uname[:120]

    manifest = _read_text(root / "_HASH_MANIFEST.txt", 500_000)
    footprint = _read_text(root / "_COLLECT_FOOTPRINT.txt", 200_000)

    report: Dict[str, Any] = {
        "hostname": hostname,
        "ip": ip,
        "os": pretty,
        "os_family": "linux",
        "collect_time": collect_time or "",
        "collector": "linuxsc",
        "source": "linuxsc",
        "timezone": tz,
        "system_info": {
            "os": pretty,
            "pretty_name": os_rel.get("PRETTY_NAME") or pretty,
            "id": os_rel.get("ID") or "",
            "version_id": os_rel.get("VERSION_ID") or "",
            "uname": uname,
            "hostnamectl": hostctl[:4000],
            "uptime": _read_text(root / "SystemInfo" / "uptime.txt").strip()[:500],
        },
        "processes": processes,
        "users": users,
        "services": services,
        "scheduled_tasks": tasks,
        "startup_items": startups,
        "drivers": drivers,
        "driver_entries": drivers,
        "file_scans": file_scans,
        "ps_artifacts": _parse_shell_history(root),
        "established_connections": conns,
        "open_ports": ports,
        "network": {
            "ss": ss_text[:100_000],
            "resolv_conf": resolv[:5000],
            "firewall": firewall[:100_000],
            "arp": _read_text(root / "Network" / "arp_an.txt", 50_000)[:30_000],
            "route": _read_text(root / "Network" / "ip_route.txt", 50_000)[:20_000],
        },
        "firewall_rules": firewall[:80_000],
        "audit_pol": audit_pol[:120_000],
        "remote_access": remote,
        "security_extras": security,
        "event_logs": event_logs,
        "event_log_summary": {"channels": list({e.get("channel") for e in event_logs})},
        "hosts_file": _read_text(
            _first_existing(root / "Network" / "etc" / "hosts", root / "SystemInfo" / "etc" / "hosts") or Path(),
            50_000,
        ),
        "errors": errors,
        "collection_quality": {
            "collector": "linuxsc",
            "version": _detect_linuxsc_version(root, footprint) or "unknown",
            "has_manifest": bool(manifest.strip()),
            "manifest_lines": len([x for x in manifest.splitlines() if x.strip()]) if manifest else 0,
            "process_count": len(processes),
            "user_count": len(users),
            "service_count": len(services),
            "connection_count": len(conns),
            "file_count": len(file_scans),
            "footprint_preview": footprint[:2000],
        },
        "linuxsc_raw": {
            "root_name": root.name,
            "preload": _read_text(
                _first_existing(root / "Persistence" / "etc" / "ld.so.preload") or Path(), 20_000
            ),
            "deleted_exe": _read_text(root / "ProcInfo" / "proc_exe_deleted.txt", 50_000)[:30_000],
            "environ_ld": _read_text(root / "ProcInfo" / "proc_environ_LD.txt", 50_000)[:30_000],
        },
    }
    report = enrich_linux_entity_sigs(report)
    try:
        from .net_process import enrich_report_connections
        enrich_report_connections(report)
    except Exception:
        pass
    return enrich_linux_startups(report)
