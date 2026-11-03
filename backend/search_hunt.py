"""跨主机威胁狩猎（检索 · 狩猎页）。

两种视角（同一操作系统内比较，Windows 不和 Linux 比）：
- rare（稀有）：只出现在少数主机上的可疑指纹。需要同系统主机足够多才有区分力。
- spread（扩散）：同一可疑指纹出现在 ≥2 台主机，提示批量投放 / 横向移动。

只因「稀有」而无任何可疑特征（脏路径、LOLBin、未签名等）的条目不展示。

信号类型：
- run：启动项名
- task_cmd：计划任务命令骨架
- service：服务名 / 映像路径
- finding：高/中危告警规则
- drop_path：可疑落点目录骨架（AppData/ProgramData/随机盘符目录）
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import paths as P
from . import db_store

_CACHE: Dict[str, Any] = {"ts": 0.0, "payload": None}
_CACHE_TTL_SEC = 60.0

# 同系统主机少于该数时，「稀有」几乎人人命中，区分力很弱
BASELINE_MIN_HOSTS = 10

_OS_LABEL = {"windows": "Windows", "linux": "Linux", "unknown": "未知系统"}

_USER_PATH_RE = re.compile(
    r"(?i)([a-z]:\\users\\)[^\\]+(\\appdata\\(?:local|roaming)\\)",
)
_DRIVE_RAND_RE = re.compile(
    r"(?i)([a-z]:\\)(?!(?:windows|program files(?: \(x86\))?|programdata|users)\\)"
    r"[^\\]{1,20}\\[a-z0-9]{2,8}(\\)",
)
_QUOTES_RE = re.compile(r'[\'"]+')
_WS_RE = re.compile(r"\s+")
_MS_TASK_PREFIX = re.compile(r"(?i)^\\microsoft\\")
_PATH_RE = re.compile(r"([a-zA-Z]:\\[^\s\"'|]+)")

_KIND_LABEL = {
    "run": "稀有启动项",
    "task_cmd": "稀有任务命令",
    "service": "稀有服务",
    "finding": "稀有告警",
    "drop_path": "可疑落点",
}

_DIRTY_TOKENS = (
    ("conhost", 3, "conhost"),
    ("headless", 2, "headless"),
    ("cmd /c", 2, "cmd"),
    ('start ""', 2, "start"),
    ("cd /d", 2, "cd"),
    ("appdata", 2, "appdata"),
    ("programdata", 2, "programdata"),
    ("\\temp\\", 2, "temp"),
    ("powershell", 2, "powershell"),
    ("rundll32", 2, "rundll32"),
    ("regsvr32", 2, "regsvr32"),
    ("mshta", 2, "mshta"),
    ("wscript", 2, "wscript"),
    ("cscript", 2, "cscript"),
    ("bitsadmin", 2, "bits"),
    ("certutil", 2, "certutil"),
    ("userinitmpr", 3, "logon_script"),
    ("drivers.dat", 3, "drivers.dat"),
    ("未签名", 2, "unsigned"),
    ("sideload", 3, "sideload"),
    ("白加黑", 3, "sideload"),
)


def _norm_cmd_skeleton(cmd: str) -> str:
    s = str(cmd or "").strip()
    if not s:
        return ""
    s = _QUOTES_RE.sub("", s)
    s = _USER_PATH_RE.sub(r"\1*\2", s)
    s = _DRIVE_RAND_RE.sub(r"\1*\2", s)
    s = _WS_RE.sub(" ", s).strip().lower()
    if len(s) > 180:
        s = s[:180]
    return s


def _norm_drop_dir(path: str) -> str:
    """落点目录骨架：弱化用户名与短随机段。"""
    s = str(path or "").strip().strip('"').strip("'")
    if not s:
        return ""
    s = s.replace("/", "\\")
    # 只要目录
    if re.search(r"\.[a-z0-9]{2,5}$", s, re.I):
        s = str(Path(s).parent)
    s = _USER_PATH_RE.sub(r"\1*\2", s)
    s = _DRIVE_RAND_RE.sub(r"\1*\2", s)
    parts = [p for p in s.split("\\") if p]
    if len(parts) > 5:
        parts = parts[:5]
    return "\\".join(parts).lower()


def _load_persist_pack(rid: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """返回 (startup_items, scheduled_tasks, services)。"""
    rid = P.report_id(rid)
    out_su: List[Dict] = []
    out_tk: List[Dict] = []
    out_sv: List[Dict] = []

    pack_path = P.report_dir(rid) / "pack" / "persistence.json"
    if pack_path.is_file():
        try:
            data = json.loads(pack_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                su = data.get("startup_items") or []
                tk = data.get("scheduled_tasks") or []
                sv = data.get("services") or []
                if isinstance(su, list):
                    out_su = [x for x in su if isinstance(x, dict)]
                if isinstance(tk, list):
                    out_tk = [x for x in tk if isinstance(x, dict)]
                if isinstance(sv, list):
                    out_sv = [x for x in sv if isinstance(x, dict)]
        except Exception:
            pass

    try:
        from .db_store import _connect, _load_one_blob
        from . import paths as paths_mod

        dbp = paths_mod.resolve_analysis_db(rid)
        if dbp and Path(dbp).is_file():
            conn = _connect(Path(dbp))
            try:
                if not out_su:
                    su = _load_one_blob(conn, "startup_items") or []
                    out_su = [x for x in su if isinstance(x, dict)] if isinstance(su, list) else []
                if not out_tk:
                    tk = _load_one_blob(conn, "scheduled_tasks") or []
                    out_tk = [x for x in tk if isinstance(x, dict)] if isinstance(tk, list) else []
                if not out_sv:
                    sv = _load_one_blob(conn, "services") or []
                    out_sv = [x for x in sv if isinstance(x, dict)] if isinstance(sv, list) else []
            finally:
                conn.close()
    except Exception:
        pass

    if not (out_su or out_tk):
        try:
            from .db_store import load_section_page
            su_page = load_section_page(rid, "startup_items", offset=0, limit=500, q="")
            tk_page = load_section_page(rid, "scheduled_tasks", offset=0, limit=500, q="")
            su = (su_page or {}).get("items") or []
            tk = (tk_page or {}).get("items") or []
            if isinstance(su, list) and su:
                out_su = [x for x in su if isinstance(x, dict)]
            if isinstance(tk, list) and tk:
                out_tk = [x for x in tk if isinstance(x, dict)]
        except Exception:
            pass

    return out_su, out_tk, out_sv


def _load_findings_slim(rid: str, limit: int = 120) -> List[Dict[str, Any]]:
    try:
        items = db_store._load_fresh_findings(rid) or []
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for f in items:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "").lower()
        if sev not in ("high", "critical", "medium"):
            continue
        out.append(f)
        if len(out) >= limit:
            break
    return out


def _skip_common_startup_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n or len(n) < 2:
        return True
    benign = {
        "onedrive", "securityhealth", "ctfmon", "igfxtray", "igfxpers",
        "adobe acrobat synchronizer", "adobearm", "googledrivefs", "steam",
        "discord", "spotify", "ituneshelper", "sunjavaupdate",
    }
    if n in benign:
        return True
    if n.startswith("microsoft edge") or n.startswith("googlechrome") or n.startswith("chrome"):
        return True
    return False


def _skip_common_task(name: str, cmd: str) -> bool:
    tn = str(name or "")
    if _MS_TASK_PREFIX.search(tn):
        return True
    c = (cmd or "").lower()
    for tok in (
        "\\onedrive\\", "onedrivestandaloneupdater", "\\wps office\\", "ksolaunch.exe",
        "\\google\\chrome\\", "\\microsoft\\edgeupdate\\", "\\windows defender\\",
        "\\adobe\\", "\\nvidia\\", "\\lenovo\\", "\\dell\\",
    ):
        if tok in c:
            return True
    if "\\windows\\system32\\" in c and "conhost" not in c and "cmd /c" not in c:
        if not any(x in c for x in ("\\users\\", "\\appdata\\", "\\programdata\\", "\\temp\\")):
            return True
    return False


def _skip_common_service(name: str, path: str) -> bool:
    n = (name or "").strip().lower()
    p = (path or "").lower()
    if not n or len(n) < 2:
        return True
    if n.startswith(("wuauserv", "windefend", "eventlog", "spooler", "dhcp", "dnscache")):
        return True
    for tok in (
        "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\program files\\windows", "\\microsoft\\",
        "\\google\\update\\", "\\adobe\\",
    ):
        if tok in p and "appdata" not in p and "programdata" not in p:
            return True
    # 合法软件常驻 ProgramData 的服务（Defender 平台目录、NVIDIA 容器等）
    for tok in (
        "\\programdata\\microsoft\\windows defender\\",
        "\\nvidia corporation\\", "\\nvidia\\",
    ):
        if tok in p:
            return True
    return False


def _interesting_drop_path(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    if len(p) < 8:
        return False
    if not any(x in p for x in ("\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\temp\\")):
        # 盘符根下短随机目录
        if not _DRIVE_RAND_RE.search(p + "\\"):
            return False
    if any(x in p for x in ("\\microsoft\\", "\\google\\", "\\windows\\", "\\packages\\")):
        return False
    return True


# 单独出现时说服力弱的特征（合法软件也常带）；扩散视角要求有强特征或 ≥2 个弱特征
_WEAK_TAGS = frozenset({"programdata", "appdata", "temp", "unsigned", "headless"})


def _strong_enough(tags: List[str]) -> bool:
    strong = [t for t in tags if t not in _WEAK_TAGS]
    return bool(strong) or len(tags) >= 2


def _item_signals(d: Dict[str, Any]) -> List[str]:
    """条目自身的签名/白加黑信号（不依赖文本关键词）。"""
    out: List[str] = []
    if not isinstance(d, dict):
        return out
    st = str(d.get("sig_status") or d.get("SigStatus") or "").strip().lower()
    if d.get("signed") is False or st in ("unsigned", "notsigned", "not signed", "未签名"):
        out.append("unsigned")
    if d.get("sideload_suspect"):
        out.append("sideload")
    try:
        if int(d.get("black_mod_count") or 0) > 0:
            out.append("sideload")
    except (TypeError, ValueError):
        pass
    return out


def _risk_of(sample: str, kind: str = "", signals: Optional[List[str]] = None) -> Tuple[int, List[str]]:
    s = str(sample or "").lower()
    score = 1
    tags: List[str] = []
    for tok, pts, tag in _DIRTY_TOKENS:
        if tok in s and tag not in tags:
            score += pts
            tags.append(tag)
    for tag in signals or []:
        if tag not in tags:
            score += 3 if tag == "sideload" else 2
            tags.append(tag)
    if kind == "drop_path":
        score += 1
    return min(score, 20), tags[:6]


def _why_text(kind: str, host_count: int, tags: List[str], mode: str = "rare", os_total: int = 0) -> str:
    if mode == "spread":
        base = {
            "run": "同名可疑启动项出现在多台主机，像同一批投放",
            "task_cmd": "同一套可疑任务命令出现在多台主机，提示批量下发或横向移动",
            "service": "同一可疑服务出现在多台主机，核对是否同源后门",
            "finding": "同一条告警打中多台主机，可能是同一攻击链在扩散",
            "drop_path": "多台主机出现相同落点目录模式，常见于批量投放",
        }.get(kind, "同一可疑指纹出现在多台主机")
    else:
        base = {
            "run": "启动项名在同系统主机里很少见，且带可疑特征",
            "task_cmd": "任务命令骨架只出现在少数主机，且带可疑特征",
            "service": "服务名/映像路径稀有且带可疑特征，核对是否后门服务",
            "finding": "同类告警只打中少数主机，优先人工复核",
            "drop_path": "落点目录模式稀有，常见于随机目录投放",
        }.get(kind, "跨主机稀有指纹，值得排查")
    hc = f"见于 {host_count}/{os_total} 台同系统主机。" if os_total else f"见于 {host_count} 台主机。"
    tag = (" 特征：" + "、".join(tags)) if tags else ""
    return f"{base}。{hc}{tag}"


def _norm_os(row: Dict[str, Any]) -> str:
    fam = str(row.get("os_family") or "").strip().lower()
    if fam in ("windows", "linux"):
        return fam
    os_s = str(row.get("os") or "").lower()
    if "windows" in os_s:
        return "windows"
    if any(x in os_s for x in ("linux", "ubuntu", "centos", "debian", "red hat", "kylin", "uos", "euler")):
        return "linux"
    return "unknown"


def rare_persist(
    *,
    user: Optional[Dict[str, Any]] = None,
    limit: int = 40,
    max_hosts: int = 3,
    report_limit: int = 80,
    force: bool = False,
    kinds: str = "",
    mode: str = "rare",
    os_family: str = "",
) -> Dict[str, Any]:
    """跨主机狩猎。

    mode=rare：只返回同系统内出现主机数 ≤ max_hosts 且带可疑特征的指纹。
    mode=spread：同系统内出现 ≥2 台且带可疑特征的指纹（批量投放 / 横向移动）。
    kinds：逗号分隔，空=全部。
    os_family：windows|linux|空；与当前应急轨道对齐，只扫/只返回该系统（空=全部但仍按系统分组对比）。
    """
    now = time.time()
    mode = "spread" if str(mode or "").strip().lower() == "spread" else "rare"
    kind_filter = {k.strip() for k in str(kinds or "").split(",") if k.strip()}
    want_os = str(os_family or "").strip().lower()
    if want_os in ("all", "any", "*"):
        want_os = ""
    if want_os not in ("", "windows", "linux"):
        want_os = ""
    cache_key = (
        f"{bool(user)}|{limit}|{max_hosts}|{report_limit}|{mode}|"
        f"{want_os}|{','.join(sorted(kind_filter))}"
    )
    if (
        not force
        and _CACHE.get("payload")
        and _CACHE.get("key") == cache_key
        and now - float(_CACHE.get("ts") or 0) < _CACHE_TTL_SEC
    ):
        return dict(_CACHE["payload"])

    rows = db_store.list_index(limit=report_limit, user=user) or []
    latest: Dict[str, Tuple[str, str]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        hn = str(r.get("hostname") or "").strip() or "unknown"
        f = str(r.get("file") or "").strip()
        if not f:
            continue
        osf = _norm_os(r)
        if want_os and osf != want_os:
            continue
        if hn not in latest:
            latest[hn] = (f, osf)

    os_hosts: Dict[str, int] = {}
    for _f, osf in latest.values():
        os_hosts[osf] = os_hosts.get(osf, 0) + 1

    buckets: Dict[str, Dict[str, Any]] = {}

    def add(
        kind: str,
        fp: str,
        sample: str,
        hostname: str,
        rid: str = "",
        extra: Optional[Dict] = None,
        osf: str = "unknown",
        signals: Optional[List[str]] = None,
    ) -> None:
        if not fp:
            return
        if kind_filter and kind not in kind_filter:
            return
        key = f"{osf}|{kind}|{fp}"
        b = buckets.get(key)
        if not b:
            b = {
                "kind": kind,
                "os": osf,
                "fingerprint": fp,
                "sample": sample[:280],
                "hosts": set(),
                "signals": set(),
                "extra": extra or {},
                "sample_file": rid,
                "sample_host": hostname,
            }
            buckets[key] = b
        b["hosts"].add(hostname)
        for s in signals or []:
            b["signals"].add(s)
        if rid and not b.get("sample_file"):
            b["sample_file"] = rid
            b["sample_host"] = hostname

    want_findings = not kind_filter or "finding" in kind_filter

    for hn, (rid, osf) in latest.items():
        startups, tasks, services = _load_persist_pack(rid)

        for si in startups:
            name = str(si.get("name") or "").strip()
            if _skip_common_startup_name(name):
                continue
            cmd = str(si.get("command") or si.get("path") or "")
            add(
                "run", name.lower(), f"{name} => {cmd}"[:280], hn, rid,
                {"name": name, "command": cmd[:200]}, osf, _item_signals(si),
            )
            for m in _PATH_RE.finditer(cmd):
                d = _norm_drop_dir(m.group(1))
                if d and _interesting_drop_path(d):
                    add("drop_path", d, m.group(1)[:240], hn, rid, {"path": m.group(1)[:200]}, osf)

        for t in tasks:
            tname = str(t.get("task_name") or t.get("name") or "")
            cmd = str(t.get("command") or t.get("actions") or t.get("path") or "")
            if isinstance(cmd, list):
                cmd = " ".join(str(x) for x in cmd)
            if _skip_common_task(tname, cmd):
                continue
            sk = _norm_cmd_skeleton(cmd)
            if len(sk) >= 8:
                add(
                    "task_cmd",
                    sk,
                    f"{tname} => {cmd}"[:280],
                    hn,
                    rid,
                    {"task_name": tname, "command": cmd[:200]},
                    osf,
                    _item_signals(t),
                )
            for m in _PATH_RE.finditer(cmd):
                d = _norm_drop_dir(m.group(1))
                if d and _interesting_drop_path(d):
                    add("drop_path", d, m.group(1)[:240], hn, rid, {"path": m.group(1)[:200]}, osf)

        for sv in services:
            name = str(sv.get("name") or sv.get("service_name") or sv.get("display_name") or "").strip()
            path = str(
                sv.get("path")
                or sv.get("image_path")
                or sv.get("bin_path")
                or sv.get("executable")
                or ""
            ).strip()
            if _skip_common_service(name, path):
                continue
            fp = (path or name).lower()
            if len(fp) < 3:
                continue
            # 优先用映像路径 basename+父目录短指纹，避免整路径噪声
            try:
                p = Path(path.replace("/", "\\")) if path else None
                if p and p.name:
                    fp = f"{(p.parent.name or '').lower()}\\{p.name.lower()}"
            except Exception:
                pass
            add(
                "service",
                fp[:160],
                f"{name} => {path}"[:280],
                hn,
                rid,
                {"name": name, "path": path[:200]},
                osf,
                _item_signals(sv),
            )

        if want_findings:
            for f in _load_findings_slim(rid, limit=80):
                rule = str(f.get("rule_id") or "").strip()
                title = str(f.get("title") or f.get("name") or "").strip()
                sev = str(f.get("severity") or "").lower()
                cat = str(f.get("category") or f.get("type") or "").strip()
                fp = (rule or title.lower())[:160]
                if not fp:
                    continue
                sample = f"[{sev}] {title}" + (f" · {cat}" if cat else "")
                add(
                    "finding",
                    fp,
                    sample[:280],
                    hn,
                    rid,
                    {
                        "rule_id": rule,
                        "title": title,
                        "severity": sev,
                        "category": cat,
                    },
                    osf,
                )
                ev = f.get("evidence")
                if isinstance(ev, list):
                    blob = " ".join(str(x) for x in ev[:6])
                else:
                    blob = str(ev or f.get("reason") or "")
                for m in _PATH_RE.finditer(blob):
                    d = _norm_drop_dir(m.group(1))
                    if d and _interesting_drop_path(d):
                        add("drop_path", d, m.group(1)[:240], hn, rid, {"path": m.group(1)[:200]}, osf)

    items: List[Dict[str, Any]] = []
    kind_stats: Dict[str, int] = {}
    dropped_plain = 0
    cap = max(1, int(max_hosts))
    for b in buckets.values():
        hosts = sorted(b["hosts"])
        hc = len(hosts)
        osf = str(b.get("os") or "unknown")
        os_total = int(os_hosts.get(osf) or 0)
        kind = str(b.get("kind") or "")
        if mode == "spread":
            if hc < 2:
                continue
            # 同系统几乎每台都有 = 基线软件，不算扩散
            if os_total >= 4 and hc >= os_total:
                continue
        elif hc < 1 or hc > cap:
            continue
        score, tags = _risk_of(str(b.get("sample") or ""), kind, sorted(b.get("signals") or []))
        # 告警本身已在告警页展示：只有带额外特征才算可疑，且不再额外加分
        if not tags or (mode == "spread" and not _strong_enough(tags)):
            dropped_plain += 1
            continue
        if kind == "finding":
            score = max(1, score - 1)
        if mode == "spread":
            score += min(6, (hc - 1) * 2)
        else:
            score += max(0, 4 - hc)
        item = {
            "kind": kind,
            "kind_label": _KIND_LABEL.get(kind, kind),
            "os_family": osf,
            "os_label": _OS_LABEL.get(osf, osf),
            "os_total": os_total,
            "fingerprint": b["fingerprint"],
            "sample": b["sample"],
            "host_count": hc,
            "hosts": hosts[:12],
            "query": _suggest_query(b),
            "risk_score": min(score, 20),
            "risk_tags": tags,
            "why": _why_text(kind, hc, tags, mode, os_total),
            "file": b.get("sample_file") or "",
            "hostname": b.get("sample_host") or (hosts[0] if hosts else ""),
            "title": _item_title(b),
        }
        extra = b.get("extra") or {}
        for k in ("name", "command", "task_name", "path", "rule_id", "severity", "category"):
            if extra.get(k):
                item[k] = extra[k]
        items.append(item)
        kind_stats[kind] = kind_stats.get(kind, 0) + 1

    if mode == "spread":
        items.sort(key=lambda x: (-int(x.get("risk_score") or 0), -x["host_count"], x["fingerprint"]))
    else:
        items.sort(key=lambda x: (-int(x.get("risk_score") or 0), x["host_count"], x["fingerprint"]))
    items = items[: max(1, min(120, int(limit)))]

    baseline = []
    for osf, n in sorted(os_hosts.items(), key=lambda kv: -kv[1]):
        baseline.append({
            "os_family": osf,
            "os_label": _OS_LABEL.get(osf, osf),
            "hosts": n,
            "enough": n >= BASELINE_MIN_HOSTS,
        })
    baseline_ok = any(b["enough"] for b in baseline)

    if mode == "spread":
        hint = (
            "扩散：同一可疑指纹（启动项/任务/服务/告警/落点）在同系统 ≥2 台主机出现，"
            "提示批量投放或横向移动。主机少时比「稀有」更有用。"
        )
    else:
        hint = (
            "稀有：同系统内只出现在少数主机、且带可疑特征（LOLBin、AppData、未签名、白加黑等）的条目。"
            "需要同系统主机足够多（建议 ≥10 台）才有区分力。"
        )

    if want_os:
        hint = f"当前轨道：{_OS_LABEL.get(want_os, want_os)}。{hint}"

    payload = {
        "ok": True,
        "mode": mode,
        "os_family": want_os or "all",
        "items": items,
        "scanned_hosts": len(latest),
        "scanned_reports": len(latest),
        "max_hosts": max_hosts,
        "kind_stats": kind_stats,
        "baseline": baseline,
        "baseline_min": BASELINE_MIN_HOSTS,
        "baseline_ok": baseline_ok,
        "dropped_plain": dropped_plain,
        "hint": hint,
        "refreshed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _CACHE["ts"] = now
    _CACHE["key"] = cache_key
    _CACHE["payload"] = payload
    return dict(payload)


def _item_title(bucket: Dict[str, Any]) -> str:
    kind = bucket.get("kind")
    extra = bucket.get("extra") or {}
    if kind == "run":
        return str(extra.get("name") or bucket.get("fingerprint") or "")
    if kind == "task_cmd":
        return str(extra.get("task_name") or bucket.get("fingerprint") or "")[:80]
    if kind == "service":
        return str(extra.get("name") or bucket.get("fingerprint") or "")
    if kind == "finding":
        return str(extra.get("title") or bucket.get("fingerprint") or "")
    if kind == "drop_path":
        return str(extra.get("path") or bucket.get("fingerprint") or "")
    return str(bucket.get("fingerprint") or "")


def _suggest_query(bucket: Dict[str, Any]) -> str:
    kind = bucket.get("kind")
    extra = bucket.get("extra") or {}
    if kind == "run":
        return str(extra.get("name") or bucket.get("fingerprint") or "").strip()
    if kind == "service":
        name = str(extra.get("name") or "").strip()
        if name:
            return name
        return str(bucket.get("fingerprint") or "")
    if kind == "finding":
        title = str(extra.get("title") or "").strip()
        rule = str(extra.get("rule_id") or "").strip()
        return title or rule or str(bucket.get("fingerprint") or "")
    if kind == "drop_path":
        path = str(extra.get("path") or bucket.get("fingerprint") or "")
        # 取有辨识度的一段
        parts = [p for p in path.replace("/", "\\").split("\\") if p and p != "*"]
        for p in reversed(parts):
            if len(p) >= 4 and p.lower() not in ("appdata", "roaming", "local", "programdata", "users", "temp"):
                return p
        return path[:60]
    cmd = str(extra.get("command") or bucket.get("fingerprint") or "")
    low = cmd.lower()
    for needle in ("conhost", "cd /d", "userinitmpr", "drivers.dat", 'start ""', "powershell", "rundll32"):
        if needle in low:
            return needle
    fp = str(bucket.get("fingerprint") or "")
    return fp[:60] if fp else cmd[:60]


# ── 敏感行为场景狩猎（主路径；稀有/扩散仅作辅助）──────────────────────────

_SCENARIO_CACHE: Dict[str, Any] = {"ts": 0.0, "payload": None, "key": ""}
_SCENARIO_CACHE_TTL = 300.0  # 5 分钟；前端再有会话缓存，避免每次点狩猎都全量扫
_SCENARIO_SCAN_LOCK = threading.Lock()

# 每条场景用多关键词 OR 扫库；q 为跳转全局检索的主语句
HUNT_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "exec-hi-cmd",
        "group": "exec",
        "group_label": "执行与下载",
        "title": "高危命令执行行为识别",
        "desc": "编码执行、绕过策略、隐蔽 PowerShell",
        "os": "windows",
        "q": "powershell -enc",
        "needles": ["powershell -enc", "-EncodedCommand", "FromBase64String", "-nop -w hidden"],
    },
    {
        "id": "exec-download",
        "group": "exec",
        "group_label": "执行与下载",
        "title": "疑似风险下载行为识别",
        "desc": "certutil / bitsadmin / curl 等下载落地",
        "os": "windows",
        "q": "certutil -urlcache",
        "needles": ["certutil -urlcache", "bitsadmin /transfer", "curl -o ", "Invoke-WebRequest"],
    },
    {
        "id": "exec-mshta",
        "group": "exec",
        "group_label": "执行与下载",
        "title": "脚本宿主可疑执行（mshta/wscript）",
        "desc": "HTA / 脚本宿主落地远程内容",
        "os": "windows",
        "q": "mshta",
        "needles": ["mshta http", "mshta javascript", "wscript.shell", "cscript //"],
    },
    {
        "id": "exec-linux-curl",
        "group": "exec",
        "group_label": "执行与下载",
        "title": "Linux 可疑下载与管道执行",
        "desc": "curl|bash、wget 落地可执行等",
        "os": "linux",
        "q": "curl | bash",
        "needles": ["curl | bash", "curl|bash", "wget | sh", "/dev/tcp"],
    },
    {
        "id": "recon-whoami",
        "group": "recon",
        "group_label": "信息探测",
        "title": "用户 / 主机信息探测",
        "desc": "whoami、systeminfo、nltest 等侦察",
        "os": "windows",
        "q": "whoami /all",
        "needles": ["whoami /all", "systeminfo", "nltest /domain"],
    },
    {
        "id": "recon-net",
        "group": "recon",
        "group_label": "信息探测",
        "title": "网络与账户枚举",
        "desc": "net user / net group 等账户枚举",
        "os": "windows",
        "q": "net user",
        "needles": ["net user /domain", "net group \"domain", "net localgroup administrators"],
    },
    {
        "id": "recon-linux",
        "group": "recon",
        "group_label": "信息探测",
        "title": "Linux 主机与用户信息收集",
        "desc": "/etc/passwd、id、uname 等",
        "os": "linux",
        "q": "cat /etc/passwd",
        "needles": ["cat /etc/passwd", "cat /etc/shadow", "uname -a"],
    },
    {
        "id": "evasion-defender",
        "group": "evasion",
        "group_label": "配置篡改与规避",
        "title": "安全软件 / 防火墙策略篡改",
        "desc": "Defender 排除项、关闭实时防护",
        "os": "windows",
        "q": "Add-MpPreference",
        "needles": ["Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring"],
    },
    {
        "id": "evasion-log",
        "group": "evasion",
        "group_label": "配置篡改与规避",
        "title": "日志清除与审计规避",
        "desc": "wevtutil 清日志等",
        "os": "windows",
        "q": "wevtutil cl",
        "needles": ["wevtutil cl", "wevtutil clear-log", "Clear-EventLog"],
    },
    {
        "id": "evasion-wdac",
        "group": "evasion",
        "group_label": "配置篡改与规避",
        "title": "恶意 WDAC 策略（SiPolicy.p7b）",
        "desc": "银狐等用 SiPolicy.p7b 卡杀软",
        "os": "windows",
        "q": "SiPolicy.p7b",
        "needles": ["SiPolicy.p7b", "CodeIntegrity\\SiPolicy"],
        "want_content": True,
    },
    {
        "id": "persist-task",
        "group": "persist",
        "group_label": "持久化控制",
        "title": "计划任务持久化行为",
        "desc": "schtasks 创建可疑任务",
        "os": "windows",
        "q": "schtasks /create",
        "needles": ["schtasks /create", "schtasks /Create"],
    },
    {
        "id": "persist-run",
        "group": "persist",
        "group_label": "持久化控制",
        "title": "启动项 / 登录脚本持久化",
        "desc": "Run 键、UserInitMprLogonScript",
        "os": "windows",
        "q": "UserInitMprLogonScript",
        "needles": ["UserInitMprLogonScript", "CurrentVersion\\Run"],
    },
    {
        "id": "persist-conhost",
        "group": "persist",
        "group_label": "持久化控制",
        "title": "conhost 隐身执行载荷",
        "desc": "conhost --headless 挂接脚本",
        "os": "windows",
        "q": "conhost --headless",
        "needles": ["conhost --headless", "conhost.exe --headless"],
    },
    {
        "id": "persist-cron",
        "group": "persist",
        "group_label": "持久化控制",
        "title": "Linux cron / systemd 持久化",
        "desc": "crontab、异常 .service",
        "os": "linux",
        "q": "crontab",
        "needles": ["crontab -e", "/etc/cron", "/etc/systemd", "systemctl enable"],
    },
    {
        "id": "lateral-psexec",
        "group": "lateral",
        "group_label": "远程访问与横移",
        "title": "PsExec / WMI 远程执行",
        "desc": "横向移动常见工具痕迹",
        "os": "windows",
        "q": "psexec",
        "needles": ["psexec", "PSEXESVC", "wmic process call create"],
    },
    {
        "id": "lateral-ssh",
        "group": "lateral",
        "group_label": "远程访问与横移",
        "title": "Linux SSH 异常与跳板",
        "desc": "authorized_keys 异常写入等",
        "os": "linux",
        "q": "authorized_keys",
        "needles": ["authorized_keys", "sshd_config"],
    },
    {
        "id": "drop-drivers",
        "group": "drop",
        "group_label": "投放与落点",
        "title": "drivers.dat 投放树",
        "desc": "盘符根随机目录 + drivers.dat",
        "os": "windows",
        "q": "drivers.dat",
        "needles": ["drivers.dat"],
        "want_content": True,
    },
    {
        "id": "drop-rundll",
        "group": "drop",
        "group_label": "投放与落点",
        "title": "rundll32 异常协议执行",
        "desc": "FileProtocolHandler 等白加黑",
        "os": "windows",
        "q": "FileProtocolHandler",
        "needles": ["FileProtocolHandler", "url.dll,"],
    },
    {
        "id": "drop-silverfox",
        "group": "drop",
        "group_label": "投放与落点",
        "title": "银狐 / Valley 常见落点",
        "desc": "wefault、DeepSer、IpDates 等",
        "os": "windows",
        "q": "wefault",
        "needles": ["wefault", "DeepSer", "IpDates"],
        "want_content": True,
    },
]

# 高级搜索模板已下线（与上方敏感行为场景重复、收益低）
HUNT_ADVANCED: List[Dict[str, Any]] = []


def _item_blob(it: Dict[str, Any]) -> str:
    parts = [
        it.get("title"), it.get("evidence"), it.get("reason"),
        it.get("rule_id"), it.get("category"), it.get("path"),
        it.get("command"), it.get("hostname"),
    ]
    extra = it.get("extra") if isinstance(it.get("extra"), dict) else {}
    for k in ("path", "command", "image_path", "name"):
        parts.append(extra.get(k))
    return " ".join(str(p or "") for p in parts).lower()


def _probe_needle(
    needle: str,
    *,
    user: Optional[Dict[str, Any]],
    want_content: bool,
) -> Tuple[List[Dict[str, Any]], int]:
    """优先走 MySQL 告警索引；仅标记 want_content 的场景才补报告内容检索。"""
    needle = str(needle or "").strip()
    if not needle:
        return [], 0
    items: List[Dict[str, Any]] = []
    total = 0
    try:
        from backend.mysql_store import search_findings_mysql
        from backend.mysql_db import mysql_ready
        if mysql_ready():
            items, total = search_findings_mysql(needle, size=20, user=user)
    except Exception:
        items, total = [], 0
    # 无 MySQL 时退回本地 findings；有结果则不再扫报告正文（正文很慢）
    if not items and not want_content:
        try:
            from backend.search import search_findings
            out = search_findings(user, needle, scope="findings", size=20, offset=0)
            extra = out.get("items") or out.get("findings") or []
            if isinstance(extra, list):
                items = [x for x in extra if isinstance(x, dict)]
                total = max(int(out.get("total") or 0), len(items))
        except Exception:
            pass
    elif want_content:
        try:
            from backend.search import search_findings
            # 必须 scope=content + contains：scope=all 在已有告警命中时会跳过正文
            out = search_findings(
                user, needle, scope="content", size=15, offset=0, match="contains",
            )
            extra = out.get("items") or out.get("findings") or []
            if isinstance(extra, list) and extra:
                seen = {
                    (
                        str(x.get("file") or x.get("report_id") or ""),
                        str(x.get("title") or ""),
                        str(x.get("rule_id") or ""),
                    )
                    for x in items
                }
                for x in extra:
                    if not isinstance(x, dict):
                        continue
                    key = (
                        str(x.get("file") or x.get("report_id") or ""),
                        str(x.get("title") or ""),
                        str(x.get("rule_id") or ""),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    items.append(x)
                total = max(total, int(out.get("total") or 0), len(items))
        except Exception:
            pass
    return items, total


def _scenario_scan_inner(
    *,
    user: Optional[Dict[str, Any]] = None,
    os_family: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    """对内置敏感行为场景批量扫库，返回每场景命中主机/条数与样本。"""
    now = time.time()
    want_os = str(os_family or "").strip().lower()
    if want_os in ("all", "any", "*"):
        want_os = ""
    if want_os not in ("", "windows", "linux"):
        want_os = ""
    rows = db_store.list_index(limit=200, user=user) or []
    # 报告条数进 cache key：新分析入库后自动失效，避免仍显示旧「无命中」
    index_sig = f"{len(rows)}|{str((rows[0] or {}).get('file') or '') if rows else ''}"
    cache_key = f"{(user or {}).get('id') if isinstance(user, dict) else ''}|{want_os}|{index_sig}"
    if (
        not force
        and _SCENARIO_CACHE.get("payload")
        and _SCENARIO_CACHE.get("key") == cache_key
        and now - float(_SCENARIO_CACHE.get("ts") or 0) < _SCENARIO_CACHE_TTL
    ):
        return dict(_SCENARIO_CACHE["payload"])

    host_os: Dict[str, str] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        hn = str(r.get("hostname") or "").strip()
        if not hn or hn == "unknown":
            continue
        if hn not in host_os:
            host_os[hn] = _norm_os(r)
    scanned = len(host_os) if not want_os else sum(1 for o in host_os.values() if o == want_os)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    scenarios_out: List[Dict[str, Any]] = []
    hit_scene_n = 0

    def _run_one(sc: Dict[str, Any]) -> Dict[str, Any]:
        host_map: Dict[str, Dict[str, Any]] = {}
        samples: List[Dict[str, Any]] = []
        seen_sample: set = set()
        needles = list(sc.get("needles") or [sc.get("q")])[:3]
        want_content = bool(sc.get("want_content"))
        matched_needle = ""
        for i, needle in enumerate(needles):
            # 内容类场景：每个词都允许补正文；否则仅告警索引
            items, _total = _probe_needle(
                needle, user=user, want_content=want_content,
            )
            got = False
            for it in items:
                if not isinstance(it, dict):
                    continue
                hn = str(it.get("hostname") or "").strip()
                if not hn or hn == "unknown":
                    # 无主机名的命中无法落到台账，跳过（避免虚报 1 台）
                    continue
                osf = host_os.get(hn) or "unknown"
                sc_os = str(sc.get("os") or "all")
                # 专轨 / 场景 OS 必须对齐；unknown 不再算进 Windows/Linux 轨，避免串台误报
                if sc_os in ("windows", "linux") and osf != sc_os:
                    continue
                if want_os and osf != want_os:
                    continue
                got = True
                if not matched_needle:
                    matched_needle = needle
                hm = host_map.get(hn)
                if not hm:
                    hm = {
                        "hostname": hn,
                        "hits": 0,
                        "file": str(it.get("file") or it.get("report_id") or ""),
                        "os_family": osf,
                    }
                    host_map[hn] = hm
                hm["hits"] += 1
                if not hm.get("file"):
                    hm["file"] = str(it.get("file") or it.get("report_id") or "")
                sk = (
                    hn,
                    str(it.get("title") or "")[:80],
                    str(it.get("rule_id") or ""),
                )
                if sk in seen_sample or len(samples) >= 8:
                    continue
                seen_sample.add(sk)
                samples.append({
                    "hostname": hn,
                    "title": str(it.get("title") or "")[:120],
                    "severity": str(it.get("severity") or ""),
                    "evidence": str(it.get("evidence") or it.get("reason") or "")[:200],
                    "file": str(it.get("file") or it.get("report_id") or ""),
                    "rule_id": str(it.get("rule_id") or ""),
                    "module": str(it.get("module") or it.get("kind") or ""),
                    "matched_needle": needle,
                })
            # 已有真实主机命中则停，避免多词把统计撑大
            if got and host_map:
                break
        hosts = sorted(host_map.values(), key=lambda x: (-int(x["hits"]), x["hostname"]))
        hit_count = sum(int(h["hits"]) for h in hosts)
        primary_q = matched_needle or sc.get("q") or (needles[0] if needles else "")
        return {
            "id": sc["id"],
            "group": sc["group"],
            "group_label": sc["group_label"],
            "title": sc["title"],
            "desc": sc.get("desc") or "",
            "os": sc.get("os") or "all",
            "os_label": {"windows": "Windows", "linux": "Linux"}.get(sc.get("os") or "", "通用"),
            "q": primary_q,
            "matched_needle": matched_needle or primary_q,
            "needles": needles,
            "match": "contains",
            "builtin": True,
            "host_count": len(hosts),
            "hit_count": hit_count,
            "hosts": hosts[:12],
            "samples": samples,
            "status": "hit" if hosts else "clean",
        }

    runnable = [
        sc for sc in HUNT_SCENARIOS
        if not want_os or str(sc.get("os") or "all") in (want_os, "all")
    ]
    with ThreadPoolExecutor(max_workers=min(10, max(2, len(runnable) or 2))) as pool:
        futs = {pool.submit(_run_one, sc): sc["id"] for sc in runnable}
        by_id: Dict[str, Dict[str, Any]] = {}
        for fut in as_completed(futs):
            try:
                by_id[futs[fut]] = fut.result()
            except Exception as e:
                sid = futs[fut]
                base = next((x for x in runnable if x["id"] == sid), {})
                by_id[sid] = {
                    "id": sid,
                    "group": base.get("group") or "",
                    "group_label": base.get("group_label") or "",
                    "title": base.get("title") or sid,
                    "desc": base.get("desc") or "",
                    "os": base.get("os") or "all",
                    "os_label": "",
                    "q": base.get("q") or "",
                    "needles": base.get("needles") or [],
                    "builtin": True,
                    "host_count": 0,
                    "hit_count": 0,
                    "hosts": [],
                    "samples": [],
                    "status": "error",
                    "error": str(e)[:120],
                }
    for sc in runnable:
        row = by_id.get(sc["id"])
        if not row:
            continue
        if row.get("status") == "hit":
            hit_scene_n += 1
        scenarios_out.append(row)

    # 有命中的排前面
    scenarios_out.sort(key=lambda x: (-int(x.get("host_count") or 0), -int(x.get("hit_count") or 0), x.get("title") or ""))

    advanced = [
        {
            **a,
            "os_label": {"windows": "Windows", "linux": "Linux"}.get(a.get("os") or "", "通用"),
        }
        for a in HUNT_ADVANCED
        if not want_os or str(a.get("os") or "all") in (want_os, "all")
    ]

    groups: Dict[str, int] = {}
    for s in scenarios_out:
        g = str(s.get("group") or "")
        if g:
            groups[g] = groups.get(g, 0) + 1

    payload = {
        "scenarios": scenarios_out,
        "advanced": advanced,
        "groups": groups,
        "hit_scenes": hit_scene_n,
        "scanned_hosts": scanned,
        "os_family": want_os or "all",
        "refreshed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hint": "宽规则敏感行为扫描；有命中≠失陷，需结合主机上下文研判。",
    }
    _SCENARIO_CACHE["ts"] = now
    _SCENARIO_CACHE["key"] = cache_key
    _SCENARIO_CACHE["payload"] = payload
    return dict(payload)


def scenario_scan(
    *,
    user: Optional[Dict[str, Any]] = None,
    os_family: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    """合并并发场景扫描，避免多个页面同时逐场景重复扫库。"""
    with _SCENARIO_SCAN_LOCK:
        return _scenario_scan_inner(user=user, os_family=os_family, force=force)
