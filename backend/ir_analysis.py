"""应急增强模块：登录横向 / 凭据盗取 / 信标画像 / 防护弱化 / 外传同步。

均对已有报告数据做二次研判，规则变更后可直接重跑，无需重采。
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import paths as P

# ─── 通用 ───────────────────────────────────────────────────────────────────

_PRIV_IP = re.compile(
    r"^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|fc|fd|fe80:)",
    re.I,
)


def _norm(p: Any) -> str:
    s = str(p or "").strip().strip('"').replace("/", "\\")
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _rid(report_or_rid: Any) -> str:
    if isinstance(report_or_rid, dict):
        from .db_store import files_rid
        return files_rid(report_or_rid) or str(
            report_or_rid.get("_rid") or report_or_rid.get("file") or ""
        ).strip()
    return P.report_id(str(report_or_rid or ""))


def _connect(rid: str):
    from .db_store import _connect as c, _init_schema
    dbp = P.resolve_analysis_db(rid)
    if not dbp or not Path(dbp).is_file():
        return None
    conn = c(Path(dbp))
    try:
        _init_schema(conn)
    except Exception:
        pass
    return conn


def _load_blob_list(rid: str, name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pack = P.report_dir(rid) / "pack"
    file_map = {
        "processes": ("processes.json", "processes"),
        "services": ("persistence.json", "services"),
        "startup_items": ("persistence.json", "startup_items"),
        "scheduled_tasks": ("persistence.json", "scheduled_tasks"),
        "installed_programs": ("persistence.json", "installed_programs"),
        "prefetch_files": ("execution.json", "prefetch_files"),
        "established_connections": ("network.json", "established_connections"),
        "open_ports": ("network.json", "open_ports"),
        "dns_cache_entries": ("network.json", "dns_cache_entries"),
    }
    if name in file_map:
        fn, key = file_map[name]
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
        from .db_store import _connect as c, _load_one_blob
        dbp = P.resolve_analysis_db(rid)
        if dbp and Path(dbp).is_file():
            conn = c(Path(dbp))
            try:
                raw = _load_one_blob(conn, name) or []
                if isinstance(raw, list):
                    out = [x for x in raw if isinstance(x, dict)]
            finally:
                conn.close()
    except Exception:
        pass
    return out


def _load_blob_obj(rid: str, name: str) -> Any:
    try:
        from .db_store import _connect as c, _load_one_blob
        dbp = P.resolve_analysis_db(rid)
        if dbp and Path(dbp).is_file():
            conn = c(Path(dbp))
            try:
                return _load_one_blob(conn, name)
            finally:
                conn.close()
    except Exception:
        pass
    pack = P.report_dir(rid) / "pack"
    for cand in (pack / f"{name}.json", pack / "extras.json"):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                if name == "security_extras" and isinstance(data, dict):
                    return data.get("security_extras") or data
                if isinstance(data, dict) and name in data:
                    return data[name]
                return data
            except Exception:
                pass
    return None


def _events_by_ids(rid: str, event_ids: List[int], limit: int = 400) -> List[Dict[str, Any]]:
    conn = _connect(rid)
    if not conn:
        return []
    try:
        from .db_store import _ensure_event_logs_table, _event_log_row_to_dict
        _ensure_event_logs_table(conn)
        if not event_ids:
            return []
        ph = ",".join("?" * len(event_ids))
        rows = conn.execute(
            f"SELECT channel,event_id,provider,time,level,computer,message,fields "
            f"FROM event_logs WHERE event_id IN ({ph}) "
            f"ORDER BY time DESC LIMIT ?",
            [*event_ids, max(1, limit)],
        ).fetchall()
        return [_event_log_row_to_dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def _files_like(rid: str, likes: List[str], limit: int = 500) -> List[Dict[str, Any]]:
    conn = _connect(rid)
    if not conn:
        return []
    try:
        out: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for pat in likes:
            rows = conn.execute(
                "SELECT full_path,name,ext,size,mtime,path FROM files "
                "WHERE lower(replace(full_path,'/','\\')) LIKE ? LIMIT ?",
                (pat.lower().replace("/", "\\"), limit),
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


def _parse_logon_type(msg: str) -> str:
    m = re.search(r"(?i)Logon\s*Type[:\s]+(\d+)", msg or "")
    return m.group(1) if m else ""


def _parse_field(msg: str, *labels: str) -> str:
    for lab in labels:
        m = re.search(rf"(?im){re.escape(lab)}\s*[:：]\s*(.+)$", msg or "")
        if m:
            return m.group(1).strip().split("\t")[0].strip()
    return ""


_LOGON_TYPE_NAME = {
    "2": "交互",
    "3": "网络",
    "4": "批处理",
    "5": "服务",
    "7": "解锁",
    "8": "网络明文",
    "9": "新凭据",
    "10": "远程交互/RDP",
    "11": "缓存交互",
}


# ─── 1. 登录与横向 ───────────────────────────────────────────────────────────

def analyze_lateral(rid: str) -> Dict[str, Any]:
    rid = _rid(rid)
    want = [4624, 4625, 4648, 4672, 4778, 4779, 21, 24, 25]  # 含部分 RDP/终端
    events = _events_by_ids(rid, want, limit=800)
    logons: List[Dict[str, Any]] = []
    fails: List[Dict[str, Any]] = []
    explicit: List[Dict[str, Any]] = []
    rdp: List[Dict[str, Any]] = []

    for ev in events:
        eid = int(ev.get("event_id") or 0)
        msg = str(ev.get("message") or "")
        account = (
            _parse_field(msg, "Account Name", "帐户名", "账户名", "User")
            or _parse_field(msg, "TargetUserName")
        )
        domain = _parse_field(msg, "Account Domain", "帐户域", "账户域", "Domain")
        src_ip = (
            _parse_field(msg, "Source Network Address", "源网络地址", "Source Address")
            or _parse_field(msg, "IpAddress", "Client Address")
        )
        lt = _parse_logon_type(msg)
        when = ev.get("time") or ""
        row = {
            "time": when,
            "event_id": eid,
            "account": account,
            "domain": domain,
            "logon_type": lt,
            "logon_type_name": _LOGON_TYPE_NAME.get(lt, lt or ""),
            "src_ip": src_ip,
            "hour_bucket": _hour_bucket(str(when)),
            "channel": ev.get("channel") or "",
            "summary": (msg or "").replace("\r", " ").replace("\n", " ")[:220],
        }
        if eid == 4624:
            logons.append(row)
            if lt in ("10", "3", "8", "9"):
                rdp.append(row)
        elif eid == 4625:
            fails.append(row)
        elif eid == 4648:
            explicit.append(row)
        elif eid in (4778, 4779, 21, 24, 25):
            rdp.append(row)

    # net session / net use 旁证
    net_sess = str(_load_blob_obj(rid, "net_sessions") or "")
    net_use = ""
    net = _load_blob_obj(rid, "network")
    if isinstance(net, dict):
        net_use = str(net.get("net_use") or "")

    # 异常启发式：非工作时段网络/RDP、多源 IP、失败激增
    flags: List[Dict[str, Any]] = []
    src_counter = Counter(
        (x.get("src_ip") or "").strip()
        for x in logons
        if (x.get("src_ip") or "").strip() and (x.get("src_ip") or "") not in ("-", "::1", "127.0.0.1")
    )
    for ip, n in src_counter.most_common(12):
        if n >= 3:
            flags.append({
                "kind": "多源登录",
                "severity": "medium" if n < 10 else "high",
                "title": f"来源 {ip} 成功登录 {n} 次",
                "evidence": f"4624 聚合 · {ip}",
            })
    night = [
        x for x in logons
        if x.get("logon_type") in ("3", "10") and _is_odd_hour(str(x.get("time") or ""))
    ]
    if night:
        flags.append({
            "kind": "异常时段",
            "severity": "medium",
            "title": f"夜间/凌晨网络或 RDP 登录 {len(night)} 次",
            "evidence": "；".join(
                f"{n.get('time')} {n.get('account')}@{n.get('src_ip')}" for n in night[:5]
            ),
        })
    if len(fails) >= 8:
        flags.append({
            "kind": "爆破迹象",
            "severity": "high",
            "title": f"登录失败 {len(fails)} 次",
            "evidence": "4625 聚合",
        })
    if explicit:
        flags.append({
            "kind": "显式凭据",
            "severity": "high",
            "title": f"显式凭据登录 {len(explicit)} 次（4648）",
            "evidence": "可能用于横向（runas / 计划任务 / WMI）",
        })

    src_ips = sorted(
        {str(x.get("src_ip") or "").strip() for x in (logons + fails + explicit + rdp)
         if (x.get("src_ip") or "").strip() and x.get("src_ip") not in ("-", "::1", "127.0.0.1")}
    )
    return {
        "ok": True,
        "file": rid,
        "logons": logons[:300],
        "failures": fails[:200],
        "explicit": explicit[:100],
        "rdp_sessions": rdp[:200],
        "flags": flags,
        "filter_src_ips": src_ips[:40],
        "net_sessions": (net_sess or "")[:8000],
        "net_use": (net_use or "")[:8000],
        "stats": {
            "logon_ok": len(logons),
            "logon_fail": len(fails),
            "explicit": len(explicit),
            "rdp_like": len(rdp),
            "flag_count": len(flags),
            "src_ips": len(src_counter),
            "night": sum(1 for x in logons if x.get("hour_bucket") == "night"),
        },
    }


def _is_odd_hour(t: str) -> bool:
    m = re.search(r"(\d{2}):\d{2}:\d{2}", t)
    if not m:
        return False
    h = int(m.group(1))
    return h < 6 or h >= 23


def _dt(s: Any) -> Optional[datetime]:
    t = str(s or "").strip().replace("T", " ").replace("/", "-")
    t = re.sub(r"[Zz]$", "", t)
    t = re.sub(r"[+-]\d{2}:?\d{2}$", "", t).strip()
    for fmt, n in (
        ("%Y-%m-%d %H:%M:%S.%f", 26),
        ("%Y-%m-%d %H:%M:%S", 19),
        ("%Y-%m-%d %H:%M", 16),
        ("%Y-%m-%d", 10),
    ):
        try:
            return datetime.strptime(t[:n], fmt)
        except ValueError:
            continue
    return None


def _hour_bucket(t: str) -> str:
    """用于前端筛选：night / work / evening。"""
    m = re.search(r"(\d{2}):\d{2}:\d{2}", t or "")
    if not m:
        return ""
    h = int(m.group(1))
    if h < 6 or h >= 23:
        return "night"
    if 9 <= h < 18:
        return "work"
    return "evening"


# ─── 5. 凭据盗取 ─────────────────────────────────────────────────────────────

_CRED_TOOL_RX = re.compile(
    r"(?i)("
    r"mimikatz|sekurlsa|lsadump|procdump|nanodump|handlekatz|safetykatz|"
    r"comsvcs(\.dll)?.*minidump|mini.?dump|lsass\.dmp|lsass\.exe.*\.dmp|"
    r"hashdump|secretsdump|pwdump|gsecdump|quarks.?pwdump|"
    r"reg\s+save\s+.*\\(sam|security|system)|"
    r"ntdsutil|ntds\.dit|impacket|rubeus|sharpdpapi|donpapi|"
    r"lazagne|sharpchromedpapi|sharpweb|"
    r"cmdkey\s+/list|vaultcmd"
    r")"
)

_DUMP_NAME_RX = re.compile(r"(?i)(lsass|mimikatz|sekurlsa|creds?|sam|ntds).*\.(dmp|dump|bin)$")


def analyze_cred_theft(rid: str) -> Dict[str, Any]:
    rid = _rid(rid)
    hits: List[Dict[str, Any]] = []

    # 进程命令行
    for pr in _load_blob_list(rid, "processes"):
        blob = " ".join(str(pr.get(k) or "") for k in (
            "name", "path", "command_line", "command", "cmdline",
        ))
        m = _CRED_TOOL_RX.search(blob)
        if not m:
            continue
        hits.append({
            "kind": "进程",
            "severity": "high",
            "title": pr.get("name") or "可疑进程",
            "path": pr.get("path") or "",
            "detail": (pr.get("command_line") or pr.get("command") or "")[:400],
            "match": m.group(1)[:80],
            "pid": pr.get("pid") or pr.get("PID") or 0,
            "time": "",
        })

    # Prefetch / 执行痕迹
    for pf in _load_blob_list(rid, "prefetch_files"):
        name = str(pf.get("name") or pf if not isinstance(pf, dict) else pf.get("name") or "")
        if isinstance(pf, dict):
            name = str(pf.get("name") or "")
        low = name.lower()
        if any(x in low for x in (
            "mimikatz", "procdump", "nanodump", "pwdump", "secretsdump",
            "lazagne", "rubeus", "handlekatz",
        )):
            hits.append({
                "kind": "Prefetch",
                "severity": "high",
                "title": name,
                "path": str(pf.get("path") or pf.get("full_path") or "") if isinstance(pf, dict) else "",
                "detail": "执行痕迹命中凭据工具名",
                "match": name,
                "pid": 0,
                "time": str(pf.get("last_run") or pf.get("mtime") or "") if isinstance(pf, dict) else "",
            })

    # dump / hive 副本文件
    for f in _files_like(rid, [
        "%\\lsass%.dmp", "%\\%.dmp", "%\\sam", "%\\security", "%\\ntds.dit",
        "%\\mimikatz%", "%\\procdump%",
    ], limit=300):
        name = str(f.get("name") or "")
        fp = str(f.get("full_path") or "")
        low = fp.lower()
        if _DUMP_NAME_RX.search(name) or _DUMP_NAME_RX.search(fp):
            sev = "high"
        elif name.lower() in ("sam", "security", "system", "ntds.dit") and "\\windows\\system32\\config\\" not in low:
            sev = "high"
        elif name.lower().endswith(".dmp") and any(x in low for x in ("\\temp\\", "\\users\\", "\\downloads\\")):
            sev = "medium"
        else:
            continue
        hits.append({
            "kind": "文件",
            "severity": sev,
            "title": name,
            "path": fp,
            "detail": f"size={f.get('size') or 0} mtime={f.get('mtime') or ''}",
            "match": name,
            "pid": 0,
            "time": str(f.get("mtime") or ""),
        })

    # 事件：4648 / 5379 / 4662 / Sysmon 10（若 message 含 lsass）
    for ev in _events_by_ids(rid, [4648, 5379, 4662, 10, 4656], limit=500):
        eid = int(ev.get("event_id") or 0)
        msg = str(ev.get("message") or "")
        low = msg.lower()
        keep = False
        title = ""
        if eid == 4648:
            keep, title = True, "显式凭据（4648）"
        elif eid == 5379:
            keep, title = True, "凭据管理器读取（5379）"
        elif eid == 10 and "lsass" in low:
            keep, title = True, "进程访问 LSASS（Sysmon 10）"
        elif eid == 4656 and "lsass" in low:
            keep, title = True, "句柄请求 LSASS（4656）"
        elif eid == 4662 and any(x in low for x in ("policysecrets", "ntds", "domain-dns")):
            keep, title = True, "目录服务对象访问（4662）"
        if not keep:
            continue
        hits.append({
            "kind": "事件",
            "severity": "high" if eid in (10, 4648, 5379) else "medium",
            "title": title,
            "path": "",
            "detail": msg.replace("\n", " ")[:360],
            "match": str(eid),
            "pid": 0,
            "time": ev.get("time") or "",
        })

    # 去重
    uniq: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for h in hits:
        k = f"{h.get('kind')}|{h.get('title')}|{h.get('path')}|{h.get('match')}"
        if k in seen:
            continue
        seen.add(k)
        uniq.append(h)
    uniq.sort(key=lambda x: (0 if x.get("severity") == "high" else 1, x.get("time") or ""), reverse=False)

    # 与远控会话 ±30 分钟硬关联
    correlated: List[Dict[str, Any]] = []
    window = timedelta(minutes=30)
    try:
        from .remote_tools import analyze_remote_tools
        rt = analyze_remote_tools(rid)
        sessions = rt.get("sessions") or []
        sess_pts: List[Tuple[datetime, Dict[str, Any]]] = []
        for s in sessions:
            for key in ("start", "end"):
                dt = _dt(s.get(key))
                if dt:
                    sess_pts.append((dt, s))
        for h in uniq:
            ht = _dt(h.get("time"))
            if not ht:
                continue
            best = None
            best_delta = None
            for st, s in sess_pts:
                delta = abs((ht - st).total_seconds())
                if delta <= window.total_seconds() and (best_delta is None or delta < best_delta):
                    best = s
                    best_delta = delta
            if best is not None and best_delta is not None:
                mins = int(best_delta // 60)
                correlated.append({
                    "cred": h.get("title"),
                    "cred_kind": h.get("kind"),
                    "cred_path": h.get("path") or "",
                    "session": best.get("summary") or best.get("tool_name"),
                    "tool_name": best.get("tool_name") or "",
                    "peer_ip": best.get("peer_ip") or "",
                    "cred_time": h.get("time") or "",
                    "session_time": best.get("start") or best.get("end") or "",
                    "delta_min": mins,
                    "severity": "high",
                    "detail": f"凭据痕迹与远控会话相差 {mins} 分钟（阈值 ±30）",
                })
                h["correlated_remote"] = True
    except Exception:
        pass

    return {
        "ok": True,
        "file": rid,
        "hits": uniq[:400],
        "correlated": correlated[:80],
        "stats": {
            "hit_count": len(uniq),
            "high": sum(1 for x in uniq if x.get("severity") == "high"),
            "by_kind": dict(Counter(x.get("kind") for x in uniq)),
            "correlated": len(correlated),
            "window_min": 30,
        },
    }


# ─── 6. 外联信标画像 ─────────────────────────────────────────────────────────

# 粗分国内外：常见国内运营商/教育网一段前缀（无 GeoIP 库时的弱启发式，误判可能）
_CN_PREFIX = (
    "1.", "14.", "27.", "36.", "39.", "42.", "49.", "58.", "59.", "60.", "61.",
    "101.", "106.", "110.", "111.", "112.", "113.", "114.", "115.", "116.", "117.",
    "118.", "119.", "120.", "121.", "122.", "123.", "124.", "125.",
    "140.", "144.", "163.", "171.", "175.", "180.", "182.", "183.",
    "202.", "210.", "211.", "218.", "219.", "220.", "221.", "222.", "223.",
)


def _ip_scope(ip: str) -> str:
    if not ip or _PRIV_IP.match(ip):
        return "private"
    if any(ip.startswith(p) for p in _CN_PREFIX):
        return "cn_likely"
    return "overseas_likely"


def analyze_beacon(rid: str) -> Dict[str, Any]:
    rid = _rid(rid)
    conns = _load_blob_list(rid, "established_connections")
    by_dest: Dict[str, Dict[str, Any]] = {}
    by_proc: Dict[str, Dict[str, Any]] = {}
    for c in conns:
        remote = str(
            c.get("remote_addr") or c.get("remote_address") or c.get("RemoteAddr") or ""
        ).strip()
        if not remote or remote.startswith("0.0.0.0") or remote.startswith("[::]"):
            continue
        ip = remote.rsplit(":", 1)[0].strip("[]")
        port = ""
        if ":" in remote.rsplit("%", 1)[0]:
            try:
                port = remote.rsplit(":", 1)[-1]
            except Exception:
                port = ""
        if _PRIV_IP.match(ip) or ip in ("*", ""):
            continue
        proc = str(c.get("process") or c.get("process_name") or c.get("name") or "") or "(未知进程)"
        path = str(c.get("process_path") or c.get("path") or c.get("exe") or "")
        key = f"{ip}:{port}"
        scope = _ip_scope(ip)
        public = scope != "private"
        slot = by_dest.setdefault(key, {
            "remote": remote, "ip": ip, "port": port, "count": 0,
            "processes": set(), "paths": set(), "public": public, "scope": scope,
        })
        slot["count"] += 1
        if proc:
            slot["processes"].add(proc)
        if path:
            slot["paths"].add(path)

        ps = by_proc.setdefault(proc.lower(), {
            "process": proc, "path": path, "dests": set(), "count": 0,
            "overseas": 0, "cn": 0, "ports": set(),
        })
        ps["count"] += 1
        ps["dests"].add(f"{ip}:{port}")
        if port:
            ps["ports"].add(port)
        if scope == "overseas_likely":
            ps["overseas"] += 1
        elif scope == "cn_likely":
            ps["cn"] += 1
        if path and not ps.get("path"):
            ps["path"] = path

    profiles: List[Dict[str, Any]] = []
    for slot in by_dest.values():
        procs = sorted(slot["processes"])
        paths = sorted(slot["paths"])
        score = 0
        reasons = []
        if slot["count"] >= 5:
            score += 20
            reasons.append(f"连接数 {slot['count']}")
        if slot["scope"] == "overseas_likely":
            score += 28
            reasons.append("疑似境外公网（前缀粗判）")
        elif slot["public"]:
            score += 12
            reasons.append("国内/未知公网")
        sys_ok = {"svchost.exe", "system", "lsass.exe", "services.exe", "explorer.exe"}
        if procs and not any(p.lower() in sys_ok for p in procs):
            score += 15
            reasons.append("非典型系统进程")
        if any("temp" in p.lower() or "appdata" in p.lower() or "users\\" in p.lower() for p in paths):
            score += 25
            reasons.append("用户目录进程外联")
        if slot.get("port") in ("443", "8080", "8443", "53", "445", "3389"):
            score += 5
        profiles.append({
            "remote": slot["remote"],
            "ip": slot["ip"],
            "port": slot["port"],
            "count": slot["count"],
            "processes": procs[:8],
            "paths": paths[:6],
            "public": bool(slot["public"]),
            "scope": slot["scope"],
            "score": score,
            "reasons": reasons,
            "severity": "high" if score >= 45 else ("medium" if score >= 25 else "low"),
        })
    profiles.sort(key=lambda x: (-int(x.get("score") or 0), -int(x.get("count") or 0)))

    # 按进程聚合：多目的地 / 境外占比高 → 周期外联嫌疑
    proc_profiles: List[Dict[str, Any]] = []
    for ps in by_proc.values():
        dest_n = len(ps["dests"])
        if dest_n < 2 and ps["count"] < 4:
            continue
        score = 0
        reasons = []
        if dest_n >= 3:
            score += 25
            reasons.append(f"{dest_n} 个公网目的地")
        if ps["count"] >= 6:
            score += 15
            reasons.append(f"连接 {ps['count']} 次")
        if ps["overseas"] >= 2:
            score += 30
            reasons.append(f"疑似境外 {ps['overseas']} 次")
        pl = str(ps.get("path") or "").lower()
        if any(x in pl for x in ("\\temp\\", "\\appdata\\", "\\users\\", "\\downloads\\")):
            score += 20
            reasons.append("用户目录进程")
        if score < 20:
            continue
        proc_profiles.append({
            "process": ps["process"],
            "path": ps.get("path") or "",
            "dest_count": dest_n,
            "count": ps["count"],
            "overseas": ps["overseas"],
            "cn": ps["cn"],
            "ports": sorted(ps["ports"])[:12],
            "dests": sorted(ps["dests"])[:12],
            "score": score,
            "reasons": reasons,
            "severity": "high" if score >= 50 else "medium",
            "summary": f"{ps['process']} → {dest_n} 目的地 / {ps['count']} 连接",
        })
    proc_profiles.sort(key=lambda x: (-x["score"], -x["count"]))

    rare = [p for p in profiles if p["severity"] in ("high", "medium")]
    return {
        "ok": True,
        "file": rid,
        "profiles": profiles[:200],
        "suspicious": rare[:80],
        "by_process": proc_profiles[:60],
        "stats": {
            "dest_count": len(profiles),
            "suspicious": len(rare),
            "public": sum(1 for p in profiles if p.get("public")),
            "overseas_likely": sum(1 for p in profiles if p.get("scope") == "overseas_likely"),
            "proc_groups": len(proc_profiles),
            "conn_total": len(conns),
        },
    }


# ─── 7. 防护弱化 ─────────────────────────────────────────────────────────────

_DEFENDER_DISABLE_RX = re.compile(
    r"(?i)(disable(d)?|turn(ed)?\s*off|排除|exclusion|real-?time.*off|"
    r"DisableRealtimeMonitoring|DisableAntiSpyware|TamperProtection.*false|"
    r"威胁.*已排除|停止|uninstall)",
)


def analyze_defense_weaken(rid: str) -> Dict[str, Any]:
    rid = _rid(rid)
    findings: List[Dict[str, Any]] = []
    sx = _load_blob_obj(rid, "security_extras")
    if not isinstance(sx, dict):
        sx = {}

    # Defender 历史
    for row in sx.get("defender_history") or []:
        if not isinstance(row, dict):
            continue
        blob = json.dumps(row, ensure_ascii=False)
        if _DEFENDER_DISABLE_RX.search(blob):
            findings.append({
                "kind": "Defender",
                "severity": "high",
                "title": str(row.get("title") or row.get("action") or row.get("name") or "Defender 变更"),
                "detail": blob[:400],
                "time": str(row.get("time") or row.get("date") or ""),
            })

    # Defender / 防火墙 / 审计 / 篡改保护相关 EventID
    weaken_ids = [
        5001, 5010, 5012, 5007, 5013,  # Defender 关停/变更/排除
        5025, 5031, 2003, 2004, 2005, 2006,  # 防火墙服务/规则
        1102, 1100,  # 日志清空/服务关停
        4719, 4907,  # 审计策略
        7034, 7035, 7036, 7040,  # 服务异常/启动类型变更
        1,  # Sysmon 配置变更（若 message 含 config）
    ]
    for ev in _events_by_ids(rid, weaken_ids, limit=500):
        eid = int(ev.get("event_id") or 0)
        msg = str(ev.get("message") or "")
        title_map = {
            5001: "Defender 实时保护被关",
            5010: "Defender 扫描被关",
            5012: "Defender 行为监控被关",
            5007: "Defender 配置变更",
            5013: "Defender 排除项变更",
            5025: "Windows 防火墙服务停止",
            5031: "防火墙阻止应用（异常密集时关注）",
            2003: "防火墙规则变更",
            2004: "防火墙规则添加",
            2005: "防火墙规则修改",
            2006: "防火墙规则删除",
            1102: "审计日志被清空",
            1100: "事件日志服务关闭",
            4719: "系统审计策略变更",
            4907: "审计策略对象变更",
            7034: "服务异常终止",
            7035: "服务控制请求",
            7040: "服务启动类型被改",
        }
        if eid in (7034, 7035, 7036, 7040) and not re.search(
            r"(?i)defender|windefend|sense|mpssvc|firewall|wscsvc|securitycenter|eventlog|wuauserv",
            msg,
        ):
            continue
        if eid == 1 and not re.search(r"(?i)config|configuration|sysmon", msg):
            continue
        if eid == 5031 and not re.search(r"(?i)block|阻止", msg):
            continue
        findings.append({
            "kind": "事件",
            "severity": "high" if eid in (5001, 5010, 5012, 1102, 5025, 1100, 7040) else "medium",
            "title": title_map.get(eid, f"Event {eid}"),
            "detail": msg.replace("\n", " ")[:360],
            "time": ev.get("time") or "",
        })

    # 服务：WinDefend / wuauserv / EventLog 异常停止
    for svc in _load_blob_list(rid, "services"):
        name = str(svc.get("name") or "")
        disp = str(svc.get("display_name") or "")
        status = str(svc.get("status") or "").upper()
        low = (name + disp).lower()
        if any(x in low for x in ("windefend", "sense", "wdnis", "mpssvc", "eventlog", "wuauserv")):
            if "STOP" in status or status in ("STOPPED", "DISABLED"):
                findings.append({
                    "kind": "服务",
                    "severity": "high",
                    "title": f"{name or disp} 已停止/禁用",
                    "detail": f"status={status} start={svc.get('start_type')}",
                    "time": "",
                })

    uniq: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for f in findings:
        k = f"{f.get('kind')}|{f.get('title')}|{f.get('time')}"
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)

    return {
        "ok": True,
        "file": rid,
        "items": uniq[:300],
        "stats": {
            "count": len(uniq),
            "high": sum(1 for x in uniq if x.get("severity") == "high"),
        },
    }


# ─── 10. 外传 / 云同步 ───────────────────────────────────────────────────────
# 分层：高危 CLI/同步器 → 网盘客户端 → 常见办公同步（仅上下文，默认不告警）

_EXFIL_HIGH = [
    ("rclone", "Rclone"),
    (r"megacmd", "MEGA CMD"),
    (r"aws\s+s3", "AWS S3 CLI"),
    ("coscli", "腾讯云 COS"),
    ("ossutil", "阿里云 OSS"),
    (r"\balist\b", "Alist"),
    (r"pscp(?:\.exe)?\b", "PSCP"),
    (r"(?<![a-z])scp(?:\.exe)?\b", "SCP"),
]
_EXFIL_MED = [
    ("winscp", "WinSCP"),
    ("filezilla", "FileZilla"),
    ("baidunetdisk", "百度网盘"),
    (r"baidu\\netdisk", "百度网盘"),
    ("megasync", "MEGA"),
    ("dropbox", "Dropbox"),
    ("坚果云", "坚果云"),
    ("nutstore", "坚果云"),
    ("googledrivesync", "Google Drive"),
    (r"box\s*sync", "Box"),
]
# 几乎每台 Windows 都有：只作参考，不进告警；与大压缩包时间接近才升权
_EXFIL_COMMON = [
    ("onedrive", "OneDrive"),
    ("icloud", "iCloud"),
    ("google drive", "Google Drive"),
]

_EXFIL_ARCH_NOISE_PATH = re.compile(
    r"(?i)(?:wxworklocal|wechat files|\\tencent\\qq|\\telegram desktop\\"
    r"|\\discord\\|\\steam\\|\\epic games\\|\\node_modules\\"
    r"|\\windows\\installer\\|\\\$recycle\.bin\\)",
)
_EXFIL_ARCH_NOISE_NAME = re.compile(
    r"(?i)(?:sysmon|nxlog|winlogbeat|elastic-agent|chrome|firefox|"
    r"vscode|python-|nodejs|node-v\d|jdk|dotnet|redis|mysql|nginx|"
    r"360ent|360safe|vpnclient|"
    r"(?:^|[^a-z])(?:setup|installer|update|patch|sample|demo)(?:[^a-z]|$)|"
    r"安装包|安装程序|客户端安装)",
)
_EXFIL_ARCH_SUS_NAME = re.compile(
    r"(?i)(?:dump|backup|back.?up|export|archive|payload|secret|passw|credential|"
    r"资料|打包|备份|外发|移交|全盘|拷贝|汇总|台账|名录|通讯录|薪资|合同)",
)


def _exfil_parse_time(s: str) -> Optional[datetime]:
    raw = str(s or "").strip().replace("T", " ").replace("/", "-")
    raw = re.sub(r"\s+", " ", raw)
    if len(raw) < 10:
        return None
    candidates = [raw[:19], raw[:16], raw[:10]]
    formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")
    for cand, fmt in zip(candidates, formats):
        try:
            return datetime.strptime(cand, fmt)
        except Exception:
            continue
    return None


def _exfil_match_label(blob: str) -> Tuple[str, str]:
    """返回 (label, tier) tier=high|medium|common；无命中则 ('', '')."""
    low = str(blob or "")
    for pat, label in _EXFIL_HIGH:
        if re.search(pat, low, re.I):
            return label, "high"
    for pat, label in _EXFIL_MED:
        if re.search(pat, low, re.I):
            return label, "medium"
    for pat, label in _EXFIL_COMMON:
        if re.search(pat, low, re.I):
            return label, "common"
    return "", ""


def _exfil_score_archive(path: str, name: str, size: int) -> Tuple[int, str, List[str]]:
    """压缩包可疑分。返回 (score, severity, reasons)。score<20 丢弃。"""
    fp = str(path or "").replace("/", "\\")
    nm = str(name or "")
    reasons: List[str] = []
    score = 0
    if _EXFIL_ARCH_NOISE_PATH.search(fp):
        return 0, "low", ["聊天/安装缓存路径，忽略"]
    if _EXFIL_ARCH_NOISE_NAME.search(nm):
        return 0, "low", ["常见软件包名，忽略"]

    fpl = fp.lower()
    if "\\desktop\\" in fpl:
        score += 18
        reasons.append("桌面")
    elif "\\temp\\" in fpl or "\\appdata\\local\\temp\\" in fpl:
        score += 22
        reasons.append("临时目录")
    elif "\\downloads\\" in fpl:
        score += 8
        reasons.append("下载目录")
    elif "\\documents\\" in fpl:
        score += 10
        reasons.append("文档目录")
    elif "\\users\\public\\" in fpl:
        score += 20
        reasons.append("Public")
    else:
        score += 4

    if size >= 50_000_000:
        score += 28
        reasons.append(f"体积 {size // 1_000_000}MB")
    elif size >= 10_000_000:
        score += 16
        reasons.append(f"体积 {size // 1_000_000}MB")
    elif size >= 2_000_000:
        score += 8
        reasons.append(f"体积 {max(1, size // 1_000_000)}MB+")
    elif size > 0 and size < 200_000:
        score -= 10
        reasons.append("体积很小")

    if _EXFIL_ARCH_SUS_NAME.search(nm):
        score += 22
        reasons.append("名称可疑")
    # 随机短名 zip（如 a1b2c3.zip / data_20240101.zip 已由 SUS 覆盖部分）
    stem = re.sub(r"\.(zip|7z|rar)$", "", nm, flags=re.I)
    if re.fullmatch(r"[a-f0-9]{8,32}", stem or "", re.I):
        score += 18
        reasons.append("哈希样文件名")

    if score < 20:
        return score, "low", reasons or ["分不足"]
    sev = "high" if score >= 50 else ("medium" if score >= 32 else "low")
    return score, sev, reasons


def analyze_exfil(rid: str) -> Dict[str, Any]:
    rid = _rid(rid)
    tools: List[Dict[str, Any]] = []

    def _hit(
        kind: str,
        title: str,
        path: str,
        detail: str = "",
        time: str = "",
        *,
        tier: str = "medium",
        raise_alert: bool = True,
    ) -> None:
        sev = "high" if tier == "high" else ("medium" if tier == "medium" else "low")
        tools.append({
            "kind": kind,
            "tier": tier,
            "severity": sev,
            "raise_alert": bool(raise_alert),
            "title": title,
            "path": path,
            "detail": (detail or "")[:400],
            "time": time,
            "reasons": (
                ["高危外传/对象存储 CLI"] if tier == "high"
                else (["网盘/传输客户端"] if tier == "medium" else ["常见办公同步，默认参考"])
            ),
        })

    for pr in _load_blob_list(rid, "processes"):
        name = str(pr.get("name") or "")
        path = str(pr.get("path") or "")
        cmd = str(pr.get("command_line") or pr.get("command") or "")
        blob = f"{name} {path} {cmd}"
        label, tier = _exfil_match_label(blob)
        if not label:
            continue
        # OneDrive 仅进程存在：common；命令含 upload/sync 非常规参数时升 medium
        raise_alert = tier in ("high", "medium")
        if tier == "common" and re.search(r"(?i)\b(?:upload|copyto|sync|/upload)\b", cmd):
            tier = "medium"
            raise_alert = True
        _hit(
            "进程", label, path, cmd,
            str(pr.get("create_time") or pr.get("start_time") or ""),
            tier=tier, raise_alert=raise_alert,
        )

    for prog in _load_blob_list(rid, "installed_programs"):
        blob = " ".join(str(prog.get(k) or "") for k in ("name", "vendor", "install_location"))
        label, tier = _exfil_match_label(blob)
        if not label:
            continue
        _hit(
            "已装程序", label, str(prog.get("install_location") or ""),
            str(prog.get("name") or ""),
            str(prog.get("install_date") or ""),
            tier=tier, raise_alert=(tier in ("high", "medium")),
        )

    # 路径级：只扫高/中危客户端目录，不再扫 OneDrive 目录（噪声）
    for pat, label, tier in (
        ("%\\rclone%.exe", "Rclone", "high"),
        ("%\\megacmd%.exe", "MEGA CMD", "high"),
        ("%\\winscp%.exe", "WinSCP", "medium"),
        ("%\\filezilla%.exe", "FileZilla", "medium"),
        ("%\\baidunetdisk%.exe", "百度网盘", "medium"),
        ("%\\dropbox%.exe", "Dropbox", "medium"),
    ):
        for f in _files_like(rid, [pat], limit=8):
            nm = str(f.get("name") or "").lower()
            if not nm.endswith(".exe"):
                continue
            # 排除卸载/更新壳
            if any(x in nm for x in ("uninstall", "update", "setup", "installer")):
                continue
            _hit(
                "文件", label, str(f.get("full_path") or ""), "发现客户端可执行文件",
                str(f.get("mtime") or ""),
                tier=tier, raise_alert=True,
            )
            break

    # 压缩包：多落点，按评分过滤
    raw_archives = _files_like(rid, [
        "%\\users\\%\\desktop\\%.zip", "%\\users\\%\\desktop\\%.7z", "%\\users\\%\\desktop\\%.rar",
        "%\\users\\%\\documents\\%.zip", "%\\users\\%\\documents\\%.7z", "%\\users\\%\\documents\\%.rar",
        "%\\users\\%\\downloads\\%.zip", "%\\users\\%\\downloads\\%.7z",
        "%\\users\\%\\appdata\\local\\temp\\%.zip", "%\\users\\%\\appdata\\local\\temp\\%.7z",
        "%\\users\\public\\%.zip", "%\\users\\public\\%.7z",
        "%\\windows\\temp\\%.zip", "%\\windows\\temp\\%.7z",
    ], limit=300)
    archive_rows: List[Dict[str, Any]] = []
    for f in raw_archives:
        size = int(f.get("size") or 0)
        score, sev, reasons = _exfil_score_archive(
            str(f.get("full_path") or ""), str(f.get("name") or ""), size,
        )
        if score < 20:
            continue
        archive_rows.append({
            "kind": "压缩包",
            "severity": sev,
            "score": score,
            "title": f.get("name") or "",
            "path": f.get("full_path") or "",
            "detail": f"size={size}；" + "、".join(reasons),
            "time": str(f.get("mtime") or ""),
            "size": size,
            "reasons": reasons,
        })
    archive_rows.sort(key=lambda x: (-int(x.get("score") or 0), str(x.get("time") or "")), reverse=True)

    uniq: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for t in tools:
        k = f"{t['title']}|{t['kind']}|{t.get('path') or ''}"
        if k in seen:
            continue
        seen.add(k)
        uniq.append(t)
    # 同名工具保留最高 tier
    by_title: Dict[str, Dict[str, Any]] = {}
    rank = {"high": 0, "medium": 1, "common": 2}
    for t in uniq:
        title = str(t.get("title") or "")
        cur = by_title.get(title)
        if not cur or rank.get(str(t.get("tier")), 9) < rank.get(str(cur.get("tier")), 9):
            by_title[title] = t
        elif cur and t.get("path") and not cur.get("path"):
            by_title[title] = t
    uniq = sorted(by_title.values(), key=lambda x: (rank.get(str(x.get("tier")), 9), x.get("title") or ""))

    # Prefetch：高/中危工具执行时刻
    prefetch_hits: List[Dict[str, Any]] = []
    for pf in _load_blob_list(rid, "prefetch_files")[:400]:
        if not isinstance(pf, dict):
            continue
        name = str(pf.get("name") or "")
        label, tier = _exfil_match_label(name)
        if not label or tier == "common":
            continue
        prefetch_hits.append({
            "time": str(pf.get("last_run") or pf.get("mtime") or ""),
            "kind": "Prefetch",
            "tier": tier,
            "severity": "high" if tier == "high" else "medium",
            "title": label,
            "path": str(pf.get("path") or pf.get("full_path") or name),
            "detail": f"Prefetch {name}",
            "raise_alert": True,
        })

    # 时间线 + 「打包→外传」关联（±45 分钟）
    timeline: List[Dict[str, Any]] = []
    for t in uniq:
        if t.get("time"):
            timeline.append({
                "time": t["time"], "kind": t["kind"], "title": t["title"],
                "path": t.get("path") or "", "detail": t.get("detail") or "",
                "severity": t.get("severity") or "low", "tier": t.get("tier") or "",
            })
    for a in archive_rows:
        if not a.get("time"):
            continue
        timeline.append({
            "time": a["time"], "kind": "压缩包", "title": a.get("title") or "",
            "path": a.get("path") or "", "detail": a.get("detail") or "",
            "severity": a.get("severity") or "low", "size": a.get("size") or 0,
            "score": a.get("score") or 0,
        })
    for pf in prefetch_hits:
        if pf.get("time"):
            timeline.append(dict(pf))

    # 关联：大压缩包之后/之前有外传工具 Prefetch 或进程时间
    tool_times: List[Tuple[datetime, str, str]] = []
    for row in timeline:
        if row.get("kind") == "压缩包":
            continue
        if str(row.get("tier") or "") == "common":
            continue
        dt = _exfil_parse_time(str(row.get("time") or ""))
        if dt:
            tool_times.append((dt, str(row.get("title") or ""), str(row.get("kind") or "")))

    correlations: List[Dict[str, Any]] = []
    for a in archive_rows:
        if int(a.get("size") or 0) < 2_000_000 and int(a.get("score") or 0) < 32:
            continue
        adt = _exfil_parse_time(str(a.get("time") or ""))
        if not adt or not tool_times:
            continue
        best = None
        best_mins = 10**9
        for tdt, ttitle, tkind in tool_times:
            mins = abs(int((tdt - adt).total_seconds() // 60))
            if mins <= 45 and mins < best_mins:
                best_mins = mins
                best = (ttitle, tkind, mins, tdt)
        if not best:
            continue
        ttitle, tkind, mins, tdt = best
        order = "先打包后外传" if adt <= tdt else "先外传工具后出现压缩包"
        corr = {
            "kind": "关联",
            "severity": "high" if int(a.get("size") or 0) >= 10_000_000 or mins <= 15 else "medium",
            "title": f"{a.get('title')} ↔ {ttitle}",
            "path": a.get("path") or "",
            "time": a.get("time") or "",
            "detail": f"{order}；间隔 {mins} 分钟；{a.get('detail') or ''}",
            "delta_min": mins,
            "tool": ttitle,
            "archive": a.get("title") or "",
            "reasons": [order, f"间隔{mins}分", *(a.get("reasons") or [])],
        }
        correlations.append(corr)
        timeline.append({
            "time": a.get("time") or "",
            "kind": "关联",
            "title": corr["title"],
            "path": corr["path"],
            "detail": corr["detail"],
            "severity": corr["severity"],
        })
        # 关联命中时抬高压缩包级别
        if str(a.get("severity") or "") == "low":
            a["severity"] = "medium"
            a["detail"] = (a.get("detail") or "") + "；近时外传工具"

    # 常见同步若与关联同现，升为 medium 仅在 UI 提示（仍可不告警）
    alert_tools = [t for t in uniq if t.get("raise_alert")]
    ref_tools = [t for t in uniq if not t.get("raise_alert")]

    timeline = [x for x in timeline if x.get("time")]
    timeline.sort(key=lambda x: str(x.get("time") or ""), reverse=True)
    correlations.sort(key=lambda x: (0 if x.get("severity") == "high" else 1, int(x.get("delta_min") or 99)))

    return {
        "ok": True,
        "file": rid,
        "tools": uniq[:200],
        "alert_tools": alert_tools[:100],
        "ref_tools": ref_tools[:100],
        "archives": archive_rows[:120],
        "correlations": correlations[:80],
        "timeline": timeline[:200],
        "stats": {
            "tool_count": len(uniq),
            "alert_tool_count": len(alert_tools),
            "ref_tool_count": len(ref_tools),
            "archive_count": len(archive_rows),
            "correlation_count": len(correlations),
            "timeline_count": len(timeline),
        },
        "hint": "OneDrive 等常见同步默认仅参考；告警侧重 Rclone/对象存储 CLI、网盘客户端，以及大压缩包与外传工具的 ±45 分钟关联。",
    }


# ─── 4. 战役聚合（跨主机） ───────────────────────────────────────────────────

# 计划任务噪声：厂商自动更新 / 系统组件，跨主机也常见，不进战役视图
_TASK_NOISE_RX = re.compile(
    r"(?i)(\\microsoft\\|\\nvidia|\\google\\|\\mozilla\\|\\adobe\\"
    r"|\\onedrive|\\edgeupdate|\\office\\|\\windowsdefender"
    r"|\\intel\\|\\realtek|\\dropbox|\\steam|\\epicgames"
    r"|selfupdate|driverupdate|profileupdater|nvprofile|nvdriver"
    r"|\\user_feed_synchronization|\\optimize.star"
    r")"
)


def _campaign_add(
    groups: Dict[str, Dict[str, Any]],
    *,
    gkey: str,
    kind: str,
    label: str,
    key: str,
    hostname: str,
    rid: str,
    collect_time: str = "",
    jump: str = "overview",
) -> None:
    g = groups[gkey]
    if not g.get("kind"):
        g.update(key=key, kind=kind, label=label, jump=jump, reports=[])
    if hostname and hostname not in g["hosts"]:
        g["hosts"].append(hostname)
    # 主机-报告配对，避免「两个打开」分不清是哪台
    entry = {"hostname": hostname, "file": rid, "collect_time": collect_time}
    exists = {f"{x.get('hostname')}|{x.get('file')}" for x in g.get("reports") or []}
    ek = f"{hostname}|{rid}"
    if ek not in exists:
        g.setdefault("reports", []).append(entry)
    g["count"] = len(g["hosts"])


def _light_remote_signals(rid: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """轻量提取远控本机 ID 与对端 IP，避免每份报告跑完整 analyze_remote_tools。"""
    ids: List[Tuple[str, str]] = []  # (tool_name, client_id)
    peers: List[str] = []
    # config.ini clientId
    for f in _files_like(rid, [
        "%\\todesk\\config.ini", "%\\oray\\%\\config.ini", "%\\awesun\\%\\config.ini",
        "%\\anydesk\\system.conf",
    ], limit=30):
        content = str(f.get("content") or "")
        if not content:
            try:
                from .db_store import load_file_content
                content = str((load_file_content(rid, f.get("full_path") or "") or {}).get("content") or "")
            except Exception:
                content = ""
        m = re.search(r"(?im)^\s*clientId\s*=\s*(\S+)", content)
        if m:
            path = str(f.get("full_path") or "").lower()
            tool = "ToDesk" if "todesk" in path else (
                "向日葵" if ("oray" in path or "awesun" in path) else (
                    "AnyDesk" if "anydesk" in path else "远控"
                )
            )
            ids.append((tool, m.group(1).strip()))
        m = re.search(r"(?im)^\s*ad\.anynet\.id\s*=\s*(\S+)", content)
        if m:
            ids.append(("AnyDesk", m.group(1).strip()))
    # history / 服务日志里的对端 IP（抽样）
    for f in _files_like(rid, ["%\\oray\\%\\history.log", "%\\awesun\\%\\history.log"], limit=8):
        content = str(f.get("content") or "")
        for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", content):
            ip = m.group(1)
            if not _PRIV_IP.match(ip) and ip not in peers:
                peers.append(ip)
                if len(peers) >= 12:
                    break
    return ids, peers


def _campaign_os_family(rid: str, meta: Optional[Dict[str, Any]] = None) -> str:
    """轻量判定报告系统族，供战役按轨道过滤。"""
    from .os_detect import detect_os_family

    blob: Dict[str, Any] = dict(meta) if isinstance(meta, dict) else {}
    if not blob.get("os_family") and not blob.get("os"):
        low = str(rid or "").lower()
        if "linuxsc" in low or "_linux_" in low or low.startswith("linux_"):
            blob.setdefault("collector", "linuxsc")
    return detect_os_family(blob)


def analyze_campaign(
    limit_hosts: int = 80,
    progress_cb: Optional[Callable[[int, str], None]] = None,
    os_family: str = "",
) -> Dict[str, Any]:
    """扫描近期报告，按远控 ID / 公网对端 / 跨主机任务 / 外传工具聚合。

    progress_cb(pct 0-100, message)
    os_family: windows|linux|all|空；专轨只扫同系统，避免 Windows 轨道冒出 Linux。
    """
    def _prog(pct: int, msg: str) -> None:
        if progress_cb:
            try:
                progress_cb(max(0, min(100, int(pct))), msg)
            except Exception:
                pass

    want = str(os_family or "").strip().lower()
    if want in ("", "all", "*"):
        want = ""
    elif want not in ("windows", "linux"):
        want = ""

    groups: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "key": "", "kind": "", "label": "", "hosts": [], "reports": [], "count": 0, "jump": "overview",
    })

    report_ids: List[Tuple[str, str, str]] = []  # (rid, hostname, collect_time)
    _prog(2, "枚举报告目录" + (f"（{want}）" if want else ""))
    try:
        from . import config as cfg
        root = cfg.REPORTS_DIR
        if root.is_dir():
            dirs = [d for d in root.iterdir() if d.is_dir() and not d.name.startswith("_")]
            dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            for d in dirs:
                meta = d / "report.json"
                host = d.name.split("_")[0]
                ct = ""
                meta_j: Dict[str, Any] = {}
                if meta.is_file():
                    try:
                        j = json.loads(meta.read_text(encoding="utf-8"))
                        if isinstance(j, dict):
                            meta_j = j
                            host = str(j.get("hostname") or host)
                            ct = str(j.get("collect_time") or "")
                    except Exception:
                        pass
                if want:
                    fam = _campaign_os_family(d.name, meta_j)
                    if fam != want:
                        continue
                report_ids.append((d.name, host, ct))
                if len(report_ids) >= limit_hosts:
                    break
    except Exception:
        pass

    total = max(1, len(report_ids))
    _prog(8, f"已枚举 {len(report_ids)} 份报告" + (f"（{want}）" if want else ""))

    for idx, (rid, hostname, ct) in enumerate(report_ids):
        pct = 8 + int(80 * (idx + 1) / total)
        _prog(pct, f"扫描 {hostname}（{idx + 1}/{total}）")
        # 远控 ID / 对端
        try:
            ids, peers = _light_remote_signals(rid)
            for tool, cid in ids:
                if len(cid) < 4:
                    continue
                _campaign_add(
                    groups, gkey=f"remote_id|{cid}", kind="远控本机ID",
                    label=f"{tool} {cid}", key=cid, hostname=hostname, rid=rid,
                    collect_time=ct, jump="remote",
                )
            for pip in peers:
                _campaign_add(
                    groups, gkey=f"peer_ip|{pip}", kind="远控对端IP",
                    label=pip, key=pip, hostname=hostname, rid=rid,
                    collect_time=ct, jump="remote",
                )
        except Exception:
            pass

        # 计划任务：仅保留非厂商噪声；最终再按跨主机过滤
        for t in _load_blob_list(rid, "scheduled_tasks")[:120]:
            name = str(t.get("task_name") or t.get("name") or "")
            if not name or len(name) < 4:
                continue
            low = name.lower()
            if low.startswith("\\microsoft") or _TASK_NOISE_RX.search(name):
                continue
            _campaign_add(
                groups, gkey=f"task|{low}", kind="计划任务",
                label=name, key=name, hostname=hostname, rid=rid,
                collect_time=ct, jump="task",
            )

        # 外传工具名跨主机
        try:
            ex = analyze_exfil(rid)
            for tool in ex.get("tools") or []:
                title = str(tool.get("title") or "").strip()
                if not title:
                    continue
                _campaign_add(
                    groups, gkey=f"exfil|{title.lower()}", kind="外传工具",
                    label=title, key=title, hostname=hostname, rid=rid,
                    collect_time=ct, jump="exfil",
                )
        except Exception:
            pass

        # 启动项短名跨主机（非 Microsoft）
        for st in _load_blob_list(rid, "startup_items")[:60]:
            name = str(st.get("name") or "").strip()
            if not name or len(name) < 3:
                continue
            low = name.lower()
            if "microsoft" in low or "windows" in low:
                continue
            _campaign_add(
                groups, gkey=f"startup|{low}", kind="启动项",
                label=name, key=name, hostname=hostname, rid=rid,
                collect_time=ct, jump="startup",
            )

    _prog(92, "聚合跨主机线索")

    out = []
    for g in groups.values():
        kind = g.get("kind") or ""
        hc = len(g.get("hosts") or [])
        # 计划任务 / 外传 / 启动项：必须跨主机；远控 ID/对端：单主机也保留
        if kind in ("计划任务", "外传工具", "启动项") and hc < 2:
            continue
        if hc < 1:
            continue
        if kind in ("远控对端IP", "远控本机ID") or hc >= 2:
            reports = g.get("reports") or []
            out.append({
                "key": g["key"],
                "kind": kind,
                "label": g["label"],
                "hosts": g["hosts"][:30],
                "files": [r.get("file") for r in reports if r.get("file")][:30],
                "reports": reports[:30],
                "host_count": hc,
                "jump": g.get("jump") or "overview",
                "hint": _campaign_hint(kind, g["label"], hc),
            })
    kind_rank = {"远控对端IP": 0, "远控本机ID": 1, "外传工具": 2, "启动项": 3, "计划任务": 4}
    out.sort(key=lambda x: (
        kind_rank.get(x["kind"], 9),
        -x["host_count"],
        x["label"],
    ))
    _prog(100, "完成")
    return {
        "ok": True,
        "groups": out[:200],
        "os_family": want or "all",
        "stats": {
            "group_count": len(out),
            "multi_host": sum(1 for x in out if x["host_count"] >= 2),
            "scanned_reports": len(report_ids),
            "remote_groups": sum(1 for x in out if "远控" in x["kind"]),
            "task_groups": sum(1 for x in out if x["kind"] == "计划任务"),
            "os_family": want or "all",
        },
    }


def _campaign_hint(kind: str, label: str, host_count: int) -> str:
    if kind == "远控本机ID":
        return f"多台机器若共用/撞上同一远控 ID，优先核对是否同一套远控账号或克隆盘（{host_count} 台）"
    if kind == "远控对端IP":
        return f"同一公网对端连入多台主机，高度可疑横向/统一运维入口：{label}"
    if kind == "外传工具":
        return f"多台主机出现同一外传/网盘客户端「{label}」，核查是否批量部署或数据外带"
    if kind == "计划任务":
        return f"非系统任务「{label}」出现在 {host_count} 台主机，比对命令行与落点是否一致"
    if kind == "启动项":
        return f"同名启动项「{label}」出现在 {host_count} 台主机，核查命令行是否一致"
    return ""
