"""登录行为时间窗关联：单条事件规则看不出的爆破 / 密码喷洒 / 失败后成功。

Windows：Security 4625（失败）/ 4624（成功），按 主机+来源IP+账号 聚合。
Linux：sshd 文本 Failed password / Accepted ... for <user> from <ip>。
时间戳缺失或不可解析的记录只计数，不用来证明“短时间内连续攻击”。
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .eventlog_rules import _field_get, event_hit_key

BURST_WINDOW_S = 300
BURST_MIN = 5
SPRAY_MIN_FAILS = 10
SPRAY_MIN_USERS = 3
SUCCESS_LOOKBACK_S = 600
UNTIMED_MIN = 10
MAX_PER_RULE = 50

_IGNORED_IPS = frozenset({"", "-", "::1", "127.0.0.1", "0.0.0.0", "localhost"})

_LINUX_FAIL = re.compile(
    r"(?i)Failed\s+(?:password|publickey|keyboard-interactive(?:/pam)?|none)\s+for\s+"
    r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)"
)
_LINUX_INVALID = re.compile(r"(?i)Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)")
_LINUX_OK = re.compile(
    r"(?i)Accepted\s+(?:password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)"
)
_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})")
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _parse_ts(raw: Any, message: str = "") -> Optional[float]:
    s = str(raw or "").strip()
    if s:
        t = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s) else s
        t = re.sub(r"[Zz]$", "+00:00", t)
        # Windows 事件时间为 7 位小数秒，fromisoformat 只认 6 位
        t = re.sub(r"(\.\d{6})\d+", r"\1", t)
        try:
            dt = datetime.fromisoformat(t)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    # syslog 无年份：同一份日志内只用于排序与间隔计算，跨年边界不处理
    m = _SYSLOG_TS.match(s) or _SYSLOG_TS.match(str(message or "").strip())
    if m and m.group("mon") in _MONTHS:
        try:
            hh, mm, ss = (int(x) for x in m.group("hms").split(":"))
            dt = datetime(2000, _MONTHS[m.group("mon")], int(m.group("day")), hh, mm, ss, tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


def _event_id(ev: Dict[str, Any]) -> int:
    try:
        return int(ev.get("event_id") or ev.get("EventID") or 0)
    except (TypeError, ValueError):
        return 0


def _msg_field(message: str, name: str) -> str:
    m = re.search(rf"\b{name}=(\S+)", message or "")
    return m.group(1) if m else ""


def _windows_login(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "security" not in str(ev.get("channel") or "").lower():
        return None
    eid = _event_id(ev)
    if eid not in (4624, 4625):
        return None
    msg = str(ev.get("message") or "")
    ip = (_field_get(ev, "IpAddress") or _msg_field(msg, "IpAddress")).strip()
    user = (_field_get(ev, "TargetUserName") or _msg_field(msg, "TargetUserName")).strip()
    if ip.lower() in _IGNORED_IPS or not user or user == "-" or user.endswith("$"):
        return None
    return {
        "kind": "fail" if eid == 4625 else "success",
        "ip": ip,
        "user": user,
        "logon_type": (_field_get(ev, "LogonType") or _msg_field(msg, "LogonType")).strip(),
    }


def _linux_login(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    msg = str(ev.get("message") or "")
    if not msg or "from" not in msg:
        return None
    m = _LINUX_OK.search(msg)
    kind = "success"
    if not m:
        m = _LINUX_FAIL.search(msg) or _LINUX_INVALID.search(msg)
        kind = "fail"
    if not m:
        return None
    ip = m.group("ip").strip()
    if ip.lower() in _IGNORED_IPS:
        return None
    return {"kind": kind, "ip": ip, "user": m.group("user").strip(), "logon_type": "ssh"}


def _extract(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        rec = _windows_login(ev) or _linux_login(ev)
        if not rec:
            continue
        rec["host"] = str(ev.get("computer") or "").strip()
        rec["ts"] = _parse_ts(ev.get("time"), str(ev.get("message") or ""))
        rec["ev"] = ev
        out.append(rec)
    return out


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "未知"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _hit(rule_id: str, title: str, level: str, anchor: Dict[str, Any], evidence: str) -> Dict[str, Any]:
    ev = anchor["ev"]
    ch = ev.get("channel") or ""
    tm = ev.get("time") or ""
    eid = _event_id(ev)
    return {
        "rule_id": rule_id,
        "title": title,
        "level": level,
        "event_id": eid,
        "channel": ch,
        "time": tm,
        "hit_key": event_hit_key(ch, eid, tm),
        "evidence": evidence[:1200],
        "provider": ev.get("provider") or "",
        "correlation": True,
    }


def _densest_window(timed: List[Dict[str, Any]], window: int) -> Tuple[int, int]:
    """返回窗口内条数最多的 [left, right] 下标（timed 已按 ts 升序）。"""
    best = (0, -1)
    left = 0
    for right in range(len(timed)):
        while timed[right]["ts"] - timed[left]["ts"] > window:
            left += 1
        if right - left > best[1] - best[0]:
            best = (left, right)
    return best


def _logon_types(recs: List[Dict[str, Any]]) -> str:
    types = sorted({r["logon_type"] for r in recs if r.get("logon_type")})
    return ",".join(types)


def correlate_logins(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    recs = _extract(events)
    if not recs:
        return []
    fails: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    oks: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    by_ip: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in recs:
        key = (r["host"].lower(), r["ip"].lower(), r["user"].lower())
        (fails if r["kind"] == "fail" else oks).setdefault(key, []).append(r)
        if r["kind"] == "fail":
            by_ip.setdefault((r["host"].lower(), r["ip"].lower()), []).append(r)

    burst: List[Tuple[int, Dict[str, Any]]] = []
    untimed: List[Tuple[int, Dict[str, Any]]] = []
    after: List[Tuple[int, Dict[str, Any]]] = []

    for key, fl in fails.items():
        timed = sorted((r for r in fl if r["ts"] is not None), key=lambda r: r["ts"])
        ip, user = fl[0]["ip"], fl[0]["user"]
        lt = _logon_types(fl)
        lt_s = f"，登录类型 {lt}" if lt else ""
        left, right = _densest_window(timed, BURST_WINDOW_S) if timed else (0, -1)
        n_win = right - left + 1
        if n_win >= BURST_MIN:
            first, last = timed[left], timed[right]
            burst.append((n_win, _hit(
                "login.bruteforce_burst",
                f"登录爆破：{ip} → {user}",
                "high",
                last,
                f"来源 {ip} 对账号 {user} 在 {BURST_WINDOW_S // 60} 分钟内失败登录 {n_win} 次"
                f"（{_fmt_ts(first['ts'])} 至 {_fmt_ts(last['ts'])}，总失败 {len(fl)} 次{lt_s}）。"
                "需核对来源是否为授权运维地址。",
            )))
        elif len(fl) >= UNTIMED_MIN and len(timed) < len(fl):
            untimed.append((len(fl), _hit(
                "login.repeated_failures_untimed",
                f"重复失败登录：{ip} → {user}",
                "medium",
                fl[-1],
                f"来源 {ip} 对账号 {user} 共失败登录 {len(fl)} 次{lt_s}；"
                f"其中 {len(fl) - len(timed)} 条缺少可解析时间，无法证明为短时间连续攻击。",
            )))

        for ok in sorted((r for r in oks.get(key, []) if r["ts"] is not None), key=lambda r: r["ts"]):
            prior = [r for r in timed if ok["ts"] - SUCCESS_LOOKBACK_S <= r["ts"] <= ok["ts"]]
            if len(prior) >= BURST_MIN:
                after.append((len(prior), _hit(
                    "login.success_after_failures",
                    f"多次失败后登录成功：{ip} → {user}",
                    "critical",
                    ok,
                    f"来源 {ip} 对账号 {user} 在登录成功前 {SUCCESS_LOOKBACK_S // 60} 分钟内失败 {len(prior)} 次，"
                    f"随后于 {_fmt_ts(ok['ts'])} 登录成功"
                    + (f"（登录类型 {ok['logon_type']}）" if ok.get("logon_type") else "")
                    + "。账号可能已失陷，需核对该会话后续的进程、文件与外联行为。",
                )))
                break

    spray: List[Tuple[int, Dict[str, Any]]] = []
    for (_, _), fl in by_ip.items():
        timed = sorted((r for r in fl if r["ts"] is not None), key=lambda r: r["ts"])
        if len(timed) < SPRAY_MIN_FAILS:
            continue
        left, right = _densest_window(timed, BURST_WINDOW_S)
        win = timed[left:right + 1]
        users = sorted({r["user"] for r in win}, key=str.lower)
        if len(win) >= SPRAY_MIN_FAILS and len(users) >= SPRAY_MIN_USERS:
            ip = win[0]["ip"]
            shown = "、".join(users[:8]) + (f" 等 {len(users)} 个" if len(users) > 8 else "")
            spray.append((len(win), _hit(
                "login.password_spray",
                f"密码喷洒：{ip} 尝试 {len(users)} 个账号",
                "high",
                win[-1],
                f"来源 {ip} 在 {BURST_WINDOW_S // 60} 分钟内对 {len(users)} 个账号失败登录 {len(win)} 次"
                f"（{_fmt_ts(win[0]['ts'])} 至 {_fmt_ts(win[-1]['ts'])}）：{shown}。",
            )))

    out: List[Dict[str, Any]] = []
    for bucket in (after, burst, spray, untimed):
        bucket.sort(key=lambda x: x[0], reverse=True)
        out.extend(h for _, h in bucket[:MAX_PER_RULE])
    return out
