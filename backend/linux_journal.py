"""Linux journal / auth 日志文本规则命中（对齐 LinuxSC event_logs 轻量结构）。

Windows Sigma（Channel+EventID）对 journal 无效；此处用内置 IOC 文案 +
rules/linux 中 category∈{journal,log,auditd,auth} 的规则扫 message。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# 内置：覆盖应急最常见的 auth/sshd/sudo 痕迹（channel 可空=全通道）
_BUILTIN: List[Dict[str, Any]] = [
    {
        "id": "linux_journal_ssh_auth_fail",
        "title": "SSH/认证失败（Failed password / pam）",
        "level": "medium",
        "pattern": r"(?i)Failed\s+password|authentication\s+failure|pam_unix\([^\)]*auth\):\s*authentication\s+failure",
        "channels": ("sshd", "journalctl-xe", "auth", "secure"),
    },
    {
        "id": "linux_journal_ssh_invalid_user",
        "title": "SSH 无效用户探测",
        "level": "medium",
        "pattern": r"(?i)Invalid\s+user\s+\S+|Failed\s+none\s+for\s+invalid\s+user",
        "channels": ("sshd", "journalctl-xe", "auth", "secure"),
    },
    {
        "id": "linux_journal_ssh_root_ok",
        "title": "SSH 接受 root 登录",
        "level": "high",
        "pattern": r"(?i)Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+root\b",
        "channels": ("sshd", "journalctl-xe", "auth", "secure"),
    },
    {
        "id": "linux_journal_breakin",
        "title": "SSH 疑似暴力破解提示",
        "level": "high",
        "pattern": r"(?i)POSSIBLE\s+BREAK-IN\s+ATTEMPT|error:\s*maximum\s+authentication\s+attempts",
        "channels": ("sshd", "journalctl-xe", "auth", "secure"),
    },
    {
        "id": "linux_journal_sudo_root",
        "title": "sudo 提权执行",
        "level": "medium",
        "pattern": r"(?i)\bsudo(?:\[\d+\])?:\s+\S+\s+:\s+.*COMMAND=|USER=root\s+;?\s*COMMAND=",
        "channels": ("journalctl-xe", "auth", "secure", "sudo"),
    },
    {
        "id": "linux_journal_useradd",
        "title": "新增用户/改密痕迹",
        "level": "high",
        "pattern": r"(?i)\b(?:useradd|adduser|usermod|passwd)\b.*(?:uid|home|/etc/passwd)|new\s+user:\s*name=",
        "channels": ("journalctl-xe", "auth", "secure"),
    },
    {
        "id": "linux_journal_cron_session",
        "title": "cron/at 会话异常提示",
        "level": "low",
        "pattern": r"(?i)CRON\[\d+\].*(?:CMD|/tmp/|/dev/shm/)|session\s+opened\s+for\s+user\s+root\s+by\s+\(uid=0\)",
        "channels": ("journalctl-xe", "cron", "auth"),
    },
    {
        "id": "linux_journal_reverse_hint",
        "title": "日志中出现反弹壳特征",
        "level": "critical",
        "pattern": r"(?i)/dev/tcp/|/dev/udp/|bash\s+-i\s+>&\s*/dev/tcp|nc\s+-[elp].*\d{2,5}|ncat\s+.*-e\s+",
        "channels": (),
    },
]


SAMPLES_PER_GROUP = 50


def _compile(pat: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pat)
    except re.error:
        return None


def _rules_from_store(store) -> List[Dict[str, Any]]:
    """从 store.linux 抽 journal/log/audit/auth 类规则。"""
    if store is None:
        return []
    linux = getattr(store, "linux", None) or {}
    if not isinstance(linux, dict):
        return []
    out: List[Dict[str, Any]] = []
    for key in ("textRules", "commandRules", "processRules"):
        for r in linux.get(key) or []:
            if not isinstance(r, dict) or r.get("enabled") is False:
                continue
            cat = str(r.get("category") or "").lower()
            tags = " ".join(str(t).lower() for t in (r.get("tags") or []) if t)
            rid = str(r.get("id") or "").lower()
            if not any(
                x in cat or x in tags or x in rid
                for x in ("journal", "audit", "auth", "sshd", "syslog", "log")
            ):
                # 仅收明确日志类；避免把全部 command 规则扫到 journal（误报/性能）
                if cat not in ("log", "journal", "auditd", "auth"):
                    continue
            pat = str(r.get("pattern") or "")
            if not pat and not r.get("containsAny"):
                continue
            out.append({
                "id": str(r.get("id") or "linux_journal_store"),
                "title": str(r.get("name") or r.get("title") or r.get("id") or "Linux 日志规则"),
                "level": str(r.get("severity") or r.get("level") or "medium").lower(),
                "pattern": pat,
                "containsAny": r.get("containsAny"),
                "channels": (),
                "source": str(r.get("source") or "linux-rules"),
            })
    return out


def _channel_ok(rule: Dict[str, Any], channel: str) -> bool:
    chs = rule.get("channels") or ()
    if not chs:
        return True
    cl = (channel or "").lower()
    return any(str(c).lower() in cl for c in chs)


def match_linux_journal(
    events: List[Dict[str, Any]],
    store=None,
    max_hits: int = 800,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rules: List[Dict[str, Any]] = list(_BUILTIN) + _rules_from_store(store)
    compiled: List[Tuple[Dict[str, Any], Optional[re.Pattern], Tuple[str, ...]]] = []
    for r in rules:
        needles = tuple(str(n).lower() for n in (r.get("containsAny") or []) if str(n).strip())
        cre = _compile(str(r.get("pattern") or "")) if r.get("pattern") else None
        if not cre and not needles:
            continue
        compiled.append((r, cre, needles))

    # 同规则同通道合并为一组：高频命中（SSH 失败等）不再占满上限挤掉后续高危命中
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    scanned = 0
    seen: Set[str] = set()
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        scanned += 1
        msg = str(ev.get("message") or "")
        if not msg.strip():
            continue
        low = msg.lower()
        ch = str(ev.get("channel") or "")
        for rule, cre, needles in compiled:
            if not _channel_ok(rule, ch):
                continue
            ok = False
            if needles and any(n in low for n in needles):
                ok = True
            elif cre and cre.search(msg):
                ok = True
            if not ok:
                continue
            rid = str(rule.get("id") or "")
            key = f"{rid}|{ch}|{str(ev.get('time') or '')}|{msg[:160]}"
            if key in seen:
                continue
            seen.add(key)
            gk = (rid, ch)
            g = groups.get(gk)
            if g is None:
                if len(groups) >= max_hits:
                    continue
                lv = str(rule.get("level") or "medium").lower()
                if lv == "informational":
                    lv = "low"
                g = groups[gk] = {
                    "rule_id": rid,
                    "title": str(rule.get("title") or rid),
                    "level": lv,
                    "event_id": ev.get("event_id") or "",
                    "channel": ch,
                    "time": ev.get("time") or "",
                    "provider": ev.get("provider") or "linuxsc",
                    "count": 0,
                    "samples": [],
                    "first_time": "",
                    "last_time": "",
                }
            g["count"] += 1
            if len(g["samples"]) < SAMPLES_PER_GROUP:
                g["samples"].append(msg[:600])
            tm = str(ev.get("time") or "").strip()
            if tm:
                g["first_time"] = g["first_time"] or tm
                g["last_time"] = tm

    hits: List[Dict[str, Any]] = []
    for (rid, ch), g in groups.items():
        n = g["count"]
        head = f"同一来源共命中 {n} 条"
        if g["first_time"]:
            head += f"（{g['first_time']} 至 {g['last_time']}）" if g["last_time"] != g["first_time"] else f"（{g['first_time']}）"
        if n > len(g["samples"]):
            head += f"，以下为前 {len(g['samples'])} 条原文"
        hits.append({
            "rule_id": rid,
            "title": g["title"],
            "level": g["level"],
            "event_id": g["event_id"],
            "channel": ch,
            "time": g["time"],
            "hit_key": f"linuxj|{rid}|{abs(hash((rid, ch))) % 10_000_000}",
            "evidence": head + "\n" + "\n".join(g["samples"]),
            "provider": g["provider"],
            "hit_count": n,
            "first_time": g["first_time"],
            "last_time": g["last_time"],
        })

    # 高危优先
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    hits.sort(key=lambda h: rank.get(str(h.get("level") or "").lower(), 0), reverse=True)
    meta = {
        "rules_loaded": len(compiled),
        "events_scanned": scanned,
        "hits": len(hits),
        "hit_lines": sum(h["hit_count"] for h in hits),
        "hits_high": sum(1 for h in hits if str(h.get("level") or "").lower() in ("high", "critical")),
        "engine": "linux_journal",
        "min_level": "low",
        "capped": len(groups) >= max_hits,
    }
    return hits, meta


def looks_like_linux_events(events: List[Any]) -> bool:
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        prov = str(ev.get("provider") or "").lower()
        ch = str(ev.get("channel") or "").lower()
        if prov == "linuxsc" or ch in ("journalctl-xe", "sshd", "last", "lastb", "auth", "secure"):
            return True
        if "journal" in ch:
            return True
    return False
