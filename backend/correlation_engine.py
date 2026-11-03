"""时间线/日志关联：频率、序列、首次出现；与 login_correlation 互补。"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from . import agent_protocol

_lock = threading.RLock()
# (agent_id, rule_id, group_key) -> deque[(ts_float, event_ref)]
_freq_state: Dict[Tuple[str, str, str], Deque[float]] = defaultdict(deque)
_RULES_CACHE: Optional[List[Dict[str, Any]]] = None
_RULES_MTIME: float = 0.0

_SIGNED_OK = frozenset({"valid", "signed", "true"})


def _rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "correlation_rules.json"


def load_correlation_rules() -> List[Dict[str, Any]]:
    global _RULES_CACHE, _RULES_MTIME
    p = _rules_path()
    try:
        mt = p.stat().st_mtime
    except OSError:
        return []
    with _lock:
        if _RULES_CACHE is not None and mt == _RULES_MTIME:
            return _RULES_CACHE
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            _RULES_CACHE = []
            _RULES_MTIME = mt
            return []
        items = raw.get("rules") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            items = []
        _RULES_CACHE = [r for r in items if isinstance(r, dict) and r.get("id")]
        _RULES_MTIME = mt
        return _RULES_CACHE


def _parse_ts(ev: Dict[str, Any]) -> float:
    s = str(ev.get("ts") or ev.get("time") or "").strip()
    if not s:
        return time.time()
    s = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s) else s
    s = re.sub(r"[Zz]$", "+00:00", s)
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return time.time()


def _detail_of(ev: Dict[str, Any]) -> Dict[str, Any]:
    d = ev.get("detail")
    return d if isinstance(d, dict) else {}


def _blob(ev: Dict[str, Any]) -> str:
    d = _detail_of(ev)
    parts = [str(ev.get("summary") or ""), str(ev.get("etype") or "")]
    parts.extend(str(v) for v in d.values() if isinstance(v, (str, int, float)))
    return "\n".join(parts)


def _field(ev: Dict[str, Any], name: str) -> str:
    d = _detail_of(ev)
    v = d.get(name)
    if v is None:
        return ""
    return str(v).strip()


def _match_rule(ev: Dict[str, Any], spec: Dict[str, Any]) -> bool:
    if not spec:
        return True
    et = str(ev.get("etype") or "").lower()
    if spec.get("etype"):
        if et != str(spec["etype"]).lower():
            return False
    et_in = spec.get("etype_in")
    if isinstance(et_in, list) and et_in:
        if et not in [str(x).lower() for x in et_in]:
            return False
    if spec.get("etype_contains"):
        if str(spec["etype_contains"]).lower() not in et:
            return False
    blob = _blob(ev)
    rx = spec.get("detail_regex")
    if rx:
        try:
            if not re.search(str(rx), blob, re.I):
                return False
        except re.error:
            return False
    prx = spec.get("parent_regex")
    if prx:
        try:
            if not re.search(str(prx), _field(ev, "parent_name") or _field(ev, "parent_path"), re.I):
                return False
        except re.error:
            return False
    nrx = spec.get("name_regex")
    if nrx:
        nm = _field(ev, "name") or _field(ev, "process_name")
        try:
            if not re.search(str(nrx), nm, re.I):
                return False
        except re.error:
            return False
    signed_not = spec.get("signed_not")
    if isinstance(signed_not, list):
        sig = str(_field(ev, "signed") or "").lower()
        if sig in _SIGNED_OK:
            return False
    return True


def _group_key(agent_id: str, rule: Dict[str, Any], ev: Dict[str, Any]) -> str:
    parts = [agent_id]
    for f in rule.get("group_by") or ["agent_id"]:
        if f == "agent_id":
            continue
        parts.append(_field(ev, f) or _field(ev, f.replace("process_", "")) or "-")
    return "|".join(parts)


def _ensure_first_seen_table(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_correlation_seen (
            agent_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, rule_id, dedupe_key)
        )"""
    )


def _first_seen_hit(agent_id: str, rule: Dict[str, Any], ev: Dict[str, Any], host: str) -> bool:
    spec = rule.get("match") or {}
    if not _match_rule(ev, spec):
        return False
    fields = rule.get("dedupe_key_fields") or ["path"]
    key_parts = []
    for f in fields:
        key_parts.append(_field(ev, f) or _field(ev, "name") or "?")
    dedupe = "|".join(key_parts).lower()[:240]
    if not dedupe or dedupe == "?":
        return False
    rid = str(rule["id"])
    from . import agent_edr
    agent_edr.ensure()
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            _ensure_first_seen_table(conn)
            row = conn.execute(
                "SELECT first_seen_at FROM agent_correlation_seen WHERE agent_id=? AND rule_id=? AND dedupe_key=?",
                (agent_id, rid, dedupe),
            ).fetchone()
            if row:
                return False
            conn.execute(
                "INSERT INTO agent_correlation_seen(agent_id, rule_id, dedupe_key, first_seen_at) VALUES(?,?,?,?)",
                (agent_id, rid, dedupe, now),
            )
            conn.commit()
        finally:
            conn.close()
    _emit(agent_id, host, rule, ev, extra={"dedupe_key": dedupe, "first_seen": True})
    return True


def _emit(
    agent_id: str,
    host: str,
    rule: Dict[str, Any],
    ev: Dict[str, Any],
    *,
    extra: Optional[Dict[str, Any]] = None,
    evidence: str = "",
) -> bool:
    sev = str(rule.get("severity") or "medium").lower()
    bb = bool(rule.get("building_block"))
    detail: Dict[str, Any] = {
        "correlation_rule_id": rule.get("id"),
        "etype": ev.get("etype"),
        "event_ts": ev.get("ts"),
        "correlation": True,
    }
    d = _detail_of(ev)
    for k in ("path", "name", "parent_name", "user", "ip", "command_line", "pid"):
        if d.get(k) is not None:
            detail[k] = d[k]
    if rule.get("mitre"):
        detail["mitre"] = rule["mitre"]
    if rule.get("note"):
        detail["investigation"] = str(rule["note"])[:500]
    if evidence:
        detail["evidence"] = evidence[:1200]
    if extra:
        detail.update(extra)
    if bb:
        detail["building_block"] = True
        if sev in ("high", "critical"):
            sev = "medium"
    risk = rule.get("risk_score")
    if risk is not None:
        detail["risk_score"] = int(risk)
    mod = "building_block" if bb else "correlation"
    r = agent_protocol.report_event({
        "agent_id": agent_id,
        "hostname": host,
        "module": mod,
        "severity": sev,
        "title": str(rule.get("title") or rule.get("id"))[:200],
        "detail": detail,
        "building_block": bb,
    })
    return bool(r.get("ok") and not r.get("suppressed") and not r.get("deduped"))


def _apply_frequency(agent_id: str, host: str, rule: Dict[str, Any], events: List[Dict[str, Any]]) -> int:
    spec = rule.get("match") or {}
    win = max(30, min(int(rule.get("window_sec") or 120), 3600))
    need = max(2, int(rule.get("min_count") or 3))
    rid = str(rule["id"])
    written = 0
    for ev in events:
        if not _match_rule(ev, spec):
            continue
        ts = _parse_ts(ev)
        gk = _group_key(agent_id, rule, ev)
        key = (agent_id, rid, gk)
        with _lock:
            dq = _freq_state[key]
            dq.append(ts)
            cutoff = ts - win
            while dq and dq[0] < cutoff:
                dq.popleft()
            cnt = len(dq)
        if cnt >= need and cnt == need:
            evidence = f"{win}s 窗口内第 {cnt} 次命中，分组 {gk}"
            if _emit(agent_id, host, rule, ev, evidence=evidence, extra={"hit_count": cnt, "window_sec": win}):
                written += 1
    return written


def _step_match(ev: Dict[str, Any], step: Dict[str, Any]) -> bool:
    if step.get("etype") and str(ev.get("etype") or "") != step["etype"]:
        return False
    if step.get("etype_contains") and str(step["etype_contains"]).lower() not in str(ev.get("etype") or "").lower():
        return False
    if step.get("summary_contains"):
        if str(step["summary_contains"]).lower() not in str(ev.get("summary") or "").lower():
            return False
    return True


def _apply_sequence(agent_id: str, host: str, rule: Dict[str, Any], events: List[Dict[str, Any]]) -> int:
    steps = rule.get("steps") or []
    if len(steps) < 2:
        return 0
    win = max(10, min(int(rule.get("window_sec") or 120), 3600))
    ordered = sorted(events, key=_parse_ts)
    written = 0
    for i, ev in enumerate(ordered):
        if not _step_match(ev, steps[0]):
            continue
        t0 = _parse_ts(ev)
        idx = 1
        chain = [ev]
        for ev2 in ordered[i + 1:]:
            if _parse_ts(ev2) - t0 > win:
                break
            if _step_match(ev2, steps[idx]):
                chain.append(ev2)
                idx += 1
                if idx >= len(steps):
                    evidence = " → ".join(str(c.get("etype") or "") for c in chain)
                    if _emit(agent_id, host, rule, ev2, evidence=evidence, extra={"chain": [c.get("etype") for c in chain]}):
                        written += 1
                    break
    return written


def _timeline_login_adapters(events: List[Dict[str, Any]], hostname: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("etype") or "")
        d = _detail_of(ev)
        ts = str(ev.get("ts") or "")
        if et == "win_logon_fail":
            out.append({
                "channel": "Security",
                "event_id": 4625,
                "time": ts,
                "IpAddress": d.get("ip"),
                "TargetUserName": d.get("user"),
                "LogonType": d.get("logon_type") or "",
                "computer": hostname,
            })
        elif et == "win_logon":
            out.append({
                "channel": "Security",
                "event_id": 4624,
                "time": ts,
                "IpAddress": d.get("ip"),
                "TargetUserName": d.get("user"),
                "LogonType": d.get("logon_type") or "",
                "computer": hostname,
            })
    return out


def _apply_login_correlation(agent_id: str, host: str, events: List[Dict[str, Any]]) -> int:
    adapted = _timeline_login_adapters(events, host)
    if not adapted:
        return 0
    try:
        from .login_correlation import correlate_logins
    except Exception:
        return 0
    hits = correlate_logins(adapted)
    n = 0
    for h in hits:
        sev = str(h.get("level") or "medium").lower()
        if sev == "informational":
            sev = "low"
        detail = {
            "correlation": True,
            "correlation_rule_id": h.get("rule_id"),
            "evidence": h.get("evidence"),
            "event_id": h.get("event_id"),
            "channel": h.get("channel"),
            "risk_score": 65 if sev == "critical" else (55 if sev == "high" else 40),
        }
        r = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": host,
            "module": "correlation",
            "severity": sev,
            "title": str(h.get("title") or "登录关联")[:200],
            "detail": detail,
        })
        if r.get("ok") and not r.get("deduped") and not r.get("suppressed"):
            n += 1
    return n


def apply_correlations(agent_id: str, host: str, events: List[Dict[str, Any]]) -> int:
    """处理本批时间线事件，返回新写入的威胁事件数。"""
    if not agent_id or not events:
        return 0
    clean = [e for e in events if isinstance(e, dict)]
    if not clean:
        return 0
    written = _apply_login_correlation(agent_id, host, clean)
    for rule in load_correlation_rules():
        if rule.get("enabled") is False:
            continue
        rtype = str(rule.get("type") or "frequency").lower()
        try:
            if rtype == "frequency":
                written += _apply_frequency(agent_id, host, rule, clean)
            elif rtype == "sequence":
                written += _apply_sequence(agent_id, host, rule, clean)
            elif rtype == "first_seen":
                for ev in clean:
                    if _first_seen_hit(agent_id, rule, ev, host):
                        written += 1
        except Exception as e:
            print("[correlation]", rule.get("id"), e)
    try:
        from .building_block import aggregate_building_blocks
        written += aggregate_building_blocks(agent_id, host)
    except Exception as e:
        print("[building_block]", e)
    return written
