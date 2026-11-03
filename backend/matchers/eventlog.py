"""系统日志匹配：Windows = Sigma（log_rules/rules）；Linux = journal 文本规则。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore
from ..eventlog_rules import event_ce_key, event_hit_key, match_events
from ..os_detect import detect_os_family
from ..linux_journal import looks_like_linux_events, match_linux_journal
from ..login_correlation import correlate_logins


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    events = report.get("event_logs") or []
    if not isinstance(events, list):
        events = []
    if not events and (report.get("_event_logs_ingested") or report.get("_rid") or report.get("_files_rid")):
        try:
            from ..db_store import load_event_logs_for_match
            rid = str(report.get("_rid") or report.get("_files_rid") or "")
            if rid:
                events = load_event_logs_for_match(rid)
        except Exception as e:
            print(f"[eventlog] load from db: {e}")
    clean = [e for e in events if isinstance(e, dict)]
    fam = detect_os_family(report) if isinstance(report, dict) else "windows"
    if fam == "linux" or looks_like_linux_events(clean):
        hits, meta = match_linux_journal(clean, store=store)
    else:
        hits, meta = match_events(clean)
    try:
        corr = correlate_logins(clean)
    except Exception as e:
        print(f"[eventlog] login correlation: {e}")
        corr = []
    if corr:
        hits = corr + list(hits)
        meta = dict(meta or {}, correlation_hits=len(corr))
    findings: List[Finding] = []
    matched = []
    hit_index: Dict[str, Dict] = {}
    hit_by_ce: Dict[str, Dict] = {}
    for h in hits:
        key = f"系统日志|{h.get('rule_id')}|{h.get('event_id')}|{h.get('evidence')}"
        if key in seen:
            continue
        seen.add(key)
        sev = str(h.get("level") or "medium").lower()
        if sev == "informational":
            sev = "low"
        # critical 保留，分析页高危筛选含 high|critical
        title = str(h.get("title") or "事件日志命中")
        from ..text_fix import fix_mojibake
        evidence = fix_mojibake(
            f"Channel={h.get('channel')} EventID={h.get('event_id')} "
            f"Time={h.get('time')} | {h.get('evidence') or ''}"
        ).strip()
        findings.append(Finding(
            "系统日志", sev, title, evidence,
            source="event_logs", rule_id=str(h.get("rule_id") or ""), matcher="eventlog",
            extra={
                "event_id": h.get("event_id"), "channel": h.get("channel"), "time": h.get("time"),
                **({"hit_count": h["hit_count"], "first_time": h.get("first_time"), "last_time": h.get("last_time")}
                   if h.get("hit_count") else {}),
            },
        ))
        matched.append({
            "category": "系统日志",
            "type": "EventID",
            "name": title,
            "event_id": h.get("event_id"),
            "rule_id": h.get("rule_id"),
        })
        hk = str(h.get("hit_key") or event_hit_key(h.get("channel"), h.get("event_id"), h.get("time")))
        if hk and hk not in hit_index:
            hit_index[hk] = {
                "title": title,
                "rule_id": str(h.get("rule_id") or ""),
                "level": sev,
                "evidence": str(h.get("evidence") or ""),
            }
        ck = event_ce_key(h.get("channel"), h.get("event_id"))
        if ck and ck not in hit_by_ce:
            hit_by_ce[ck] = hit_index.get(hk) or {
                "title": title,
                "rule_id": str(h.get("rule_id") or ""),
                "level": sev,
            }
    return findings, {
        "matched_suspicious": matched,
        "eventlog_meta": meta,
        "eventlog_hit_index": hit_index,
        "eventlog_hit_by_ce": hit_by_ce,
    }
