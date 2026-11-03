"""外联信标 / 可疑公网画像告警。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    from ..db_store import files_rid
    from ..ir_analysis import analyze_beacon

    rid = files_rid(report) or str(report.get("_rid") or "").strip()
    if not rid:
        return [], {"beacon": {"skipped": "no_rid"}}
    try:
        pack = analyze_beacon(rid)
    except Exception as e:
        return [], {"beacon": {"error": str(e)}}

    findings: List[Finding] = []
    for p in (pack.get("suspicious") or [])[:15]:
        if str(p.get("severity") or "") == "low":
            continue
        title = f"可疑外联 {p.get('ip')}:{p.get('port')}"
        key = f"外联画像|{title}|beacon"
        if key in seen:
            continue
        seen.add(key)
        procs = "、".join(p.get("processes") or []) or "?"
        reasons = "；".join(p.get("reasons") or [])
        findings.append(Finding(
            "外联画像",
            str(p.get("severity") or "medium"),
            title,
            f"进程 {procs} · 连接 {p.get('count')} · {reasons}",
            "beacon",
            str(p.get("ip") or ""),
            "beacon",
        ))
    return findings, {"beacon": pack.get("stats") or {}}
