"""防护弱化史告警。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    from ..db_store import files_rid
    from ..ir_analysis import analyze_defense_weaken

    rid = files_rid(report) or str(report.get("_rid") or "").strip()
    if not rid:
        return [], {"defense_weaken": {"skipped": "no_rid"}}
    try:
        pack = analyze_defense_weaken(rid)
    except Exception as e:
        return [], {"defense_weaken": {"error": str(e)}}

    findings: List[Finding] = []
    for it in (pack.get("items") or [])[:25]:
        title = str(it.get("title") or "防护弱化")
        key = f"防护弱化|{it.get('kind')}|{title}|defense"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "防护弱化",
            str(it.get("severity") or "medium"),
            title,
            str(it.get("detail") or ""),
            "defense_weaken",
            str(it.get("kind") or "item"),
            "defense_weaken",
        ))
    return findings, {"defense_weaken": pack.get("stats") or {}}
