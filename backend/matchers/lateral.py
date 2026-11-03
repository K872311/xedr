"""登录与横向移动告警。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    from ..db_store import files_rid
    from ..ir_analysis import analyze_lateral

    rid = files_rid(report) or str(report.get("_rid") or "").strip()
    if not rid:
        return [], {"lateral": {"skipped": "no_rid"}}
    try:
        pack = analyze_lateral(rid)
    except Exception as e:
        return [], {"lateral": {"error": str(e)}}

    findings: List[Finding] = []
    for fl in pack.get("flags") or []:
        title = str(fl.get("title") or fl.get("kind") or "登录异常")
        key = f"登录横向|{title}|lateral"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "登录横向",
            str(fl.get("severity") or "medium"),
            title,
            str(fl.get("evidence") or ""),
            "lateral",
            str(fl.get("kind") or "flag"),
            "lateral",
        ))
    st = pack.get("stats") or {}
    return findings, {"lateral": st}
