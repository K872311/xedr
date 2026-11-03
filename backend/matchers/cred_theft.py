"""凭据盗取痕迹告警。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding, build_anchor


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    from ..db_store import files_rid
    from ..ir_analysis import analyze_cred_theft

    rid = files_rid(report) or str(report.get("_rid") or "").strip()
    if not rid:
        return [], {"cred_theft": {"skipped": "no_rid"}}
    try:
        pack = analyze_cred_theft(rid)
    except Exception as e:
        return [], {"cred_theft": {"error": str(e)}}

    findings: List[Finding] = []
    # 同类合并：每种 kind 最多报若干条，避免刷屏
    by_kind: Dict[str, int] = {}
    for h in pack.get("hits") or []:
        kind = str(h.get("kind") or "其他")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if by_kind[kind] > 8:
            continue
        title = str(h.get("title") or "凭据威胁")
        key = f"凭据威胁|{kind}|{title}|{h.get('path') or ''}|cred_theft"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "凭据威胁",
            str(h.get("severity") or "high"),
            f"{kind}: {title}"[:120],
            str(h.get("detail") or h.get("match") or ""),
            "cred_theft",
            str(h.get("match") or kind),
            "cred_theft",
            anchor=build_anchor(path=str(h.get("path") or "")) if h.get("path") else None,
        ))
    if pack.get("correlated"):
        key = "凭据威胁|远控关联|cred_theft"
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                "凭据威胁",
                "high",
                "凭据操作与远控会话时间邻近",
                f"关联 {len(pack['correlated'])} 条",
                "cred_theft",
                "correlated",
                "cred_theft",
            ))
    return findings, {"cred_theft": pack.get("stats") or {}}
