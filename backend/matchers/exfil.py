"""云同步 / 外传工具告警（收紧：常见 OneDrive 不报；侧重 CLI/网盘 + 打包关联）。"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding, build_anchor


def run(report: Dict, store, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    from ..db_store import files_rid
    from ..ir_analysis import analyze_exfil

    rid = files_rid(report) or str(report.get("_rid") or "").strip()
    if not rid:
        return [], {"exfil": {"skipped": "no_rid"}}
    try:
        pack = analyze_exfil(rid)
    except Exception as e:
        return [], {"exfil": {"error": str(e)}}

    findings: List[Finding] = []

    # 1) 高/中危工具（raise_alert）
    seen_tool: Set[str] = set()
    for t in pack.get("alert_tools") or pack.get("tools") or []:
        if t.get("raise_alert") is False:
            continue
        label = str(t.get("title") or "")
        tier = str(t.get("tier") or "medium")
        if not label or label in seen_tool:
            continue
        if tier == "common":
            continue
        seen_tool.add(label)
        key = f"外传同步|{label}|exfil"
        if key in seen:
            continue
        seen.add(key)
        sev = "high" if tier == "high" else "medium"
        reasons = t.get("reasons") or []
        ev = f"{t.get('kind')}: {t.get('path') or t.get('detail') or ''}"
        if reasons:
            ev = f"{ev}（{'；'.join(str(x) for x in reasons[:3])}）"
        findings.append(Finding(
            "外传同步",
            sev,
            f"外传工具 · {label}" if tier == "high" else label,
            ev[:400],
            "exfil",
            f"exfil.tool.{label}",
            "exfil",
            anchor=build_anchor(path=str(t.get("path") or "")) if t.get("path") else None,
        ))

    # 2) 打包↔外传关联（比单独工具更有价值）
    for c in pack.get("correlations") or []:
        title = str(c.get("title") or "打包外传关联")
        key = f"外传同步|关联|{title}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "外传同步",
            str(c.get("severity") or "medium"),
            f"疑似打包外传 · {c.get('archive') or title}",
            str(c.get("detail") or "")[:400],
            "exfil",
            "exfil.pack_upload",
            "exfil",
            anchor=build_anchor(path=str(c.get("path") or "")) if c.get("path") else None,
        ))

    # 3) 高分压缩包（无关联时也提示，避免漏「只打包未上传」）
    for a in pack.get("archives") or []:
        if str(a.get("severity") or "") != "high":
            continue
        title = str(a.get("title") or "")
        key = f"外传同步|压缩包|{a.get('path') or title}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "外传同步",
            "medium",
            f"可疑压缩包 · {title}",
            str(a.get("detail") or a.get("path") or "")[:400],
            "exfil",
            "exfil.archive",
            "exfil",
            anchor=build_anchor(path=str(a.get("path") or "")) if a.get("path") else None,
        ))

    return findings, {"exfil": pack.get("stats") or {}}
