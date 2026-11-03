"""WinInfoSC 远控路径 / 采集覆盖度 — rules-wininfosc.json"""
from __future__ import annotations
from typing import Dict, List, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore
from .util import expand_env_path


TOOL_NAMES = {
    "anydesk": "AnyDesk",
    "teamviewer": "TeamViewer",
    "todesk": "ToDesk",
    "sunlogin": "向日葵",
}


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched = []
    remote = (store.wininfosc.get("collection") or {}).get("remoteToolPaths") or {}
    scans = report.get("file_scans") or []
    if scans:
        paths = [(f.get("full_path") or "").replace("/", "\\").lower() for f in scans]
    else:
        paths = []
        from ..db_store import files_rid, query_files
        rid = files_rid(report)
        if rid:
            for key, entries in (remote or {}).items():
                for ent in entries or []:
                    frag = expand_env_path(ent.get("path", ""))
                    if not frag or len(frag) < 4:
                        continue
                    needle = frag.replace("/", "\\")
                    try:
                        for row in query_files(rid, path_contains=needle, limit=3):
                            paths.append((row.get("full_path") or "").replace("/", "\\").lower())
                    except Exception:
                        pass
    # 也扫进程/服务/启动路径
    extra_texts = []
    for p in report.get("processes") or []:
        extra_texts.append((p.get("path") or p.get("name") or "").lower())
    for s in report.get("services") or []:
        extra_texts.append((s.get("path") or s.get("name") or "").lower())
    for si in report.get("startup_items") or []:
        extra_texts.append((si.get("command") or si.get("name") or "").lower())
    corpus = "\n".join(paths + extra_texts)

    for key, entries in remote.items():
        tool = TOOL_NAMES.get(key, key)
        for ent in entries or []:
            frag = expand_env_path(ent.get("path", ""))
            if not frag or len(frag) < 4:
                continue
            needle = frag.replace("/", "\\")
            if needle.lower() in corpus or frag.lower() in corpus:
                evidence = f"WinInfoSC路径: {ent.get('path')} ({ent.get('type', '')})"
                k = f"远控痕迹|{tool}|{evidence}|wininfosc"
                if k in seen:
                    continue
                seen.add(k)
                matched.append({"tool": tool, "path": ent.get("path")})
                findings.append(Finding(
                    "远控痕迹", "high", tool, evidence, "wininfosc", key, "wininfosc",
                ))
                break
        # 名称直接出现
        if key in corpus or tool.lower() in corpus:
            k = f"远控痕迹|{tool}|名称命中|wininfosc"
            if k not in seen:
                # 若已有 RMM 同类可跳过重复标题过多
                pass

    # 采集覆盖度提示（不作为告警，进 pipeline meta）
    coverage = {
        "has_processes": bool(report.get("processes")),
        "has_netstat": bool(report.get("established_connections")),
        "has_prefetch": bool(report.get("prefetch_files")),
        "has_ps_history": bool(report.get("ps_history")),
        "has_wmi": bool(report.get("wmi_subscriptions")),
        "has_tasks": bool(report.get("scheduled_tasks")),
    }
    return findings, {"matched_wininfosc": matched, "collection_coverage": coverage}
