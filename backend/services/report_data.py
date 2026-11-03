"""Report data service.

Keeps route validation/authentication separate from SQLite/MySQL repository calls.
"""
from typing import Any, Dict, List, Optional

from backend.services import threat_trace as threat_trace_service
from backend.db_store import (
    load_file_content,
    load_files_for_tree,
    load_finding_evidence_page,
    load_process_detail,
    load_section_page,
    load_sections_batch,
    query_file_directory,
    query_files_under_dir,
)


def normalize_page(page: Optional[Dict[str, Any]], *, offset: int, limit: int) -> Optional[Dict[str, Any]]:
    if page is None:
        return None
    out = dict(page)
    items = list(out.get("items") or [])
    total = max(0, int(out.get("total") or 0))
    actual_offset = max(0, int(out.get("offset", offset) or 0))
    actual_limit = max(1, int(out.get("limit", limit) or limit))
    out.update(
        items=items,
        total=total,
        offset=actual_offset,
        limit=actual_limit,
        has_next=actual_offset + len(items) < total,
    )
    return out


def section_page(
    rid: str,
    name: str,
    *,
    offset: int,
    limit: int,
    q: str = "",
    channel: str = "",
    hits_only: bool = False,
) -> Optional[Dict[str, Any]]:
    page = load_section_page(
        rid, name, offset=offset, limit=limit, q=q, channel=channel, hits_only=hits_only,
    )
    return normalize_page(page, offset=offset, limit=limit)


def files_under(rid: str, directory: str, *, offset: int, limit: int) -> Dict[str, Any]:
    page = query_files_under_dir(rid, directory, offset=offset, limit=limit)
    page["file"] = rid
    return normalize_page(page, offset=offset, limit=limit) or {}


def directory_page(
    rid: str,
    directory: str,
    *,
    offset: int,
    limit: int,
    q: str = "",
    hidden_only: bool = False,
) -> Dict[str, Any]:
    page = query_file_directory(
        rid, directory, offset=offset, limit=limit, q=q, hidden_only=hidden_only,
    )
    page["file"] = rid
    return normalize_page(page, offset=offset, limit=limit) or {}


def file_content(rid: str, path: str) -> Optional[Dict[str, Any]]:
    item = load_file_content(rid, path)
    if item is not None:
        item["file"] = rid
    return item


def remote_tools(rid: str) -> Dict[str, Any]:
    """远控软件实例 + 会话解析（向日葵 / ToDesk 等）。"""
    from backend.remote_tools import analyze_remote_tools

    return analyze_remote_tools(rid)


def ir_lateral(rid: str) -> Dict[str, Any]:
    from backend.ir_analysis import analyze_lateral
    return analyze_lateral(rid)


def ir_cred_theft(rid: str) -> Dict[str, Any]:
    from backend.ir_analysis import analyze_cred_theft
    return analyze_cred_theft(rid)


def ir_beacon(rid: str) -> Dict[str, Any]:
    from backend.ir_analysis import analyze_beacon
    return analyze_beacon(rid)


def ir_defense_weaken(rid: str) -> Dict[str, Any]:
    from backend.ir_analysis import analyze_defense_weaken
    return analyze_defense_weaken(rid)


def ir_exfil(rid: str) -> Dict[str, Any]:
    from backend.ir_analysis import analyze_exfil
    return analyze_exfil(rid)


def ir_campaign(limit_hosts: int = 80, os_family: str = "") -> Dict[str, Any]:
    from backend.ir_analysis import analyze_campaign
    return analyze_campaign(limit_hosts=limit_hosts, os_family=os_family)


def process_detail(rid: str, pid: int) -> Optional[Dict[str, Any]]:
    item = load_process_detail(rid, pid)
    if item is None:
        return None
    return {"ok": True, "file": rid, "pid": pid, "item": item}


def threat_trace(
    rid: str,
    *,
    q: str = "",
    pid: Optional[int] = None,
    file: str = "",
    limit: int = 80,
) -> Dict[str, Any]:
    return threat_trace_service.build_threat_trace(rid, q=q, pid=pid, file=file, limit=limit)


def threat_trace_ai(
    rid: str,
    *,
    q: str = "",
    pid: Optional[int] = None,
    file: str = "",
    limit: int = 80,
    user: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """先跑溯检拿窗口，再调大模型；返回 system + ai 结论。"""
    from backend.ai.analyzer import analyze_trace_with_ai

    trace = threat_trace_service.build_threat_trace(rid, q=q, pid=pid, file=file, limit=limit)
    system = (trace.get("conclusion") or {}).get("system") or threat_trace_service.build_system_conclusion(trace)
    pack = threat_trace_service.slim_trace_for_ai(trace)
    ai = analyze_trace_with_ai(pack, user=user)
    parked = None
    # 无配置 / 调用失败 / 无锚点时，把溯检线索推入停车场（候选）
    try:
        mode = str((ai or {}).get("mode") or "")
        if mode in ("need_config", "error") or (ai or {}).get("error"):
            from backend import parking as parking_mod
            host = ""
            try:
                host = str((trace.get("host") or trace.get("hostname") or "")).strip()
            except Exception:
                host = ""
            parked = parking_mod.park_deferred(
                rid=rid,
                hostname=host,
                source="threat_trace",
                title=f"威胁溯检延期：{(q or file or 'trace')[:80]}",
                reason=str((ai or {}).get("summary") or (ai or {}).get("error") or mode or "延期"),
                payload={
                    "q": q,
                    "pid": pid,
                    "file": file,
                    "mode": mode,
                    "stats": trace.get("stats") or {},
                },
            )
    except Exception as e:
        print(f"[parking] threat_trace_ai: {e}")
    return {
        "ok": True,
        "file": rid,
        "query": q,
        "pid": trace.get("pid") or pid or 0,
        "anchor_file": file or trace.get("anchor_file") or "",
        "conclusion": {
            "system": system,
            "ai": ai,
        },
        "stats": trace.get("stats") or {},
        "parked": parked,
    }


def finding_evidence(rid: str, finding_id: str, *, offset: int, limit: int) -> Optional[Dict[str, Any]]:
    page = load_finding_evidence_page(rid, finding_id, offset=offset, limit=limit)
    return normalize_page(page, offset=offset, limit=limit)


def sections(rid: str, names: List[str], *, limit: int) -> Dict[str, Any]:
    pack = load_sections_batch(rid, names, limit=limit)
    for page in (pack.get("sections") or {}).values():
        if isinstance(page, dict) and "items" in page:
            page.update(normalize_page(page, offset=0, limit=limit) or page)
    return pack


def file_tree(
    rid: str,
    *,
    q: str,
    hidden_only: bool,
    limit: int,
    offset: int,
    root: str,
    include_tree: bool,
    recent_days: int = 0,
    mtime_from: str = "",
    mtime_to: str = "",
) -> Dict[str, Any]:
    out = load_files_for_tree(
        rid, q=q, hidden_only=hidden_only, limit=limit, offset=offset,
        root=root, include_tree=include_tree, recent_days=recent_days,
        mtime_from=mtime_from, mtime_to=mtime_to,
    )
    returned = max(0, int(out.get("returned") or len(out.get("files") or [])))
    total = max(0, int(out.get("filtered_total", out.get("total", 0)) or 0))
    out.update(
        offset=max(0, int(offset)),
        limit=max(1, int(limit)),
        has_next=max(0, int(offset)) + returned < total,
    )
    return out
