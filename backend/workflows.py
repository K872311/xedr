"""轻量工作流模板：一键跑标准应急动作（不引入 Celery/OpenRelik）。"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import paths as P
from .platform import export_html, export_markdown

TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "standard_ir",
        "label": "标准应急",
        "desc": "分析 → 导出 HTML → 写审计",
        "steps": ["analyze", "export_html", "audit"],
    },
    {
        "id": "analyze_only",
        "label": "仅分析",
        "desc": "全量规则匹配（异步入队）",
        "steps": ["analyze"],
    },
    {
        "id": "export_pack",
        "label": "导出包",
        "desc": "基于已有分析结果导出 HTML + Markdown（不重分析）",
        "steps": ["export_html", "export_md", "audit"],
    },
]


def list_templates() -> List[Dict[str, Any]]:
    return list(TEMPLATES)


def get_template(wf_id: str) -> Optional[Dict[str, Any]]:
    wid = (wf_id or "").strip()
    for t in TEMPLATES:
        if t["id"] == wid:
            return t
    return None


def _export_to_disk(rid: str, report: Dict[str, Any], analysis: Dict[str, Any], fmt: str) -> str:
    out_dir = P.report_dir(rid, create=True) / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "html":
        body = export_html(report, analysis, rid)
        path = out_dir / f"report_{ts}.html"
        path.write_text(body, encoding="utf-8")
    else:
        body = export_markdown(report, analysis, rid)
        path = out_dir / f"report_{ts}.md"
        path.write_text(body, encoding="utf-8")
    return str(path)


def _load_report_analysis(rid: str):
    rj = P.resolve_report_json(rid)
    if not rj or not rj.exists():
        raise FileNotFoundError("report not found")
    import json
    with open(rj, encoding="utf-8") as f:
        report = json.load(f)
    result_p = P.result_json_path(rid)
    analysis: Dict[str, Any] = {}
    if result_p.exists():
        with open(result_p, encoding="utf-8") as f:
            data = json.load(f)
        analysis = data.get("analysis") or {}
    return report, analysis


def finish_after_analyze(
    workflow_id: str,
    rid: str,
    report: Dict[str, Any],
    analysis: Dict[str, Any],
    user: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """分析任务完成后执行模板里除 analyze 外的步骤。"""
    tpl = get_template(workflow_id)
    if not tpl:
        return {"ok": False, "error": "unknown workflow"}
    done: List[Dict[str, Any]] = []
    for step in tpl.get("steps") or []:
        if step == "analyze":
            continue
        if step == "export_html":
            path = _export_to_disk(rid, report, analysis, "html")
            done.append({"step": step, "path": path})
        elif step == "export_md":
            path = _export_to_disk(rid, report, analysis, "md")
            done.append({"step": step, "path": path})
        elif step == "audit":
            try:
                from .audit import write_audit
                write_audit(
                    "workflow",
                    username=(user or {}).get("username") or "system",
                    role=(user or {}).get("role") or "system",
                    target=rid,
                    detail=f"workflow={workflow_id}; steps_done={len(done)+1}",
                    user=user,
                )
                done.append({"step": step, "ok": True})
            except Exception as e:
                done.append({"step": step, "ok": False, "error": str(e)})
    return {"ok": True, "workflow": workflow_id, "file": rid, "done": done}


def start_workflow(
    workflow_id: str,
    report_file: str,
    hostname: str = "",
    force: bool = True,
    user: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """启动工作流。含 analyze 的模板会入队；纯导出则立即执行。"""
    tpl = get_template(workflow_id)
    if not tpl:
        raise ValueError("未知工作流模板")
    rid = P.report_id(report_file)
    steps = list(tpl.get("steps") or [])

    if "analyze" in steps:
        from .jobs import enqueue_analyze
        job = enqueue_analyze(
            rid,
            hostname=hostname,
            force=force,
            workflow=workflow_id,
        )
        return {
            "ok": True,
            "workflow": workflow_id,
            "label": tpl.get("label"),
            "queued": True,
            "job": job,
            "hint": "分析完成后将自动导出并写审计（若模板包含）",
        }

    # 无分析：直接用已有结果导出
    report, analysis = _load_report_analysis(rid)
    if not analysis:
        raise ValueError("尚无分析结果，请先分析或选用含「分析」的模板")
    out = finish_after_analyze(workflow_id, rid, report, analysis, user=user)
    out["queued"] = False
    out["label"] = tpl.get("label")
    return out
