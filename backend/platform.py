"""统一时间线 / 多报告 Diff / 导出 / 质量摘要"""
from __future__ import annotations
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config
from .ingest import slim_report, assess_quality

# 与分析页模块命名保持一致
QL_NAME = {
    "processes": "进程",
    "services": "服务",
    "scheduled_tasks": "计划任务",
    "startup": "启动项",
    "users": "本地用户",
    "ps": "PowerShell",
    "ps_history": "PS历史",
    "browser_artifacts": "浏览器",
    "office": "Office",
    "wmi": "WMI",
    "drivers": "驱动",
    "dns": "DNS",
    "prefetch": "Prefetch",
    "user_registry": "用户注册表",
    "file_scans": "文件扫描",
    "network": "网络",
    "event_logs": "系统日志",
    "wifi": "Wi-Fi",
    "execution": "执行痕迹",
    "remote_access": "远程访问",
    "security_extras": "安全扩展",
    "amcache_apps": "Amcache内容",
    "srum_file": "SRUM库",
    "user_hives": "多用户注册表",
    "eventlog_coverage": "事件通道覆盖",
    "timezone": "时区",
    "gap_files": "缺口文件面",
    "browser_policies": "浏览器策略",
    "antivirus_logs": "杀软日志",
}
# 已下线的内存 / $MFT 采集项：旧报告的质量记录不再导出
_QL_RETIRED = frozenset({"memory", "mft", "memory_artifacts", "mft_artifacts"})


def build_timeline(report: Dict[str, Any], analysis: Optional[Dict] = None) -> List[Dict[str, Any]]:
    events = []
    # 采集时间作为锚点
    ct = report.get("collect_time") or ""
    events.append({"time": ct, "type": "collect", "title": "采集完成", "detail": report.get("hostname")})

    for t in report.get("scheduled_tasks") or []:
        events.append({
            "time": t.get("next_run") or "",
            "type": "task",
            "title": t.get("task_name") or "",
            "detail": t.get("command") or "",
        })
    for pf in (report.get("prefetch_files") or [])[:200]:
        name = pf.get("name") if isinstance(pf, dict) else str(pf)
        events.append({"time": "", "type": "prefetch", "title": name, "detail": ""})
    for block in report.get("ps_history") or []:
        user = "ps"
        text = block if isinstance(block, str) else str(block)
        if ":" in text[:40]:
            user, text = text.split(":", 1)
        for i, line in enumerate(text.splitlines()[:100]):
            line = line.strip()
            if not line:
                continue
            events.append({"time": "", "type": "ps", "title": user.strip(), "detail": line[:300]})
    # 浏览器 SQL 历史/下载（高价值）
    for art in report.get("browser_artifacts") or []:
        if not isinstance(art, dict) or art.get("kind") not in ("history", "downloads"):
            continue
        for row in (art.get("rows") or [])[:80]:
            if not isinstance(row, dict):
                continue
            url = row.get("url") or row.get("origin_url") or ""
            title = row.get("title") or row.get("full_path") or ""
            tm = row.get("visit_time_iso") or row.get("last_visit_time_iso") or row.get("start_time_iso") or ""
            events.append({
                "time": tm,
                "type": f"browser_{art.get('kind')}",
                "title": f"{art.get('browser')}:{title or url}"[:120],
                "detail": str(url)[:300],
            })
    for c in report.get("established_connections") or []:
        from .matchers.util import conn_local, conn_remote
        rm = conn_remote(c) if isinstance(c, dict) else ""
        la = conn_local(c) if isinstance(c, dict) else ""
        events.append({
            "time": "",
            "type": "network",
            "title": rm or "",
            "detail": (
                f"{(c.get('process_name') or c.get('process') or '')} "
                f"pid={(c.get('pid') if isinstance(c, dict) else '')} {la}->{rm}"
            ).strip(),
        })
    for ev in (report.get("event_logs") or [])[:400]:
        if not isinstance(ev, dict):
            continue
        events.append({
            "time": ev.get("time") or "",
            "type": "eventlog",
            "title": f"{ev.get('channel') or ''}#{ev.get('event_id') or ''}",
            "detail": (ev.get("message") or ev.get("provider") or "")[:300],
        })
    if analysis:
        for f in (analysis.get("findings_aggregated") or analysis.get("findings") or [])[:80]:
            events.append({
                "time": "",
                "type": "finding",
                "title": f.get("title") or f.get("name"),
                "detail": (f.get("reason") or (f.get("evidence")[0] if isinstance(f.get("evidence"), list) and f.get("evidence") else f.get("evidence") or ""))[:300],
                "severity": f.get("severity"),
                "category": f.get("category") or f.get("type"),
            })
    return events


def diff_reports(
    old: Dict[str, Any],
    new: Dict[str, Any],
    *,
    old_analysis: Optional[Dict[str, Any]] = None,
    new_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    def names(items, key="name"):
        return set((x.get(key) or "").lower() for x in (items or []) if isinstance(x, dict) and x.get(key))

    def task_names(items):
        return set((x.get("task_name") or "").lower() for x in (items or []) if isinstance(x, dict))

    def ips(conns):
        from .matchers.util import conn_remote_ip
        out = set()
        for c in conns or []:
            if not isinstance(c, dict):
                continue
            ra = conn_remote_ip(c)
            if ra:
                out.add(ra)
        return out

    def finding_map(analysis: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """rule_id|title -> 摘要，用于告警集合差。"""
        out: Dict[str, Dict[str, Any]] = {}
        if not isinstance(analysis, dict):
            return out
        findings: List[Any] = []
        raw = analysis.get("findings")
        if isinstance(raw, list):
            findings.extend(raw)
        ms = analysis.get("matched_suspicious")
        if isinstance(ms, list):
            findings.extend(ms)
        fbm = analysis.get("findings_by_module")
        if isinstance(fbm, dict):
            for block in fbm.values():
                if isinstance(block, dict):
                    findings.extend(block.get("findings") or [])
        for f in findings:
            if not isinstance(f, dict):
                continue
            rid = str(f.get("rule_id") or "").strip()
            title = str(f.get("title") or f.get("name") or "").strip()
            if not rid and not title:
                continue
            key = f"{rid}|{title}".lower()
            if key in out:
                continue
            out[key] = {
                "key": key,
                "rule_id": rid,
                "title": title[:200],
                "severity": str(f.get("severity") or "medium"),
                "category": str(f.get("category") or f.get("type") or "")[:80],
            }
        return out

    op, np_ = names(old.get("processes")), names(new.get("processes"))
    os_, ns_ = names(old.get("services")), names(new.get("services"))
    ostart, nstart = names(old.get("startup_items")), names(new.get("startup_items"))
    ot, nt = task_names(old.get("scheduled_tasks")), task_names(new.get("scheduled_tasks"))
    oi, ni = ips(old.get("established_connections")), ips(new.get("established_connections"))

    ofm = finding_map(old_analysis)
    nfm = finding_map(new_analysis)
    added_keys = sorted(set(nfm) - set(ofm))[:80]
    removed_keys = sorted(set(ofm) - set(nfm))[:80]

    return {
        "processes_added": sorted(np_ - op)[:100],
        "processes_removed": sorted(op - np_)[:100],
        "services_added": sorted(ns_ - os_)[:100],
        "services_removed": sorted(os_ - ns_)[:100],
        "startup_added": sorted(nstart - ostart)[:50],
        "startup_removed": sorted(ostart - nstart)[:50],
        "tasks_added": sorted(nt - ot)[:80],
        "tasks_removed": sorted(ot - nt)[:80],
        "egress_added": sorted(ni - oi)[:80],
        "egress_removed": sorted(oi - ni)[:80],
        "findings_added": [nfm[k] for k in added_keys],
        "findings_removed": [ofm[k] for k in removed_keys],
    }


def _mod_hit_count(block: Dict[str, Any]) -> int:
    if not isinstance(block, dict):
        return 0
    return int(block.get("count") or len(block.get("findings") or []) or 0)


def _finding_path(f: Dict[str, Any]) -> str:
    p = f.get("path") or ""
    if not p and isinstance(f.get("extra"), dict):
        p = f["extra"].get("path") or ""
    if not p and isinstance(f.get("file"), dict):
        p = f["file"].get("full_path") or f["file"].get("path") or ""
    return str(p or "")


def _finding_file_count(f: Dict[str, Any]) -> int:
    n = f.get("file_count")
    if n is None and isinstance(f.get("extra"), dict):
        n = f["extra"].get("file_count")
    try:
        return int(n or 0)
    except Exception:
        return 0


def _collect_export_evidence(f: Dict[str, Any], by_mod: Dict[str, Any], limit: int = 10000) -> Tuple[List[str], bool, int]:
    """合并聚合证据 + 同标题模块样本，尽量补全导出证据。"""
    evs = f.get("evidence") or []
    if isinstance(evs, str):
        out = [evs] if evs.strip() else []
    elif isinstance(evs, list):
        out = [str(x) for x in evs if str(x or "").strip()]
    else:
        out = [str(evs)] if evs else []
    seen = {x for x in out}
    title = str(f.get("title") or f.get("name") or "").strip()
    matcher = str(f.get("matcher") or "").strip()
    candidates = []
    if matcher and isinstance(by_mod.get(matcher), dict):
        candidates.extend((by_mod[matcher].get("findings") or [])[:800])
    elif by_mod:
        for block in by_mod.values():
            if isinstance(block, dict):
                candidates.extend((block.get("findings") or [])[:200])
    for it in candidates:
        if not isinstance(it, dict):
            continue
        it_title = str(it.get("title") or it.get("name") or "").strip()
        if title and it_title and it_title != title:
            continue
        piece = it.get("evidence") or it.get("reason") or it.get("path") or ""
        if isinstance(piece, list):
            for p in piece:
                s = str(p or "").strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
                if len(out) >= limit:
                    break
        else:
            s = str(piece or "").strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        if len(out) >= limit:
            break
    path = _finding_path(f)
    if path and path not in seen:
        out.insert(0, path)
    # 优先用聚合写入的 evidence_total / count，避免 ×26 却只展示 8 条还看不出差
    try:
        declared = int(
            f.get("evidence_total")
            or (f.get("extra") or {}).get("evidence_total")
            or f.get("count")
            or len(out)
            or 1
        )
    except Exception:
        declared = max(int(f.get("count") or 1), len(out))
    total_hits = max(declared, len(out), int(f.get("count") or 1))
    truncated = bool(f.get("evidence_truncated") or (f.get("extra") or {}).get("evidence_truncated")) or (
        total_hits > len(out[:limit])
    ) or (len(out) > limit)
    return out[:limit], truncated, total_hits


def _sev_bucket(item: Dict[str, Any]) -> str:
    s = str((item or {}).get("severity") or "medium").lower()
    if s in ("high", "critical"):
        return "high"
    if s == "medium":
        return "medium"
    return "low"


def _export_index_row(report_file: str) -> Dict[str, Any]:
    rid = str(report_file or "").strip()
    if not rid:
        return {}
    try:
        from .db_store import get_index_meta
        m = get_index_meta(rid) or {}
        if m:
            return m
    except Exception:
        pass
    try:
        rows = []
        from .db_store import list_index
        for r in list_index(limit=300) or []:
            if str(r.get("file") or "") == rid:
                return r
            rows.append(r)
    except Exception:
        pass
    return {}


def _export_host_profile(report: Dict[str, Any], report_file: str = "") -> Dict[str, Any]:
    meta = _export_index_row(report_file)
    host = str(report.get("hostname") or meta.get("hostname") or "unknown").strip() or "unknown"
    ip_raw = str(report.get("ip") or meta.get("ip") or "").strip()
    ip = ip_raw.split(",")[0].strip() if ip_raw else ""
    ct = str(report.get("collect_time") or meta.get("time") or meta.get("collect_time") or "")[:19].replace("T", " ")
    os_name = str(
        report.get("os")
        or meta.get("os")
        or report.get("os_caption")
        or ""
    ).strip()
    os_family = str(report.get("os_family") or meta.get("os_family") or "").strip()
    if not os_family and os_name:
        low = os_name.lower()
        if "linux" in low or "ubuntu" in low or "centos" in low:
            os_family = "linux"
        elif "windows" in low or "win" in low:
            os_family = "windows"
    return {
        "hostname": host,
        "ip": ip,
        "collect_time": ct,
        "os": os_name,
        "os_family": os_family,
        "processes": len(report.get("processes") or []),
        "services": len(report.get("services") or []),
        "tasks": len(report.get("scheduled_tasks") or []),
        "startup": len(report.get("startup_items") or report.get("startup") or []),
        "connections": len(report.get("established_connections") or []),
        "browser": len(report.get("browser_artifacts") or []),
        "files": len(report.get("file_scans") or []),
        "users": len(report.get("users") or report.get("local_users") or []),
        "drivers": len(report.get("drivers") or []),
        "event_logs": len(report.get("event_logs") or []),
    }


def _export_risk_verdict(
    summary: Dict[str, Any],
    gate: Optional[Dict[str, Any]] = None,
    review: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """兼容旧调用；完整逻辑见 quality_gate.build_ir_verdict。"""
    try:
        from .quality_gate import build_ir_verdict
        return build_ir_verdict(summary, gate, review)
    except Exception:
        hi = int(summary.get("high") or 0)
        md = int(summary.get("medium") or 0)
        lo = int(summary.get("low") or 0)
        total = int(summary.get("total") or (hi + md + lo) or 0)
        if hi >= 1:
            return {"level": "高风险", "tone": "high", "text": f"聚合告警 {total}（高危 {hi}）"}
        if total:
            return {"level": "低风险", "tone": "low", "text": f"聚合告警 {total}"}
        return {"level": "未见告警", "tone": "ok", "text": "本期无聚合告警"}


def _finding_reason(f: Dict[str, Any]) -> str:
    for k in ("reason", "description", "detail", "summary"):
        s = str((f or {}).get(k) or "").strip()
        if s:
            return s
    return ""


def _finding_mitre(f: Dict[str, Any]) -> List[str]:
    raw = (f or {}).get("mitre") or (f or {}).get("mitre_attack") or []
    if isinstance(raw, str):
        raw = [x.strip() for x in re.split(r"[,;\s]+", raw) if x.strip()]
    out: List[str] = []
    seen = set()
    for x in raw if isinstance(raw, list) else []:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out[:12]


def _findings_by_category(findings: List[Dict[str, Any]]) -> List[Tuple[str, int, int]]:
    """(category, total, high) sorted by high desc then total."""
    bucket: Dict[str, List[int]] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        cat = str(f.get("category") or f.get("type") or "其它").strip() or "其它"
        hi = 1 if _sev_bucket(f) == "high" else 0
        cur = bucket.setdefault(cat, [0, 0])
        cur[0] += 1
        cur[1] += hi
    rows = [(k, v[0], v[1]) for k, v in bucket.items()]
    rows.sort(key=lambda x: (-x[2], -x[1], x[0]))
    return rows


def _export_asset_tables(report: Dict[str, Any]) -> Dict[str, Any]:
    """关键资产摘录，供 MD/HTML 共用。"""
    from .matchers.util import conn_local, conn_remote

    procs = []
    for p in (report.get("processes") or [])[:40]:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or p.get("process_name") or "").strip()
        path = str(p.get("path") or p.get("executable") or p.get("image_path") or "").strip()
        cmd = str(p.get("cmdline") or p.get("command_line") or "").strip()
        pid = p.get("pid") or p.get("PID") or ""
        if not (name or path or cmd):
            continue
        procs.append({"name": name, "pid": pid, "path": path, "cmdline": cmd[:220]})

    svcs = []
    for s in (report.get("services") or [])[:30]:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name") or s.get("service_name") or "").strip()
        disp = str(s.get("display_name") or s.get("caption") or "").strip()
        path = str(s.get("path") or s.get("image_path") or s.get("binpath") or "").strip()
        state = str(s.get("state") or s.get("status") or "").strip()
        if not (name or path):
            continue
        svcs.append({"name": name or disp, "state": state, "path": path[:220]})

    tasks = []
    for t in (report.get("scheduled_tasks") or [])[:25]:
        if not isinstance(t, dict):
            continue
        name = str(t.get("task_name") or t.get("name") or "").strip()
        cmd = str(t.get("command") or t.get("actions") or t.get("exec") or "").strip()
        if not (name or cmd):
            continue
        tasks.append({"name": name, "command": cmd[:260]})

    conns = []
    for c in (report.get("established_connections") or [])[:25]:
        if not isinstance(c, dict):
            continue
        conns.append({
            "remote": conn_remote(c),
            "local": conn_local(c),
            "process": str(c.get("process_name") or c.get("process") or ""),
            "pid": str(c.get("pid") or ""),
        })

    ps_lines: List[str] = []
    for block in (report.get("ps_history") or [])[:2]:
        text = block if isinstance(block, str) else str(block or "")
        for line in text.splitlines():
            s = line.strip()
            if s:
                ps_lines.append(s[:300])
            if len(ps_lines) >= 40:
                break
        if len(ps_lines) >= 40:
            break

    return {"processes": procs, "services": svcs, "tasks": tasks, "connections": conns, "ps_history": ps_lines}


def _prepare_export_analysis(analysis: Dict[str, Any], report_file: str = "") -> Dict[str, Any]:
    """导出与分析页默认视图一致：去掉已加白（rejected）及全局白名单命中。"""
    a = dict(analysis or {})
    try:
        from .finding_review import attach_review
    except Exception:
        return a

    def _visible(items: List[Any]) -> List[Dict[str, Any]]:
        rows = [x for x in (items or []) if isinstance(x, dict)]
        attached = attach_review(rows, report_file or "")
        return [f for f in attached if str(f.get("review_status") or "pending").lower() != "rejected"]

    raw = a.get("findings_aggregated") or a.get("findings") or []
    if not isinstance(raw, list):
        raw = []
    kept = _visible(raw)
    # 已确认告警排前，便于导出阅读
    kept.sort(
        key=lambda f: (
            0 if str(f.get("review_status") or "").lower() == "accepted" else 1,
            _sev_bucket(f) != "high",
            str(f.get("title") or ""),
        )
    )
    a["findings_aggregated"] = kept

    hi = md = lo = 0
    for f in kept:
        b = _sev_bucket(f)
        if b == "high":
            hi += 1
        elif b == "medium":
            md += 1
        else:
            lo += 1
    old_sum = dict(a.get("summary_aggregated") or a.get("summary") or {})
    a["summary_aggregated"] = {
        **old_sum,
        "total": len(kept),
        "high": hi,
        "medium": md,
        "low": lo,
    }
    try:
        from .quality_gate import review_stats
        a["_export_review"] = review_stats(kept)
    except Exception:
        a["_export_review"] = {}

    by = a.get("findings_by_module") or {}
    if isinstance(by, dict):
        new_by: Dict[str, Any] = {}
        for mk, block in by.items():
            if not isinstance(block, dict):
                new_by[mk] = block
                continue
            fl = block.get("findings") or []
            if not isinstance(fl, list) or not fl:
                new_by[mk] = block
                continue
            vis = _visible(fl)
            nb = dict(block)
            nb["findings"] = vis
            nb["count"] = len(vis)
            nb["high"] = sum(1 for f in vis if _sev_bucket(f) == "high")
            new_by[mk] = nb
        a["findings_by_module"] = new_by
    return a


def _ai_export_payload(ai: Any) -> Dict[str, Any]:
    """规范化导出用的 AI 字段；无有效内容时返回空 dict。"""
    if not isinstance(ai, dict):
        return {}
    verdict = str(ai.get("verdict") or ai.get("risk_level") or "").strip()
    summary = str(ai.get("summary") or "").strip()
    highlights = [str(x).strip() for x in (ai.get("highlights") or []) if str(x).strip()]
    recs = [str(x).strip() for x in (ai.get("recommendations") or []) if str(x).strip()]
    mode = str(ai.get("mode") or ai.get("model") or "").strip()
    if not (verdict or summary or highlights or recs):
        return {}
    return {
        "verdict": verdict,
        "summary": summary,
        "highlights": highlights[:12],
        "recommendations": recs[:12],
        "mode": mode,
    }


def _esc_html_ai(s: Any) -> str:
    return (
        str(s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _ai_inline_html(text: str) -> str:
    """转义后处理 **粗体**、`代码`、路径/IP 高亮。"""
    s = _esc_html_ai(text)

    def _code(m):
        return f"<code>{m.group(1)}</code>"

    def _bold(m):
        return f"<strong>{m.group(1)}</strong>"

    s = re.sub(r"`([^`]+)`", _code, s)
    s = re.sub(r"\*\*([^*]+)\*\*", _bold, s)
    # critical / high 标记
    s = re.sub(
        r"\((critical|严重)\)",
        r'<span class="sev-tag sev-crit">\1</span>',
        s,
        flags=re.I,
    )
    s = re.sub(
        r"\((high|高危)\)",
        r'<span class="sev-tag sev-high">\1</span>',
        s,
        flags=re.I,
    )
    return s


def _ai_verdict_badge_html(verdict: str) -> str:
    v = str(verdict or "").strip()
    if not v:
        return ""
    tone = "sev-crit" if re.search(r"严重|critical", v, re.I) else (
        "sev-high" if re.search(r"高|high", v, re.I) else "sev-mid"
    )
    return f"<span class='ai-v-inline {tone}'>{_esc_html_ai(v)}</span>"


def _ai_markdown_to_html(raw: str, *, verdict: str = "") -> str:
    """将模型常见 Markdown 摘要渲染为导出用 HTML（不依赖第三方库）。

    verdict：挂到「总体风险等级」标题后展示，避免顶部再单独放大字「严重」。
    """
    text = str(raw or "").replace("\r\n", "\n").strip()
    verd = str(verdict or "").strip()
    if not text and not verd:
        return ""
    if not text and verd:
        return (
            "<div class='ai-md'>"
            f"<h4 class='ai-h'>总体风险等级 {_ai_verdict_badge_html(verd)}</h4>"
            "</div>"
        )
    # 正文若无该小节，先补一行标题，便于把等级挂上去
    if verd and not re.search(r"总体风险等级", text):
        text = f"## 总体风险等级\n\n{text}"

    lines = text.split("\n")
    out: List[str] = []
    i = 0
    list_buf: List[str] = []
    list_ordered = False
    verdict_placed = False
    verd_l = verd.lower().rstrip("。．.")

    def flush_list():
        nonlocal list_buf, list_ordered
        if not list_buf:
            return
        tag = "ol" if list_ordered else "ul"
        items = "".join(f"<li>{_ai_inline_html(x)}</li>" for x in list_buf)
        out.append(f"<{tag}>{items}</{tag}>")
        list_buf = []
        list_ordered = False

    def heading_html(level: int, title: str) -> str:
        nonlocal verdict_placed
        badge = ""
        if verd and not verdict_placed and re.search(r"总体风险等级", title):
            badge = " " + _ai_verdict_badge_html(verd)
            verdict_placed = True
        return f"<h{level + 2} class='ai-h'>{_ai_inline_html(title)}{badge}</h{level + 2}>"

    while i < len(lines):
        raw_line = lines[i]
        t = raw_line.strip()
        i += 1
        if not t:
            flush_list()
            continue
        # fenced code
        if t.startswith("```"):
            flush_list()
            code: List[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1
            out.append(f"<pre class='ai-pre'>{_esc_html_ai(chr(10).join(code))}</pre>")
            continue
        mh = re.match(r"^(#{1,6})\s+(.+)$", t)
        if mh:
            flush_list()
            level = min(3, max(1, len(mh.group(1))))
            title = re.sub(r"^\d+[.)、）]\s*", "", mh.group(2).strip())
            title = re.sub(r"\*\*([^*]+)\*\*", r"\1", title)
            out.append(heading_html(level, title))
            continue
        # unordered list
        um = re.match(r"^[-*•]\s+(.+)$", t)
        if um:
            if list_buf and list_ordered:
                flush_list()
            list_ordered = False
            list_buf.append(um.group(1).strip())
            continue
        # ordered list (1. / 1) / 1、)
        om = re.match(r"^(\d+)[.)、）]\s+(.+)$", t)
        if om:
            body = om.group(2).strip()
            # 短标题型编号当作小节，不当列表
            if len(body) <= 28 and re.match(
                r"^(总体|可能|优先|重点|处置|总结|建议|需优先|攻击|风险)", body
            ):
                flush_list()
                out.append(heading_html(2, body))
                continue
            if list_buf and not list_ordered:
                flush_list()
            list_ordered = True
            list_buf.append(body)
            continue
        flush_list()
        # 等级已挂到标题后，跳过正文里单独一行的「严重。」避免重复
        plain = re.sub(r"[*_\s。．.]+", "", t).lower()
        if verd_l and verdict_placed and plain in {verd_l, f"**{verd_l}**".replace("*", "")}:
            continue
        if verd_l and verdict_placed and plain.startswith(verd_l) and len(plain) <= len(verd_l) + 2:
            continue
        out.append(f"<p>{_ai_inline_html(t)}</p>")
    flush_list()
    if verd and not verdict_placed:
        out.insert(0, heading_html(2, "总体风险等级"))
    return f"<div class='ai-md'>{''.join(out)}</div>"


def export_markdown(
    report: Dict[str, Any],
    analysis: Dict[str, Any],
    report_file: str = "",
    *,
    manual_conclusion: str = "",
    include_ai: bool = False,
) -> str:
    try:
        from .net_process import enrich_report_connections
        enrich_report_connections(report)
    except Exception:
        pass
    analysis = _prepare_export_analysis(analysis, report_file)
    profile = _export_host_profile(report, report_file)
    host, ip, ct = profile["hostname"], profile["ip"], profile["collect_time"]
    summary = analysis.get("summary_aggregated") or analysis.get("summary") or {}
    ai = analysis.get("ai") or {}
    q = report.get("collection_quality") or (analysis.get("meta") or {}).get("collection_quality") or assess_quality(report)
    findings = analysis.get("findings_aggregated") or []
    by_mod = analysis.get("findings_by_module") or {}
    raw_total = summary.get("raw_total", (analysis.get("summary") or {}).get("total", 0))
    try:
        from .quality_gate import evaluate_quality_gate
        gate = evaluate_quality_gate(report, quality=q, os_family=profile.get("os_family") or "")
    except Exception:
        gate = {}
    review = analysis.get("_export_review") or {}
    verdict = _export_risk_verdict(summary, gate, review)
    cats = _findings_by_category(findings)
    manual_note = str(manual_conclusion or "").strip()
    ai_pack = _ai_export_payload(ai) if include_ai else {}

    ql_name = QL_NAME
    ql_st = {
        "ok": "正常（有数据）",
        "empty": "无数据（已采集但为空）",
        "degraded": "不完整",
        "missing": "缺失/失败",
    }
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _esc(s: Any) -> str:
        return str(s or "").replace("\r\n", "\n").strip()

    os_line = profile["os"] or profile["os_family"] or "-"
    conf_lab = verdict.get("confidence_label") or gate.get("confidence_label") or "-"
    lines: List[str] = [
        "# 终端应急分析报告",
        "",
        f"> **主机** `{host}` · **IP** `{ip or '-'}` · **系统** `{_esc(os_line)}` · **采集** `{ct or '-'}`",
        "",
        f"> **风险结论：{verdict['level']}**（采集置信度 {conf_lab}）— {verdict['text']}",
        "",
    ]
    if manual_note or include_ai:
        lines += ["## 结论对照", ""]
        if manual_note:
            lines += ["### 人工结论", "", manual_note, ""]
        if include_ai:
            lines += ["### AI 研判", ""]
            if ai_pack:
                if ai_pack.get("mode"):
                    lines.append(f"- 模式/模型: `{_esc(ai_pack['mode'])}`")
                verd = _esc(ai_pack.get("verdict") or "")
                summary = _esc(ai_pack.get("summary") or "")
                if verd and re.search(r"总体风险等级", summary):
                    # 等级跟在小节标题后：总体风险等级 · 严重
                    summary = re.sub(
                        r"(总体风险等级)(\s*)",
                        rf"\1 · **{verd}**\2",
                        summary,
                        count=1,
                    )
                    lines += ["", summary, ""]
                elif verd and summary:
                    lines += ["", f"#### 总体风险等级 · **{verd}**", "", summary, ""]
                elif verd:
                    lines += ["", f"#### 总体风险等级 · **{verd}**", ""]
                elif summary:
                    lines += ["", summary, ""]
                if ai_pack.get("highlights"):
                    lines.append("- **要点**:")
                    lines.extend(f"  - {_esc(x)}" for x in ai_pack["highlights"])
                    lines.append("")
                if ai_pack.get("recommendations"):
                    lines.append("- **建议**:")
                    lines.extend(f"  - {_esc(x)}" for x in ai_pack["recommendations"])
                    lines.append("")
            else:
                lines += ["_报告中尚无可用 AI 研判结果（请先在分析页生成）。_", ""]
    lines += [
        "---",
        "",
        "## 目录",
        "",
        "1. 主机概况",
        "2. 风险摘要",
        "3. 采集质量",
        "4. 聚合告警明细",
        "5. IOC 全量扫描",
        "",
        "---",
        "",
        "## 1. 主机概况",
        "",
    ]
    lines += [
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 主机名 | `{host}` |",
        f"| IP | `{ip or '-'}` |",
        f"| 操作系统 | `{_esc(os_line)}` |",
        f"| 采集时间 | `{ct or '-'}` |",
        f"| 进程 / 服务 / 计划任务 | {profile['processes']} / {profile['services']} / {profile['tasks']} |",
        f"| 启动项 / 本地用户 / 驱动 | {profile['startup']} / {profile['users']} / {profile['drivers']} |",
        f"| 外联 / 浏览器 / 文件扫描 | {profile['connections']} / {profile['browser']} / {profile['files']} |",
        f"| 系统日志条目 | {profile['event_logs']} |",
        "",
        "## 2. 风险摘要",
        "",
        "| 指标 | 数量 |",
        "| --- | ---: |",
        f"| 可见聚合告警（已排除加白） | **{summary.get('total', len(findings))}** |",
        f"| 高危 / Critical | **{summary.get('high', 0)}** |",
        f"| 中危 | {summary.get('medium', 0)} |",
        f"| 低危 | {summary.get('low', 0)} |",
        f"| 原始命中（去重前） | {raw_total} |",
        f"| 已排除（加白） | {review.get('rejected', 0)} |",
        f"| 风险等级 | **{verdict['level']}** |",
        f"| 采集置信度 | **{conf_lab}** |",
        "",
        verdict["text"],
        "",
    ]
    if not gate.get("can_claim_clean", True):
        lines += [
            "> ⚠️ **质量门禁**：关键采集面不完整，本报告不得作为「主机已安全」的依据。",
            "",
        ]

    if cats:
        lines += ["### 告警分类分布", "", "| 分类 | 条数 | 高危 |", "| --- | ---: | ---: |"]
        for cat, n, hi in cats[:24]:
            lines.append(f"| {_esc(cat)} | {n} | {hi} |")
        lines.append("")

    sec_q = 3
    lines += [
        f"## {sec_q}. 采集质量与置信度",
        "",
        f"- **置信度**：{conf_lab}（{gate.get('confidence') or '-'}）",
        f"- **说明**：{_esc(gate.get('summary') or '—')}",
        f"- **可否主张主机干净**：{'否' if not gate.get('can_claim_clean', True) else '审慎可以（仍须人工复核）'}",
        "",
    ]
    if gate.get("gaps"):
        lines += ["### 关键缺口", "", "| 模块 | 状态 | 影响 |", "| --- | --- | --- |"]
        for g in gate["gaps"][:20]:
            lines.append(
                f"| {_esc(g.get('label'))} | {_esc(g.get('status'))} | {_esc(g.get('hint'))} |"
            )
        lines.append("")
    if q:
        lines += ["### 模块状态明细", "", "| 模块 | 状态 |", "| --- | --- |"]
        for k, v in sorted(q.items(), key=lambda x: str(x[0])):
            st = str(v or "missing").lower()
            if k in ("version", "collector", "tool") or k in _QL_RETIRED:
                continue
            lines.append(f"| {ql_name.get(k, k)} | {ql_st.get(st, st)} |")
        lines += [
            "",
            "> **无数据** = 该项已尝试采集但结果为空（如本机无 Office 痕迹），一般不代表采集失败。",
            "",
        ]

    sec_find = 4
    lines += [
        f"## {sec_find}. 聚合告警明细",
        "",
        f"_共 {len(findings)} 条（与分析页聚合列表一致）；含原因、MITRE、规则与证据（单条证据上限 10000）。_",
        "",
    ]
    if not findings:
        lines += ["_本期无聚合告警。_", ""]
    else:
        ordered = sorted(
            findings,
            key=lambda f: (sev_rank.get(str(f.get("severity") or "medium").lower(), 9), str(f.get("title") or "")),
        )
        for i, f in enumerate(ordered, 1):
            sev = str(f.get("severity") or "medium").upper()
            cat = _esc(f.get("category") or f.get("type") or "")
            title = _esc(f.get("title") or f.get("name") or "未命名")
            cnt = f.get("count", 1)
            lines.append(f"### {sec_find}.{i} [{sev}] {cat} — {title} ×{cnt}")
            reason = _finding_reason(f)
            if reason:
                lines.append(f"- **原因**: {_esc(reason)[:800]}")
            mitre = _finding_mitre(f)
            if mitre:
                lines.append("- **MITRE**: " + ", ".join(f"`{_esc(m)}`" for m in mitre))
            if f.get("persist_kind"):
                lines.append(f"- **持久化类型**: `{_esc(f.get('persist_kind'))}`")
            meta_bits = []
            if f.get("matcher"):
                meta_bits.append(f"matcher=`{_esc(f.get('matcher'))}`")
            if f.get("rule_id"):
                meta_bits.append(f"rule=`{_esc(f.get('rule_id'))}`")
            sources = f.get("sources") or []
            if sources:
                meta_bits.append("sources=" + ", ".join(f"`{_esc(s)}`" for s in sources[:8]))
            if meta_bits:
                lines.append("- **来源**: " + " · ".join(meta_bits))
            path = _finding_path(f)
            fc = _finding_file_count(f)
            if path:
                lines.append(f"- **路径**: `{_esc(path)}`")
            if fc:
                lines.append(f"- **关联文件数**: {fc}")
            evs, trunc, total_hits = _collect_export_evidence(f, by_mod, limit=10000)
            if evs:
                lines.append(f"- **证据**（{len(evs)}/{total_hits}）:")
                for ev in evs:
                    lines.append(f"  - {_esc(ev)[:1200]}")
                if trunc:
                    lines.append(f"  - _… 证据已截断，命中共 {total_hits} 次_")
            lines.append("")

    try:
        from .ioc_full_scan import markdown_section_for_report
        ioc_md = markdown_section_for_report(report_file)
    except Exception:
        ioc_md = ""
    if ioc_md:
        lines += [ioc_md]

    lines += [
        "---",
        "",
        f"_由 CNPC 终端应急响应分析平台生成 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
        "",
    ]
    return "\n".join(lines)


_EXPORT_EV_PREVIEW = 8

_EXPORT_HTML_CSS = """
:root{
  --ink:#152033;--text:#243247;--sub:#4a5d73;--muted:#7a8ba0;
  --line:#e2e8f0;--bg:#f3f6fa;--card:#fff;
  --red:#c62828;--warn:#b86a00;--ok:#1b7f4a;--cyan:#0e7490;--navy:#0f1b2d;
}
*{box-sizing:border-box}
html,body{margin:0;font-family:"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif;color:var(--text);background:var(--bg);line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:min(1520px,96vw);margin:0 auto;padding:22px 22px 52px;width:100%}
.hero{background:var(--navy);color:#e8f0fa;border-radius:12px;padding:22px 22px 18px;position:relative;overflow:hidden}
.hero:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,#e53935,#0e7490)}
.brand{font-size:11px;letter-spacing:.16em;color:#7eb8c9;font-weight:600;margin-bottom:6px}
.hero h1{margin:0 0 10px;font-size:22px;font-weight:700;letter-spacing:.01em}
.meta{display:flex;flex-wrap:wrap;gap:8px 16px;font-size:13px;color:rgba(200,220,235,.88)}
.meta b{color:#fff;font-weight:650}
.verdict{margin-top:14px;padding:12px 14px;border-radius:8px;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);display:flex;gap:12px;align-items:flex-start}
.verdict .lv{flex:0 0 auto;font-size:12px;font-weight:800;letter-spacing:.06em;padding:4px 10px;border-radius:6px;background:#c62828;color:#fff}
.verdict.tone-med .lv{background:#b86a00}
.verdict.tone-low .lv,.verdict.tone-ok .lv{background:#1b7f4a}
.verdict.tone-crit .lv{background:#8b0000}
.verdict p{margin:0;font-size:13px;color:rgba(230,240,250,.92);line-height:1.55}
.hero-foot{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:center;margin-top:12px;font-size:12px;color:rgba(200,220,235,.8)}
.conf{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid transparent}
.conf.high{background:#e8f7ee;color:#1b7f4a;border-color:#c6e6d2}
.conf.medium{background:#fff7eb;color:#8a5a00;border-color:#f0d2a0}
.conf.low,.conf.insufficient{background:#fff1f0;color:#c62828;border-color:#f0c2c0}
.hero-foot .conf.high{background:rgba(27,127,74,.28);border-color:rgba(120,200,150,.45);color:#b8f0cf}
.hero-foot .conf.medium{background:rgba(184,106,0,.28);border-color:rgba(240,210,160,.4);color:#ffe0a8}
.hero-foot .conf.low,.hero-foot .conf.insufficient{background:rgba(198,40,40,.28);border-color:rgba(240,160,160,.4);color:#ffc9c9}
.stat-pills{display:inline-flex;flex-wrap:wrap;gap:6px}
.stat-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:6px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.16);font-size:12px;font-weight:650;color:#e8f0fa}
.stat-pill em{font-style:normal;color:rgba(200,220,235,.75);font-weight:500;margin-right:2px}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:14px 0 0}
@media (max-width:900px){.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:520px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
.metric{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 8px;text-align:center}
.metric.filter{cursor:pointer;transition:border-color .12s,box-shadow .12s}
.metric.filter:hover,.metric.filter.on{border-color:#9bb4d0;box-shadow:0 4px 12px rgba(15,30,55,.08)}
.metric .n{font-size:22px;font-weight:750;font-variant-numeric:tabular-nums;letter-spacing:-.02em;color:var(--ink)}
.metric .l{font-size:11px;color:var(--muted);margin-top:4px;letter-spacing:.03em}
.metric.h .n{color:var(--red)}.metric.m .n{color:var(--warn)}.metric.l .n{color:var(--cyan)}
.gate-warn{margin:14px 0 0;padding:10px 12px;border-radius:8px;background:#fff7eb;border:1px solid #f0d2a0;color:#8a5a00;font-size:13px}
.sec{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-top:12px;box-shadow:0 1px 8px rgba(15,30,55,.04)}
.sec>summary,.grp>summary,.finding>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sec>summary::-webkit-details-marker,.grp>summary::-webkit-details-marker,.finding>summary::-webkit-details-marker{display:none}
.sec>summary:before,.grp>summary:before,.finding>summary:before{content:"";width:6px;height:6px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);transform:rotate(-45deg);margin-right:2px;transition:transform .12s;flex-shrink:0}
.sec[open]>summary:before,.grp[open]>summary:before,.finding[open]>summary:before{transform:rotate(45deg);margin-top:-2px}
.sec>summary h2{margin:0;font-size:14px;font-weight:700;color:var(--ink);letter-spacing:.02em}
.sec-count{margin-left:auto;font-size:12px;color:var(--muted);font-weight:400}
.manual{border-left:3px solid var(--cyan);background:#f7fbfd}
.manual-box{margin-top:8px;font-size:13px;line-height:1.7;color:var(--ink);white-space:pre-wrap}
/* 结论对照：上下排列，避免左右等高把人工结论撑出大片空白 */
.compare{display:flex;flex-direction:column;gap:12px;margin-top:12px;align-items:stretch}
.compare-card{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:#fff;min-width:0;height:auto;align-self:stretch}
.compare-card.human{border-left:3px solid var(--cyan);background:#f7fbfd}
.compare-card.robot{border-left:3px solid #7c3aed;background:#faf8ff}
.compare-h{display:flex;align-items:center;gap:8px;margin:0 0 8px;font-size:13px;font-weight:700;color:var(--ink)}
.compare-h .tag{font-size:11px;font-weight:650;padding:2px 7px;border-radius:999px;background:#eef6fa;color:var(--cyan);border:1px solid #d5e8f0}
.compare-card.robot .compare-h .tag{background:#f3eefc;color:#6d28d9;border-color:#e4d8f7}
.compare-body{font-size:13px;line-height:1.7;color:var(--ink);word-break:break-word}
.compare-body.plain{white-space:pre-wrap;margin:0;padding:10px 12px;border-radius:8px;background:rgba(255,255,255,.72);border:1px solid rgba(14,116,144,.12);font-size:14px;font-weight:650;line-height:1.65;color:var(--ink);min-height:0}
.compare-body ul,.compare-body ol,.ai-md ul,.ai-md ol{margin:8px 0 10px;padding-left:1.25em}
.compare-body li,.ai-md li{margin:5px 0;color:var(--sub);line-height:1.65}
.compare-empty{color:var(--muted);font-size:12px}
.ai-md{margin-top:4px}
.ai-md p{margin:0 0 10px;color:var(--ink);line-height:1.7}
.ai-md .ai-h{margin:14px 0 8px;padding:6px 0 6px 10px;border-left:3px solid #7c3aed;color:var(--ink);font-size:13px;font-weight:750;line-height:1.4;background:linear-gradient(90deg,rgba(124,58,237,.06),transparent);display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.ai-md h3.ai-h{font-size:14px}
.ai-md h4.ai-h{font-size:13px;border-left-color:#0e7490;background:linear-gradient(90deg,rgba(14,116,144,.06),transparent)}
.ai-md h5.ai-h{font-size:12.5px;border-left-color:#94a3b8}
.ai-md .ai-v-inline{display:inline-block;font-size:13px;font-weight:800;letter-spacing:.04em;padding:2px 10px;border-radius:6px;line-height:1.35;vertical-align:middle}
.ai-md .ai-v-inline.sev-crit{background:#fff1f0;color:#c62828;border:1px solid #f5c2c0}
.ai-md .ai-v-inline.sev-high{background:#fff7eb;color:#b86a00;border:1px solid #f0d2a0}
.ai-md .ai-v-inline.sev-mid{background:#eef6fa;color:#0e7490;border:1px solid #d5e8f0}
.ai-md strong{color:var(--ink);font-weight:700}
.ai-md code,.ai-md .ai-pre{font-family:Consolas,"Cascadia Mono",ui-monospace,monospace;font-size:12px}
.ai-md code{padding:1px 5px;border-radius:4px;background:#eef2f7;color:#334155;word-break:break-all}
.ai-md .ai-pre{display:block;margin:8px 0;padding:10px 12px;background:#0f1b2d;color:#d7e8f5;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.sev-tag{display:inline-block;margin-left:4px;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:700;vertical-align:middle;letter-spacing:.02em}
.sev-tag.sev-crit{background:#fff1f0;color:#c62828}
.sev-tag.sev-high{background:#fff7eb;color:#b86a00}
.profile{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px}
@media (max-width:720px){.profile{grid-template-columns:1fr}}
.prof-block{border:1px solid var(--line);border-radius:8px;background:#fafbfc;padding:10px 12px}
.prof-h{font-size:11px;letter-spacing:.1em;color:var(--muted);font-weight:700;margin:0 0 6px;text-transform:uppercase}
.kv{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px dashed var(--line);font-size:13px}
.kv:last-child{border-bottom:0}
.kv span{color:var(--muted)}.kv b{color:var(--ink);font-weight:650;text-align:right;word-break:break-all}
.prof-metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:6px}
.pm{border:1px solid var(--line);border-radius:6px;padding:8px 6px;text-align:center;background:#fff}
.pm .v{font-size:15px;font-weight:750;color:var(--ink);font-variant-numeric:tabular-nums}
.pm .k{font-size:11px;color:var(--muted);margin-top:2px}
.cats{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}
.cat-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border:1px solid var(--line);border-radius:6px;background:#f7fafc;font-size:12px}
.cat-pill b{font-variant-numeric:tabular-nums}.cat-pill .hi{color:var(--red);font-weight:700}
.ql-row{display:flex;flex-wrap:wrap;gap:6px}
.ql{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 8px 0 7px;border:1px solid var(--line);border-radius:4px;font-size:12px;background:#f8fafc;white-space:nowrap}
.ql i{width:7px;height:7px;border-radius:50%;display:block}
.ql.ok i{background:#2fbf71}.ql.empty i{background:#94a3b8}.ql.deg i{background:#e6a23c}.ql.miss i{background:var(--red)}
.note{font-size:12px;color:var(--muted);margin:6px 0 0}
.gate-gaps{margin:8px 0 10px;padding-left:18px;font-size:12px;color:var(--sub)}
.gate-gaps li{margin:3px 0}
.toolbar{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0 10px}
.toolbar input{flex:1 1 200px;min-width:140px;height:32px;border:1px solid var(--line);border-radius:6px;padding:0 10px;font:inherit;font-size:13px;background:#fff}
.chip{height:28px;border:1px solid var(--line);background:#f8fafc;border-radius:6px;padding:0 9px;font:inherit;font-size:12px;cursor:pointer;color:var(--sub)}
.chip.on{background:var(--navy);color:#fff;border-color:var(--navy)}
.grp{border:1px solid var(--line);border-radius:8px;margin:0 0 8px;background:#fafbfc}
.grp>summary{padding:9px 11px;font-weight:650;font-size:13px}
.grp>summary .hint{font-weight:400;color:var(--muted);font-size:12px;margin-left:auto}
.grp-body{padding:0 8px 8px}
.finding{border:1px solid var(--line);border-radius:8px;margin:6px 0 0;background:#fff}
.finding.sev-h{border-left:3px solid var(--red)}
.finding.sev-m{border-left:3px solid var(--warn)}
.finding.sev-l{border-left:3px solid var(--cyan)}
.finding>summary{padding:8px 10px}
.finding .fh{display:flex;flex-wrap:wrap;align-items:center;gap:7px;flex:1;min-width:0}
.finding .fh strong{font-size:13px;font-weight:650;color:var(--ink)}
.sev{font-size:10px;font-weight:750;padding:2px 6px;border-radius:4px;background:#fff1f0;color:var(--red)}
.sev-m .sev{background:#fff7eb;color:var(--warn)}
.sev-l .sev{background:#eef9fb;color:var(--cyan)}
.cnt{margin-left:auto;font-size:11px;color:var(--muted);white-space:nowrap}
.finding .body{padding:0 10px 10px}
.finding .reason{margin-top:4px;padding:8px 10px;background:#f5f8fc;border-radius:6px;font-size:12px;color:var(--sub);border:1px solid var(--line);word-break:break-word}
.finding .reason b{color:var(--ink)}
.finding .tags{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
.tag{font-size:11px;padding:1px 7px;border-radius:999px;background:#eef6fa;color:#0e7490;border:1px solid #d5e8f0;font-family:Consolas,ui-monospace,monospace}
.tag.rej{background:#f3f4f6;color:#5b6472;border-color:#e2e5ea}
.finding .meta-line{font-size:11px;color:var(--muted);margin-top:5px;font-family:Consolas,ui-monospace,monospace;word-break:break-all}
.finding .path{font-size:12px;color:var(--sub);margin-top:4px;word-break:break-all}
.ev{margin:6px 0 0;padding-left:16px;font-size:12px;color:var(--sub)}
.ev li{margin:2px 0;word-break:break-all}
.ev li.more{color:var(--muted);list-style:none;margin-left:-10px}
.more-ev{margin-top:6px;height:26px;border:1px dashed var(--line);background:#f8fafc;border-radius:6px;padding:0 9px;font:inherit;font-size:12px;cursor:pointer;color:var(--sub)}
.table-scroll{width:100%;overflow-x:auto;margin-top:8px;-webkit-overflow-scrolling:touch;border:1px solid var(--line);border-radius:8px;background:#fff}
.table-scroll table{margin:0;border:0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px;table-layout:fixed}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:normal;overflow-wrap:anywhere}
th{color:var(--muted);font-size:11px;letter-spacing:.02em;background:#f7fafc;font-weight:650}
td.mono,th.mono,.mono{font-family:Consolas,"Cascadia Mono",ui-monospace,monospace;font-size:12px;word-break:break-all}
td.nowrap,th.nowrap,.nowrap{white-space:nowrap;word-break:keep-all;overflow-wrap:normal}
td.col-src,th.col-src{width:56px;white-space:nowrap;word-break:keep-all}
td.col-kind,th.col-kind{width:72px;white-space:nowrap;word-break:keep-all}
td.col-name,th.col-name{width:28%}
td.col-path,th.col-path{width:32%}
td.col-hash,th.col-hash{width:26%}
.ioc-table td.col-src{color:var(--sub);font-weight:650}
.ai-box{background:#f7fbfd;border:1px solid var(--line);border-radius:8px;padding:12px}
.ai-v{font-weight:750;color:var(--red);margin-bottom:4px}
.empty{color:var(--muted);padding:14px;text-align:center}
.hidden{display:none !important}
.guide{font-size:12px;color:var(--muted);margin:0;padding-left:18px}
.guide li{margin:3px 0}
.foot{margin-top:18px;text-align:center;font-size:11px;color:var(--muted)}
@media print{
  body{background:#fff}
  .toolbar,.more-ev{display:none}
  .sec,.grp,.finding{break-inside:avoid}
  details{open:true}
}
"""

_EXPORT_HTML_JS = """
(function(){
  var sev='all', q='';
  var chips=document.querySelectorAll('[data-sev]');
  var cards=document.querySelectorAll('.metric.filter');
  var findings=document.querySelectorAll('.finding');
  var groups=document.querySelectorAll('.grp');
  var box=document.getElementById('q');
  function apply(){
    var nq=(q||'').toLowerCase();
    findings.forEach(function(el){
      var okSev = sev==='all' || el.getAttribute('data-sev')===sev;
      var okQ = !nq || (el.getAttribute('data-q')||'').indexOf(nq)>=0;
      el.classList.toggle('hidden', !(okSev && okQ));
    });
    groups.forEach(function(g){
      var any=[].some.call(g.querySelectorAll('.finding'), function(el){ return !el.classList.contains('hidden'); });
      g.classList.toggle('hidden', !any);
    });
    chips.forEach(function(c){ c.classList.toggle('on', c.getAttribute('data-sev')===sev); });
    cards.forEach(function(c){ c.classList.toggle('on', c.getAttribute('data-filter')===sev); });
  }
  chips.forEach(function(c){ c.addEventListener('click', function(){ sev=c.getAttribute('data-sev')||'all'; apply(); }); });
  cards.forEach(function(c){
    c.addEventListener('click', function(){
      var f=c.getAttribute('data-filter')||'all';
      sev = (sev===f) ? 'all' : f;
      apply();
      var el=document.getElementById('findings');
      if(el) el.scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
  if(box){ box.addEventListener('input', function(){ q=box.value||''; apply(); }); }
  var ex=document.getElementById('expand-all');
  var cl=document.getElementById('collapse-all');
  if(ex) ex.addEventListener('click', function(){ document.querySelectorAll('.finding,.grp,#findings').forEach(function(d){ d.open=true; }); });
  if(cl) cl.addEventListener('click', function(){ document.querySelectorAll('.finding,.grp').forEach(function(d){ d.open=false; }); });
  document.addEventListener('click', function(e){
    var btn=e.target.closest('.more-ev');
    if(!btn) return;
    var tpl=btn.parentNode.querySelector('template.ev-rest');
    var ul=btn.parentNode.querySelector('ul.ev');
    if(tpl && ul){ ul.appendChild(tpl.content.cloneNode(true)); }
    btn.remove();
  });
  window.addEventListener('beforeprint', function(){
    document.querySelectorAll('details').forEach(function(d){ d.open=true; });
    document.querySelectorAll('.more-ev').forEach(function(b){ b.click(); });
  });
})();
"""


def export_html(
    report: Dict[str, Any],
    analysis: Dict[str, Any],
    report_file: str = "",
    *,
    manual_conclusion: str = "",
    include_ai: bool = False,
) -> str:
    try:
        from .net_process import enrich_report_connections
        enrich_report_connections(report)
    except Exception:
        pass
    analysis = _prepare_export_analysis(analysis, report_file)
    profile = _export_host_profile(report, report_file)
    host, ip, ct = profile["hostname"], profile["ip"], profile["collect_time"]
    os_line = profile["os"] or profile["os_family"] or "-"
    summary = analysis.get("summary_aggregated") or analysis.get("summary") or {}
    ai = analysis.get("ai") or {}
    q = report.get("collection_quality") or (analysis.get("meta") or {}).get("collection_quality") or assess_quality(report)
    findings = analysis.get("findings_aggregated") or []
    by_mod = analysis.get("findings_by_module") or {}
    try:
        from .quality_gate import evaluate_quality_gate
        gate = evaluate_quality_gate(report, quality=q, os_family=profile.get("os_family") or "")
    except Exception:
        gate = {}
    review = analysis.get("_export_review") or {}
    verdict = _export_risk_verdict(summary, gate, review)
    cats = _findings_by_category(findings)
    manual_note = str(manual_conclusion or "").strip()
    ai_pack = _ai_export_payload(ai) if include_ai else {}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    ql_name = QL_NAME
    ql_st = {
        "ok": ("正常", "ok"),
        "empty": ("无数据", "empty"),
        "degraded": ("不完整", "deg"),
        "missing": ("缺失", "miss"),
    }

    def h(s: Any) -> str:
        return (
            str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    n_total = int(summary.get("total", len(findings)) or 0)
    n_high = int(summary.get("high", 0) or 0)
    n_med = int(summary.get("medium", 0) or 0)
    n_low = int(summary.get("low", 0) or 0)
    n_rejected = int(review.get("rejected") or 0)

    metrics = [
        ("告警", n_total, "", "all"),
        ("高危", n_high, "h", "h"),
        ("中危", n_med, "m", "m"),
        ("低危", n_low, "l", "l"),
        ("外联", profile["connections"], "", ""),
    ]
    metrics_html = "".join(
        (
            f'<div class="metric {cls} filter" data-filter="{filt}" role="button" tabindex="0">'
            f'<div class="n">{h(val)}</div><div class="l">{h(lab)}</div></div>'
            if filt
            else f'<div class="metric {cls}"><div class="n">{h(val)}</div><div class="l">{h(lab)}</div></div>'
        )
        for lab, val, cls, filt in metrics
    )

    cat_html = "".join(
        f'<span class="cat-pill">{h(cat)} <b>{n}</b>'
        + (f' <span class="hi">高危 {hi}</span>' if hi else "")
        + "</span>"
        for cat, n, hi in cats[:16]
    )

    ql_html = ""
    for k, v in sorted((q or {}).items(), key=lambda x: str(x[0])):
        if k in ("version", "collector", "tool") or k in _QL_RETIRED:
            continue
        st = str(v or "missing").lower()
        lab, cls = ql_st.get(st, (st, "miss"))
        ql_html += f'<span class="ql {cls}"><i></i>{h(ql_name.get(k, k))} · {h(lab)}</span>'

    conf_raw = str(verdict.get("confidence") or gate.get("confidence") or "medium")
    conf_lab = h(verdict.get("confidence_label") or gate.get("confidence_label") or "-")
    conf_cls = "high" if conf_raw == "high" else (
        "medium" if conf_raw == "medium" else ("insufficient" if conf_raw == "insufficient" else "low")
    )
    gate_banner = ""
    if not gate.get("can_claim_clean", True):
        gate_banner = (
            f'<div class="gate-warn"><b>质量门禁</b>：采集置信度 {conf_lab}。'
            f"{h(gate.get('summary') or '')} 本报告不得作为「主机已安全」依据。</div>"
        )
    gaps_html = ""
    if gate.get("gaps"):
        gaps_html = "<ul class='gate-gaps'>" + "".join(
            f"<li><b>{h(g.get('label'))}</b>（{h(g.get('status'))}）— {h(g.get('hint'))}</li>"
            for g in gate["gaps"][:10]
        ) + "</ul>"
    review_pills = (
        f'<span class="stat-pill"><em>已排除</em>{n_rejected}</span>'
        if n_rejected
        else ""
    )
    conf_badge = f'<span class="conf {conf_cls}">{conf_lab}</span>'
    ev_logs = profile.get("event_logs")
    ev_logs_disp = h(ev_logs) if ev_logs not in (None, "", 0, "0") else "—"

    findings_html = ""
    if not findings:
        findings_html = '<div class="empty">本期无可见聚合告警（已排除加白）</div>'
    else:
        ordered = sorted(
            findings,
            key=lambda f: (
                0 if str(f.get("review_status") or "").lower() == "accepted" else 1,
                sev_rank.get(str(f.get("severity") or "medium").lower(), 9),
                str(f.get("title") or ""),
            ),
        )
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for f in ordered:
            cat = str(f.get("category") or f.get("type") or "其它").strip() or "其它"
            grouped.setdefault(cat, []).append(f)
        findings_html += (
            f'<p class="note">共 {len(ordered)} 条（已排除加白）。点击条目展开原因与证据。</p>'
            '<div class="toolbar">'
            '<input id="q" type="search" placeholder="搜索标题 / 路径 / 规则 / MITRE…">'
            f'<button type="button" class="chip on" data-sev="all">全部 {len(ordered)}</button>'
            f'<button type="button" class="chip" data-sev="h">高危 {n_high}</button>'
            f'<button type="button" class="chip" data-sev="m">中危 {n_med}</button>'
            f'<button type="button" class="chip" data-sev="l">低危 {n_low}</button>'
            '<button type="button" class="chip" id="expand-all">全部展开</button>'
            '<button type="button" class="chip" id="collapse-all">全部收起</button>'
            "</div>"
        )
        for cat, items in grouped.items():
            hi = sum(1 for f in items if str(f.get("severity") or "").lower() in ("high", "critical"))
            hint = f"{len(items)} 条" + (f" · 高危 {hi}" if hi else "")
            # 有高危的分类默认展开，其余收起，减少首屏噪音
            grp_open = " open" if hi else ""
            body = []
            for f in items:
                sev = str(f.get("severity") or "medium").lower()
                sev_cls = "h" if sev in ("high", "critical") else ("m" if sev == "medium" else "l")
                title = h(f.get("title") or f.get("name") or "未命名")
                cnt = f.get("count", 1)
                meta = []
                if f.get("matcher"):
                    meta.append(h(f.get("matcher")))
                if f.get("rule_id"):
                    meta.append("rule:" + h(f.get("rule_id")))
                sources = f.get("sources") or []
                if sources:
                    meta.append(h(", ".join(str(s) for s in sources[:5])))
                path = _finding_path(f)
                fc = _finding_file_count(f)
                reason = _finding_reason(f)
                mitre = _finding_mitre(f)
                reason_html = (
                    f"<div class='reason'><b>原因</b>：{h(reason[:720])}</div>" if reason else ""
                )
                tags = "".join(f"<span class='tag'>{h(m)}</span>" for m in mitre)
                if f.get("persist_kind"):
                    tags += f"<span class='tag'>{h(f.get('persist_kind'))}</span>"
                rv = str(f.get("review_status") or "pending").lower()
                if rv == "rejected":
                    tags += "<span class='tag rej'>已排除</span>"
                tags_html = f"<div class='tags'>{tags}</div>" if tags else ""
                extra_bits = ""
                if path:
                    extra_bits += f"<div class='path'>路径：{h(path)}</div>"
                if fc:
                    extra_bits += f"<div class='path'>关联文件数：{h(fc)}</div>"
                evs, trunc, total_hits = _collect_export_evidence(f, by_mod, limit=10000)
                preview, rest = evs[:_EXPORT_EV_PREVIEW], evs[_EXPORT_EV_PREVIEW:]
                ev_html = "".join(f"<li>{h(str(ev)[:800])}</li>" for ev in preview)
                rest_html = "".join(f"<li>{h(str(ev)[:800])}</li>" for ev in rest)
                if trunc or total_hits > len(evs):
                    rest_html += (
                        f"<li class='more'>… 证据 {len(evs)}/{h(total_hits)}</li>"
                    )
                more_btn = (
                    f"<button type='button' class='more-ev'>显示其余 {len(rest)} 条证据</button>"
                    f"<template class='ev-rest'>{rest_html}</template>"
                    if rest_html and rest
                    else (f"<template class='ev-rest'>{rest_html}</template>" if rest_html else "")
                )
                if rest_html and not rest:
                    ev_html += rest_html
                    more_btn = ""
                qblob = " ".join(
                    [
                        str(f.get("title") or ""),
                        str(f.get("category") or ""),
                        str(f.get("rule_id") or ""),
                        str(path or ""),
                        str(f.get("matcher") or ""),
                        str(reason or ""),
                        " ".join(mitre),
                    ]
                ).lower()
                ev_block = f"<ul class='ev'>{ev_html}</ul>{more_btn}" if ev_html or more_btn else ""
                cnt_lab = f"×{h(cnt)}"
                if evs:
                    cnt_lab += f" · 证据 {len(evs)}"
                meta_html = f"<div class='meta-line'>{' · '.join(meta)}</div>" if meta else ""
                # 高危默认展开首屏可读
                find_open = " open" if sev_cls == "h" and hi <= 8 else ""
                body.append(
                    f"<details class='finding sev-{sev_cls}'{find_open} data-sev='{sev_cls}' data-q='{h(qblob)}'>"
                    f"<summary><div class='fh'><span class='sev'>{h(sev.upper())}</span>"
                    f"<strong>{title}</strong><span class='cnt'>{cnt_lab}</span></div></summary>"
                    f"<div class='body'>{reason_html}{tags_html}{meta_html}{extra_bits}{ev_block}</div></details>"
                )
            findings_html += (
                f"<details class='grp'{grp_open}><summary>{h(cat)}<span class='hint'>{h(hint)}</span></summary>"
                f"<div class='grp-body'>{''.join(body)}</div></details>"
            )

    compare_sec = ""
    if manual_note or include_ai:
        cols = []
        if manual_note:
            cols.append(
                "<div class='compare-card human'>"
                "<div class='compare-h'>人工结论 <span class='tag'>分析员</span></div>"
                f"<div class='compare-body plain'>{h(manual_note).replace(chr(10), '<br>')}</div>"
                "</div>"
            )
        if include_ai:
            if ai_pack:
                bits = []
                if ai_pack.get("mode"):
                    bits.append(f"<div class='note' style='margin:0 0 8px'>模式/模型：{h(ai_pack['mode'])}</div>")
                # 风险等级挂在「总体风险等级」标题后，不再顶部单独放大「严重」
                bits.append(_ai_markdown_to_html(
                    ai_pack.get("summary") or "",
                    verdict=str(ai_pack.get("verdict") or ""),
                ))
                if ai_pack.get("highlights"):
                    bits.append(
                        "<div class='ai-h' style='margin-top:12px'>要点</div>"
                        "<ul>" + "".join(f"<li>{_ai_inline_html(x)}</li>" for x in ai_pack["highlights"]) + "</ul>"
                    )
                if ai_pack.get("recommendations"):
                    bits.append(
                        "<div class='ai-h' style='margin-top:12px'>处置建议</div>"
                        "<ul>" + "".join(f"<li>{_ai_inline_html(x)}</li>" for x in ai_pack["recommendations"]) + "</ul>"
                    )
                ai_body = "".join(bits)
            else:
                ai_body = (
                    "<div class='compare-empty'>"
                    "尚无可用 AI 研判。请先在「我的大模型」配置个人 Key，"
                    "或于分析页生成后再导出；勾选导出 AI 时也会尝试自动生成。"
                    "</div>"
                )
            cols.append(
                "<div class='compare-card robot'>"
                "<div class='compare-h'>AI 研判 <span class='tag'>模型</span></div>"
                f"<div class='compare-body'>{ai_body}</div>"
                "</div>"
            )
        compare_sec = (
            "<details class='sec' open>"
            "<summary><h2>结论对照</h2>"
            f"<span class='sec-count'>{'人工 + AI（上下）' if manual_note and include_ai else ('人工结论' if manual_note else 'AI 研判')}</span>"
            "</summary>"
            f"<div class='compare'>{''.join(cols)}</div>"
            "</details>"
        )

    gen_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        from .ioc_full_scan import html_section_for_report
        ioc_sec = html_section_for_report(report_file)
    except Exception:
        ioc_sec = ""
    tone = h(verdict.get("tone") or "high")
    hero_review = (
        f'<span>研判 <span class="stat-pills">{review_pills}</span></span>'
        if review_pills
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>应急分析报告 · {h(host)}</title>
<style>{_EXPORT_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <div class="brand">CNPC · FORENSIC OPS</div>
    <h1>终端应急分析报告</h1>
    <div class="meta">
      <span>主机 <b>{h(host)}</b></span>
      <span>IP <b>{h(ip or '-')}</b></span>
      <span>系统 <b>{h(os_line)}</b></span>
      <span>采集 <b>{h(ct or '-')}</b></span>
    </div>
    <div class="verdict tone-{tone}">
      <span class="lv">{h(verdict['level'])}</span>
      <p>{h(verdict['text'])}</p>
    </div>
    <div class="hero-foot">
      <span>采集置信度 {conf_badge}</span>
      {hero_review}
    </div>
  </header>

  {gate_banner}
  <div class="metrics">{metrics_html}</div>

  {compare_sec}

  <details class="sec" open>
    <summary><h2>主机概况</h2></summary>
    <div class="profile">
      <div class="prof-block">
        <div class="prof-h">主机信息</div>
        <div class="kv"><span>主机名</span><b>{h(host)}</b></div>
        <div class="kv"><span>IP</span><b>{h(ip or '-')}</b></div>
        <div class="kv"><span>操作系统</span><b>{h(os_line)}</b></div>
        <div class="kv"><span>采集时间</span><b>{h(ct or '-')}</b></div>
        <div class="kv"><span>采集置信度</span><b>{conf_badge}</b></div>
      </div>
      <div class="prof-block">
        <div class="prof-h">资产规模</div>
        <div class="prof-metrics">
          <div class="pm"><div class="v">{h(profile['processes'])}</div><div class="k">进程</div></div>
          <div class="pm"><div class="v">{h(profile['services'])}</div><div class="k">服务</div></div>
          <div class="pm"><div class="v">{h(profile['tasks'])}</div><div class="k">计划任务</div></div>
          <div class="pm"><div class="v">{h(profile['startup'])}</div><div class="k">启动项</div></div>
          <div class="pm"><div class="v">{h(profile['users'])}</div><div class="k">本地用户</div></div>
          <div class="pm"><div class="v">{h(profile['drivers'])}</div><div class="k">驱动</div></div>
          <div class="pm"><div class="v">{h(profile['connections'])}</div><div class="k">外联</div></div>
          <div class="pm"><div class="v">{h(profile['browser'])}</div><div class="k">浏览器</div></div>
          <div class="pm"><div class="v">{h(profile['files'])}</div><div class="k">文件扫描</div></div>
        </div>
        <div class="kv" style="margin-top:8px"><span>系统日志条目</span><b>{ev_logs_disp}</b></div>
      </div>
    </div>
    {f'<div class="cats">{cat_html}</div>' if cat_html else ''}
  </details>

  <details class="sec">
    <summary><h2>采集质量</h2><span class="sec-count">{conf_lab}</span></summary>
    <p class="note">{h(gate.get('summary') or '')}</p>
    {gaps_html}
    <div class="ql-row">{ql_html or '<span class="empty">无质量数据</span>'}</div>
    <p class="note">「无数据」表示已采集但结果为空，不等于采集失败。</p>
  </details>

  <details class="sec" id="findings">
    <summary><h2>聚合告警</h2><span class="sec-count">{h(n_total)} 条</span></summary>
    {findings_html}
  </details>

  {ioc_sec}

  <div class="foot">由 CNPC 终端应急响应分析平台生成 · {h(gen_at)}</div>
</div>
<script>{_EXPORT_HTML_JS}</script>
</body>
</html>"""


def quality_summary(report: Dict[str, Any]) -> Dict[str, str]:
    """兼容旧调用。"""
    return report.get("collection_quality") or assess_quality(report)

