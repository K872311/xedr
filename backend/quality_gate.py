# -*- coding: utf-8 -*-
"""应急分析：残包质量门禁与结论置信度。

目标：采集不完整时不得给出过强「未见告警 / 低风险」结论；
导出与概览展示置信度、缺口与研判确认统计。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# 应急关键面：进程必采；持久化面至少一类有数据
_CRIT_KEYS = ("processes",)
_PERSIST_KEYS = ("services", "scheduled_tasks", "startup", "startup_items")
_SUPPORT_KEYS = ("established_connections", "file_scans", "event_logs", "users")

_LABELS = {
    "processes": "进程",
    "services": "服务",
    "scheduled_tasks": "计划任务",
    "startup": "启动项",
    "startup_items": "启动项",
    "established_connections": "外联",
    "network": "网络",
    "file_scans": "文件扫描",
    "event_logs": "系统日志",
    "users": "本地用户",
    "ps_history": "PS历史",
}


def _norm_status(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in ("ok", "normal", "ready"):
        return "ok"
    if s in ("degraded", "partial", "incomplete"):
        return "degraded"
    if s in ("empty", "none", "no_data"):
        return "empty"
    if s in ("missing", "miss", "failed", "error", "fail", "skipped"):
        return "missing"
    return s or "missing"


def _is_bad(st: str) -> bool:
    return st in ("empty", "missing", "")


def _is_weak(st: str) -> bool:
    return st == "degraded" or _is_bad(st)


def _status_of(quality: Dict[str, Any], key: str, counts: Optional[Dict[str, Any]] = None) -> str:
    if key in (quality or {}):
        return _norm_status(quality.get(key))
    # 兼容 network 键
    if key == "established_connections" and "network" in (quality or {}):
        return _norm_status(quality.get("network"))
    if key == "startup" and "startup_items" in (quality or {}):
        return _norm_status(quality.get("startup_items"))
    if counts:
        alias = "startup_items" if key == "startup" else key
        try:
            n = int(counts.get(alias) or counts.get(key) or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            return "ok"
        if alias in counts or key in counts:
            return "empty"
    return "missing"


def evaluate_quality_gate(
    report: Optional[Dict[str, Any]] = None,
    *,
    quality: Optional[Dict[str, Any]] = None,
    counts: Optional[Dict[str, Any]] = None,
    os_family: str = "",
) -> Dict[str, Any]:
    """评估采集完整度 → confidence / gaps / can_claim_clean。"""
    report = report if isinstance(report, dict) else {}
    q = dict(quality or report.get("collection_quality") or {})
    if not q:
        try:
            from .ingest import assess_quality
            q = assess_quality(report)
        except Exception:
            q = {}
    cnt = counts if isinstance(counts, dict) else {}
    if not cnt:
        for k in ("processes", "services", "scheduled_tasks", "startup_items", "file_scans",
                  "established_connections", "event_logs", "users"):
            try:
                n = len(report.get(k) or []) if not isinstance(report.get(k), dict) else 0
            except Exception:
                n = 0
            if n:
                cnt[k] = n

    fam = (os_family or report.get("os_family") or "").strip().lower()
    if fam not in ("windows", "linux"):
        fam = "linux" if "linux" in str(report.get("os") or "").lower() else "windows"

    gaps: List[Dict[str, Any]] = []
    crit_bad = 0
    persist_ok = 0
    support_ok = 0

    for key in _CRIT_KEYS:
        st = _status_of(q, key, cnt)
        if _is_bad(st):
            crit_bad += 1
            gaps.append({
                "key": key,
                "label": _LABELS.get(key, key),
                "status": st,
                "level": "critical",
                "hint": "缺少进程列表时，规则与 IOC 对照面严重不足",
            })
        elif st == "degraded":
            gaps.append({
                "key": key,
                "label": _LABELS.get(key, key),
                "status": st,
                "level": "major",
                "hint": "进程数据不完整（如缺路径），部分规则可能漏报",
            })

    for key in _PERSIST_KEYS:
        st = _status_of(q, key, cnt)
        if st == "ok":
            persist_ok += 1
        elif key in ("startup", "startup_items") and any(
            g.get("key") in ("startup", "startup_items") for g in gaps
        ):
            continue
        elif _is_weak(st) and key != "startup":  # startup 与 startup_items 等价，避免重复
            # 仅记录真正缺失的持久化面，汇总用
            pass

    # 持久化面：服务 / 计划任务 / 启动项 至少一个 ok
    persist_statuses = [_status_of(q, k, cnt) for k in ("services", "scheduled_tasks", "startup_items")]
    if not any(s == "ok" for s in persist_statuses):
        # startup 别名
        if _status_of(q, "startup", cnt) != "ok":
            gaps.append({
                "key": "persistence",
                "label": "持久化面（服务/计划任务/启动项）",
                "status": "empty",
                "level": "critical" if crit_bad else "major",
                "hint": "持久化相关模块均无有效数据，后门/驻留类检出受限",
            })
            persist_ok = 0
        else:
            persist_ok = 1
    else:
        persist_ok = sum(1 for s in persist_statuses if s == "ok")

    for key in _SUPPORT_KEYS:
        st = _status_of(q, key, cnt)
        if st == "ok":
            support_ok += 1
        elif _is_bad(st):
            gaps.append({
                "key": key,
                "label": _LABELS.get(key, key),
                "status": st,
                "level": "minor",
                "hint": "辅助模块缺失，不影响主威胁面，但外联/文件/日志线索可能不足",
            })

    # 置信度
    if crit_bad >= 1 and persist_ok == 0:
        confidence, conf_label = "insufficient", "不足"
        can_claim_clean = False
        summary = "关键采集面严重缺失（进程与持久化），当前结论不可作为「主机干净」依据。"
    elif crit_bad >= 1:
        confidence, conf_label = "low", "较低"
        can_claim_clean = False
        summary = "缺少进程等关键采集数据，检出面不足，风险结论置信度降低。"
    elif persist_ok == 0:
        confidence, conf_label = "low", "较低"
        can_claim_clean = False
        summary = "持久化相关模块无有效数据，驻留类威胁可能漏报，结论需降级。"
    elif any(g.get("level") == "major" for g in gaps) or support_ok <= 1:
        confidence, conf_label = "medium", "中等"
        can_claim_clean = True
        summary = "主采集面基本可用，部分辅助模块缺失或不完整，结论宜结合缺口解读。"
    else:
        confidence, conf_label = "high", "较高"
        can_claim_clean = True
        summary = "关键采集面（进程与持久化）数据可用，结论置信度较高。"

    # 去重 gaps（同 key）
    seen = set()
    uniq_gaps = []
    for g in gaps:
        k = g.get("key")
        if k in seen:
            continue
        seen.add(k)
        uniq_gaps.append(g)

    return {
        "confidence": confidence,
        "confidence_label": conf_label,
        "can_claim_clean": can_claim_clean,
        "summary": summary,
        "gaps": uniq_gaps,
        "os_family": fam,
        "stats": {
            "critical_bad": crit_bad,
            "persist_ok": persist_ok,
            "support_ok": support_ok,
            "gap_count": len(uniq_gaps),
        },
    }


def review_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    pending = accepted = rejected = 0
    acc_high = 0
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        st = str(f.get("review_status") or "pending").lower()
        sev = str(f.get("severity") or "").lower()
        if st == "accepted":
            accepted += 1
            if sev in ("high", "critical"):
                acc_high += 1
        elif st == "rejected":
            rejected += 1
        else:
            pending += 1
    return {
        "pending": pending,
        "accepted": accepted,
        "rejected": rejected,
        "accepted_high": acc_high,
        "total_reviewed": accepted + rejected,
    }


def build_ir_verdict(
    summary: Optional[Dict[str, Any]],
    gate: Optional[Dict[str, Any]] = None,
    review: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """在告警统计基础上叠加质量门禁与确认告警，生成应急结论。"""
    summary = summary if isinstance(summary, dict) else {}
    gate = gate if isinstance(gate, dict) else {}
    review = review if isinstance(review, dict) else {}

    hi = int(summary.get("high") or 0)
    md = int(summary.get("medium") or 0)
    lo = int(summary.get("low") or 0)
    total = int(summary.get("total") or (hi + md + lo) or 0)
    conf = str(gate.get("confidence") or "medium")
    can_clean = bool(gate.get("can_claim_clean", True))
    acc = int(review.get("accepted") or 0)
    acc_hi = int(review.get("accepted_high") or 0)
    pending = int(review.get("pending") or 0)

    if hi >= 20 or (hi >= 8 and md >= 10):
        level, tone = "严重", "crit"
        text = (
            f"本期可见聚合告警 {total} 条（高危 {hi} / 中危 {md} / 低危 {lo}）。"
            "高危偏多，建议优先处置防御绕过、持久化与可疑外联。"
        )
    elif hi >= 1:
        level, tone = "高风险", "high"
        text = (
            f"本期可见聚合告警 {total} 条（高危 {hi} / 中危 {md} / 低危 {lo}）。"
            "请核实高危证据与关联进程，区分真实入侵与误报。"
        )
    elif md >= 1:
        level, tone = "中风险", "med"
        text = (
            f"本期可见聚合告警 {total} 条（中危 {md} / 低危 {lo}），暂无高危。"
            "建议关注持久化与异常执行痕迹。"
        )
    elif total:
        level, tone = "低风险", "low"
        text = f"本期可见聚合告警 {total} 条，均为低危。可按优先级抽查。"
    else:
        level, tone = "未见告警", "ok"
        text = "本期无可见聚合告警（已排除加白项）。"

    # 残包：禁止过强「干净」表述
    if not can_clean and level in ("未见告警", "低风险"):
        level, tone = "结论受限", "low"
        text = (
            f"{text} 但采集完整度置信度「{gate.get('confidence_label') or conf}」，"
            f"{gate.get('summary') or '关键模块缺失'}。"
            "不得据此认定主机安全，建议补采后再评。"
        )
    elif conf in ("low", "insufficient"):
        text = f"{text} 【置信度{gate.get('confidence_label') or conf}】{gate.get('summary') or ''}"
    elif conf == "medium" and gate.get("summary"):
        text = f"{text} （采集置信度中等：{gate.get('summary')}）"

    # 研判进度：报告不展示「待审 / 已确认」，仅保留已排除（加白）口径
    rej = int(review.get("rejected") or 0)
    if rej and total:
        text = f"{text} 已排除 {rej} 条。"

    return {
        "level": level,
        "tone": tone,
        "text": text.strip(),
        "confidence": conf,
        "confidence_label": gate.get("confidence_label") or "",
        "can_claim_clean": can_clean,
        "accepted": acc,
        "accepted_high": acc_hi,
        "pending": pending,
        "rejected": rej,
    }


def attach_gate_to_analysis(
    analysis: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
    *,
    counts: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """写入 analysis.meta.quality_gate，供概览/导出复用。"""
    a = analysis if isinstance(analysis, dict) else {}
    meta = dict(a.get("meta") or {})
    q = report.get("collection_quality") if isinstance(report, dict) else None
    q = q or meta.get("collection_quality")
    gate = evaluate_quality_gate(
        report,
        quality=q if isinstance(q, dict) else None,
        counts=counts,
        os_family=str((report or {}).get("os_family") or meta.get("os_family") or ""),
    )
    meta["quality_gate"] = gate
    a["meta"] = meta
    return a
