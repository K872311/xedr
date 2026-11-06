"""Agentic SOC 风格多智能体研判流水线（对齐阿里云 Agentic SOC 工作流）。

分层：
  Team Leader → 威胁检测 / 事件调查 / 实体研判 / 响应协同 / 安全报告

阶段（感知→调查→根因→处置建议→报告）：
  事件概述 → 溯源调查 → 根因分析 → 处置建议 →（人工审核后）响应
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


_ATTCK_HINTS = (
    (r"persist|startup|run\\\\|schtask|计划任务|注册表|wmi_persist", "T1547", "持久化", "Persistence"),
    (r"powershell|encodedcommand|scriptblock|mshta|wscript|cscript|lolbin", "T1059", "执行", "Execution"),
    (r"network_connect|c2|外联|dns_|beacon|cobalt", "T1071", "命令与控制", "Command and Control"),
    (r"logon_fail|brute|password|credential|mimikatz|lsass", "T1110", "凭证访问", "Credential Access"),
    (r"inject|remote_thread|process_access|hollow", "T1055", "防御绕过", "Defense Evasion"),
    (r"file_create|drop|可疑目录|webshell|fim_", "T1105", "横向/投递", "Lateral Movement"),
    (r"service_install|driver_load|特权|special_priv", "T1543", "权限提升", "Privilege Escalation"),
)

_IOC_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_IOC_DOM = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|xyz|top|info|ru|cc)\b", re.I)
_IOC_SHA = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IOC_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']+\.(?:exe|dll|bat|cmd|ps1|js|vbs|scr|hta)", re.I)


def run_agent_team(pack: Dict[str, Any], *, skills: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """本地启发式 Agent Team：不调用大模型，毫秒级产出结构化研判。"""
    host = pack.get("agent") or {}
    events = pack.get("threat_events") or []
    security_logs = pack.get("security_logs") or []
    timeline = pack.get("timeline") or []
    cats = pack.get("log_categories") or {}
    log_rule_hits = pack.get("log_rule_hits") or []
    log_rule_meta = pack.get("log_rule_meta") or {}

    detect = _agent_detect(events, security_logs, cats)
    investigate = _agent_investigate(events, security_logs, timeline, host)
    entities = _agent_entities(events, security_logs, pack)
    respond = _agent_respond(entities, detect, host, investigate)
    report = _agent_report(host, detect, investigate, entities, respond, skills or [])
    alert_meta = _build_alert_meta(host, detect, investigate, events)
    # 先产出「AI 对每条威胁的研判结论」，再写入思维链（避免模板空话）
    threat_events = _annotate_threat_events(
        events,
        detect=detect,
        investigate=investigate,
        entities=entities,
        log_rule_hits=log_rule_hits,
        skills=skills or [],
    )
    thinking = _build_thinking_chain(
        host, detect, investigate, entities, respond, skills or [],
        threat_events=threat_events,
        security_logs=security_logs,
        log_rule_hits=log_rule_hits,
    )

    agents = [
        {"id": "leader", "name": "Team Leader", "role": "全局调度", "status": "done",
         "summary": f"已拆解为检测→调查→实体→响应→报告；主机 {host.get('hostname') or host.get('agent_id')}"},
        {"id": "detect", "name": "威胁检测 Agent", "role": "告警聚合/分类", "status": "done",
         "summary": detect.get("summary") or ""},
        {"id": "investigate", "name": "事件调查 Agent", "role": "攻击链/时间线/思维链", "status": "done",
         "summary": investigate.get("summary") or ""},
        {"id": "entity", "name": "实体研判 Agent", "role": "恶意实体识别", "status": "done",
         "summary": f"识别实体 {len(entities)} 个，恶意/可疑 {sum(1 for e in entities if e.get('risk') in ('malicious','suspicious'))} 个"},
        {"id": "respond", "name": "响应协同 Agent", "role": "处置建议(需人工审核)", "status": "done",
         "summary": respond.get("summary") or ""},
        {"id": "report", "name": "安全报告 Agent", "role": "调查报告", "status": "done",
         "summary": "已生成事件调查技术报告（含加固建议）"},
    ]

    verdict = detect.get("verdict") or "信息不足"
    risk_level = detect.get("risk_level") or "低"
    risk_score = int(detect.get("risk_score") or 0)

    markdown = _render_markdown(
        host=host,
        verdict=verdict,
        risk_level=risk_level,
        risk_score=risk_score,
        detect=detect,
        investigate=investigate,
        entities=entities,
        respond=respond,
        report=report,
        alert_meta=alert_meta,
        security_logs=security_logs,
        log_rule_hits=log_rule_hits,
        log_rule_meta=log_rule_meta,
        skills=skills or [],
    )

    highlights = list(detect.get("highlights") or [])[:8]
    for e in entities[:4]:
        if e.get("value"):
            highlights.append(f"实体[{e.get('type')}/{e.get('risk')}] {e.get('value')} · {e.get('reason') or ''}")

    return {
        "architecture": "agentic_soc",
        "framework": "ReAct+CoT",
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "summary": report.get("abstract") or detect.get("summary") or "",
        "highlights": highlights[:12],
        "recommendations": [d.get("label") + "：" + (d.get("reason") or "") for d in (respond.get("dispositions") or [])][:8]
            or list(respond.get("notes") or [])[:6],
        "team": {"leader": agents[0], "agents": agents},
        "pipeline": [
            {"stage": "事件概述", "goal": "确定发生了什么",
             "output": detect.get("overview"),
             "deliverables": ["事件概述", "攻击时间线", "ATT&CK 阶段", "攻击手段类型"]},
            {"stage": "溯源调查", "goal": "评估影响范围",
             "output": investigate.get("impact"),
             "deliverables": ["告警上下文", "受影响资产", "恶意实体列表"]},
            {"stage": "根因分析", "goal": "查找入侵点",
             "output": investigate.get("root_cause"),
             "deliverables": ["调查日志证据", "可疑入侵点", "研判结论"]},
            {"stage": "处置建议", "goal": "制定止血和加固方案",
             "output": respond.get("summary"),
             "deliverables": ["应急响应", "系统加固", "误报加白", "日志补充"]},
            {"stage": "事件响应", "goal": "人工审核后调用工具执行",
             "output": "待人工确认后下发 EDR 处置指令",
             "deliverables": ["处置计划", "人工审核", "工具调用"]},
        ],
        "alert_meta": alert_meta,
        "overview": detect.get("overview") or {},
        "attack_chain": investigate.get("attack_chain") or [],
        "attack_timeline": investigate.get("attack_timeline") or [],
        "attack_graph": investigate.get("attack_graph") or {},
        "attck": investigate.get("attck") or [],
        "threat_events": threat_events,
        "entities": entities[:20],
        "iocs": investigate.get("iocs") or [],
        "root_cause": investigate.get("root_cause") or "",
        "impact": investigate.get("impact") or "",
        "dispositions": respond.get("dispositions") or [],
        "hardening": respond.get("hardening") or [],
        "thinking_chain": thinking,
        "human_in_the_loop": True,
        "markdown": markdown,
    }


def merge_llm_into_agentic(base: Dict[str, Any], llm_text: str) -> Dict[str, Any]:
    """把大模型正文并入 Agentic 结果：保留结构化字段，用 LLM 精炼报告正文。"""
    out = dict(base or {})
    text = (llm_text or "").strip()
    if not text:
        return out
    # 尝试从模型文本抽判决
    for v in ("真实攻击", "疑似误报", "信息不足"):
        if v in text[:400]:
            out["verdict"] = v
            break
    out["markdown"] = text
    out["summary"] = _first_line(text) or out.get("summary")
    out["llm_refined"] = True

    # 把本地模型精炼结果挂进思维链，突出「AI 分析」
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    excerpt = lines[:6]
    chain = list(out.get("thinking_chain") or [])
    chain.append({
        "id": "llm_refine",
        "phase": "模型精炼",
        "title": "本地大模型精炼调查结论",
        "clue": f"模型已重写报告正文（{len(text)} 字），判决={out.get('verdict')}",
        "hypothesis": out.get("verdict") or "信息不足",
        "reasoning": excerpt or ["模型返回正文过短"],
        "observation": (out.get("summary") or "")[:240],
        "evidence": excerpt[:5] or [text[:160]],
        "agent": "本地 LLM / 安全报告 Agent",
    })
    out["thinking_chain"] = chain
    return out


def _agent_detect(events: List[Dict], security_logs: List[Dict], cats: Dict[str, int]) -> Dict[str, Any]:
    crit = sum(1 for e in events if str(e.get("severity") or "").lower() == "critical")
    high = sum(1 for e in events if str(e.get("severity") or "").lower() == "high")
    med = sum(1 for e in events if str(e.get("severity") or "").lower() == "medium")
    hot_logs = sum(1 for t in security_logs if str(t.get("severity") or "").lower() in ("high", "critical", "medium"))

    score = min(
        98,
        crit * 25 + high * 12 + med * 5
        + min(18, len(security_logs) // 2)
        + min(12, hot_logs * 2)
        + min(10, int(cats.get("script") or 0) + int(cats.get("persist") or 0)),
    )
    if crit or high >= 3 or (high and any(_looks_active_intrusion(e) for e in events[:12])):
        level, verdict = ("严重" if crit else "高"), "真实攻击"
    elif high or med >= 4 or hot_logs >= 5:
        level, verdict = "中", "真实攻击" if high else "疑似误报"
    elif events or security_logs:
        level, verdict = "低", "信息不足"
        score = max(score, 18)
    else:
        level, verdict = "低", "信息不足"
        score = max(score, 10)

    # 下调：大量 IOC 误报噪声时不要一律「真实攻击」
    ioc_only = sum(1 for e in events if "情报 IOC" in str(e.get("title") or "") or e.get("module") == "ioc")
    if verdict == "真实攻击" and high <= 1 and ioc_only >= max(3, len(events) // 2) and not any(_looks_active_intrusion(e) for e in events):
        verdict = "疑似误报"
        level = "中"

    highlights = []
    for e in events[:8]:
        highlights.append(
            f"[{e.get('severity') or '?'}] {e.get('title') or e.get('rule_id') or '威胁'} · "
            f"{str(e.get('matched') or e.get('summary') or e.get('path') or '')[:140]}"
        )
    for t in security_logs[:5]:
        highlights.append(f"日志[{t.get('category') or 'other'}] {t.get('etype')}: {str(t.get('summary') or '')[:120]}")

    titles = [str(e.get("title") or "") for e in events[:6] if e.get("title")]
    overview = {
        "what": (
            f"聚合未关闭/近期威胁 {len(events)} 条（critical={crit}, high={high}, medium={med}），"
            f"重点安全日志 {len(security_logs)} 条。"
            + (f" 代表告警：{'；'.join(titles[:3])}。" if titles else "")
        ),
        "log_categories": cats,
        "top_alerts": titles[:5],
    }
    return {
        "verdict": verdict,
        "risk_level": level,
        "risk_score": score,
        "summary": f"研判结论：{verdict}；风险 {level}（{score}/100）。{overview['what']}",
        "overview": overview,
        "highlights": highlights,
        "counts": {"critical": crit, "high": high, "medium": med, "security_logs": len(security_logs)},
    }


def _agent_investigate(
    events: List[Dict],
    security_logs: List[Dict],
    timeline: List[Dict],
    host: Dict[str, Any],
) -> Dict[str, Any]:
    chain: List[Dict[str, Any]] = []
    attck: List[Dict[str, str]] = []
    seen_tech = set()
    blob_rows = list(events[:20]) + list(security_logs[:30]) + list(timeline[:40])

    for row in blob_rows:
        text = " ".join(
            str(row.get(k) or "")
            for k in ("title", "summary", "matched", "etype", "command_line", "path", "rule_id")
        ).lower()
        for pat, tid, stage, tactic in _ATTCK_HINTS:
            if re.search(pat, text, re.I):
                if tid not in seen_tech:
                    seen_tech.add(tid)
                    attck.append({"id": tid, "stage": stage, "tactic": tactic})
                if len(chain) < 10:
                    evid = str(row.get("matched") or row.get("summary") or row.get("title") or row.get("command_line") or "")[:180]
                    if evid and not any(c.get("evidence") == evid for c in chain):
                        chain.append({
                            "stage": stage,
                            "technique": tid,
                            "evidence": evid,
                            "etype": str(row.get("etype") or ""),
                        })
                break

    # 保证阶段顺序：执行 → 持久化 → C2 等常见链
    stage_order = {"初始访问": 0, "执行": 1, "持久化": 2, "权限提升": 3, "防御绕过": 4, "凭证访问": 5, "命令与控制": 6, "横向/投递": 7}
    chain.sort(key=lambda x: stage_order.get(str(x.get("stage") or ""), 99))

    iocs = _extract_iocs(blob_rows)
    timeline_rows: List[Dict[str, Any]] = []
    for e in events[:12]:
        timeline_rows.append({
            "ts": str(e.get("ts") or e.get("created_at") or ""),
            "kind": "threat",
            "title": str(e.get("title") or "")[:120],
            "severity": e.get("severity") or "",
            "detail": str(e.get("matched") or e.get("summary") or e.get("path") or "")[:160],
        })
    for t in security_logs[:8]:
        timeline_rows.append({
            "ts": str(t.get("ts") or ""),
            "kind": "log",
            "title": f"{t.get('etype') or 'log'}: {str(t.get('summary') or '')[:80]}",
            "severity": t.get("severity") or "",
            "detail": str(t.get("command_line") or t.get("path") or "")[:160],
        })
    timeline_rows.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)

    root = ""
    for e in events:
        title = str(e.get("title") or "")
        if any(k in title for k in ("持久化", "LOLBin", "编码", "计划任务", "可疑路径", "多阶段")):
            root = f"可疑入口/行为：{title} · {str(e.get('matched') or e.get('summary') or e.get('path') or '')[:160]}"
            break
    if not root and events:
        e0 = events[0]
        root = f"优先复核：{e0.get('title')} · {str(e0.get('matched') or e0.get('path') or '')[:160]}"
    if not root:
        root = "证据不足，暂无法定位明确入侵点；建议补充进程树与 PowerShell 脚本块日志。"

    impact = (
        f"受影响主机：{host.get('hostname') or host.get('agent_id') or '—'} "
        f"（{host.get('ip') or host.get('last_ip') or '—'}）。"
        f"关联威胁 {len(events)} 条，安全日志 {len(security_logs)} 条，"
        f"识别 IoC {len(iocs)} 个，ATT&CK 技术 {len(attck)} 项。"
    )
    attack_graph = _build_attack_graph(
        chain=chain,
        attck=attck,
        events=events,
        security_logs=security_logs,
        timeline_rows=timeline_rows,
        host=host,
    )
    return {
        "summary": f"攻击链阶段 {len({c.get('stage') for c in chain}) or 0} 个，ATT&CK {len(attck)} 项。",
        "attack_chain": chain[:12],
        "attack_timeline": timeline_rows[:16],
        "attack_graph": attack_graph,
        "attck": attck[:12],
        "iocs": iocs[:20],
        "root_cause": root,
        "impact": impact,
        "vectors": list({c.get("stage") for c in chain if c.get("stage")})[:8],
    }


def _build_attack_graph(
    *,
    chain: List[Dict[str, Any]],
    attck: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    security_logs: List[Dict[str, Any]],
    timeline_rows: List[Dict[str, Any]],
    host: Dict[str, Any],
) -> Dict[str, Any]:
    """生成可串联展示的杀伤链图：阶段节点 + 证据边 + 时序边。"""
    stage_order = ["初始访问", "执行", "持久化", "权限提升", "防御绕过", "凭证访问", "命令与控制", "横向/投递"]
    stage_kw = {
        "初始访问": ("phishing", "macro", "office", "lnk", "投递", "dcom"),
        "执行": ("powershell", "script", "lolbin", "mshta", "cmd", "wscript", "encoded"),
        "持久化": ("persist", "startup", "schtask", "run", "计划", "服务安装"),
        "权限提升": ("特权", "uac", "privilege", "token"),
        "防御绕过": ("inject", "spoof", "unsigned", "bypass", "amsi", "etw"),
        "凭证访问": ("lsass", "credential", "password", "mimikatz", "dpapi"),
        "命令与控制": ("network", "dns", "beacon", "外联", "c2", "connect"),
        "横向/投递": ("lateral", "smb", "wmi", "psexec", "remote"),
    }

    def _stage_of(row: Dict[str, Any]) -> str:
        blob = " ".join(
            str(row.get(k) or "")
            for k in ("title", "summary", "matched", "etype", "command_line", "path", "kind", "detail")
        ).lower()
        for stage, kws in stage_kw.items():
            if any(k in blob for k in kws):
                return stage
        # fallback from chain technique match
        for c in chain:
            if str(c.get("etype") or "") and str(c.get("etype")) == str(row.get("etype") or ""):
                return str(c.get("stage") or "执行")
        return ""

    # 合并阶段：有证据才出现
    stage_items: Dict[str, List[Dict[str, Any]]] = {s: [] for s in stage_order}
    for e in events[:30]:
        st = _stage_of(e) or ("执行" if str(e.get("severity") or "").lower() in ("critical", "high") else "")
        if not st:
            continue
        stage_items[st].append({
            "kind": "threat",
            "ts": str(e.get("ts") or e.get("created_at") or ""),
            "title": str(e.get("title") or "")[:100],
            "detail": str(e.get("matched") or e.get("summary") or e.get("path") or "")[:140],
            "severity": e.get("severity") or "",
            "id": e.get("id"),
        })
    for t in security_logs[:40]:
        st = _stage_of(t)
        if not st:
            continue
        stage_items[st].append({
            "kind": "log",
            "ts": str(t.get("ts") or ""),
            "title": str(t.get("etype") or t.get("category") or "log")[:80],
            "detail": str(t.get("summary") or t.get("command_line") or "")[:140],
            "severity": t.get("severity") or "",
            "category": t.get("category") or "",
        })
    # 用 ATT&CK / chain 补空洞阶段
    for c in chain:
        st = str(c.get("stage") or "")
        if st in stage_items and not stage_items[st]:
            stage_items[st].append({
                "kind": "infer",
                "ts": "",
                "title": f"{c.get('technique') or ''} {st}".strip(),
                "detail": str(c.get("evidence") or "")[:140],
                "severity": "",
            })

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    flow: List[str] = []
    prev_id = None
    host_id = "host"
    nodes.append({
        "id": host_id,
        "type": "host",
        "label": host.get("hostname") or host.get("agent_id") or "目标主机",
        "sub": host.get("ip") or host.get("last_ip") or "",
        "count": 0,
    })

    for st in stage_order:
        items = stage_items.get(st) or []
        if not items:
            continue
        # 每阶段最多挂 4 条证据，按时间
        items = sorted(items, key=lambda x: str(x.get("ts") or ""))[:4]
        nid = f"stage:{st}"
        tech = next((a.get("id") for a in attck if a.get("stage") == st), "")
        tech = tech or next((c.get("technique") for c in chain if c.get("stage") == st), "")
        nodes.append({
            "id": nid,
            "type": "stage",
            "label": st,
            "sub": tech or "",
            "count": len(items),
            "items": items,
        })
        flow.append(st)
        if prev_id is None:
            edges.append({"from": host_id, "to": nid, "label": "受影响"})
        else:
            edges.append({"from": prev_id, "to": nid, "label": "推进"})
        prev_id = nid

    # 无阶段时仍给主机→时间线兜底
    if len(nodes) <= 1 and timeline_rows:
        nid = "stage:观察"
        nodes.append({
            "id": nid,
            "type": "stage",
            "label": "观察取证",
            "sub": "",
            "count": min(4, len(timeline_rows)),
            "items": [
                {
                    "kind": t.get("kind") or "log",
                    "ts": t.get("ts") or "",
                    "title": str(t.get("title") or "")[:100],
                    "detail": str(t.get("detail") or "")[:140],
                    "severity": t.get("severity") or "",
                }
                for t in timeline_rows[:4]
            ],
        })
        edges.append({"from": host_id, "to": nid, "label": "取证"})
        flow.append("观察取证")

    return {
        "ok": True,
        "flow": flow,
        "nodes": nodes,
        "edges": edges,
        "stage_count": max(0, len(nodes) - 1),
        "summary": (
            f"串联 {max(0, len(nodes) - 1)} 个攻击阶段"
            + (f"：{' → '.join(flow)}" if flow else "（证据不足）")
        ),
    }


def _agent_entities(events: List[Dict], security_logs: List[Dict], pack: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(etype: str, value: str, risk: str, reason: str, action: str = "", extra: Optional[Dict] = None):
        v = str(value or "").strip()
        if not v or len(v) < 2:
            return
        key = (etype, v.lower())
        if key in seen:
            return
        seen.add(key)
        analysis = _entity_analysis(etype, v, risk, reason, action, extra or {})
        item = {
            "type": etype,
            "value": v[:260],
            "risk": risk,
            "reason": (reason or "")[:200],
            "action": action,
            "analysis": analysis,
        }
        if extra:
            item.update(extra)
        out.append(item)

    host = pack.get("agent") or {}
    add("host", str(host.get("hostname") or host.get("agent_id") or ""), "suspicious" if events else "unknown", "研判目标主机")

    for e in events[:25]:
        title = str(e.get("title") or "")
        sev = str(e.get("severity") or "").lower()
        risk = "malicious" if sev in ("critical", "high") else ("suspicious" if sev == "medium" else "unknown")
        if e.get("process_name") or e.get("pid"):
            add(
                "process",
                str(e.get("process_name") or e.get("name") or f"PID {e.get('pid')}"),
                risk,
                title or "威胁关联进程",
                "kill_process" if risk == "malicious" else "",
                {"pid": e.get("pid"), "path": e.get("path") or "", "command_line": str(e.get("command_line") or "")[:200]},
            )
        path = str(e.get("path") or "")
        if path and re.search(r"\.(exe|dll|bat|cmd|ps1|js|vbs|scr)$", path, re.I):
            add("file", path, risk, title or "威胁关联文件", "quarantine_file" if risk == "malicious" else "")
        if e.get("remote"):
            add("ip", str(e.get("remote")).split(":")[0], risk, title or "外联地址", "")
        # 注册表持久化
        blob = str(e.get("matched") or e.get("summary") or e.get("path") or "")
        if "persist" in str(e.get("etype") or "") or "持久化" in title or "HKCU\\Run" in blob or "HKLM\\Run" in blob:
            add("registry", blob[:200] or title, "malicious" if sev in ("critical", "high") else "suspicious", "持久化线索", "isolate_network")

    for t in security_logs[:20]:
        et = str(t.get("etype") or "")
        if et.startswith("persist") or "registry" in et:
            add("registry", str(t.get("summary") or t.get("key") or t.get("reg_key") or et)[:200], "suspicious", "安全日志持久化/注册表", "")
        if t.get("command_line") and re.search(r"powershell|mshta|wscript|cmd\.exe", str(t.get("command_line")), re.I):
            add("process", str(t.get("process_name") or "script-host"), "suspicious", "脚本类命令行", "")

    # 快照补充：可疑临时目录进程
    for p in (((pack.get("snapshots") or {}).get("process") or {}).get("items") or [])[:40]:
        path = str(p.get("path") or "")
        name = str(p.get("name") or "")
        if re.search(r"\\(temp|appdata\\local\\temp|users\\public)\\", path, re.I) and name.lower().endswith(".exe"):
            add("process", name, "suspicious", f"临时/公共目录进程 {path}", "kill_process", {"pid": p.get("pid"), "path": path})

    return out[:20]


def _agent_respond(
    entities: List[Dict],
    detect: Dict[str, Any],
    host: Dict[str, Any],
    investigate: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    dispositions: List[Dict[str, Any]] = []
    verdict = detect.get("verdict")
    notes = [
        "所有处置需人工审核后下发（Human-in-the-loop）",
        "优先止血，再做根因加固与加白复核",
    ]
    investigate = investigate or {}

    if verdict == "真实攻击":
        dispositions.append({
            "action": "isolate_network",
            "label": "网络隔离",
            "target": host.get("hostname") or host.get("agent_id") or "本机",
            "reason": "研判为真实攻击，建议先限制外联保留管理通道",
            "needs_approval": True,
            "priority": 1,
            "category": "emergency",
        })
    for e in entities:
        if e.get("risk") != "malicious":
            continue
        act = e.get("action") or ""
        if act == "kill_process" and e.get("pid"):
            dispositions.append({
                "action": "kill_process",
                "label": "结束进程",
                "target": f"{e.get('value')} (PID {e.get('pid')})",
                "reason": e.get("reason") or "恶意进程",
                "needs_approval": True,
                "priority": 2,
                "category": "emergency",
                "params": {"pid": e.get("pid"), "path": e.get("path") or ""},
            })
        elif act == "quarantine_file" and e.get("value"):
            dispositions.append({
                "action": "quarantine_file",
                "label": "隔离文件",
                "target": e.get("value"),
                "reason": e.get("reason") or "恶意文件",
                "needs_approval": True,
                "priority": 2,
                "category": "emergency",
                "params": {"path": e.get("value")},
            })

    # 去重 action+target
    uniq = []
    seen = set()
    for d in sorted(dispositions, key=lambda x: int(x.get("priority") or 9)):
        key = (d.get("action"), d.get("target"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)
    if not uniq and verdict != "信息不足":
        uniq.append({
            "action": "review",
            "label": "打开威胁视图复核",
            "target": host.get("hostname") or "",
            "reason": "证据不足以下发自动处置，建议人工打开进程树与匹配特征",
            "needs_approval": True,
            "priority": 9,
            "category": "review",
        })

    hardening = [
        {"type": "harden", "title": "核查启动项/计划任务/Run 键", "detail": "重点核对本机近 24h 持久化变更，清除未知自启动"},
        {"type": "harden", "title": "收紧脚本执行策略", "detail": "限制 PowerShell 编码执行与未签名脚本，开启 ScriptBlock 日志"},
        {"type": "intel", "title": "对照 IoC 做全网狩猎", "detail": f"对提取的 {len(investigate.get('iocs') or [])} 个 IoC 在其它终端检索"},
    ]
    if verdict == "疑似误报":
        hardening.insert(0, {
            "type": "allow",
            "title": "误报加白建议",
            "detail": "若确认为运维/安装行为，按规则 ID + 路径/哈希精准加白，避免整类放过",
        })
    if not (investigate.get("attack_timeline") or []):
        hardening.append({
            "type": "log",
            "title": "日志源补充建议",
            "detail": "建议确认 Winlog 安全/PowerShell/Sysmon 通道已启用，便于后续自动调查",
        })

    return {
        "summary": f"生成 {len(uniq)} 条应急处置 + {len(hardening)} 条加固建议，均需人工确认",
        "dispositions": uniq[:8],
        "hardening": hardening[:8],
        "notes": notes,
    }


def _agent_report(
    host: Dict[str, Any],
    detect: Dict[str, Any],
    investigate: Dict[str, Any],
    entities: List[Dict],
    respond: Dict[str, Any],
    skills: List[Dict[str, Any]],
) -> Dict[str, Any]:
    skill_names = [str(s.get("name") or s.get("id")) for s in skills[:4]]
    abstract = (
        f"【{detect.get('verdict')}】主机 {host.get('hostname') or host.get('agent_id')} "
        f"风险 {detect.get('risk_level')}（{detect.get('risk_score')}/100）。"
        f"{investigate.get('impact') or ''}"
    )
    return {
        "abstract": abstract[:400],
        "skills": skill_names,
        "sections": ["事件定性", "攻击链路", "影响面", "根因", "IoC", "处置建议"],
    }


def _entity_analysis(
    etype: str,
    value: str,
    risk: str,
    reason: str,
    action: str,
    extra: Dict[str, Any],
) -> Dict[str, Any]:
    """对齐实体研判 Agent：基本信息 / 研判过程 / 结论 / 处置建议。"""
    basics = {
        "type": etype,
        "value": value[:260],
        "pid": extra.get("pid"),
        "path": extra.get("path") or "",
        "command_line": str(extra.get("command_line") or "")[:200],
    }
    process = [
        f"收集实体类型={etype}，关联告警线索：{reason or '无'}",
        f"结合严重度线索判定风险为 {risk}",
    ]
    if extra.get("pid"):
        process.append(f"观察到 PID={extra.get('pid')}，可映射到结束进程剧本")
    if etype in ("file", "registry") and value:
        process.append("对象具备持久化/落地特征，优先考虑隔离或人工核销")
    conclusion = {
        "malicious": "判定为恶意实体，建议进入应急处置",
        "suspicious": "判定为可疑实体，建议人工复核后再处置",
        "unknown": "信息不足，暂不自动处置",
    }.get(risk, "待复核")
    advice = "暂无自动剧本，建议打开威胁视图"
    if action == "kill_process":
        advice = "推荐剧本：结束进程（需人工确认）"
    elif action == "quarantine_file":
        advice = "推荐剧本：隔离文件（需人工确认）"
    elif action == "isolate_network":
        advice = "推荐剧本：主机网络隔离（需人工确认）"
    return {
        "basic": basics,
        "process": process,
        "conclusion": conclusion,
        "advice": advice,
    }


def _annotate_threat_events(
    events: List[Dict[str, Any]],
    *,
    detect: Dict[str, Any],
    investigate: Dict[str, Any],
    entities: List[Dict[str, Any]],
    log_rule_hits: Optional[List[Dict[str, Any]]] = None,
    skills: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """把原始 EDR 告警转成「AI 研判事件」：每条带结论 / 置信度 / 推理 / 建议。"""
    attck = investigate.get("attck") or []
    chain = investigate.get("attack_chain") or []
    hits = log_rule_hits or []
    skill_names = [str(s.get("name") or s.get("id")) for s in (skills or [])[:4]]
    host_verdict = detect.get("verdict") or "信息不足"
    out: List[Dict[str, Any]] = []

    hot_attack = (
        "powershell", "encoded", "empire", "cobalt", "beacon", "mimikatz", "lsass",
        "persist", "持久化", "lolbin", "mshta", "wscript", "inject", "spoof",
        "外联", "c2", "schtasks", "regsvcs", "rundll32", "frombase64",
    )
    soft_noise = ("sca", "合规", "guest", "策略检查", "基线", "inventory", "asset")

    for e in events[:40]:
        if not isinstance(e, dict):
            continue
        title = str(e.get("title") or "")
        sev = str(e.get("severity") or "").lower()
        blob = " ".join(
            str(e.get(k) or "")
            for k in ("title", "matched", "summary", "path", "command_line", "process_name", "etype")
        ).lower()

        linked_attck = []
        for a in attck:
            tid = str(a.get("id") or "")
            stage = str(a.get("stage") or "")
            stage_kw = {
                "执行": ("powershell", "script", "lolbin", "mshta", "cmd"),
                "持久化": ("persist", "startup", "schtask", "run", "计划"),
                "命令与控制": ("network", "dns", "beacon", "外联", "c2"),
                "凭证访问": ("lsass", "credential", "password", "mimikatz"),
                "防御绕过": ("inject", "spoof", "unsigned", "bypass"),
            }
            kws = stage_kw.get(stage) or ()
            if any(k in blob for k in kws) or tid.lower() in blob:
                linked_attck.append(f"{tid} {stage}".strip())

        linked_entities = []
        for ent in entities:
            val = str(ent.get("value") or "").lower()
            if not val or len(val) < 3:
                continue
            if val in blob or (ent.get("type") == "process" and val in str(e.get("process_name") or "").lower()):
                linked_entities.append({
                    "type": ent.get("type"),
                    "value": ent.get("value"),
                    "risk": ent.get("risk"),
                })
            if len(linked_entities) >= 4:
                break

        related_rules = []
        for h in hits:
            ev = str(h.get("evidence") or "").lower()
            rt = str(h.get("rule_title") or "")
            if not rt:
                continue
            if any(tok in ev for tok in (str(e.get("process_name") or "").lower(), str(e.get("etype") or "").lower()) if tok):
                related_rules.append(rt)
            elif any(tok in blob for tok in re.findall(r"[a-z0-9]{5,}", rt.lower())[:4]):
                related_rules.append(rt)
            if len(related_rules) >= 3:
                break

        chain_hit = next(
            (c for c in chain if any(
                x and x.lower() in blob
                for x in (str(c.get("evidence") or "")[:40], str(c.get("etype") or ""))
            )),
            None,
        )

        attack_hits = [k for k in hot_attack if k in blob]
        is_noise = any(k in blob for k in soft_noise) and not attack_hits

        # —— AI 单条结论（不是原样复述 EDR 级别）——
        reasoning: List[str] = []
        if is_noise:
            conclusion = "疑似误报/合规噪音"
            confidence = 62
            ai_role = "上下文"
            recommendation = "建议对照 SCA/基线策略确认，勿直接隔离主机"
            reasoning.append(f"标题「{title[:80]}」更像合规/策略检查，缺少入侵行为关键词")
            reasoning.append("未命中 PowerShell 编码、持久化、C2、注入等攻击特征")
        elif sev in ("critical", "high") or len(attack_hits) >= 2:
            conclusion = "支撑真实攻击"
            confidence = min(95, 70 + len(attack_hits) * 5 + (8 if sev in ("critical", "high") else 0))
            ai_role = "关键证据"
            recommendation = "纳入攻击链关键节点；优先处置关联进程/文件，必要时隔离主机"
            reasoning.append(f"告警级别 {sev or '—'}，命中攻击特征：{('、'.join(attack_hits[:4]) if attack_hits else '高危等级')}")
            if chain_hit:
                reasoning.append(f"对齐攻击链阶段「{chain_hit.get('stage')} / {chain_hit.get('technique')}」")
        elif sev == "medium" or attack_hits:
            conclusion = "可疑需复核"
            confidence = 55 + min(20, len(attack_hits) * 6)
            ai_role = "佐证"
            recommendation = "结合进程树与日志取证复核，暂不单独定性为真实攻击"
            reasoning.append(f"存在部分可疑信号（{('、'.join(attack_hits[:3]) if attack_hits else '中危告警')}），证据链不完整")
        else:
            conclusion = "信息不足"
            confidence = 35
            ai_role = "上下文"
            recommendation = "保留为环境上下文，等待更多日志/关联告警"
            reasoning.append("证据偏弱，不足以单独支撑主机级判决")

        if linked_entities:
            reasoning.append(
                "关联实体：" + "；".join(f"{x.get('type')}:{x.get('value')}" for x in linked_entities[:3])
            )
        if related_rules:
            reasoning.append(f"对照日志规则：{related_rules[0]}")
        if skill_names and ai_role == "关键证据":
            reasoning.append(f"参考 Skill：{skill_names[0]}")

        note = (
            f"【AI 结论】{conclusion}（置信 {confidence}%）。"
            f"对本机总判「{host_verdict}」的贡献：{ai_role}。"
            f"{recommendation}"
        )

        item = dict(e)
        item["ai"] = {
            "analyzed": True,
            "conclusion": conclusion,
            "confidence": confidence,
            "role": ai_role,
            "note": note[:320],
            "reasoning": reasoning[:6],
            "recommendation": recommendation,
            "verdict_support": host_verdict,
            "attck": linked_attck[:4],
            "entities": linked_entities[:4],
            "rules": related_rules[:3],
            "skills": skill_names[:3],
            "in_attack_chain": bool(chain_hit),
            "chain_stage": (chain_hit or {}).get("stage") or "",
            "signals": attack_hits[:6],
        }
        out.append(item)

    # 关键证据靠前，方便「AI 研判事件」列表阅读
    out.sort(key=lambda x: (
        0 if (x.get("ai") or {}).get("role") == "关键证据" else 1,
        0 if (x.get("ai") or {}).get("role") == "佐证" else 1,
        -int((x.get("ai") or {}).get("confidence") or 0),
    ))
    return out


def _build_alert_meta(
    host: Dict[str, Any],
    detect: Dict[str, Any],
    investigate: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """对齐调查报告「告警基本信息」字段。"""
    counts = detect.get("counts") or {}
    attck = investigate.get("attck") or []
    return {
        "source": "EDR Agent / 本地 Agentic SOC",
        "analysis_rule": "Agent Team 聚合研判（威胁事件 + 安全日志 + 快照）",
        "attck_stages": [f"{a.get('id')} {a.get('stage')}" for a in attck[:8]],
        "affected_assets": 1 if host else 0,
        "related_alerts": len(events),
        "hostname": host.get("hostname") or "",
        "agent_id": host.get("agent_id") or "",
        "ip": host.get("ip") or host.get("last_ip") or "",
        "severity_high": int(counts.get("high") or 0) + int(counts.get("critical") or 0),
        "verdict": detect.get("verdict") or "",
        "risk_level": detect.get("risk_level") or "",
        "risk_score": detect.get("risk_score") or 0,
    }


def _build_thinking_chain(
    host: Dict[str, Any],
    detect: Dict[str, Any],
    investigate: Dict[str, Any],
    entities: List[Dict[str, Any]],
    respond: Dict[str, Any],
    skills: List[Dict[str, Any]],
    *,
    threat_events: Optional[List[Dict[str, Any]]] = None,
    security_logs: Optional[List[Dict[str, Any]]] = None,
    log_rule_hits: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """ReAct 思维链：每步挂具体 AI 研判证据，避免空模板。"""
    host_name = host.get("hostname") or host.get("agent_id") or "目标主机"
    skill_names = [str(s.get("name") or s.get("id")) for s in skills[:4]]
    malicious = [e for e in entities if e.get("risk") == "malicious"]
    suspicious = [e for e in entities if e.get("risk") == "suspicious"]
    chain = investigate.get("attack_chain") or []
    attck = investigate.get("attck") or []
    tevs = threat_events or []
    logs = security_logs or []
    hits = log_rule_hits or []

    key_tevs = [t for t in tevs if (t.get("ai") or {}).get("role") == "关键证据"]
    soft_tevs = [t for t in tevs if (t.get("ai") or {}).get("role") == "佐证"]
    noise_tevs = [t for t in tevs if "误报" in str((t.get("ai") or {}).get("conclusion") or "")]

    def _ev_line(t: Dict[str, Any]) -> str:
        ai = t.get("ai") or {}
        return (
            f"{t.get('title') or '告警'} → {ai.get('conclusion') or '—'}"
            f"（置信 {ai.get('confidence', '—')}%）"
        )

    evidence_perceive = [
        *[_ev_line(t) for t in (key_tevs or tevs)[:4]],
        *[
            f"日志[{l.get('etype') or l.get('category') or 'log'}] {(l.get('summary') or l.get('command_line') or '')[:90]}"
            for l in logs[:3]
        ],
        *[f"规则命中：{h.get('rule_title')}" for h in hits[:3]],
    ] or [f"{host_name} 暂无足够告警/日志样本"]

    evidence_chain = [
        f"{c.get('stage')}/{c.get('technique')}：{str(c.get('evidence') or '')[:100]}"
        for c in chain[:5]
    ] or ["未形成清晰多阶段攻击链"]
    evidence_entity = [
        f"[{e.get('risk')}] {e.get('type')}:{e.get('value')} — {e.get('reason') or ''}"[:140]
        for e in (malicious or suspicious or entities)[:5]
    ] or ["未抽出可处置实体"]
    evidence_plan = [
        *[_ev_line(t) for t in key_tevs[:3]],
        *[f"处置：{d.get('label')} → {d.get('target')}" for d in (respond.get("dispositions") or [])[:3]],
        *[f"加固：{h.get('title')}" for h in (respond.get("hardening") or [])[:2]],
    ]

    steps = [
        {
            "id": "perceive",
            "phase": "感知环境",
            "title": "汇聚主机告警并做 AI 初筛",
            "clue": (
                f"{host_name}：威胁 {len(tevs)} / 关键证据 {len(key_tevs)} / 佐证 {len(soft_tevs)}"
                f" / 合规噪音 {len(noise_tevs)}；安全日志 {len(logs)}；规则命中 {len(hits)}"
            ),
            "hypothesis": "先区分「攻击信号」与「合规噪音」，避免 SCA/基线类告警抬高风险",
            "reasoning": [
                f"Skill：{('、'.join(skill_names) if skill_names else '通用研判')}",
                f"对每条威胁生成 AI 结论（支撑真实攻击 / 可疑需复核 / 疑似误报）",
                f"代表研判：{('；'.join(_ev_line(t) for t in (key_tevs or tevs)[:2]) if tevs else '暂无威胁')}",
            ],
            "observation": detect.get("summary") or "",
            "evidence": evidence_perceive[:8],
            "agent": "Team Leader / 威胁检测 Agent",
        },
        {
            "id": "reason_chain",
            "phase": "推理分析",
            "title": "用 AI 结论还原攻击链与 ATT&CK",
            "clue": f"攻击链 {len(chain)} 节点 · ATT&CK {len(attck)}："
                    + "、".join(f"{a.get('id')}" for a in attck[:5]),
            "hypothesis": "仅关键证据/佐证进入攻击链；合规噪音不参与阶段推断",
            "reasoning": [
                f"手段类型：{'、'.join(investigate.get('vectors') or []) or '待补充'}",
                "按执行→持久化→C2 等顺序排列证据",
                f"关键证据条数 {len(key_tevs)}，若≥2 且跨阶段则抬升「真实攻击」置信",
            ],
            "observation": "；".join(
                f"{c.get('stage')}:{str(c.get('evidence') or '')[:60]}" for c in chain[:4]
            ) or "链路证据不足",
            "evidence": evidence_chain[:6],
            "agent": "事件调查 Agent",
        },
        {
            "id": "reason_entity",
            "phase": "推理分析",
            "title": "实体风险研判（AI）",
            "clue": f"恶意 {len(malicious)} / 可疑 {len(suspicious)} / 总计 {len(entities)}",
            "hypothesis": "与「支撑真实攻击」告警绑定的进程/文件优先作为处置锚点",
            "reasoning": [
                "从 AI 关键证据抽取 process/file/ip/registry",
                "输出基本信息→研判过程→结论→建议",
                f"优先实体：{('；'.join(str(e.get('value') or '')[:40] for e in (malicious or suspicious)[:3]) or '无')}",
            ],
            "observation": "；".join(
                f"{e.get('type')}:{str(e.get('value') or '')[:40]}" for e in (malicious or suspicious)[:4]
            ) or "未抽出强恶意实体",
            "evidence": evidence_entity[:6],
            "agent": "实体研判 Agent",
        },
        {
            "id": "plan",
            "phase": "规划行动",
            "title": "形成主机级 AI 结论与处置计划",
            "clue": f"主机结论={detect.get('verdict')}，风险={detect.get('risk_level')}（{detect.get('risk_score')}/100）",
            "hypothesis": investigate.get("root_cause") or "根因待定",
            "reasoning": [
                f"汇总：关键证据 {len(key_tevs)} · 可疑 {len(soft_tevs)} · 噪音 {len(noise_tevs)}",
                "应急：隔离 / 杀进程 / 隔离文件（需人工审核）",
                "并行：加固、加白、日志补充、IoC 狩猎",
            ],
            "observation": respond.get("summary") or "",
            "evidence": evidence_plan[:8],
            "agent": "响应协同 Agent",
        },
        {
            "id": "act",
            "phase": "执行操作",
            "title": "输出 AI 报告并等待人工审核",
            "clue": f"处置 {(respond.get('dispositions') or []) and len(respond.get('dispositions') or [])} 条，"
                    f"加固 {len(respond.get('hardening') or [])} 条；本地模型可再精炼报告正文",
            "hypothesis": "关键决策必须人工确认，防止误隔离/误杀",
            "reasoning": [
                "报告 Agent 汇总：定性、攻击链、实体、根因、IoC、逐条 AI 威胁结论",
                "前端「AI 研判事件 / 处置」页签供审核下发",
                "Human-in-the-loop：不自动封禁",
            ],
            "observation": "等待分析员确认后下发",
            "evidence": [
                *[f"待审：{d.get('label')} → {d.get('target')}" for d in (respond.get("dispositions") or [])[:4]],
                *[_ev_line(t) for t in key_tevs[:2]],
            ] or ["无自动处置项，仅报告复核"],
            "agent": "安全报告 Agent / 事件处置 Agent",
        },
        {
            "id": "conclude",
            "phase": "结论总结",
            "title": f"最终研判：{detect.get('verdict')}",
            "clue": investigate.get("impact") or "",
            "hypothesis": detect.get("verdict") or "信息不足",
            "reasoning": [
                f"根因：{investigate.get('root_cause') or '—'}",
                f"影响面：{investigate.get('impact') or '—'}",
                f"AI 已标注威胁 {len(tevs)} 条（关键 {len(key_tevs)} / 噪音 {len(noise_tevs)}）",
            ],
            "observation": detect.get("summary") or "",
            "evidence": [
                f"主机结论：{detect.get('verdict')}（{detect.get('risk_level')}/{detect.get('risk_score')}）",
                *[_ev_line(t) for t in (key_tevs or tevs)[:4]],
                f"根因：{(investigate.get('root_cause') or '—')[:120]}",
            ],
            "agent": "事件调查 Agent",
        },
    ]
    return steps


def _render_markdown(
    *,
    host: Dict[str, Any],
    verdict: str,
    risk_level: str,
    risk_score: int,
    detect: Dict[str, Any],
    investigate: Dict[str, Any],
    entities: List[Dict],
    respond: Dict[str, Any],
    report: Dict[str, Any],
    alert_meta: Optional[Dict[str, Any]] = None,
    security_logs: Optional[List[Dict]] = None,
    log_rule_hits: Optional[List[Dict]] = None,
    log_rule_meta: Optional[Dict[str, Any]] = None,
    skills: Optional[List[Dict]] = None,
) -> str:
    meta = alert_meta or {}
    lines = [
        "## 事件定性与摘要",
        f"**研判结论：{verdict}** · 风险 {risk_level}（{risk_score}/100）",
        f"主机：`{host.get('hostname') or host.get('agent_id')}` · IP `{host.get('ip') or host.get('last_ip') or '—'}`",
        f"来源：{meta.get('source') or 'EDR'} · 关联告警 {meta.get('related_alerts') or 0} · "
        f"分析规则：{meta.get('analysis_rule') or 'Agent Team'}",
        "",
        report.get("abstract") or detect.get("summary") or "",
        "",
        "## 攻击链路与时间线",
    ]
    chain = investigate.get("attack_chain") or []
    if chain:
        for i, c in enumerate(chain[:8], 1):
            lines.append(f"{i}. **{c.get('stage')}**（{c.get('technique')}）：{c.get('evidence')}")
    else:
        lines.append("未见清晰多阶段链路，见关键告警列表。")

    attck = investigate.get("attck") or []
    if attck:
        lines.append("")
        lines.append("ATT&CK：" + "、".join(f"{a.get('id')} {a.get('stage')}" for a in attck[:8]))

    tl = investigate.get("attack_timeline") or []
    if tl:
        lines += ["", "### 攻击时间线（摘录）"]
        for row in tl[:8]:
            lines.append(f"- `{row.get('ts') or '—'}` [{row.get('kind')}] {row.get('title')}")

    lines += ["", "## 影响面与恶意实体"]
    lines.append(investigate.get("impact") or "")
    for e in entities[:8]:
        lines.append(f"- [{e.get('type')}/{e.get('risk')}] `{e.get('value')}` — {e.get('reason')}")

    lines += ["", "## 根因分析", investigate.get("root_cause") or "待复核"]

    iocs = investigate.get("iocs") or []
    lines += ["", "## IoC 证据指标"]
    if iocs:
        for x in iocs[:12]:
            lines.append(f"- {x.get('type')}: `{x.get('value')}`")
    else:
        lines.append("未见可提取 IoC，或证据中未包含可解析指标。")

    lines += ["", "## 处置建议（需人工审核）"]
    for d in (respond.get("dispositions") or [])[:8]:
        lines.append(f"- **{d.get('label')}** → {d.get('target')}：{d.get('reason')}")
    harden = respond.get("hardening") or []
    if harden:
        lines += ["", "## 体系化加固建议"]
        for h in harden[:8]:
            lines.append(f"- **{h.get('title')}**：{h.get('detail')}")
    for n in (respond.get("notes") or []):
        lines.append(f"- {n}")

    logs = security_logs or []
    hits = log_rule_hits or []
    meta_lr = log_rule_meta or {}
    lines += ["", "## 日志研判"]
    lines.append(
        f"重点安全日志 {len(logs)} 条；规则库索引 {meta_lr.get('rules_indexed') or 0}，"
        f"命中 {len(hits)}（来源 log_rules / logrules）。"
    )
    if logs:
        for t in logs[:6]:
            lines.append(
                f"- `{t.get('ts') or '—'}` [{t.get('etype') or t.get('category') or 'log'}] "
                f"{(t.get('summary') or t.get('command_line') or '')[:120]}"
            )
    else:
        lines.append("- 暂无重点安全日志样本（请确认终端已上报 Winlog / 持久化 / 脚本类事件）。")
    if hits:
        lines.append("")
        lines.append("### 日志规则命中")
        for h in hits[:8]:
            lines.append(
                f"- **{h.get('rule_title') or '—'}**（{h.get('source') or h.get('match') or 'rule'}）"
                f"：{(h.get('evidence') or '')[:100]}"
            )

    used = skills or []
    if used:
        lines += ["", "## 匹配 Skill"]
        for s in used[:8]:
            why = "；".join((s.get("why") or [])[:2])
            lines.append(
                f"- **{s.get('name') or s.get('id')}**"
                + (f" · 分值 {s.get('score')}" if s.get("score") is not None else "")
                + (f" · {why}" if why else "")
            )

    lines += [
        "",
        "## Agent Team 协同说明",
        "本报告由 Team Leader 按 ReAct（感知→推理→规划→执行→观察）调度 "
        "威胁检测 / 事件调查 / 实体研判 / 响应协同 / 安全报告 Agent 生成；"
        "关键处置默认人工确认，对齐阿里云 Agentic SOC 工作流。",
    ]
    return "\n".join(lines)


def _looks_active_intrusion(e: Dict[str, Any]) -> bool:
    t = str(e.get("title") or "") + " " + str(e.get("matched") or "") + " " + str(e.get("etype") or "")
    keys = ("持久化", "LOLBin", "编码", "多阶段", "计划任务", "Cobalt", "注入", "凭证", "persist", "beacon")
    return any(k.lower() in t.lower() for k in keys)


def _extract_iocs(rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for row in rows:
        blob = " ".join(str(row.get(k) or "") for k in ("matched", "summary", "title", "command_line", "path", "remote", "value"))
        for m in _IOC_SHA.findall(blob):
            key = ("sha256", m.lower())
            if key not in seen:
                seen.add(key)
                found.append({"type": "sha256", "value": m.lower()})
        for m in _IOC_IP.findall(blob):
            if m.startswith(("127.", "0.", "255.", "169.254.")):
                continue
            if m.startswith(("10.", "192.168.", "172.")):
                # 保留外联公网优先；内网也记但标记
                pass
            key = ("ip", m)
            if key not in seen:
                seen.add(key)
                found.append({"type": "ip", "value": m})
        for m in _IOC_DOM.findall(blob):
            low = m.lower()
            if low.endswith((".microsoft.com", ".windows.com", ".office.com")):
                continue
            key = ("domain", low)
            if key not in seen:
                seen.add(key)
                found.append({"type": "domain", "value": low})
        for m in _IOC_PATH.findall(blob):
            key = ("path", m.lower())
            if key not in seen:
                seen.add(key)
                found.append({"type": "path", "value": m})
        if len(found) >= 24:
            break
    return found


def _first_line(text: str) -> str:
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            return s[:300]
    return ""
