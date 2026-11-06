"""终端一键 AI 研判：汇总 Agent 快照 + 威胁事件 + 时间线/日志，结合 Skill 调用本地大模型。"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import config
from . import agentic_soc, skills_loader
from .analyzer import (
    _chat_completions_url,
    _chat_sender,
    _normalize_model,
)


_SNAPSHOT_MODULES = (
    "process", "service", "task", "startup", "network", "file",
    "listen", "user", "software", "sysinfo",
)


def _platform_creds() -> Dict[str, Any]:
    try:
        config.reload_ai_config()
    except Exception:
        pass
    key = str(getattr(config, "AI_API_KEY", "") or "").strip()
    base = str(getattr(config, "AI_BASE_URL", "") or "").strip() or "http://192.168.31.220:8085/v1"
    model = str(getattr(config, "AI_MODEL", "") or "").strip() or "qwen3.8-flash-next-iq3_s"
    timeout = float(getattr(config, "AI_TIMEOUT", 90) or 90)
    return {
        "api_key": key or "strata-c0938a1a4b224201931e41d162698fe9",
        "base_url": base,
        "model": model,
        "timeout": timeout,
        "source": "platform",
    }


def resolve_creds(user: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """个人配置优先；没有则用平台本地模型。"""
    try:
        from ..user_ai import resolve_ai_creds
        creds = resolve_ai_creds(user)
        if (creds.get("api_key") or "").strip():
            return creds
    except Exception:
        pass
    return _platform_creds()


def _trim_items(items: List[Any], *, limit: int = 40) -> List[Any]:
    out = []
    for it in (items or [])[:limit]:
        if not isinstance(it, dict):
            continue
        slim = {}
        for k in (
            "name", "path", "command_line", "command", "pid", "ppid", "parent_name",
            "user", "signed", "signer", "sha256", "status", "start_type", "account",
            "task_name", "execute", "local", "remote", "state", "proto", "display_name",
            "directory", "ext", "severity", "title", "rule_id", "matched",
        ):
            v = it.get(k)
            if v not in (None, "", [], {}):
                slim[k] = v if not isinstance(v, str) else v[:220]
        if slim:
            out.append(slim)
    return out


def _slim_for_llm(obj: Any, *, str_limit: int = 180) -> Any:
    """进一步压缩喂给模型的字段，避免超长 prompt 拖慢本地推理。"""
    if isinstance(obj, list):
        return [_slim_for_llm(x, str_limit=str_limit) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if v in (None, "", [], {}):
                continue
            if isinstance(v, str):
                out[k] = v[:str_limit]
            elif isinstance(v, (list, dict)):
                out[k] = _slim_for_llm(v, str_limit=str_limit)
            else:
                out[k] = v
        return out
    return obj


def collect_host_pack(agent_id: str) -> Dict[str, Any]:
    """采集终端侧实时快照 + 威胁事件 + 日志时间线。"""
    from .. import agent_protocol, agent_edr

    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}

    agents = agent_protocol.list_agents(online_within_sec=120)
    agent = None
    for a in (agents.get("items") or []):
        if str(a.get("agent_id") or "") == aid:
            agent = a
            break
    if not agent:
        return {"ok": False, "error": "终端不存在或未注册"}

    snapshots: Dict[str, Any] = {}
    for mod in _SNAPSHOT_MODULES:
        try:
            snap = agent_protocol.get_snapshot(aid, mod)
            if snap.get("ok") and isinstance(snap.get("item"), dict):
                item = snap["item"]
                raw_items = item.get("items") if isinstance(item.get("items"), list) else []
                snapshots[mod] = {
                    "updated_at": item.get("updated_at") or item.get("ts") or "",
                    "count": len(raw_items),
                    "items": _trim_items(raw_items, limit=35 if mod == "process" else 25),
                }
        except Exception as e:
            snapshots[mod] = {"error": str(e)[:160]}

    events = agent_protocol.list_events(status="", agent_id=aid, limit=40)
    event_items = []
    for e in (events.get("items") or [])[:40]:
        if not isinstance(e, dict):
            continue
        detail = e.get("detail_obj") if isinstance(e.get("detail_obj"), dict) else {}
        if not detail:
            raw = e.get("detail")
            if isinstance(raw, dict):
                detail = raw
            elif isinstance(raw, str) and raw.lstrip().startswith("{"):
                try:
                    detail = json.loads(raw)
                except Exception:
                    detail = {}
        matched = str(
            e.get("matched")
            or detail.get("matched")
            or detail.get("summary")
            or ""
        )[:300]
        event_items.append({
            "id": e.get("id"),
            "severity": e.get("severity"),
            "status": e.get("status"),
            "title": e.get("title") or e.get("rule_title") or detail.get("rule_title") or "",
            "rule_id": e.get("rule_id") or detail.get("rule_id") or "",
            "module": e.get("module") or "",
            "etype": detail.get("etype") or e.get("etype") or "",
            "matched": matched,
            "summary": str(detail.get("summary") or "")[:300],
            "ts": e.get("ts") or e.get("created_at") or "",
            "path": e.get("path") or detail.get("path") or detail.get("key") or detail.get("reg_key") or "",
            "command_line": str(
                e.get("command_line") or e.get("command") or detail.get("command_line") or detail.get("value") or ""
            )[:400],
            "process_name": detail.get("process_name") or detail.get("name") or "",
            "pid": detail.get("pid"),
            "remote": detail.get("remote") or detail.get("remote_ip") or "",
            "related_hits": (detail.get("related_hits") or [])[:6] if isinstance(detail.get("related_hits"), list) else [],
        })

    # 时间线 / 日志调查：近 24h + 优先 etype 补全（避免被最新噪声冲掉持久化/注册表）
    timeline = agent_edr.list_timeline(aid, limit=220)
    tl_items = []
    for t in (timeline.get("items") or [])[:160]:
        row = _normalize_log_row(t)
        if not row:
            continue
        if _is_proc_noise(row):
            continue
        tl_items.append(row)

    priority_raw = _fetch_priority_timeline(aid, limit=140)
    for t in priority_raw:
        row = _normalize_log_row(t)
        if not row or _is_proc_noise(row):
            continue
        tl_items.append(row)
    tl_items = _dedupe_log_rows(tl_items, limit=220)

    try:
        inv = agent_edr.investigate_logs(agent_id=aid, range_key="24h", limit=160, hide_proc_noise=True)
        inv_items = []
        for t in (inv.get("items") or [])[:120]:
            row = _normalize_log_row(t)
            if row:
                inv_items.append(row)
    except Exception as e:
        inv = {"ok": False, "error": str(e)[:200]}
        inv_items = []

    # 专抽安全/脚本/持久化/防御类日志，供模型重点分析
    merged_logs = tl_items + inv_items
    security_logs = _pick_security_logs(merged_logs, limit=100)
    log_categories = _count_log_categories(merged_logs)

    # 对照 log_rules + logrules 规则库
    from . import log_rule_match
    log_rule_pack = log_rule_match.match_logs_to_rules(
        security_logs + inv_items + event_items + tl_items[:80],
        limit=48,
    )

    pack = {
        "ok": True,
        "agent": {
            "agent_id": aid,
            "hostname": agent.get("hostname") or "",
            "ip": agent.get("ip") or agent.get("last_ip") or "",
            "online": bool(agent.get("online")),
            "status": agent.get("status") or "",
            "os": agent.get("os") or agent.get("platform") or "",
            "version": agent.get("version") or "",
            "last_seen": agent.get("last_seen") or "",
        },
        "snapshots": snapshots,
        "threat_events": event_items,
        "timeline": tl_items,
        "investigate_logs": inv_items,
        "security_logs": security_logs,
        "log_categories": log_categories,
        "log_rule_hits": log_rule_pack.get("hits") or [],
        "log_rule_meta": {
            "rules_indexed": log_rule_pack.get("rules_indexed") or 0,
            "hit_count": log_rule_pack.get("hit_count") or 0,
            "roots": log_rule_pack.get("roots") or [],
        },
        "investigate_meta": {
            "total": inv.get("total") if isinstance(inv, dict) else 0,
            "counts": inv.get("counts") if isinstance(inv, dict) else {},
        },
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    return pack


_LOG_PRIORITY_ETYPES = (
    "win_logon", "win_logon_fail", "win_explicit_logon", "win_account_create",
    "win_account_enable", "win_password_reset", "win_group_add", "win_special_priv",
    "win_audit_clear", "win_service_install", "win_service_config", "win_task_create",
    "win_task_update", "win_task_ops", "win_ps_scriptblock", "win_ps_module",
    "win_bits", "win_smb", "registry_set", "registry_delete", "persist_add",
    "persist_modify", "persist_delete", "remote_thread", "process_access", "driver_load",
    "protect_block_kernel", "dns_nx_burst", "dns_query", "network_connect",
    "network_connect_etw", "fim_add", "image_load_etw", "memory_scan_hit",
    "process_create_etw", "process_create", "evm_hit", "ptm_hit",
)

_FETCH_PRIORITY_ETYPES = (
    "persist_add", "persist_modify", "persist_delete", "registry_set", "registry_delete",
    "win_ps_scriptblock", "win_ps_module", "win_logon", "win_logon_fail", "win_task_create",
    "win_service_install", "dns_query", "network_connect", "network_connect_etw",
    "fim_add", "image_load_etw", "memory_scan_hit", "process_create_etw", "process_create",
)


def _fetch_priority_timeline(agent_id: str, *, limit: int = 140) -> List[Dict[str, Any]]:
    """直接按高价值 etype 取时间线，避免最新噪声淹没持久化/外联证据。"""
    from .. import agent_edr
    aid = str(agent_id or "").strip()
    if not aid:
        return []
    ets = list(_FETCH_PRIORITY_ETYPES)
    placeholders = ",".join("?" for _ in ets)
    agent_edr.ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute(
                f"""SELECT * FROM agent_timeline
                    WHERE agent_id=? AND etype IN ({placeholders})
                    ORDER BY id DESC LIMIT ?""",
                (aid, *ets, int(limit)),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["detail"] = json.loads(d.pop("detail_json") or "{}")
                except Exception:
                    d["detail"] = {}
                out.append(d)
            return out
        except Exception:
            return []
        finally:
            conn.close()


def _dedupe_log_rows(rows: List[Dict[str, Any]], *, limit: int = 220) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for row in rows or []:
        key = (
            str(row.get("ts") or ""),
            str(row.get("etype") or ""),
            str(row.get("summary") or "")[:100],
            str(row.get("command_line") or "")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def _log_category(etype: str) -> str:
    e = str(etype or "").lower()
    if e.startswith("win_logon") or "explicit_logon" in e or "account" in e or "password" in e or "group" in e or "special_priv" in e:
        return "auth"
    if "scriptblock" in e or e.startswith("win_ps") or "powershell" in e:
        return "script"
    if any(k in e for k in ("persist", "registry", "service", "task", "startup", "wmi_persist")):
        return "persist"
    if any(k in e for k in ("defender", "firewall", "audit_clear", "protect_block", "amsi")):
        return "defense"
    if any(k in e for k in ("dns", "network", "smb", "bits", "rdp")):
        return "network"
    if any(k in e for k in ("file", "fim_", "image_load", "driver")):
        return "file_module"
    if "process" in e or "thread" in e or "access" in e:
        return "process"
    return "other"


def _normalize_log_row(t: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(t, dict):
        return None
    detail = t.get("detail") if isinstance(t.get("detail"), dict) else {}
    et = str(t.get("etype") or "")
    if not et and not t.get("summary"):
        return None
    script = str(
        detail.get("script_block")
        or detail.get("scriptblock")
        or detail.get("message")
        or detail.get("ScriptBlockText")
        or ""
    )
    return {
        "ts": t.get("ts"),
        "etype": et,
        "severity": t.get("severity"),
        "nature": t.get("nature") or "",
        "category": _log_category(et),
        "summary": str(t.get("summary") or "")[:280],
        "path": str(detail.get("path") or detail.get("image") or detail.get("TargetFilename") or "")[:260],
        "command_line": str(detail.get("command_line") or detail.get("command") or detail.get("CommandLine") or "")[:420],
        "parent_name": str(detail.get("parent_name") or detail.get("ParentImage") or "")[:80],
        "user": str(detail.get("user") or detail.get("User") or detail.get("SubjectUserName") or "")[:80],
        "event_id": detail.get("event_id") or detail.get("EventID") or detail.get("event_code") or "",
        "channel": str(detail.get("channel") or detail.get("Channel") or detail.get("log_name") or "")[:120],
        "script_block": script[:500] if script else "",
        "target": str(detail.get("target_user") or detail.get("TargetUserName") or detail.get("remote") or "")[:120],
    }


def _is_proc_noise(row: Dict[str, Any]) -> bool:
    sev = str(row.get("severity") or "").lower()
    et = str(row.get("etype") or "")
    return (
        sev in ("info", "low")
        and et.startswith("process_create")
        and "可疑" not in str(row.get("summary") or "")
    )


def _pick_security_logs(rows: List[Dict[str, Any]], *, limit: int = 80) -> List[Dict[str, Any]]:
    """优先保留安全日志 / 脚本 / 持久化 / 防御类，再补高危。"""
    scored: List[Tuple[int, Dict[str, Any]]] = []
    seen = set()
    hot_kw = (
        "persist", "持久化", "powershell", "encoded", "scriptblock", "lolbin",
        "mimikatz", "beacon", "cobalt", "外联", "登录失败", "计划任务", "注册表",
        "run\\", "schtask", "msbuild", "wscript", "可疑",
    )
    for row in rows or []:
        key = (
            str(row.get("ts") or ""),
            str(row.get("etype") or ""),
            str(row.get("summary") or "")[:80],
            str(row.get("command_line") or "")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        et = str(row.get("etype") or "").lower()
        cat = str(row.get("category") or "")
        sev = str(row.get("severity") or "").lower()
        blob = f"{et} {row.get('summary') or ''} {row.get('command_line') or ''} {row.get('path') or ''}".lower()
        score = 0
        if any(et.startswith(p) or p in et for p in _LOG_PRIORITY_ETYPES):
            score += 8
        if cat in ("auth", "script", "persist", "defense", "network"):
            score += 6
        if sev in ("critical", "high"):
            score += 5
        elif sev == "medium":
            score += 2
        if row.get("script_block"):
            score += 4
        if any(k in blob for k in hot_kw):
            score += 5
        if et in ("evm_hit", "ptm_hit") and any(k in blob for k in ("persist", "持久", "powershell", "外联", "lolbin")):
            score += 6
        if score <= 0:
            continue
        scored.append((score, row))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("ts") or "")))
    return [r for _, r in scored[: max(1, min(int(limit or 80), 160))]]


def _count_log_categories(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for row in rows or []:
        cat = str(row.get("category") or "other")
        out[cat] = out.get(cat, 0) + 1
    return out


def _evidence_blob(pack: Dict[str, Any]) -> str:
    parts = [
        json.dumps(pack.get("threat_events") or [], ensure_ascii=False)[:4000],
        json.dumps(pack.get("security_logs") or [], ensure_ascii=False)[:6000],
        json.dumps(pack.get("timeline") or [], ensure_ascii=False)[:4000],
        json.dumps(pack.get("investigate_logs") or [], ensure_ascii=False)[:4000],
        json.dumps(pack.get("log_rule_hits") or [], ensure_ascii=False)[:3000],
    ]
    proc = ((pack.get("snapshots") or {}).get("process") or {}).get("items") or []
    parts.append(json.dumps(proc[:25], ensure_ascii=False)[:4000])
    return "\n".join(parts).lower()


def analyze_agent(
    agent_id: str,
    *,
    user: Optional[Dict[str, Any]] = None,
    skill_ids: Optional[List[str]] = None,
    use_llm: bool = True,
) -> Dict[str, Any]:
    t0 = time.time()
    pack = collect_host_pack(agent_id)
    if not pack.get("ok"):
        return pack

    blob = _evidence_blob(pack)
    if skill_ids:
        skills = []
        for sid in skill_ids[:6]:
            full = skills_loader.load_skill_body(str(sid), limit=1800)
            if full.get("ok"):
                skills.append({
                    "id": full["id"],
                    "name": full.get("name"),
                    "description": full.get("description"),
                    "guidance": full.get("guidance"),
                    "mitre": full.get("mitre") or [],
                })
    else:
        skills = skills_loader.select_skills_for_evidence(blob, max_skills=6)

    # 压缩喂给模型的证据包（日志优先，严格控长以免本地推理过慢）
    compact = _slim_for_llm({
        "agent": pack.get("agent"),
        "threat_events": (pack.get("threat_events") or [])[:12],
        "log_categories": pack.get("log_categories") or {},
        "security_logs": (pack.get("security_logs") or [])[:24],
        "log_rule_hits": (pack.get("log_rule_hits") or [])[:16],
        "timeline_sample": (pack.get("timeline") or [])[:18],
        "investigate_log_sample": (pack.get("investigate_logs") or [])[:16],
        "process_sample": (((pack.get("snapshots") or {}).get("process") or {}).get("items") or [])[:16],
        "startup_sample": (((pack.get("snapshots") or {}).get("startup") or {}).get("items") or [])[:8],
        "task_sample": (((pack.get("snapshots") or {}).get("task") or {}).get("items") or [])[:8],
        "network_sample": (((pack.get("snapshots") or {}).get("network") or {}).get("items") or [])[:10],
    }, str_limit=160)
    evidence_json = json.dumps(compact, ensure_ascii=False)[:12000]

    # Agentic SOC：Team Leader + 多专业 Agent 先产出结构化结论（毫秒级）
    agentic = agentic_soc.run_agent_team(pack, skills=skills)
    agentic["log_rule_hits"] = pack.get("log_rule_hits") or []
    agentic["log_rule_meta"] = pack.get("log_rule_meta") or {}
    agentic["security_logs"] = (pack.get("security_logs") or [])[:40]
    agentic["log_categories"] = pack.get("log_categories") or {}
    # 日志取证：Agent 回传时间线/调查日志合集（不只规则命中）
    forensics = []
    seen_fk = set()
    for row in (pack.get("security_logs") or []) + (pack.get("investigate_logs") or []) + (pack.get("timeline") or [])[:80]:
        if not isinstance(row, dict):
            continue
        key = (
            str(row.get("ts") or ""),
            str(row.get("etype") or ""),
            str(row.get("summary") or row.get("command_line") or "")[:80],
        )
        if key in seen_fk:
            continue
        seen_fk.add(key)
        forensics.append(row)
        if len(forensics) >= 120:
            break
    agentic["forensics_logs"] = forensics
    agentic["data_scope"] = {
        "note": "基于 Agent 回传：快照 + 威胁事件 + 时间线/调查日志；规则命中为增强对照，非唯一输入",
        "snapshots": sorted([
            k for k, v in (pack.get("snapshots") or {}).items()
            if isinstance(v, dict) and not v.get("error")
        ]),
        "threat_events": len(pack.get("threat_events") or []),
        "timeline": len(pack.get("timeline") or []),
        "investigate_logs": len(pack.get("investigate_logs") or []),
        "security_logs": len(pack.get("security_logs") or []),
        "log_rule_hits": len(pack.get("log_rule_hits") or []),
    }
    if not agentic.get("threat_events"):
        agentic["threat_events"] = pack.get("threat_events") or []
    skills_used = [{
        "id": s.get("id"),
        "name": s.get("name"),
        "score": s.get("score"),
        "why": s.get("why") or [],
        "matched": bool(s.get("matched", True)),
        "mitre": s.get("mitre") or [],
    } for s in skills]
    if not use_llm:
        return {
            "ok": True,
            "mode": "agentic_heuristic",
            "agent": pack.get("agent"),
            "skills_used": skills_used,
            "result": agentic,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "pack_stats": _pack_stats(pack),
        }

    creds = resolve_creds(user)
    api_key = str(creds.get("api_key") or "").strip()
    base_url = str(creds.get("base_url") or "").strip()
    model = _normalize_model(str(creds.get("model") or ""), base_url)
    timeout = float(creds.get("timeout") or 120)

    skill_prompt = []
    for s in skills[:3]:
        skill_prompt.append(
            f"### {s.get('name') or s.get('id')}\n"
            f"{(s.get('description') or '')[:180]}\n"
            f"{(s.get('guidance') or '')[:600]}\n"
        )

    # 对齐阿里云事件调查报告结构；模型只精炼正文，结构化字段由 Agent Team 保留
    system = (
        "你是 Agentic SOC 的「事件调查报告 Agent」。只依据证据，禁止编造。\n"
        "输出简洁中文 Markdown，结构固定：\n"
        "## 事件定性与摘要\n（首句必须给出：真实攻击 / 疑似误报 / 信息不足）\n"
        "## 攻击链路与时间线\n## 影响面与恶意实体\n## 根因分析\n## IoC 证据指标\n"
        "## 处置建议（需人工审核）\n## 日志研判\n"
        "风险等级只用：严重/高/中/低。全文控制在 900 字内。"
    )
    seed = {
        "verdict": agentic.get("verdict"),
        "risk_level": agentic.get("risk_level"),
        "risk_score": agentic.get("risk_score"),
        "attack_chain": (agentic.get("attack_chain") or [])[:6],
        "entities": (agentic.get("entities") or [])[:8],
        "iocs": (agentic.get("iocs") or [])[:10],
        "dispositions": (agentic.get("dispositions") or [])[:5],
        "root_cause": agentic.get("root_cause"),
    }
    user_msg = (
        f"【Skill】\n" + "\n".join(skill_prompt) +
        f"\n【Agent Team 初判 JSON】\n```json\n{json.dumps(seed, ensure_ascii=False)[:3500]}\n```\n"
        f"\n【证据 JSON】\n```json\n{evidence_json}\n```\n"
        f"请在初判基础上精炼调查报告；判决只能是 真实攻击/疑似误报/信息不足 之一。"
    )

    try:
        url = _chat_completions_url(base_url)
        send = _chat_sender(url, api_key, model, min(timeout, 60.0), max_tokens=1200)
        text = send([
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ])
        if not (text or "").strip():
            raise RuntimeError("模型返回空内容")
        result = agentic_soc.merge_llm_into_agentic(agentic, text.strip())
        return {
            "ok": True,
            "mode": "agentic_llm",
            "agent": pack.get("agent"),
            "skills_used": skills_used,
            "model": model,
            "base_url": base_url,
            "config_source": creds.get("source") or "platform",
            "result": result,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "pack_stats": _pack_stats(pack),
        }
    except Exception as e:
        fallback = dict(agentic)
        fallback["markdown"] = (
            (agentic.get("markdown") or "")
            + f"\n\n> 模型精炼失败，已保留 Agent Team 结论：{str(e)[:200]}"
        )
        return {
            "ok": True,
            "mode": "agentic_fallback",
            "agent": pack.get("agent"),
            "skills_used": skills_used,
            "model": model,
            "base_url": base_url,
            "error": str(e)[:400],
            "result": fallback,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "pack_stats": _pack_stats(pack),
        }


def _pack_stats(pack: Dict[str, Any]) -> Dict[str, Any]:
    snaps = pack.get("snapshots") or {}
    meta = pack.get("log_rule_meta") or {}
    return {
        "threat_events": len(pack.get("threat_events") or []),
        "timeline": len(pack.get("timeline") or []),
        "logs": len(pack.get("investigate_logs") or []),
        "security_logs": len(pack.get("security_logs") or []),
        "log_rule_hits": len(pack.get("log_rule_hits") or []),
        "log_rules_indexed": int(meta.get("rules_indexed") or 0),
        "log_rule_roots": meta.get("roots") or [],
        "log_categories": pack.get("log_categories") or {},
        "process": int(((snaps.get("process") or {}).get("count") or 0)),
        "modules": sorted([k for k, v in snaps.items() if isinstance(v, dict) and not v.get("error")]),
    }


def _first_para(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return (lines[0] if lines else "")[:300]


def _heuristic_summary(pack: Dict[str, Any]) -> Dict[str, Any]:
    events = pack.get("threat_events") or []
    timeline = pack.get("timeline") or []
    logs = pack.get("investigate_logs") or []
    security_logs = pack.get("security_logs") or []
    cats = pack.get("log_categories") or {}
    crit = sum(1 for e in events if str(e.get("severity") or "").lower() == "critical")
    high = sum(1 for e in events if str(e.get("severity") or "").lower() == "high")
    med = sum(1 for e in events if str(e.get("severity") or "").lower() == "medium")
    hot_logs = sum(1 for t in security_logs if str(t.get("severity") or "").lower() in ("high", "critical", "medium"))
    score = min(
        98,
        crit * 25 + high * 12 + med * 5
        + min(18, len(security_logs) // 2)
        + min(12, hot_logs * 2)
        + min(10, int(cats.get("script") or 0) + int(cats.get("auth") or 0)),
    )
    if crit or high >= 3 or hot_logs >= 8:
        level = "严重" if crit >= 1 and high >= 1 else ("高" if crit or high >= 2 or hot_logs >= 8 else "中")
    elif high or med >= 3 or hot_logs >= 3:
        level = "中"
    elif events or any(str(t.get("severity") or "").lower() in ("high", "critical") for t in timeline):
        level = "中"
    else:
        level = "低"
        score = max(score, 15)

    highlights = []
    for e in events[:8]:
        title = e.get("title") or e.get("rule_id") or "威胁事件"
        highlights.append(f"[{e.get('severity') or '?'}] {title} · {str(e.get('matched') or e.get('path') or '')[:160]}")
    for t in security_logs[:8]:
        highlights.append(
            f"日志[{t.get('category') or 'other'}] {t.get('etype')}: {t.get('summary')}"
            + (f" | {str(t.get('command_line') or t.get('script_block') or '')[:120]}" if (t.get("command_line") or t.get("script_block")) else "")
        )

    recs = [
        "复核「威胁命中」进程的父链、命令行与签名",
        "核对本机近期计划任务 / 启动项 / 服务变更与相关 Windows 日志",
        "对照登录失败、PowerShell 脚本块、外联与 DNS，确认是否存在未授权远控",
    ]
    if crit or high:
        recs.insert(0, "优先隔离或限制该终端外联，保留内存与磁盘证据")

    host = (pack.get("agent") or {}).get("hostname") or agent_id_safe(pack)
    cat_txt = "、".join(f"{k}:{v}" for k, v in sorted(cats.items(), key=lambda x: -x[1])[:6]) or "无"
    summary = (
        f"主机 {host} 共关联威胁事件 {len(events)} 条（critical={crit}, high={high}），"
        f"时间线 {len(timeline)} 条，调查日志 {len(logs)} 条，重点安全日志 {len(security_logs)} 条"
        f"（分类 {cat_txt}）。启发式风险：{level}（{score}/100）。"
    )
    return {
        "risk_level": level,
        "risk_score": score,
        "summary": summary,
        "highlights": highlights[:12],
        "recommendations": recs[:8],
    }


def agent_id_safe(pack: Dict[str, Any]) -> str:
    return str((pack.get("agent") or {}).get("agent_id") or "")
