# -*- coding: utf-8 -*-
"""Composable host / 分组条件：按终端元数据覆盖集成开关（对齐 Elastic composable providers）。"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "agent_composable.json"


def _read() -> Dict[str, Any]:
    if not _CONFIG.is_file():
        return {"version": "1", "rules": [], "group_tags": {}}
    try:
        return json.loads(_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return {"version": "1", "rules": [], "group_tags": {}}


def _group_matches(name: str, tags_cfg: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    nl = (name or "").lower()
    for tag, patterns in (tags_cfg or {}).items():
        for p in patterns or []:
            ps = str(p).lower()
            if ps in nl or (ps and ps in name):
                out.append(tag)
                break
    return out


def groups_for_agent(agent_id: str) -> List[Dict[str, Any]]:
    from . import agent_edr

    aid = str(agent_id or "").strip()
    if not aid:
        return []
    try:
        gl = agent_edr.list_groups()
        items = gl.get("items") or []
    except Exception:
        return []
    matched: List[Dict[str, Any]] = []
    for g in items:
        raw = g.get("agent_ids") or g.get("agent_ids_json")
        ids: List[str] = []
        if isinstance(raw, list):
            ids = [str(x) for x in raw]
        elif isinstance(raw, str) and raw.strip():
            try:
                ids = [str(x) for x in json.loads(raw)]
            except Exception:
                ids = []
        if aid in ids:
            matched.append({"id": g.get("id"), "name": g.get("name") or "", "note": g.get("note") or ""})
    return matched


def host_context(agent_id: str, host_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    doc = _read()
    tags_cfg = doc.get("group_tags") if isinstance(doc.get("group_tags"), dict) else {}
    groups = groups_for_agent(agent_id)
    tag_hits: List[str] = []
    for g in groups:
        tag_hits.extend(_group_matches(str(g.get("name") or ""), tags_cfg))
        tag_hits.extend(_group_matches(str(g.get("note") or ""), tags_cfg))
    tag_hits = list(dict.fromkeys(tag_hits))
    hm = dict(host_meta or {})
    in_high = "high_sensitivity" in tag_hits
    if not in_high:
        for g in groups:
            if re.search(r"高敏|high[\-_]?sens", str(g.get("name") or ""), re.I):
                in_high = True
                break
    ctx = {
        "host": hm,
        "groups": groups,
        "group_tags": tag_hits,
        "in_high_sensitivity_group": in_high or bool(hm.get("in_high_sensitivity_group")),
        "is_domain_controller": bool(hm.get("is_domain_controller")),
    }
    return ctx


def _match_when(when: Any, ctx: Dict[str, Any]) -> bool:
    if not isinstance(when, dict):
        return False
    for k, want in when.items():
        if k == "host.is_domain_controller":
            if bool(want) != ctx["is_domain_controller"]:
                return False
        elif k == "host.in_high_sensitivity_group":
            if bool(want) != ctx["in_high_sensitivity_group"]:
                return False
        elif k.startswith("group:"):
            tag = k.split(":", 1)[1]
            if tag not in ctx["group_tags"]:
                return False
    return True


def apply_composable_integrations(
    defaults: Dict[str, Any],
    agent_id: str,
    host_meta: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """返回 (merged_defaults, applied_rule_ids)。"""
    doc = _read()
    rules = doc.get("rules") if isinstance(doc.get("rules"), list) else []
    ctx = host_context(agent_id, host_meta)
    merged = dict(defaults or {})
    applied: List[str] = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _match_when(rule.get("when"), ctx):
            continue
        ints = rule.get("integrations")
        if not isinstance(ints, dict):
            continue
        for ik, iv in ints.items():
            if isinstance(iv, bool):
                merged[str(ik)] = iv
        rid = str(rule.get("id") or "")
        if rid:
            applied.append(rid)
    return merged, applied


def apply_composable_policy(
    policy: Dict[str, Any],
    agent_id: str,
    host_meta: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """按分组条件覆盖策略字段（winevent 通道 / memory_scan 等灰度）。"""
    doc = _read()
    rules = doc.get("rules") if isinstance(doc.get("rules"), list) else []
    ctx = host_context(agent_id, host_meta)
    merged = dict(policy or {})
    applied: List[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not _match_when(rule.get("when"), ctx):
            continue
        patch = rule.get("policy")
        if not isinstance(patch, dict) or not patch:
            continue
        for k, v in patch.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                nested = dict(merged[k])
                nested.update(v)
                merged[k] = nested
            else:
                merged[k] = v
        rid = str(rule.get("id") or "")
        if rid:
            applied.append(rid)
    return merged, applied


def composable_variables(agent_id: str, host_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ctx = host_context(agent_id, host_meta)
    return {
        "host": ctx["host"],
        "groups": ctx["groups"],
        "group_tags": ctx["group_tags"],
        "in_high_sensitivity_group": ctx["in_high_sensitivity_group"],
        "is_domain_controller": ctx["is_domain_controller"],
    }
