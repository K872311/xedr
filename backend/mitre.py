"""ATT&CK 技术映射：从规则 mitre 字段落到告警，并提供中文名。"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)

_STAGE_CN = {
    "persistence": "持久化",
    "execution": "执行",
    "persistence_execution": "持久化/执行",
    "defense_evasion": "防御绕过",
    "privilege_escalation": "权限提升",
    "credential_access": "凭证访问",
    "discovery": "发现",
    "lateral_movement": "横向移动",
    "collection": "收集",
    "command_and_control": "命令与控制",
    "exfiltration": "数据渗出",
    "impact": "影响",
    "initial_access": "初始访问",
}

# 无规则 mitre 时的粗粒度回退（宁可少标，不乱标）
_FALLBACK_BY_PERSIST = {
    "task": ["T1053.005"],
    "service": ["T1543.003"],
    "startup": ["T1547.001"],
    "registry": ["T1112"],
    "wmi": ["T1047"],
}
_FALLBACK_BY_CATEGORY = {
    "可疑进程": ["T1059"],
    "网络外联": ["T1071"],
}


@lru_cache(maxsize=1)
def _technique_catalog() -> Dict[str, Dict[str, str]]:
    p = Path(__file__).resolve().parent / "data" / "mitre_techniques_cn.json"
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: Dict[str, Dict[str, str]] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            tid = normalize_technique_id(k)
            if not tid or not isinstance(v, dict):
                continue
            out[tid] = {
                "name_en": str(v.get("name_en") or ""),
                "name_cn": str(v.get("name_cn") or v.get("name_en") or tid),
            }
    return out


def normalize_technique_id(raw: Any) -> str:
    s = str(raw or "").strip().upper().replace(" ", "")
    if not s:
        return ""
    if s.startswith("ATTACK."):
        s = s[7:]
    if not s.startswith("T"):
        s = "T" + s
    return s if _TECH_RE.match(s) else ""


def normalize_technique_ids(values: Any) -> List[str]:
    out: List[str] = []
    seen = set()
    if isinstance(values, str):
        values = re.split(r"[,;\s]+", values)
    if not isinstance(values, (list, tuple, set)):
        return out
    for v in values:
        tid = normalize_technique_id(v)
        if tid and tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def technique_meta(tid: str) -> Dict[str, str]:
    tid_n = normalize_technique_id(tid)
    cat = _technique_catalog()
    info = cat.get(tid_n) or {}
    if not info and "." in tid_n:
        info = cat.get(tid_n.split(".", 1)[0]) or {}
    name_cn = info.get("name_cn") or ""
    name_en = info.get("name_en") or ""
    label = f"{tid_n} · {name_cn}" if name_cn else tid_n
    return {
        "id": tid_n,
        "name_cn": name_cn,
        "name_en": name_en,
        "label": label,
    }


def stage_label(stage: Any) -> str:
    s = str(stage or "").strip()
    if not s:
        return ""
    return _STAGE_CN.get(s.lower(), s)


def mitre_labels(ids: Sequence[str]) -> List[Dict[str, str]]:
    return [technique_meta(t) for t in ids if normalize_technique_id(t)]


def enrich_extra_from_rule(extra: Optional[Dict[str, Any]], rule: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """匹配时把规则上的 mitre / attackStage 写入 Finding.extra。"""
    out = dict(extra or {})
    if not isinstance(rule, dict):
        return out
    m = normalize_technique_ids(rule.get("mitre"))
    if m:
        out["mitre"] = m
    stage = rule.get("attackStage") or rule.get("attack_stage")
    if stage:
        out["attack_stage"] = str(stage).strip()
    tags = rule.get("tags")
    if isinstance(tags, list) and tags and "tags" not in out:
        out["tags"] = [str(t) for t in tags if t][:12]
    return out


def _fallback_mitre(item: Dict[str, Any]) -> List[str]:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    kind = str(extra.get("persist_kind") or "").strip().lower()
    if kind in _FALLBACK_BY_PERSIST:
        return list(_FALLBACK_BY_PERSIST[kind])
    cat = str(item.get("category") or item.get("type") or "").strip()
    if cat in _FALLBACK_BY_CATEGORY:
        return list(_FALLBACK_BY_CATEGORY[cat])
    return []


def resolve_mitre_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """给单条告警解析 ATT&CK：优先已有字段 → 规则库 → 回退。"""
    if not isinstance(item, dict):
        return {"mitre": [], "mitre_labels": [], "attack_stage": "", "attack_stage_label": ""}
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    ids = normalize_technique_ids(item.get("mitre") or extra.get("mitre"))
    stage = str(item.get("attack_stage") or extra.get("attack_stage") or "").strip()
    if not ids:
        rid = str(item.get("rule_id") or "").strip()
        if rid:
            try:
                from .rules_loader import get_store
                rule = get_store().rule_by_id(rid)
            except Exception:
                rule = None
            if isinstance(rule, dict):
                ids = normalize_technique_ids(rule.get("mitre"))
                if not stage:
                    stage = str(rule.get("attackStage") or rule.get("attack_stage") or "").strip()
    if not ids:
        ids = _fallback_mitre(item)
    return {
        "mitre": ids,
        "mitre_labels": mitre_labels(ids),
        "attack_stage": stage,
        "attack_stage_label": stage_label(stage),
    }


def enrich_finding_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return item
    info = resolve_mitre_for_item(item)
    if info["mitre"]:
        item["mitre"] = info["mitre"]
        item["mitre_labels"] = info["mitre_labels"]
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        extra = dict(extra)
        extra["mitre"] = info["mitre"]
        if info["attack_stage"]:
            extra["attack_stage"] = info["attack_stage"]
            item["attack_stage"] = info["attack_stage"]
            item["attack_stage_label"] = info["attack_stage_label"]
        item["extra"] = extra
    elif info["attack_stage"]:
        item["attack_stage"] = info["attack_stage"]
        item["attack_stage_label"] = info["attack_stage_label"]
    return item


def enrich_findings_list(items: Optional[List[Any]]) -> List[Any]:
    out: List[Any] = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(enrich_finding_dict(it))
        else:
            out.append(it)
    return out
