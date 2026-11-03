# -*- coding: utf-8 -*-
"""Agent 统一同步：策略/规则/YARA/白名单/IOC/EVM/PTM/AR/集成 的 rev+hash 摘要与增量拉取。"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_lock = threading.RLock()
_sync_rev = 1

_CONFIG = Path(__file__).resolve().parent.parent / "config"
_PTM = _CONFIG / "agent_ptm_rules.json"
_AR = _CONFIG / "agent_active_response.json"
_INT = _CONFIG / "agent_integrations.json"


def _sha(obj: Any) -> str:
    blob = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def bump_sync(part: str = "content") -> int:
    global _sync_rev
    with _lock:
        _sync_rev += 1
        rev = _sync_rev
    try:
        from . import agent_protocol
        agent_protocol.bump_live("sync", part=part, rev=rev)
    except Exception:
        pass
    return rev


def sync_revision() -> int:
    with _lock:
        return int(_sync_rev)


# 管理台可开关的 Agent 集成项（写入 config/agent_integrations.json → 同步包 integrations）
INTEGRATION_KEYS = (
    "evm", "ptm", "amsi", "api_etw", "memory_scan", "wmi_process",
    "etw", "winevent", "fim", "registry", "sca", "rootcheck",
)
# 仅服务端时间线入库路径使用，不下发 Agent
SERVER_DETECTION_KEYS = (
    "evm_ingest",
    "elastic_evm_ingest",
    "lolbin_ingest",
)
_SERVER_DETECTION_DEFAULTS = {
    "evm_ingest": True,
    "elastic_evm_ingest": True,
    "lolbin_ingest": True,
}


def get_integrations_document() -> Dict[str, Any]:
    doc = _read_json(_INT)
    if not isinstance(doc, dict):
        doc = {}
    defs = doc.get("defaults")
    if not isinstance(defs, dict):
        defs = {}
    # 与 Agent integrations.go 默认对齐
    merged = {
        "etw": True, "winevent": True, "wmi_process": False, "fim": True, "registry": True,
        "persist": True, "kernel_user": True, "memory_scan": True, "inventory": True,
        "rootcheck": True, "sca": True, "evm": True, "ptm": True, "amsi": True, "api_etw": True,
    }
    for k, v in defs.items():
        if isinstance(v, bool):
            merged[k] = v
    srv_in = doc.get("server")
    if not isinstance(srv_in, dict):
        srv_in = {}
    server = dict(_SERVER_DETECTION_DEFAULTS)
    for k, v in srv_in.items():
        if k in _SERVER_DETECTION_DEFAULTS and isinstance(v, bool):
            server[k] = v
    return {
        "ok": True,
        "version": str(doc.get("version") or "1"),
        "updated_at": str(doc.get("updated_at") or ""),
        "defaults": merged,
        "server": server,
        "labels": {
            "evm": "端上 EVM（Agent 本地实时匹配）",
            "ptm": "PTM 行为序列",
            "amsi": "AMSI 脚本扫描",
            "api_etw": "API / Threat Intel ETW",
            "memory_scan": "内存 YARA 扫描触发",
            "wmi_process": "WMI 进程创建订阅",
            "etw": "原生 ETW 采集",
            "winevent": "Windows 事件日志回退",
            "fim": "文件完整性监控",
            "registry": "注册表监控",
            "sca": "SCA 合规扫描",
            "rootcheck": "Rootcheck",
            "evm_ingest": "云端 EVM（入库时自定义/Agent-live 规则二次匹配）",
            "elastic_evm_ingest": "云端 Elastic/Protections EVM（入库时匹配）",
            "lolbin_ingest": "云端 LOLBin（入库时进程白名单滥用检测）",
        },
        "server_note": "云端开关只影响服务端，Agent 无需同步；修改后立即生效。",
    }


def server_detection_enabled(key: str) -> bool:
    k = str(key or "").strip()
    if k not in _SERVER_DETECTION_DEFAULTS:
        return True
    try:
        return bool(get_integrations_document().get("server", {}).get(k, True))
    except Exception:
        return bool(_SERVER_DETECTION_DEFAULTS.get(k, True))


def save_integrations_defaults(
    updates: Dict[str, Any],
    *,
    server_updates: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    doc = _read_json(_INT)
    if not isinstance(doc, dict):
        doc = {"version": "1", "defaults": {}}
    defs = doc.get("defaults")
    if not isinstance(defs, dict):
        defs = {}
    for k, v in (updates or {}).items():
        key = str(k).strip()
        if key not in INTEGRATION_KEYS:
            continue
        if isinstance(v, bool):
            defs[key] = v
    auto_wmi_bump = False
    if defs.get("ptm") and defs.get("evm"):
        wmi_explicit_off = "wmi_process" in (updates or {}) and updates.get("wmi_process") is False
        if not wmi_explicit_off and not defs.get("wmi_process"):
            defs["wmi_process"] = True
            auto_wmi_bump = True
    doc["defaults"] = defs
    bumped_agent = bool(updates) or auto_wmi_bump
    if server_updates:
        srv = doc.get("server")
        if not isinstance(srv, dict):
            srv = {}
        for k, v in server_updates.items():
            key = str(k).strip()
            if key in SERVER_DETECTION_KEYS and isinstance(v, bool):
                srv[key] = v
        doc["server"] = srv
    doc["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    _INT.parent.mkdir(parents=True, exist_ok=True)
    _INT.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if bumped_agent:
        bump_sync("integrations")
    elif server_updates:
        bump_sync("server_detection")
    return get_integrations_document()


def _part_policy() -> Dict[str, Any]:
    from . import agent_edr
    pol = agent_edr.get_policy("global")
    body = pol.get("policy") or {}
    return {"rev": int(pol.get("rev") or 1), "hash": _sha(body)[:16]}


def _part_evm() -> Dict[str, Any]:
    from . import agent_rules
    doc = agent_rules.export_evm_document()
    return {"rev": doc.get("rev") or "", "hash": _sha(doc)[:16], "count": len(doc.get("rules") or [])}


def _part_memory_yara() -> Dict[str, Any]:
    from . import memory_yara
    b = memory_yara.bundle()
    return {
        "rev": str(b.get("rev") or ""),
        "hash": str(b.get("sha256") or "")[:16],
        "rule_count": b.get("rule_count"),
    }


def _part_whitelist() -> Dict[str, Any]:
    from . import agent_edr
    wl = agent_edr.list_whitelist()
    items = wl.get("items") or []
    en = [x for x in items if x.get("enabled")]
    return {"rev": _sha(en)[:12], "hash": _sha(en)[:16], "count": len(en)}


def _part_ioc() -> Dict[str, Any]:
    from . import agent_edr
    ioc = agent_edr.list_ioc()
    items = [x for x in (ioc.get("items") or []) if x.get("enabled", True)]
    return {"rev": _sha(items)[:12], "hash": _sha(items)[:16], "count": len(items)}


def _part_sca() -> Dict[str, Any]:
    from . import wazuh_ruleset
    doc = wazuh_ruleset.export_agent_bundle_document()
    n = sum(len(p.get("checks") or []) for p in (doc.get("policies") or []) if isinstance(p, dict))
    return {"rev": str(doc.get("updated_at") or ""), "hash": _sha(doc)[:16], "policies": len(doc.get("policies") or []), "checks": n}


def _part_static(name: str, path: Path) -> Dict[str, Any]:
    doc = _read_json(path)
    return {"rev": str(doc.get("version") or doc.get("updated_at") or ""), "hash": _sha(doc)[:16]}


def _part_amsi() -> Dict[str, Any]:
    try:
        from . import protections_import as pi
        doc = pi.export_amsi_document()
    except Exception:
        doc = _read_json(_CONFIG / "protections_amsi_rules.json")
    return {"rev": str(doc.get("rev") or doc.get("updated_at") or ""), "hash": _sha(doc)[:16], "count": len(doc.get("rules") or [])}


def _part_api_rules() -> Dict[str, Any]:
    try:
        from . import protections_import as pi
        doc = pi.export_api_rules_document()
    except Exception:
        doc = _read_json(_CONFIG / "protections_api_rules.json")
    return {"rev": str(doc.get("rev") or doc.get("updated_at") or ""), "hash": _sha(doc)[:16], "count": len(doc.get("rules") or [])}


def manifest() -> Dict[str, Any]:
    parts = {
        "policy": _part_policy(),
        "evm": _part_evm(),
        "memory_yara": _part_memory_yara(),
        "whitelist": _part_whitelist(),
        "ioc": _part_ioc(),
        "sca": _part_sca(),
        "ptm": _part_static("ptm", _PTM),
        "amsi_rules": _part_amsi(),
        "api_rules": _part_api_rules(),
        "active_response": _part_static("ar", _AR),
        "integrations": _part_static("integrations", _INT),
    }
    agg = _sha({"sync_rev": _sync_rev, "parts": parts})[:16]
    return {
        "ok": True,
        "sync_rev": sync_revision(),
        "aggregate_hash": agg,
        "server_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "parts": parts,
        "detection_rules_corpus": "rules/windows|linux|cross-platform",
        "elastic_detection_catalog": "rules/published/elastic-detection-catalog.json",
        "wazuh_sca_catalog": "rules/published/wazuh-sca-catalog.json",
        "wazuh_sca_bundle": "config/agent_sca_bundle.json",
        "wazuh_mitre_json": "rules/ruleset/mitre/enterprise-attack.json",
        "note": "Elastic TOML → elastic_detection_import；Wazuh ruleset/sca → wazuh_ruleset + Agent SCA 同步。",
    }


def _host_meta_for_sync(agent_id: str) -> Dict[str, Any]:
    try:
        from . import agent_protocol
        agents = agent_protocol.list_agents(online_within_sec=86400 * 7)
        for a in agents.get("items") or []:
            if str(a.get("agent_id")) != str(agent_id):
                continue
            h = a.get("health") or {}
            if isinstance(h.get("host"), dict):
                return dict(h["host"])
    except Exception:
        pass
    return {}


def bundle(agent_id: str, since_rev: int = 0, *, parts: Optional[List[str]] = None) -> Dict[str, Any]:
    """since_rev 小于当前 sync_rev 时返回各块正文；否则 304 式 unchanged。"""
    m = manifest()
    cur = int(m.get("sync_rev") or 0)
    if since_rev > 0 and since_rev >= cur:
        return {"ok": True, "unchanged": True, "sync_rev": cur, "manifest": m}

    want = set(parts or [])
    full = not want
    out: Dict[str, Any] = {"ok": True, "sync_rev": cur, "manifest": m, "agent_id": agent_id}

    from . import agent_edr, agent_rules, memory_yara

    if full or "policy" in want:
        pol = agent_edr.get_policy("global")
        body = dict(pol.get("policy") or {})
        try:
            from . import agent_composable as comp
            body, pol_rules = comp.apply_composable_policy(
                body, agent_id, host_meta=_host_meta_for_sync(agent_id),
            )
            if pol_rules:
                out["composable_policy_applied"] = pol_rules
        except Exception:
            pass
        out["policy"] = body
        out["policy_rev"] = pol.get("rev")

    if full or "evm" in want:
        out["evm"] = agent_rules.export_evm_document()

    if full or "memory_yara" in want:
        out["memory_yara"] = memory_yara.bundle()

    if full or "whitelist" in want:
        wl = agent_edr.list_whitelist()
        out["whitelist"] = [
            {"kind": x.get("kind"), "value": x.get("value")}
            for x in (wl.get("items") or [])
            if x.get("enabled")
        ][:500]

    if full or "ioc" in want:
        ioc = agent_edr.list_ioc()
        out["ioc"] = [
            {"type": x.get("ioc_type"), "value": x.get("value"), "severity": x.get("severity")}
            for x in (ioc.get("items") or [])
            if x.get("enabled", True)
        ][:1000]

    if full or "sca" in want:
        from . import wazuh_ruleset
        out["sca"] = wazuh_ruleset.export_agent_bundle_document()

    if full or "ptm" in want:
        out["ptm"] = _read_json(_PTM)

    if full or "amsi_rules" in want or "api_rules" in want:
        try:
            from . import protections_import as pi
            out["api_rules"] = pi.export_api_rules_document()
            out["amsi_rules"] = pi.export_amsi_document()
        except Exception:
            out["api_rules"] = _read_json(_CONFIG / "protections_api_rules.json")
            out["amsi_rules"] = _read_json(_CONFIG / "protections_amsi_rules.json")

    if full or "active_response" in want:
        out["active_response"] = _read_json(_AR)

    if full or "integrations" in want:
        doc = get_integrations_document()
        defs = dict(doc.get("defaults") or {})
        applied_rules: List[str] = []
        try:
            from . import agent_composable as comp
            defs, applied_rules = comp.apply_composable_integrations(defs, agent_id, host_meta=_host_meta_for_sync(agent_id))
            out["composable_variables"] = comp.composable_variables(agent_id, host_meta=_host_meta_for_sync(agent_id))
        except Exception:
            pass
        out["integrations"] = {
            "version": doc.get("version"),
            "defaults": defs,
            "server": doc.get("server"),
            "composable_applied": applied_rules,
        }

    if full or "rule_fim" in want:
        try:
            out["rule_fim_paths"] = agent_rules.rule_fim_paths()
        except Exception:
            out["rule_fim_paths"] = []

    if full or "fim_registry" in want:
        out["fim_registry_paths"] = agent_rules.rule_registry_fim_paths()

    return out
