# -*- coding: utf-8 -*-
"""Fleet 态势：组件 expected/actual 漂移、PolicyApplied 未收敛。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from . import agent_sync

# 与 Agent integrations / component_model 对齐
_COMPONENT_IDS = (
    "etw", "winevent", "wmi_process", "fim", "registry", "evm", "ptm",
    "amsi", "api_etw", "memory_scan", "rootcheck", "sca",
)


def _expected_integrations(agent_id: str, host_meta: Optional[Dict[str, Any]] = None) -> Set[str]:
    doc = agent_sync.get_integrations_document()
    defs = dict(doc.get("defaults") or {})
    try:
        from . import agent_composable as comp

        defs, _ = comp.apply_composable_integrations(defs, agent_id, host_meta=host_meta)
    except Exception:
        pass
    out: Set[str] = set()
    for k in _COMPONENT_IDS:
        if defs.get(k) is True:
            out.add(k)
    return out


def _actual_components(health: Dict[str, Any]) -> Dict[str, str]:
    h = health or {}
    sensors = h.get("sensors") if isinstance(h.get("sensors"), dict) else {}
    raw = sensors.get("components") or h.get("components") or []
    if not isinstance(raw, list):
        return {}
    out: Dict[str, str] = {}
    for c in raw:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or c.get("id") or "").strip()
        if not name:
            continue
        out[name] = str(c.get("state") or "OK").upper()
    return out


def component_drift_for_agent(agent: Dict[str, Any]) -> Dict[str, Any]:
    aid = str(agent.get("agent_id") or "")
    health = agent.get("health") if isinstance(agent.get("health"), dict) else {}
    host_meta = health.get("host") if isinstance(health.get("host"), dict) else {}
    expected = _expected_integrations(aid, host_meta)
    actual = _actual_components(health)

    missing: List[str] = []
    failed: List[str] = []
    degraded: List[str] = []
    for name in sorted(expected):
        st = actual.get(name)
        if st is None:
            missing.append(name)
        elif st in ("FAILED", "OFF", "STOPPED"):
            failed.append(name)
        elif st == "DEGRADED":
            degraded.append(name)

    unexpected: List[str] = []
    for name, st in actual.items():
        if name not in expected and st not in ("OFF", "STOPPED", ""):
            unexpected.append(name)

    fleet = health.get("fleet") or health.get("fleet_report") or {}
    policy_applied = bool(fleet.get("policy_applied"))
    local_sync = int(fleet.get("local_sync_rev") or 0)
    server_sync = int(fleet.get("server_sync_rev") or 0)
    sync_drift = bool(agent.get("online")) and server_sync > 0 and local_sync < server_sync
    policy_drift = bool(agent.get("online")) and not policy_applied

    drift = bool(missing or failed or degraded or sync_drift or policy_drift)

    return {
        "agent_id": aid,
        "hostname": agent.get("hostname") or "",
        "online": bool(agent.get("online")),
        "drift": drift,
        "expected_count": len(expected),
        "missing": missing,
        "failed": failed,
        "degraded": degraded,
        "unexpected": unexpected,
        "sync_drift": sync_drift,
        "policy_drift": policy_drift,
        "local_sync_rev": local_sync,
        "server_sync_rev": server_sync,
        "policy_applied": policy_applied,
    }


def fleet_drift_summary(*, online_within_sec: int = 45) -> Dict[str, Any]:
    from . import agent_protocol

    doc = agent_protocol.list_agents(online_within_sec=online_within_sec)
    items = [component_drift_for_agent(a) for a in (doc.get("items") or [])]
    drift_agents = [x for x in items if x.get("drift")]
    online_drift = [x for x in drift_agents if x.get("online")]
    return {
        "ok": True,
        "items": items,
        "summary": {
            "total": len(items),
            "drift_count": len(drift_agents),
            "online_drift_count": len(online_drift),
            "component_drift": sum(
                1 for x in online_drift if x.get("missing") or x.get("failed") or x.get("degraded")
            ),
            "sync_drift": sum(1 for x in online_drift if x.get("sync_drift")),
            "policy_drift": sum(1 for x in online_drift if x.get("policy_drift")),
        },
    }
