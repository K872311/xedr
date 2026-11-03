"""积木告警聚合：同一主机多战术/多规则命中后升级为威胁事件。"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any, Dict, List, Set

from . import agent_protocol

_lock = threading.RLock()
# agent_id -> last upgrade ts (avoid spam)
_last_upgrade: Dict[str, float] = {}
_UPGRADE_COOLDOWN_SEC = 900
_MIN_DISTINCT_RULES = 3
_LOOKBACK_SEC = 1800


def _tactic_of(detail: Dict[str, Any]) -> str:
    mitre = detail.get("mitre")
    if isinstance(mitre, list) and mitre:
        t = str(mitre[0]).upper()
        if t.startswith("T"):
            return t.split(".")[0]
    m = detail.get("mitre_tactic") or detail.get("tactic")
    if m:
        return str(m).lower()
    rid = str(detail.get("correlation_rule_id") or detail.get("rule_id") or "")
    if "login" in rid or "credential" in rid:
        return "credential_access"
    if "net" in rid or "c2" in rid:
        return "command_and_control"
    if "proc" in rid or "office" in rid:
        return "execution"
    return "unknown"


def aggregate_building_blocks(agent_id: str, host: str) -> int:
    if not agent_id:
        return 0
    now = time.time()
    with _lock:
        if now - _last_upgrade.get(agent_id, 0) < _UPGRADE_COOLDOWN_SEC:
            return 0
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - _LOOKBACK_SEC))
    from . import agent_edr
    agent_edr.ensure()
    rows: List[Any] = []
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            rows = conn.execute(
                """SELECT id, title, detail, module, severity FROM agent_events
                   WHERE agent_id=? AND status='open' AND created_at>=?
                   ORDER BY id DESC LIMIT 80""",
                (agent_id, since),
            ).fetchall()
        finally:
            conn.close()
    bb_rules: Set[str] = set()
    tactics: Set[str] = set()
    for r in rows:
        mod = str(r["module"] or "")
        detail_raw = str(r["detail"] or "")
        detail: Dict[str, Any] = {}
        try:
            detail = json.loads(detail_raw) if detail_raw.startswith("{") else {}
        except Exception:
            detail = {}
        is_bb = mod == "building_block" or detail.get("building_block") is True
        if not is_bb and mod != "correlation":
            continue
        if str(r["severity"] or "").lower() in ("critical", "high"):
            continue
        rid = str(detail.get("correlation_rule_id") or detail.get("rule_id") or r["title"] or "")
        if rid:
            bb_rules.add(rid)
        tac = _tactic_of(detail)
        if tac != "unknown":
            tactics.add(tac)
    if len(bb_rules) < _MIN_DISTINCT_RULES and len(tactics) < 2:
        return 0
    title = f"多阶段可疑行为：{host or agent_id} 命中 {len(bb_rules)} 条积木/关联"
    detail = {
        "building_block_upgrade": True,
        "distinct_rules": sorted(bb_rules)[:20],
        "tactics": sorted(tactics),
        "window_sec": _LOOKBACK_SEC,
        "investigation": "同一主机在 30 分钟内出现多条低置信关联/积木告警，建议打开威胁视图做进程树与外联溯源。",
        "risk_score": 72,
    }
    r = agent_protocol.report_event({
        "agent_id": agent_id,
        "hostname": host,
        "module": "correlation",
        "severity": "high",
        "title": title[:200],
        "detail": detail,
    })
    if r.get("ok") and not r.get("deduped") and not r.get("suppressed"):
        with _lock:
            _last_upgrade[agent_id] = now
        return 1
    return 0
