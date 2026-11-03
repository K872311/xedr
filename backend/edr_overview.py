# -*- coding: utf-8 -*-
"""数据概览：终端态势、24h 采集、威胁分类统计。"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List

from . import agent_edr, agent_protocol


def _connect() -> sqlite3.Connection:
    agent_edr.ensure()
    return agent_edr._connect()


def _ts_cutoff(hours: int = 24) -> str:
    return (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")


def _fmt_wan(n: int) -> str:
    if n >= 10000:
        return f"{n / 10000:.1f}万"
    return str(n)


def _hourly_buckets(conn: sqlite3.Connection, sql: str, args: tuple, hours: int = 24) -> List[int]:
    """按本地小时聚合，返回从 (now-23h) 到 now 共 24 个桶。"""
    now = datetime.now()
    keys = [(now - timedelta(hours=h)).strftime("%Y-%m-%d %H") for h in range(hours - 1, -1, -1)]
    counts = {k: 0 for k in keys}
    for row in conn.execute(sql, args):
        hkey = str(row[0] or "")[:13].replace("T", " ")
        if hkey in counts:
            counts[hkey] += int(row[1] or 0)
    return [counts[k] for k in keys]


def get_overview(*, online_within_sec: int = 45) -> Dict[str, Any]:
    agents_doc = agent_protocol.list_agents(online_within_sec=online_within_sec)
    items = agents_doc.get("items") or []
    total = len(items)
    online = sum(1 for a in items if a.get("online"))
    cutoff = _ts_cutoff(24)
    tl_total = dns_total = 0
    tl_buckets: List[int] = [0] * 24
    dns_buckets: List[int] = [0] * 24
    network_exits = 0
    alerted_hosts = 0
    malware_total = malware_handled = 0
    endpoint_total = endpoint_handled = 0
    external_total = external_handled = 0
    top_malware: List[Dict[str, Any]] = []

    with agent_edr._lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM agent_timeline WHERE ts >= ?",
                (cutoff,),
            ).fetchone()
            tl_total = int(row[0] or 0) if row else 0
            tl_buckets = _hourly_buckets(
                conn,
                """SELECT substr(ts, 1, 13) AS h, COUNT(*) FROM agent_timeline
                   WHERE ts >= ? GROUP BY substr(ts, 1, 13)""",
                (cutoff,),
            )
            dns_etypes = ("dns_query", "dns_summary", "dns_nx_burst", "dns_query_etw")
            placeholders = ",".join("?" * len(dns_etypes))
            row = conn.execute(
                f"SELECT COUNT(*) FROM agent_timeline WHERE ts >= ? AND etype IN ({placeholders})",
                (cutoff, *dns_etypes),
            ).fetchone()
            dns_total = int(row[0] or 0) if row else 0
            dns_buckets = _hourly_buckets(
                conn,
                f"""SELECT substr(ts, 1, 13) AS h, COUNT(*) FROM agent_timeline
                   WHERE ts >= ? AND etype IN ({placeholders}) GROUP BY substr(ts, 1, 13)""",
                (cutoff, *dns_etypes),
            )
            row = conn.execute(
                """SELECT COUNT(DISTINCT json_extract(detail_json, '$.remote_ip'))
                   FROM agent_timeline
                   WHERE ts >= ? AND etype LIKE 'network%' AND json_extract(detail_json, '$.remote_ip') IS NOT NULL""",
                (cutoff,),
            ).fetchone()
            network_exits = int(row[0] or 0) if row else 0

            row = conn.execute(
                """SELECT COUNT(DISTINCT agent_id) FROM agent_events
                   WHERE severity IN ('high','critical','medium') AND status != 'ignored'""",
            ).fetchone()
            alerted_hosts = int(row[0] or 0) if row else 0

            malware_total = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE (module IN ('file','fim','malware') OR title LIKE '%文件%' OR title LIKE '%恶意%')
                       AND status != 'ignored'""",
                ).fetchone()[0]
                or 0
            )
            malware_handled = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE (module IN ('file','fim','malware') OR title LIKE '%文件%' OR title LIKE '%恶意%')
                       AND status IN ('closed','resolved')""",
                ).fetchone()[0]
                or 0
            )

            endpoint_total = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE module IN ('process','evm','ptm','timeline','memory','script')
                       AND status != 'ignored'""",
                ).fetchone()[0]
                or 0
            )
            endpoint_handled = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE module IN ('process','evm','ptm','timeline','memory','script')
                       AND status IN ('closed','resolved')""",
                ).fetchone()[0]
                or 0
            )

            external_total = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE (module IN ('network','dns') OR title LIKE '%外联%' OR title LIKE '%DNS%')
                       AND status != 'ignored'""",
                ).fetchone()[0]
                or 0
            )
            external_handled = int(
                conn.execute(
                    """SELECT COUNT(*) FROM agent_events
                       WHERE (module IN ('network','dns') OR title LIKE '%外联%' OR title LIKE '%DNS%')
                       AND status IN ('closed','resolved')""",
                ).fetchone()[0]
                or 0
            )

            for r in conn.execute(
                """SELECT title, COUNT(*) AS c FROM agent_events
                   WHERE (module IN ('file','fim','malware') OR title LIKE '%恶意%' OR title LIKE '%文件%')
                   GROUP BY title ORDER BY c DESC LIMIT 5""",
            ):
                top_malware.append({"title": r[0], "count": int(r[1] or 0)})
        finally:
            conn.close()

    groups_n = 0
    try:
        groups_n = len(agent_edr.list_groups().get("items") or [])
    except Exception:
        pass

    degraded = sum(
        1
        for a in items
        if _agent_degraded(a)
    )
    drift_summary: Dict[str, Any] = {
        "drift_count": 0,
        "online_drift_count": 0,
        "component_drift": 0,
        "sync_drift": 0,
        "policy_drift": 0,
    }
    try:
        from . import agent_fleet

        ds = agent_fleet.fleet_drift_summary(online_within_sec=online_within_sec)
        drift_summary = ds.get("summary") or drift_summary
    except Exception:
        pass

    return {
        "ok": True,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "agents": {
            "total": total,
            "online": online,
            "agent": total,
            "va": 0,
            "degraded_capture": degraded,
            "component_drift": drift_summary.get("online_drift_count", 0),
            "sync_drift": drift_summary.get("sync_drift", 0),
            "policy_drift": drift_summary.get("policy_drift", 0),
        },
        "fleet_drift": drift_summary,
        "groups": groups_n,
        "network_exits": network_exits,
        "timeline_24h": {
            "total": tl_total,
            "display": _fmt_wan(tl_total),
            "buckets": tl_buckets,
        },
        "dns_24h": {
            "total": dns_total,
            "display": _fmt_wan(dns_total),
            "buckets": dns_buckets,
        },
        "threats": {
            "alerted_hosts": alerted_hosts,
            "malware_total": malware_total,
            "malware_handled": malware_handled,
            "endpoint_total": endpoint_total,
            "endpoint_handled": endpoint_handled,
            "endpoint_need_auth": max(0, endpoint_total - endpoint_handled),
            "external_total": external_total,
            "external_handled": external_handled,
            "top_malware": top_malware,
        },
    }


def _agent_degraded(a: Dict[str, Any]) -> bool:
    h = a.get("health") or {}
    comps = h.get("sensors", {}).get("components") if isinstance(h.get("sensors"), dict) else None
    if not isinstance(comps, list):
        return False
    for c in comps:
        if isinstance(c, dict) and str(c.get("state") or "").upper() == "DEGRADED":
            return True
    cs = (h.get("sensors") or {}).get("capture_status") if isinstance(h.get("sensors"), dict) else {}
    if isinstance(cs, dict) and cs.get("etw_session_ok") is False and a.get("online"):
        return True
    return False
