# -*- coding: utf-8 -*-
"""v2 幂等批量上报：POST /api/agent/v2/events/batch。

语义（至少一次投递 + 服务端去重 = 效果上恰好一次）：
- 每条事件带 Agent 生成的 event_uuid（持久化在 Agent 本地 outbox 里，重试不变）。
- 整个批次放进同一个 SQLite 事务；每条事件用 SAVEPOINT 隔离：
    * 已有回执 → 视为重复，直接确认，不重复写业务数据；
    * 业务写入与回执在同一事务提交，崩溃只会整体回滚，不会出现"写了业务没回执"；
    * 业务校验失败（永久错误）→ 写 rejected 回执并告知 Agent 丢弃，避免毒丸阻塞队列；
    * 未预期异常（暂时性）→ 回滚该条且不确认，Agent 稍后重试。
- 响应逐条给出 acked / rejected。Agent 本地会合并或丢弃低优先级事件，序号天然不连续，
  因此不做"连续序列 ACK"，改为记录每流 high_seq 与计数用于诊断。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from . import agent_protocol as ap

KINDS = ("timeline", "event", "snapshot", "snapshot_delta", "ack")
MAX_BATCH = 200
RECEIPT_TTL_SEC = 7 * 86400
_last_purge = 0.0


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _apply(kind: str, agent_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    from . import agent_edr
    payload = dict(payload)
    payload["agent_id"] = agent_id  # 以认证身份为准，忽略 payload 自报
    if kind == "timeline":
        return agent_edr.ingest_timeline(payload)
    if kind == "event":
        return ap.report_event(payload)
    if kind == "snapshot":
        return ap.upsert_snapshot(payload)
    if kind == "snapshot_delta":
        return ap.apply_snapshot_delta(payload)
    if kind == "ack":
        return agent_edr.ack_command(
            str(payload.get("id") or payload.get("command_id") or ""),
            ok=bool(payload.get("ok", True)),
            result=payload.get("result") if isinstance(payload.get("result"), dict) else {},
            caller_agent_id=agent_id,
        )
    return {"ok": False, "error": f"未知 kind: {kind}"}


def _purge_receipts(conn: Any) -> None:
    global _last_purge
    if time.time() - _last_purge < 3600:
        return
    _last_purge = time.time()
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - RECEIPT_TTL_SEC))
    conn.execute("DELETE FROM agent_receipts WHERE received_at<?", (cutoff,))


def ingest_batch(agent_id: str, events: List[Any], *, stream: str = "main") -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    if not isinstance(events, list) or not events:
        return {"ok": True, "acked": [], "rejected": [], "duplicates": 0}
    if len(events) > MAX_BATCH:
        return {"ok": False, "error": f"批次过大（>{MAX_BATCH}）"}
    stream = str(stream or "main")[:32]

    acked: List[str] = []
    rejected: List[Dict[str, str]] = []
    dup = 0
    high_seq = 0
    now = _now()
    ap.ensure_db()
    from . import agent_edr
    agent_edr.ensure()

    with ap.batch_tx() as conn:
        for ev in events:
            if not isinstance(ev, dict):
                continue
            uid = str(ev.get("uuid") or "").strip()
            kind = str(ev.get("kind") or "").strip().lower()
            seq = int(ev.get("seq") or 0) if str(ev.get("seq") or "0").lstrip("-").isdigit() else 0
            payload = ev.get("payload")
            if not (8 <= len(uid) <= 64):
                rejected.append({"uuid": uid[:64], "error": "uuid 无效"})
                continue
            high_seq = max(high_seq, seq)
            if kind not in KINDS or not isinstance(payload, dict):
                _receipt(conn, aid, uid, kind, stream, seq, "rejected", "kind/payload 无效", now)
                rejected.append({"uuid": uid, "error": "kind/payload 无效"})
                continue
            if conn.execute(
                "SELECT 1 FROM agent_receipts WHERE agent_id=? AND event_uuid=?", (aid, uid)
            ).fetchone():
                dup += 1
                acked.append(uid)
                continue
            conn.execute("SAVEPOINT ev")
            try:
                out = _apply(kind, aid, payload)
            except Exception as e:  # 暂时性错误：回滚该条，不确认，Agent 重试
                conn.execute("ROLLBACK TO ev")
                conn.execute("RELEASE ev")
                print(f"[ingest_v2] {kind} {uid} transient error:", e)
                continue
            if out.get("ok"):
                _receipt(conn, aid, uid, kind, stream, seq, "ok", "", now)
                conn.execute("RELEASE ev")
                acked.append(uid)
            else:
                err = str(out.get("error") or "rejected")[:200]
                conn.execute("ROLLBACK TO ev")
                _receipt(conn, aid, uid, kind, stream, seq, "rejected", err, now)
                conn.execute("RELEASE ev")
                rejected.append({"uuid": uid, "error": err})
        conn.execute(
            """INSERT INTO agent_streams(agent_id, stream, high_seq, received, rejected, updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(agent_id, stream) DO UPDATE SET
                 high_seq=MAX(high_seq, excluded.high_seq),
                 received=received+excluded.received,
                 rejected=rejected+excluded.rejected,
                 updated_at=excluded.updated_at""",
            (aid, stream, high_seq, len(acked) - dup, len(rejected), now),
        )
        _purge_receipts(conn)

    return {
        "ok": True,
        "acked": acked,
        "rejected": rejected,
        "duplicates": dup,
        "high_seq": high_seq,
        "server_time": now,
    }


def _receipt(conn: Any, aid: str, uid: str, kind: str, stream: str, seq: int, status: str, err: str, now: str) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO agent_receipts(agent_id, event_uuid, kind, stream, seq, status, error, received_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (aid, uid, kind[:16], stream, seq, status, err[:200], now),
    )
