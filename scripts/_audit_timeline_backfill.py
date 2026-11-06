# -*- coding: utf-8 -*-
import json
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "reports" / "agents.db"
IDS = [1661, 1664, 1665, 1666, 1667, 1700]

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row
for eid in IDS:
    ev = conn.execute("SELECT * FROM agent_events WHERE id=?", (eid,)).fetchone()
    if not ev:
        continue
    print("=== event", eid, ev["title"], ev["created_at"])
    rows = conn.execute(
        """SELECT id, etype, summary, substr(detail_json,1,200) as dj, ts FROM agent_timeline
           WHERE agent_id=? AND ts >= datetime(?, '-5 minutes') AND ts <= datetime(?, '+2 minutes')
           ORDER BY id DESC LIMIT 30""",
        (ev["agent_id"], ev["created_at"], ev["created_at"]),
    ).fetchall()
    for r in rows:
        print(f"  tl {r['id']} {r['etype']} {r['summary'][:60]}")
    # ptm/evm hit in timeline
    hits = conn.execute(
        """SELECT id, etype, summary, detail_json FROM agent_timeline
           WHERE agent_id=? AND etype IN ('ptm_hit','evm_hit')
           AND created_at >= datetime(?, '-1 day') ORDER BY id DESC LIMIT 5""",
        (ev["agent_id"], ev["created_at"]),
    ).fetchall()
    for h in hits:
        d = json.loads(h["detail_json"] or "{}")
        print(f"  HIT tl{h['id']} keys={list(d.keys())[:12]} matched={str(d.get('matched',''))[:60]}")

conn.close()
