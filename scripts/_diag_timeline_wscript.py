# -*- coding: utf-8 -*-
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import agent_edr, agent_protocol as ap

agent_edr.ensure()
db = ap.db_path()
print("db:", db)
conn = sqlite3.connect(str(db))
conn.row_factory = sqlite3.Row

print("\n=== agents (recent) ===")
for r in conn.execute(
    "SELECT agent_id, hostname, last_seen FROM agents ORDER BY last_seen DESC LIMIT 10"
):
    print(dict(r))

print("\n=== policy timeline_process ===")
row = conn.execute("SELECT policy_json FROM agent_policy WHERE scope='global'").fetchone()
if row:
    pol = json.loads(row["policy_json"] or "{}")
    print("timeline_process:", pol.get("timeline_process", "(default true)"))

print("\n=== timeline wscript (last 15) ===")
tl = conn.execute(
    """SELECT id, agent_id, hostname, etype, summary, severity, ts, detail_json
       FROM agent_timeline
       WHERE lower(summary) LIKE '%wscript%' OR lower(detail_json) LIKE '%wscript%'
       ORDER BY id DESC LIMIT 15"""
).fetchall()
empty_cmd = 0
for r in tl:
    d = {}
    try:
        d = json.loads(r["detail_json"] or "{}")
    except Exception:
        pass
    cl = str(d.get("command_line") or d.get("command") or "")
    if not cl.strip():
        empty_cmd += 1
    print(
        r["id"],
        r["hostname"],
        r["etype"],
        (r["summary"] or "")[:70],
        "| cmd_len=",
        len(cl),
        "|",
        cl[:140],
    )
print(f"wscript rows: {len(tl)}, empty command_line: {empty_cmd}")

print("\n=== timeline PS hidden/rem/scriptblock (last 10) ===")
for r in conn.execute(
    """SELECT id, hostname, etype, summary, detail_json FROM agent_timeline
       WHERE lower(detail_json) LIKE '%scriptblock%'
          OR lower(detail_json) LIKE '%rem#%'
          OR lower(detail_json) LIKE '%windowstyle hidden%'
       ORDER BY id DESC LIMIT 10"""
):
    d = json.loads(r["detail_json"] or "{}")
    cl = d.get("command_line") or ""
    print(r["id"], r["hostname"], r["summary"][:55], "cmd_empty=", not bool(cl))

print("\n=== threat events (wscript/ps/evm/lol/hidden/temp) last 25 ===")
ev = conn.execute(
    """SELECT id, agent_id, title, severity, module, status, created_at FROM agent_events
       WHERE lower(title) LIKE '%wscript%'
          OR lower(title) LIKE '%powershell%'
          OR lower(title) LIKE '%evm%'
          OR lower(title) LIKE '%lolbin%'
          OR lower(title) LIKE '%lol-%'
          OR lower(title) LIKE '%隐藏%'
          OR lower(title) LIKE '%temp/public%'
       ORDER BY id DESC LIMIT 25"""
).fetchall()
for r in ev:
    print(dict(r))
print("open events total:", conn.execute("SELECT COUNT(*) FROM agent_events WHERE status='open'").fetchone()[0])

# simulate server-side match on latest wscript etw
print("\n=== live EVM match on latest wscript process_create_etw ===")
from backend import agent_rules as ar

latest = conn.execute(
    """SELECT etype, summary, detail_json FROM agent_timeline
       WHERE etype LIKE '%process%' AND lower(detail_json) LIKE '%wscript%'
       ORDER BY id DESC LIMIT 1"""
).fetchone()
if latest:
    det = json.loads(latest["detail_json"] or "{}")
    ev = {"etype": latest["etype"], "summary": latest["summary"], "detail": det}
    hits = ar.match_live_evm_events(ev)
    print("etype:", latest["etype"], "hits:", [h.get("id") for h in hits])
    from backend import lolbin

    print("lolbin:", [h.get("rule_id") for h in lolbin.match(det)])
else:
    print("no process wscript row")

print("\n=== timeline id>=87180 ===")
for r in conn.execute(
    "SELECT id, ts, etype, summary, detail_json FROM agent_timeline WHERE id>=87180 ORDER BY id"
):
    d = json.loads(r["detail_json"] or "{}")
    cl = d.get("command_line") or ""
    print(r["id"], r["ts"], r["etype"], (r["summary"] or "")[:55], "cmd_len", len(cl))
    if r["etype"] == "process_create_etw" and "powershell" in (r["summary"] or "").lower():
        ev = {"etype": r["etype"], "summary": r["summary"], "detail": d}
        print("  evm:", [x.get("id") for x in ar.match_live_evm_events(ev)])
        print("  lol:", [x.get("rule_id") for x in lolbin.match(d)])

print("\n=== events since 10:07 ===")
for r in conn.execute(
    """SELECT id, title, severity, created_at FROM agent_events
       WHERE created_at >= '2026-11-02T10:07:00' ORDER BY id"""
):
    print(dict(r))

conn.close()
