# -*- coding: utf-8 -*-
"""威胁事件 detail 从时间线回填 / 补全（PTM、EVM、SCA 等缺字段告警）。"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "agent_ptm_rules.json"
_PTM_RULES: Optional[Dict[str, Dict[str, Any]]] = None

_USEFUL = frozenset({
    "matched", "chain", "command_line", "path", "reg_key", "key", "remote", "remote_ip",
    "domain", "local", "process_name", "name", "value", "value_name", "source_summary",
    "checks",
})


def detail_is_thin(d: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(d, dict) or not d:
        return True
    if isinstance(d.get("failed"), list) and d["failed"] and not d.get("matched"):
        return True
    if any(d.get(k) for k in _USEFUL):
        if d.get("chain") and isinstance(d["chain"], list) and d["chain"]:
            return False
        if d.get("matched") and len(str(d["matched"])) > 8:
            return False
    et = str(d.get("etype") or "")
    keys = {k for k, v in d.items() if v not in (None, "", [], {})}
    meta_only = keys <= {
        "etype", "rule_id", "rule_title", "title", "rule_source", "building_block",
        "count", "failed", "steps", "window_sec", "first", "entity_id", "parent_entity_id",
        "pid", "evm_rev", "source_etype", "event_ts",
    }
    if et in ("ptm_hit", "evm_hit") and meta_only:
        return True
    if str(d.get("module") or "") == "sca" or (d.get("failed") and not d.get("matched")):
        if isinstance(d.get("failed"), list) and d["failed"]:
            return True
    return meta_only and not d.get("path")


def _load_ptm_rules() -> Dict[str, Dict[str, Any]]:
    global _PTM_RULES
    if _PTM_RULES is not None:
        return _PTM_RULES
    out: Dict[str, Dict[str, Any]] = {}
    try:
        raw = json.loads(_CONFIG.read_text(encoding="utf-8"))
        for r in raw.get("rules") or []:
            if isinstance(r, dict) and r.get("id"):
                out[str(r["id"])] = r
    except Exception:
        pass
    _PTM_RULES = out
    return out


def _parse_detail(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            o = json.loads(raw)
            return o if isinstance(o, dict) else {}
        except ValueError:
            return {}
    return {}


def _timeline_evidence(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        d = json.loads(row["detail_json"] or "{}")
    except Exception:
        d = {}
    if not isinstance(d, dict):
        d = {}
    out: Dict[str, Any] = {"etype": row["etype"], "summary": row["summary"]}
    for k in (
        "path", "key", "reg_key", "hive", "value", "value_name", "name", "process_name",
        "command_line", "command", "remote", "remote_ip", "domain", "local", "proto", "pid",
        "parent_name", "ppid", "operation", "image", "module_name", "entity_id",
        "process_path", "script_block", "payload",
    ):
        if d.get(k) not in (None, ""):
            out[k] = d[k]
    if not out.get("reg_key") and out.get("key"):
        out["reg_key"] = out["key"]
    return out


def _step_match(step: Dict[str, Any], etype: str, summary: str, det: Dict[str, Any]) -> bool:
    if not step:
        return False
    want = str(step.get("etype") or "").strip().lower()
    if want and want != str(etype or "").lower():
        return False
    sub = str(step.get("summary_contains") or "")
    if sub and sub.lower() not in str(summary or "").lower():
        return False
    pr = str(step.get("path_regex") or "")
    if pr:
        path = str(det.get("path") or det.get("reg_key") or det.get("key") or "")
        try:
            if not re.search(pr, path, re.I):
                return False
        except re.error:
            return False
    return True


def _build_matched_from_chain(chain: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for i, c in enumerate(chain[:8]):
        s = str(c.get("summary") or c.get("etype") or "").strip()
        rk = str(c.get("reg_key") or c.get("key") or "").strip()
        if rk:
            vn = str(c.get("value_name") or "")
            val = str(c.get("value") or "")
            if vn or val:
                s = f"{rk} → {vn}={val}".strip()
            else:
                s = rk
        elif c.get("remote") or c.get("remote_ip"):
            s = str(c.get("summary") or c.get("process_name") or "network")
            rm = str(c.get("remote") or c.get("remote_ip"))
            s = f"{s} → {rm}"
            if c.get("domain"):
                s += f" ({c['domain']})"
        if s:
            parts.append(f"{i + 1}) {s}")
    return " | ".join(parts)[:500]


def _sca_matched(d: Dict[str, Any]) -> str:
    failed = d.get("failed")
    if not isinstance(failed, list):
        return ""
    names = []
    for x in failed:
        if isinstance(x, dict):
            t = str(x.get("title") or x.get("id") or "").strip()
            if t:
                names.append(t)
    return "；".join(names)[:500]


def _find_process_command(
    conn: sqlite3.Connection,
    agent_id: str,
    *,
    pid: int = 0,
    entity_id: str = "",
) -> Optional[Dict[str, Any]]:
    if pid:
        try:
            row = conn.execute(
                """SELECT command_line, path, name, ppid, parent_entity_id, user
                   FROM agent_processes WHERE agent_id=? AND pid=?
                   ORDER BY last_seen DESC LIMIT 1""",
                (agent_id, int(pid)),
            ).fetchone()
            if row and str(row["command_line"] or "").strip():
                return {
                    "command_line": str(row["command_line"]).strip(),
                    "path": row["path"] or "",
                    "name": row["name"] or "",
                    "process_name": row["name"] or "",
                    "ppid": row["ppid"],
                    "user": row["user"] or "",
                }
        except sqlite3.Error:
            pass
    args: List[Any] = [agent_id]
    clauses = [
        "agent_id=?",
        "etype IN ('process_create_etw','process_create_live','process_create')",
    ]
    if pid:
        clauses.append("(detail_json LIKE ? OR summary LIKE ?)")
        args.extend([f'%"pid": {pid}%', f" {pid} "])
    elif entity_id:
        clauses.append("detail_json LIKE ?")
        args.append(f"%{entity_id[:16]}%")
    else:
        return None
    sql = f"""SELECT etype, summary, detail_json FROM agent_timeline
              WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT 8"""
    try:
        rows = conn.execute(sql, tuple(args)).fetchall()
    except sqlite3.Error:
        return None
    for row in rows:
        ev = _timeline_evidence(row)
        cmd = str(ev.get("command_line") or ev.get("command") or "").strip()
        if cmd:
            return ev
    return None


def _apply_command_line_backfill(
    conn: sqlite3.Connection,
    agent_id: str,
    d: Dict[str, Any],
) -> bool:
    if str(d.get("command_line") or d.get("command") or "").strip():
        return False
    chain = d.get("chain")
    if isinstance(chain, list):
        for c in reversed(chain):
            if not isinstance(c, dict):
                continue
            cmd = str(c.get("command_line") or c.get("command") or "").strip()
            if cmd:
                d["command_line"] = cmd
                if not d.get("pid") and c.get("pid"):
                    d["pid"] = c["pid"]
                if not d.get("process_name") and c.get("process_name"):
                    d["process_name"] = c["process_name"]
                if not d.get("path") and (c.get("path") or c.get("image")):
                    d["path"] = c.get("path") or c.get("image")
                return True
    try:
        pid = int(d.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    eid = str(d.get("entity_id") or "")
    info = _find_process_command(conn, agent_id, pid=pid, entity_id=eid)
    if not info:
        return False
    cmd = str(info.get("command_line") or info.get("command") or "").strip()
    if not cmd:
        return False
    d["command_line"] = cmd
    for k in ("path", "name", "process_name", "ppid", "user", "parent_name"):
        if not d.get(k) and info.get(k):
            d[k] = info[k]
    return True


def _find_persist_evidence(
    conn: sqlite3.Connection,
    agent_id: str,
    *,
    pid: int = 0,
) -> Optional[Dict[str, Any]]:
    clauses = ["agent_id=?", "etype LIKE 'persist_%'"]
    args: List[Any] = [agent_id]
    if pid:
        clauses.append("detail_json LIKE ?")
        args.append(f'%"pid": {pid}%')
    sql = f"""SELECT etype, summary, detail_json, ts FROM agent_timeline
              WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT 5"""
    try:
        rows = conn.execute(sql, tuple(args)).fetchall()
    except sqlite3.Error:
        return None
    if not rows:
        rows = conn.execute(
            """SELECT etype, summary, detail_json, ts FROM agent_timeline
               WHERE agent_id=? AND etype LIKE 'persist_%' ORDER BY id DESC LIMIT 3""",
            (agent_id,),
        ).fetchall()
    if not rows:
        return None
    return _timeline_evidence(rows[0])


def _find_network_evidence(
    conn: sqlite3.Connection,
    agent_id: str,
    *,
    pid: int = 0,
    entity_id: str = "",
    around_ts: str,
) -> Optional[Dict[str, Any]]:
    args: List[Any] = [agent_id]
    clauses = ["agent_id=?", "etype='network_connect_etw'"]
    if pid:
        clauses.append("(detail_json LIKE ? OR summary LIKE ?)")
        args.extend([f'%"pid": {pid}%', f"%({pid}%)%"])
    elif entity_id:
        clauses.append("detail_json LIKE ?")
        args.append(f'%{entity_id[:16]}%')
    sql = f"""SELECT etype, summary, detail_json, ts FROM agent_timeline
              WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT 20"""
    try:
        rows = conn.execute(sql, tuple(args)).fetchall()
    except sqlite3.Error:
        return None
    if not rows:
        rows = conn.execute(
            """SELECT etype, summary, detail_json, ts FROM agent_timeline
               WHERE agent_id=? AND etype='network_connect_etw' ORDER BY id DESC LIMIT 5""",
            (agent_id,),
        ).fetchall()
    if not rows:
        return None
    return _timeline_evidence(rows[0])


def _find_registry_chain(
    conn: sqlite3.Connection,
    agent_id: str,
    steps: List[Dict[str, Any]],
    *,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    try:
        rows = conn.execute(
            """SELECT etype, summary, detail_json, ts FROM agent_timeline
               WHERE agent_id=? AND etype='registry_set' ORDER BY id DESC LIMIT ?""",
            (agent_id, max(limit * 3, 24)),
        ).fetchall()
    except sqlite3.Error:
        return []
    rows = list(reversed(rows))
    chain: List[Dict[str, Any]] = []
    step_i = 0
    for row in rows:
        if step_i >= len(steps):
            break
        try:
            det = json.loads(row["detail_json"] or "{}")
        except Exception:
            det = {}
        if not isinstance(det, dict):
            det = {}
        if _step_match(steps[step_i], row["etype"], row["summary"], det):
            chain.append(_timeline_evidence(row))
            step_i += 1
    if len(chain) >= 2:
        return chain
    # 宽松：最近 N 条 registry_set
    if len(rows) >= 2:
        return [_timeline_evidence(r) for r in rows[-2:]]
    return chain


def _find_generic_sequence_chain(
    conn: sqlite3.Connection,
    agent_id: str,
    steps: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not steps:
        return []
    etypes = list({str(s.get("etype") or "").strip() for s in steps if s.get("etype")})
    if not etypes:
        return []
    placeholders = ",".join("?" for _ in etypes)
    try:
        rows = conn.execute(
            f"""SELECT etype, summary, detail_json, ts FROM agent_timeline
                WHERE agent_id=? AND etype IN ({placeholders}) ORDER BY id DESC LIMIT 80""",
            (agent_id, *etypes),
        ).fetchall()
    except sqlite3.Error:
        return []
    rows = list(reversed(rows))
    chain: List[Dict[str, Any]] = []
    step_i = 0
    for row in rows:
        if step_i >= len(steps):
            break
        try:
            det = json.loads(row["detail_json"] or "{}")
        except Exception:
            det = {}
        if _step_match(steps[step_i], row["etype"], row["summary"], det or {}):
            chain.append(_timeline_evidence(row))
            step_i += 1
    return chain if len(chain) >= len(steps) else chain


def enrich_detail_from_timeline(
    conn: sqlite3.Connection,
    *,
    agent_id: str,
    title: str,
    detail: Dict[str, Any],
    created_at: str = "",
) -> Tuple[Dict[str, Any], bool]:
    """返回 (detail, changed)。"""
    d = dict(detail or {})
    changed = False
    if _apply_command_line_backfill(conn, agent_id, d):
        changed = True

    if not detail_is_thin(d):
        if d.get("failed") and not d.get("matched"):
            m = _sca_matched(d)
            if m:
                d["matched"] = m
                d.setdefault("etype", "sca_fail")
                changed = True
        if changed and not d.get("matched") and d.get("command_line"):
            d["matched"] = str(d["command_line"])[:500]
        return d, changed

    et = str(d.get("etype") or "")
    t = str(title or "")

    if d.get("failed") and isinstance(d["failed"], list):
        m = _sca_matched(d)
        if m:
            d["matched"] = m
            d["etype"] = d.get("etype") or "sca_fail"
            return d, True

    if et == "evm_hit" or t.startswith("EVM") or t.startswith("EVM："):
        src_et = str(d.get("source_etype") or "")
        if src_et.startswith("network") or d.get("rule_id") == "sensor-etw-net":
            ev = _find_network_evidence(
                conn, agent_id,
                pid=int(d.get("pid") or 0),
                entity_id=str(d.get("entity_id") or ""),
                around_ts=str(d.get("event_ts") or created_at),
            )
            if ev:
                for k, v in ev.items():
                    if v not in (None, "") and not d.get(k):
                        d[k] = v
                d["matched"] = d.get("matched") or _build_matched_from_chain([ev])
                if not d.get("source_summary") and ev.get("summary"):
                    d["source_summary"] = ev["summary"]
                changed = True
        elif src_et.startswith("registry") or "注册表" in t:
            chain = _find_registry_chain(conn, agent_id, [{"etype": "registry_set"}], limit=2)
            if chain:
                d["chain"] = chain
                d["matched"] = _build_matched_from_chain(chain)
                changed = True
        elif src_et.startswith("persist") or "持久化" in t:
            ev = _find_persist_evidence(conn, agent_id, pid=int(d.get("pid") or 0))
            if ev:
                for k, v in ev.items():
                    if v not in (None, "") and not d.get(k):
                        d[k] = v
                d["matched"] = d.get("matched") or str(ev.get("summary") or ev.get("path") or "")[:500]
                if ev.get("summary"):
                    d["source_summary"] = ev["summary"]
                changed = True

    if et == "ptm_hit" or t.startswith("PTM") or "PTM:" in t:
        rid = str(d.get("rule_id") or "")
        rule = _load_ptm_rules().get(rid) or {}
        steps = rule.get("steps") if isinstance(rule.get("steps"), list) else []
        n = int(d.get("steps") or len(steps) or 2)
        chain: List[Dict[str, Any]] = []
        if steps:
            if all(str(s.get("etype") or "") == "registry_set" for s in steps[:n]):
                chain = _find_registry_chain(conn, agent_id, steps[:n])
            else:
                chain = _find_generic_sequence_chain(conn, agent_id, steps[:n])
        if len(chain) < 2:
            chain = _find_registry_chain(conn, agent_id, [{"etype": "registry_set"}] * min(n, 2))
        if chain:
            d["chain"] = chain
            d["matched"] = _build_matched_from_chain(chain)
            if rule.get("title"):
                d.setdefault("rule_title", rule["title"])
            changed = True

    if _apply_command_line_backfill(conn, agent_id, d):
        changed = True
    if not str(d.get("matched") or "").strip() and str(d.get("command_line") or "").strip():
        d["matched"] = str(d["command_line"])[:500]
        changed = True
    return d, changed


def backfill_agent_events(
    conn: sqlite3.Connection,
    *,
    limit: int = 500,
    write: bool = True,
) -> Dict[str, Any]:
    rows = conn.execute(
        """SELECT id, agent_id, title, detail, created_at FROM agent_events
           ORDER BY id DESC LIMIT ?""",
        (int(limit),),
    ).fetchall()
    scanned = fixed = 0
    for row in rows:
        scanned += 1
        d = _parse_detail(row["detail"])
        has_cmd = bool(str(d.get("command_line") or d.get("command") or "").strip())
        if not detail_is_thin(d) and has_cmd:
            continue
        new_d, changed = enrich_detail_from_timeline(
            conn,
            agent_id=str(row["agent_id"] or ""),
            title=str(row["title"] or ""),
            detail=d,
            created_at=str(row["created_at"] or ""),
        )
        if not changed:
            continue
        fixed += 1
        if write:
            from . import agent_protocol as ap
            payload = json.dumps(new_d, ensure_ascii=False, default=str)
            payload = ap.fit_detail(new_d) if hasattr(ap, "fit_detail") else payload[:4000]
            conn.execute(
                "UPDATE agent_events SET detail=?, updated_at=? WHERE id=?",
                (payload, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()), int(row["id"])),
            )
    if write and fixed:
        conn.commit()
    return {"ok": True, "scanned": scanned, "fixed": fixed}
