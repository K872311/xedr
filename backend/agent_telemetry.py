# -*- coding: utf-8 -*-
"""阶段 2 遥测落库：进程实体（含墓碑）与 DNS 域名聚合。

- 进程实体：Agent 以 boot_id + pid + 创建时间(100ns) 生成 entity_id，服务端按 (agent_id, entity_id)
  upsert，进程退出只改 exit_time，不删除，便于事后按实体追溯父子链与关联事件。
- DNS：按 (agent_id, domain) 聚合首末次时间、次数、NXDOMAIN 次数、进程与应答 IP，支持跨主机狩猎。
写入发生在时间线入库的同一连接/事务里（v2 批量上报时与回执一起提交）。
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

PROC_CREATE = {"process_create", "process_create_etw", "process_create_live", "process_create_kernel"}
PROC_EXIT = {"process_exit", "process_exit_etw", "process_exit_kernel"}
DNS_TYPES = {"dns_query", "dns_summary", "dns_nx_burst"}
_last_purge = 0.0


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _s(v: Any, n: int = 512) -> str:
    return str(v if v is not None else "")[:n]


def _i(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0


def _merge_list(raw: str, add: Iterable[str], cap: int) -> str:
    try:
        cur = json.loads(raw or "[]")
        if not isinstance(cur, list):
            cur = []
    except Exception:
        cur = []
    for x in add:
        x = str(x or "").strip()
        if x and x not in cur:
            cur.append(x)
    return json.dumps(cur[-cap:], ensure_ascii=False)


def migrate(conn: sqlite3.Connection) -> None:
    """agent_protocol 迁移 v4 调用。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_processes (
               agent_id TEXT NOT NULL,
               entity_id TEXT NOT NULL,
               boot_id TEXT DEFAULT '',
               pid INTEGER DEFAULT 0,
               ppid INTEGER DEFAULT 0,
               parent_entity_id TEXT DEFAULT '',
               name TEXT DEFAULT '',
               path TEXT DEFAULT '',
               command_line TEXT DEFAULT '',
               user TEXT DEFAULT '',
               integrity TEXT DEFAULT '',
               elevated TEXT DEFAULT '',
               create_time TEXT DEFAULT '',
               create_time_100ns INTEGER DEFAULT 0,
               exit_time TEXT DEFAULT '',
               exit_code INTEGER,
               source TEXT DEFAULT '',
               first_seen TEXT DEFAULT '',
               last_seen TEXT DEFAULT '',
               PRIMARY KEY(agent_id, entity_id)
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_pid ON agent_processes(agent_id, pid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_parent ON agent_processes(agent_id, parent_entity_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_proc_seen ON agent_processes(agent_id, last_seen)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_dns (
               agent_id TEXT NOT NULL,
               domain TEXT NOT NULL,
               first_seen TEXT DEFAULT '',
               last_seen TEXT DEFAULT '',
               hits INTEGER DEFAULT 0,
               nx_hits INTEGER DEFAULT 0,
               last_qtype TEXT DEFAULT '',
               last_status TEXT DEFAULT '',
               processes_json TEXT DEFAULT '[]',
               answers_json TEXT DEFAULT '[]',
               max_dga REAL DEFAULT 0,
               PRIMARY KEY(agent_id, domain)
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_domain ON agent_dns(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_seen ON agent_dns(agent_id, last_seen)")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(agent_timeline)").fetchall()}
    if "entity_id" not in cols:
        conn.execute("ALTER TABLE agent_timeline ADD COLUMN entity_id TEXT DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tl_entity ON agent_timeline(agent_id, entity_id)")


def apply(conn: sqlite3.Connection, agent_id: str, events: List[Tuple[str, Dict[str, Any], str]]) -> Dict[str, int]:
    """events: [(etype, detail, ts)]，含被展示过滤掉的事件（实体状态不受展示开关影响）。"""
    procs = dns = 0
    now = _now()
    for etype, d, ts in events:
        if not isinstance(d, dict):
            continue
        try:
            if etype in PROC_CREATE and d.get("entity_id"):
                _upsert_proc_create(conn, agent_id, d, ts, now, etype)
                procs += 1
            elif etype in PROC_EXIT and d.get("entity_id"):
                _upsert_proc_exit(conn, agent_id, d, ts, now)
                procs += 1
            elif etype in DNS_TYPES:
                dns += _apply_dns(conn, agent_id, etype, d, ts)
        except sqlite3.OperationalError as e:
            # 表尚未迁移（极端情况下旧库）：不影响时间线主写入
            if "no such table" in str(e):
                return {"processes": 0, "dns": 0}
            raise
    _maybe_purge(conn)
    return {"processes": procs, "dns": dns}


def _upsert_proc_create(conn: sqlite3.Connection, aid: str, d: Dict[str, Any], ts: str, now: str, etype: str) -> None:
    conn.execute(
        """INSERT INTO agent_processes(agent_id, entity_id, boot_id, pid, ppid, parent_entity_id, name, path,
               command_line, user, integrity, elevated, create_time, create_time_100ns, source, first_seen, last_seen)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(agent_id, entity_id) DO UPDATE SET
               boot_id=COALESCE(NULLIF(excluded.boot_id,''), boot_id),
               ppid=CASE WHEN excluded.ppid>0 THEN excluded.ppid ELSE ppid END,
               parent_entity_id=COALESCE(NULLIF(excluded.parent_entity_id,''), parent_entity_id),
               name=COALESCE(NULLIF(excluded.name,''), name),
               path=COALESCE(NULLIF(excluded.path,''), path),
               command_line=COALESCE(NULLIF(excluded.command_line,''), command_line),
               user=COALESCE(NULLIF(excluded.user,''), user),
               integrity=COALESCE(NULLIF(excluded.integrity,''), integrity),
               elevated=COALESCE(NULLIF(excluded.elevated,''), elevated),
               create_time_100ns=CASE WHEN excluded.create_time_100ns>0 THEN excluded.create_time_100ns ELSE create_time_100ns END,
               last_seen=excluded.last_seen""",
        (
            aid, _s(d.get("entity_id"), 64), _s(d.get("boot_id"), 32), _i(d.get("pid")), _i(d.get("ppid")),
            _s(d.get("parent_entity_id"), 64), _s(d.get("name"), 260), _s(d.get("path"), 520),
            _s(d.get("command_line"), 2000), _s(d.get("user"), 128), _s(d.get("integrity"), 32),
            _s(d.get("elevated"), 8), _s(d.get("create_time") or ts, 40), _i(d.get("create_time_100ns")),
            etype, now, now,
        ),
    )


def _upsert_proc_exit(conn: sqlite3.Connection, aid: str, d: Dict[str, Any], ts: str, now: str) -> None:
    code = d.get("exit_code")
    conn.execute(
        """INSERT INTO agent_processes(agent_id, entity_id, boot_id, pid, ppid, parent_entity_id, name, path,
               create_time_100ns, exit_time, exit_code, source, first_seen, last_seen)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(agent_id, entity_id) DO UPDATE SET
               exit_time=excluded.exit_time,
               exit_code=COALESCE(excluded.exit_code, exit_code),
               name=COALESCE(NULLIF(name,''), excluded.name),
               path=COALESCE(NULLIF(path,''), excluded.path),
               last_seen=excluded.last_seen""",
        (
            aid, _s(d.get("entity_id"), 64), _s(d.get("boot_id"), 32), _i(d.get("pid")), _i(d.get("ppid")),
            _s(d.get("parent_entity_id"), 64), _s(d.get("name"), 260), _s(d.get("path"), 520),
            _i(d.get("create_time_100ns")), _s(ts, 40), _i(code) if code is not None else None,
            "exit", now, now,
        ),
    )


def _apply_dns(conn: sqlite3.Connection, aid: str, etype: str, d: Dict[str, Any], ts: str) -> int:
    proc = _s(d.get("process_name"), 128)
    if etype == "dns_query":
        dom = _s(d.get("query"), 253).lower().rstrip(".")
        if not dom:
            return 0
        nx = 1 if str(d.get("status_name") or "") == "NXDOMAIN" else 0
        answers = [str(x) for x in (d.get("answers") or []) if x][:10]
        hits = 1 + _i(d.get("repeat_prev_window"))
        _upsert_dns(conn, aid, dom, ts, hits, nx, _s(d.get("qtype_name"), 16), _s(d.get("status_name"), 16),
                    [proc] if proc else [], answers, float(d.get("dga_score") or 0))
        return 1
    if etype == "dns_summary":
        n = 0
        for it in (d.get("top") or [])[:20]:
            if not isinstance(it, dict):
                continue
            dom = _s(it.get("query"), 253).lower().rstrip(".")
            # 首条查询已计 1 次，汇总里多出来的才是被合并的重复
            extra = max(0, _i(it.get("count")) - 1)
            if dom and extra:
                _upsert_dns(conn, aid, dom, ts, extra, 0, "", "", [proc] if proc else [], [], 0.0)
                n += 1
        return n
    if etype == "dns_nx_burst":
        n = 0
        for dom in (d.get("samples") or [])[:30]:
            dom = _s(dom, 253).lower().rstrip(".")
            if dom:
                _upsert_dns(conn, aid, dom, ts, 0, 0, "", "NXDOMAIN", [proc] if proc else [], [], 0.0)
                n += 1
        return n
    return 0


def _upsert_dns(conn: sqlite3.Connection, aid: str, dom: str, ts: str, hits: int, nx: int, qtype: str,
                status: str, procs: List[str], answers: List[str], dga: float) -> None:
    row = conn.execute(
        "SELECT processes_json, answers_json FROM agent_dns WHERE agent_id=? AND domain=?", (aid, dom)
    ).fetchone()
    if row is None:
        conn.execute(
            """INSERT INTO agent_dns(agent_id, domain, first_seen, last_seen, hits, nx_hits, last_qtype, last_status,
                   processes_json, answers_json, max_dga) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (aid, dom, ts, ts, hits, nx, qtype, status, _merge_list("[]", procs, 10),
             _merge_list("[]", answers, 16), dga),
        )
        return
    conn.execute(
        """UPDATE agent_dns SET last_seen=MAX(last_seen, ?), first_seen=MIN(first_seen, ?), hits=hits+?, nx_hits=nx_hits+?,
               last_qtype=COALESCE(NULLIF(?,''), last_qtype), last_status=COALESCE(NULLIF(?,''), last_status),
               processes_json=?, answers_json=?, max_dga=MAX(max_dga, ?)
           WHERE agent_id=? AND domain=?""",
        (ts, ts, hits, nx, qtype, status, _merge_list(row[0], procs, 10), _merge_list(row[1], answers, 16),
         dga, aid, dom),
    )


def _maybe_purge(conn: sqlite3.Connection) -> None:
    global _last_purge
    if time.time() - _last_purge < 3600:
        return
    _last_purge = time.time()
    try:
        from . import agent_store
        days = int(agent_store.retention_config().get("timeline_days") or 14)
    except Exception:
        days = 14
    cut = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))
    conn.execute("DELETE FROM agent_processes WHERE last_seen<?", (cut,))
    cut_dns = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - max(days, 30) * 86400))
    conn.execute("DELETE FROM agent_dns WHERE last_seen<?", (cut_dns,))


# ---------- 查询 ----------

def _rows(conn: sqlite3.Connection, sql: str, args: tuple) -> List[Dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def list_processes(agent_id: str, *, q: str = "", alive: Optional[bool] = None, limit: int = 200) -> Dict[str, Any]:
    from . import agent_edr
    agent_edr.ensure()
    limit = max(1, min(int(limit or 200), 1000))
    clauses, args = ["agent_id=?"], [agent_id]
    if q:
        like = f"%{q}%"
        clauses.append("(name LIKE ? OR path LIKE ? OR command_line LIKE ? OR entity_id=? OR CAST(pid AS TEXT)=?)")
        args += [like, like, like, q, q]
    if alive is True:
        clauses.append("exit_time=''")
    elif alive is False:
        clauses.append("exit_time<>''")
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            items = _rows(conn, f"SELECT * FROM agent_processes WHERE {' AND '.join(clauses)} "
                                "ORDER BY create_time DESC, last_seen DESC LIMIT ?", (*args, limit))
        finally:
            conn.close()
    return {"ok": True, "items": items}


def process_detail(agent_id: str, entity_id: str, *, events_limit: int = 200) -> Dict[str, Any]:
    from . import agent_edr
    agent_edr.ensure()
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            got = _rows(conn, "SELECT * FROM agent_processes WHERE agent_id=? AND entity_id=?", (agent_id, entity_id))
            ent = got[0] if got else None
            ancestors: List[Dict[str, Any]] = []
            cur = ent
            seen = {entity_id}
            while cur and cur.get("parent_entity_id") and len(ancestors) < 12:
                pid = cur["parent_entity_id"]
                if pid in seen:
                    break
                seen.add(pid)
                p = _rows(conn, "SELECT * FROM agent_processes WHERE agent_id=? AND entity_id=?", (agent_id, pid))
                if not p:
                    ancestors.append({"entity_id": pid, "missing": True})
                    break
                ancestors.append(p[0])
                cur = p[0]
            children = _rows(conn, "SELECT * FROM agent_processes WHERE agent_id=? AND parent_entity_id=? "
                                   "ORDER BY create_time LIMIT 200", (agent_id, entity_id))
            events = _rows(conn, "SELECT id, etype, summary, severity, ts, detail_json FROM agent_timeline "
                                 "WHERE agent_id=? AND entity_id=? ORDER BY ts DESC, id DESC LIMIT ?",
                           (agent_id, entity_id, max(1, min(int(events_limit or 200), 1000))))
        finally:
            conn.close()
    if not ent and not events:
        return {"ok": False, "error": "进程实体不存在或已过保留期"}
    counts: Dict[str, int] = {}
    for e in events:
        counts[e["etype"]] = counts.get(e["etype"], 0) + 1
    return {"ok": True, "entity": ent, "ancestors": ancestors, "children": children,
            "events": events, "event_counts": counts}


def _looks_ipv4(s: str) -> bool:
    parts = str(s or "").strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _dns_ioc_db_path() -> Optional[Path]:
    """DNS 情报源：只用项目根 ioc_data.db（或 FORENSIC_IOC_DB）。禁止回退 ioc/、ioc_update。"""
    try:
        from . import config
        root = (Path(getattr(config, "ROOT", ".")) / "ioc_data.db").resolve()
    except Exception:
        root = Path("ioc_data.db").resolve()
    import os
    env = (os.getenv("FORENSIC_IOC_DB") or "").strip()
    if env:
        p = Path(env).resolve()
        if "ioc_update" in {x.lower() for x in p.parts}:
            return None
        return p if p.is_file() else None
    if "ioc_update" in {x.lower() for x in root.parts}:
        return None
    return root if root.is_file() else None


_ioc_ro_lock = threading.Lock()
_ioc_ro_state: Dict[str, Any] = {"sig": None, "conn": None, "has_ip_idx": False}


def _ioc_text_factory(b: Union[bytes, bytearray, str]) -> str:
    if isinstance(b, str):
        return b
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("utf-8", "replace")


def _get_ioc_ro_conn(db_path: Path) -> tuple[Optional[sqlite3.Connection], str, bool]:
    """复用只读连接；返回 (conn, err, has_ip_idx)。"""
    try:
        st = db_path.stat()
        sig = (str(db_path), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))), int(st.st_size))
    except Exception as e:
        return None, f"无法访问情报库: {e}", False
    with _ioc_ro_lock:
        if _ioc_ro_state["conn"] is not None and _ioc_ro_state["sig"] == sig:
            return _ioc_ro_state["conn"], "", bool(_ioc_ro_state["has_ip_idx"])
        old = _ioc_ro_state["conn"]
        _ioc_ro_state["conn"] = None
        _ioc_ro_state["sig"] = None
        if old is not None:
            try:
                old.close()
            except Exception:
                pass
        conn = None
        try:
            conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=15, check_same_thread=False)
            conn.text_factory = _ioc_text_factory
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("SELECT 1 FROM ioc_records LIMIT 1").fetchone()
        except Exception as e1:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            try:
                conn = sqlite3.connect(str(db_path), timeout=15, check_same_thread=False)
                conn.text_factory = _ioc_text_factory
                conn.row_factory = sqlite3.Row
                conn.execute("SELECT 1 FROM ioc_records LIMIT 1").fetchone()
            except Exception as e2:
                err = str(e2 or e1)
                if "malformed" in err.lower():
                    return None, f"ioc_data.db 损坏（malformed），请替换完整库：{db_path}", False
                return None, f"无法打开情报库: {err}", False
        has_ip_idx = False
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_ip_only'"
            ).fetchone()
            has_ip_idx = bool(row)
        except Exception:
            has_ip_idx = False
        _ioc_ro_state["conn"] = conn
        _ioc_ro_state["sig"] = sig
        _ioc_ro_state["has_ip_idx"] = has_ip_idx
        return conn, "", has_ip_idx


def _norm_ioc_vals(values: List[str]) -> List[str]:
    out, seen = [], set()
    for v in values or []:
        s = str(v or "").strip().lower().strip("[]").rstrip(".")
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _exact_ioc_lookup_conn(
    conn: sqlite3.Connection,
    kind: str,
    values: List[str],
    *,
    has_ip_idx: bool = False,
) -> tuple[Dict[str, List[Dict[str, Any]]], str]:
    """精确匹配：domain 走 (type,value) 索引；IP 只查 ip_only（库内 value 多为 ip:port）。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    vals = _norm_ioc_vals(values)
    for s in vals:
        out[s] = []
    if not vals:
        return out, ""
    kind = "ip" if kind == "ip" else "domain"
    try:
        chunk = 200
        for i in range(0, len(vals), chunk):
            batch = vals[i : i + chunk]
            ph = ",".join("?" * len(batch))
            if kind == "ip":
                # 关键：用 idx_ip_only；勿带 type=? 否则会扫全量 IP
                if has_ip_idx:
                    sql = (
                        f"SELECT id, value, ip_only, source, malware FROM ioc_records "
                        f"INDEXED BY idx_ip_only WHERE ip_only IN ({ph})"
                    )
                else:
                    sql = (
                        f"SELECT id, value, ip_only, source, malware FROM ioc_records "
                        f"WHERE ip_only IN ({ph}) AND ip_only!=''"
                    )
                rows = conn.execute(sql, batch).fetchall()
            else:
                sql = (
                    f"SELECT id, value, ip_only, source, malware FROM ioc_records "
                    f"WHERE type='domain' AND value IN ({ph})"
                )
                rows = conn.execute(sql, batch).fetchall()
            skip_benign = None
            if kind == "domain":
                try:
                    from .ioc_db import is_benign_host as skip_benign
                except Exception:
                    skip_benign = None
            for r in rows or []:
                value = str(r["value"] or "").strip().lower()
                ip_only = str(r["ip_only"] or "").strip().lower()
                matched = ip_only if kind == "ip" and ip_only else value
                if kind == "domain" and skip_benign and matched and skip_benign(matched):
                    continue
                hit = {
                    "matched": matched,
                    "type": kind,
                    "malware": str(r["malware"] or ""),
                    "source": str(r["source"] or ""),
                    "id": r["id"],
                }
                key = ip_only if kind == "ip" else value
                if key in out:
                    out[key].append(hit)
        return out, ""
    except Exception as e:
        err = str(e)
        if "malformed" in err.lower():
            return out, f"ioc_data.db 损坏（malformed）"
        return out, f"查询失败: {err}"


def _enrich_dns_ioc(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """只对照项目根 ioc_data.db：域名/应答 IP 精确匹配。不读 ioc_update。"""
    meta: Dict[str, Any] = {
        "lib": "ioc_data", "path": "", "matched": 0, "ok": False,
        "hint": "", "mode": "exact", "ms": 0,
    }
    for it in items:
        it["ioc_hit"] = False
        it["ioc_hits"] = []
    if not items:
        return meta

    t0 = time.perf_counter()
    db_path = _dns_ioc_db_path()
    meta["path"] = str(db_path) if db_path else str(Path("ioc_data.db"))
    if not db_path:
        meta["hint"] = "未找到项目根 ioc_data.db（不会回退 ioc/ 或 ioc_update）"
        return meta

    domains: List[str] = []
    ips: List[str] = []
    dseen, iseen = set(), set()
    for it in items:
        dom = str(it.get("domain") or "").strip().lower().rstrip(".")
        if dom and dom not in dseen and not _looks_ipv4(dom) and "." in dom:
            dseen.add(dom)
            domains.append(dom)
        for raw in it.get("answers") or []:
            a = str(raw or "").strip().lower().strip("[]")
            if a and _looks_ipv4(a) and a not in iseen:
                iseen.add(a)
                ips.append(a)

    conn, err, has_ip_idx = _get_ioc_ro_conn(db_path)
    if err or conn is None:
        meta["hint"] = err or "情报库连接失败"
        meta["ok"] = False
        meta["ms"] = int((time.perf_counter() - t0) * 1000)
        return meta

    dom_map: Dict[str, List[Dict[str, Any]]] = {}
    ip_map: Dict[str, List[Dict[str, Any]]] = {}
    if domains:
        dom_map, err = _exact_ioc_lookup_conn(conn, "domain", domains, has_ip_idx=has_ip_idx)
    if not err and ips:
        ip_map, err2 = _exact_ioc_lookup_conn(conn, "ip", ips, has_ip_idx=has_ip_idx)
        err = err or err2
    if err:
        meta["hint"] = err
        meta["ok"] = False
        meta["ms"] = int((time.perf_counter() - t0) * 1000)
        return meta
    meta["ok"] = True

    matched_n = 0
    for it in items:
        hits: List[Dict[str, Any]] = []
        dom = str(it.get("domain") or "").strip().lower().rstrip(".")
        for h in (dom_map.get(dom) or [])[:3]:
            hits.append({**h, "via": "domain"})
        for raw in it.get("answers") or []:
            a = str(raw or "").strip().lower().strip("[]")
            if not _looks_ipv4(a):
                continue
            for h in (ip_map.get(a) or [])[:2]:
                hits.append({**h, "via": "answer"})
        uniq, seen_k = [], set()
        for h in hits:
            key = f"{h.get('type')}|{h.get('matched')}|{h.get('malware')}"
            if key in seen_k:
                continue
            seen_k.add(key)
            uniq.append(h)
        it["ioc_hit"] = bool(uniq)
        it["ioc_hits"] = uniq[:5]
        if uniq:
            matched_n += 1
    meta["matched"] = matched_n
    meta["ms"] = int((time.perf_counter() - t0) * 1000)
    return meta


def list_dns(
    agent_id: str = "",
    *,
    q: str = "",
    nx_only: bool = False,
    limit: int = 200,
    match_ioc: bool = True,
) -> Dict[str, Any]:
    from . import agent_edr
    agent_edr.ensure()
    limit = max(1, min(int(limit or 200), 1000))
    clauses, args = [], []
    if agent_id:
        clauses.append("d.agent_id=?")
        args.append(agent_id)
    if q:
        clauses.append("(d.domain LIKE ? OR d.answers_json LIKE ? OR d.processes_json LIKE ?)")
        like = f"%{q.lower()}%"
        args += [like, f"%{q}%", f"%{q}%"]
    if nx_only:
        clauses.append("d.nx_hits>0")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with agent_edr._lock:
        conn = agent_edr._connect()
        try:
            items = _rows(conn, f"SELECT d.*, a.hostname FROM agent_dns d LEFT JOIN agents a ON a.agent_id=d.agent_id"
                                f"{where} ORDER BY d.last_seen DESC LIMIT ?", (*args, limit))
        finally:
            conn.close()
    for it in items:
        for k in ("processes_json", "answers_json"):
            try:
                it[k.replace("_json", "")] = json.loads(it.pop(k) or "[]")
            except Exception:
                it[k.replace("_json", "")] = []
        it.setdefault("ioc_hit", False)
        it.setdefault("ioc_hits", [])
    ioc_meta: Dict[str, Any] = {"lib": "ioc_data", "matched": 0, "ok": False}
    if match_ioc and items:
        ioc_meta = _enrich_dns_ioc(items)
    return {"ok": True, "items": items, "ioc": ioc_meta}
