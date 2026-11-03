# -*- coding: utf-8 -*-
"""EDR 扩展：远程处置指令、审计、时间线、策略、狩猎。"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import agent_protocol, config, timeline_filter

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_commands (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT DEFAULT '{}',
    status TEXT DEFAULT 'pending',
    result_json TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT '',
    acked_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cmd_agent_status ON agent_commands(agent_id, status);

CREATE TABLE IF NOT EXISTS agent_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT DEFAULT '',
    action TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    actor TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON agent_audit(created_at);

CREATE TABLE IF NOT EXISTS agent_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    etype TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    detail_json TEXT DEFAULT '',
    severity TEXT DEFAULT 'info',
    ts TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tl_agent_ts ON agent_timeline(agent_id, ts);
CREATE INDEX IF NOT EXISTS idx_tl_etype ON agent_timeline(etype);
CREATE INDEX IF NOT EXISTS idx_tl_ts ON agent_timeline(ts);
CREATE INDEX IF NOT EXISTS idx_tl_sev_ts ON agent_timeline(severity, ts);

CREATE TABLE IF NOT EXISTS agent_policy (
    scope TEXT PRIMARY KEY,
    policy_json TEXT DEFAULT '{}',
    rev INTEGER DEFAULT 1,
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_groups (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    agent_ids_json TEXT DEFAULT '[]',
    note TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_whitelist (
    id TEXT PRIMARY KEY,
    kind TEXT DEFAULT '',
    value TEXT DEFAULT '',
    note TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_ioc (
    id TEXT PRIMARY KEY,
    ioc_type TEXT DEFAULT '',
    value TEXT DEFAULT '',
    severity TEXT DEFAULT 'high',
    note TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    hits INTEGER DEFAULT 0,
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON agent_ioc(ioc_type, value);

CREATE TABLE IF NOT EXISTS agent_tags (
    agent_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY(agent_id, tag)
);

CREATE TABLE IF NOT EXISTS agent_seq_rules (
    id TEXT PRIMARY KEY,
    title TEXT DEFAULT '',
    severity TEXT DEFAULT 'high',
    window_sec INTEGER DEFAULT 120,
    steps_json TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    note TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS agent_upgrade_packages (
    id TEXT PRIMARY KEY,
    version TEXT DEFAULT '',
    filename TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    note TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    sig_ed25519 TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_upgrade_created ON agent_upgrade_packages(created_at);
"""

_lock = threading.RLock()

# 命令租约：Agent 取走后在 lease 内必须 ack，否则重投；超过 max_attempts 或 deadline 终止。
COMMAND_LEASE_DEFAULT_SEC = 60
COMMAND_LEASE_SEC = {
    "scan_memory": 180, "upgrade": 300, "rollback_upgrade": 300, "refresh_modules": 90,
    "run_cmd": 120, "reg_read": 90, "fs_list": 90, "fs_stat": 60, "fs_read": 120, "fs_volumes": 60,
    "shell_open": 60, "shell_write": 45, "shell_poll": 45, "shell_close": 30,
}
COMMAND_MAX_ATTEMPTS = 3
COMMAND_TTL_DEFAULT_SEC = 1800
COMMAND_TTL_SEC = {"upgrade": 86400, "rollback_upgrade": 86400, "uninstall_agent": 86400,
                   "unisolate_network": 86400, "isolate_network": 3600}
ACTIONS = (
    "kill_process",
    "quarantine_file",
    "isolate_network",
    "unisolate_network",
    "refresh_modules",
    "upgrade",
    "scan_memory",
    "restore_file",
    "rollback_upgrade",
    "cancel_upgrade",
    "uninstall_agent",
    "collect_diagnostics",
    "reg_read",
    "fs_list",
    "fs_stat",
    "fs_read",
    "fs_volumes",
    "live_query",
    "run_cmd",
    "shell_open",
    "shell_write",
    "shell_poll",
    "shell_close",
)

_REMOTE_OPS_READ = frozenset({"reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "live_query", "shell_poll"})
_REMOTE_OPS_SHELL = frozenset({"shell_open", "shell_write", "shell_poll", "shell_close"})
_REMOTE_OPS_ALL = _REMOTE_OPS_READ | frozenset({"run_cmd"}) | _REMOTE_OPS_SHELL


def _remote_ops_policy_cfg() -> Dict[str, Any]:
    try:
        pol = (get_policy("global").get("policy") or {})
    except Exception:
        pol = dict(_DEFAULT_POLICY)
    ro = pol.get("remote_ops") if isinstance(pol.get("remote_ops"), dict) else {}
    return {
        "enabled": bool(pol.get("remote_ops_enabled", ro.get("enabled", True))),
        "read_only": bool(ro.get("read_only", False)),
        "run_cmd_enabled": bool(ro.get("run_cmd_enabled", True)),
        "shell_enabled": bool(ro.get("shell_enabled", True)),
    }


def _validate_remote_ops_command(action: str, params: Dict[str, Any]) -> str:
    act = str(action or "").strip().lower()
    if act not in _REMOTE_OPS_ALL:
        return ""
    cfg = _remote_ops_policy_cfg()
    if not cfg["enabled"]:
        return "远程运维未启用（策略 remote_ops）"
    if act == "run_cmd":
        if cfg["read_only"] or not cfg["run_cmd_enabled"]:
            return "远程命令执行未启用或处于只读模式"
    if act in ("shell_open", "shell_write", "shell_poll", "shell_close") and not cfg["shell_enabled"]:
        return "交互式 Shell 未启用"
    _ = params
    return ""

# ATT&CK 战术顺序（看板列）
_ATTCK_TACTICS = [
    ("initial_access", "初始访问"),
    ("execution", "执行"),
    ("persistence", "持久化"),
    ("privilege_escalation", "权限提升"),
    ("defense_evasion", "防御绕过"),
    ("credential_access", "凭证访问"),
    ("discovery", "发现"),
    ("lateral_movement", "横向移动"),
    ("collection", "收集"),
    ("command_and_control", "命令与控制"),
    ("exfiltration", "数据渗出"),
    ("impact", "影响"),
]

# 粗粒度：模块 / 标题关键字 → 技术
_ATTCK_HINTS = [
    (["日志被清空", "win_audit_clear"], "T1070.001", "defense_evasion"),
    (["账号创建", "win_account_create"], "T1136.001", "persistence"),
    (["加入本地组", "加入组", "加入通用组", "win_group_add"], "T1098", "persistence"),
    (["登录失败", "win_logon_fail"], "T1110", "credential_access"),
    (["显式凭据", "win_explicit_logon"], "T1078", "defense_evasion"),
    (["lsass"], "T1003.001", "credential_access"),
    (["进程打开", "process_access"], "T1055", "defense_evasion"),
    (["疑似dga", "dns_nx_burst", "nxdomain"], "T1568.002", "command_and_control"),
    (["情报 ioc"], "T1071", "command_and_control"),
    (["powershell 脚本块", "win_ps_scriptblock", "win_ps_module"], "T1059.001", "execution"),
    (["服务安装", "win_service_install"], "T1543.003", "persistence"),
    (["计划任务创建", "win_task_create"], "T1053.005", "persistence"),
    (["defender排除", "defender\\", "exclusions", "disableantispyware", "disablerealtimemonitoring"], "T1562.001", "defense_evasion"),
    (["持久化新增", "持久化修改", "winlogon", "appinit", "image file execution", "ifeo"], "T1547.001", "persistence"),
    (["远程线程", "remote_thread"], "T1055", "defense_evasion"),
    (["拦截对 agent", "protect_block"], "T1562.001", "defense_evasion"),
    (["dll 加载", "image_load", "未签名 dll", "目录 dll", "系统目录未签名"], "T1574.002", "defense_evasion"),
    (["fim新增", "fim修改", "fim删除", "fim_add", "fim_modify", "文件完整性"], "T1036.005", "defense_evasion"),
    (["powershell", "pwsh", "cmd.exe", "wscript", "cscript", "编码执行"], "T1059", "execution"),
    (["临时目录", "\\temp\\", "\\appdata\\"], "T1105", "command_and_control"),
    (["计划任务创建", "计划任务更新", "schtasks", "win_task"], "T1053.005", "persistence"),
    (["服务安装", "win_service_install", "服务启动类型"], "T1543.003", "persistence"),
    (["启动项", "run\\\\", "startup"], "T1547.001", "persistence"),
    (["网络隔离", "firewall", "etw外联", "network_connect"], "T1071", "command_and_control"),
    (["ioc 命中", "ioc命中", "file_hash", "哈希"], "T1204", "execution"),
    (["行为序列", "office", "winword", "excel"], "T1566", "initial_access"),
    (["隔离文件", "quarantine", "落地"], "T1105", "command_and_control"),
    (["凭证", "lsass", "mimikatz", "password"], "T1003", "credential_access"),
    (["横向", "psexec", "wmi", "smb"], "T1021", "lateral_movement"),
    (["注册表", "reg ", "registry"], "T1112", "defense_evasion"),
]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _db() -> Path:
    return agent_protocol.db_path()


def _connect() -> sqlite3.Connection:
    amb = agent_protocol.ambient_conn()
    if amb is not None:  # v2 批量事务内共享同一连接
        return amb  # type: ignore[return-value]
    conn = sqlite3.connect(str(_db()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    agent_protocol.migrate(conn)
    return conn


_ensured = False


def ensure() -> None:
    global _ensured
    with _lock:
        conn = _connect()
        # 默认全局策略（避免 get_policy→ensure 递归）
        row = conn.execute("SELECT scope FROM agent_policy WHERE scope='global'").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,1,?)",
                ("global", json.dumps(_DEFAULT_POLICY, ensure_ascii=False), _now()),
            )
            conn.commit()
        conn.close()
        _ensured = True


def _audit(action: str, *, agent_id: str = "", detail: str = "", actor: str = "") -> None:
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO agent_audit(agent_id, action, detail, actor, created_at) VALUES(?,?,?,?,?)",
                (agent_id, action, detail[:2000], actor[:64], _now()),
            )
            conn.commit()
        finally:
            conn.close()


def purge_agent_data(agent_id: str) -> Dict[str, Any]:
    """删除终端后清理时间线、指令、标签等残留。"""
    ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    with _lock:
        conn = _connect()
        try:
            n_tl = conn.execute("DELETE FROM agent_timeline WHERE agent_id=?", (aid,)).rowcount
            n_cmd = conn.execute("DELETE FROM agent_commands WHERE agent_id=?", (aid,)).rowcount
            n_tag = 0
            try:
                n_tag = conn.execute("DELETE FROM agent_tags WHERE agent_id=?", (aid,)).rowcount
            except Exception:
                pass
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "timeline": n_tl, "commands": n_cmd, "tags": n_tag}


_ORPHAN_TABLES = (
    "agent_events", "agent_timeline", "agent_snapshots", "agent_commands",
    "agent_tags", "agent_receipts", "agent_streams",
)


def purge_orphan_agent_data() -> Dict[str, int]:
    """清理已删除终端残留的告警 / 时间线等（旧版本删除不彻底或删除后仍有回传）。"""
    ensure()
    out: Dict[str, int] = {}
    with _lock:
        conn = _connect()
        try:
            for tbl in _ORPHAN_TABLES:
                try:
                    cur = conn.execute(
                        f"DELETE FROM {tbl} WHERE agent_id NOT IN (SELECT agent_id FROM agents)"
                    )
                except sqlite3.Error:
                    continue
                if cur.rowcount:
                    out[tbl] = int(cur.rowcount)
            conn.commit()
        finally:
            conn.close()
    if out.get("agent_events"):
        agent_protocol.bump_live("event")
    return out


def create_command(
    agent_id: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    actor: str = "",
    idempotency_key: str = "",
    ttl_sec: int = 0,
) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    act = str(action or "").strip().lower()
    if not aid or act not in ACTIONS:
        return {"ok": False, "error": "agent_id 或 action 无效"}
    pol_err = _validate_remote_ops_command(act, params or {})
    if pol_err:
        return {"ok": False, "error": pol_err}
    cid = uuid.uuid4().hex
    now = _now()
    blob = json.dumps(params or {}, ensure_ascii=False)
    idem = str(idempotency_key or "").strip()[:96]
    ttl = int(ttl_sec or 0) or COMMAND_TTL_SEC.get(act, COMMAND_TTL_DEFAULT_SEC)
    deadline = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() + ttl))
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT agent_id FROM agents WHERE agent_id=?", (aid,)).fetchone()
            if not row:
                return {"ok": False, "error": "终端不存在"}
            if idem:
                # 同一幂等键且未失败/过期的命令直接复用，避免前端重复点击重复下发
                dup = conn.execute(
                    """SELECT id, status FROM agent_commands
                       WHERE agent_id=? AND idempotency_key=? AND status NOT IN ('failed','expired')
                       ORDER BY created_at DESC LIMIT 1""",
                    (aid, idem),
                ).fetchone()
                if dup:
                    return {"ok": True, "id": dup["id"], "action": act, "status": dup["status"], "deduped": True}
            conn.execute(
                """INSERT INTO agent_commands(id, agent_id, action, params_json, status, created_by, created_at, updated_at,
                                              deadline, idempotency_key, max_attempts, attempts, lease_until)
                   VALUES(?,?,?,?, 'pending', ?, ?, ?, ?, ?, ?, 0, '')""",
                (cid, aid, act, blob, actor[:64], now, now, deadline, idem, COMMAND_MAX_ATTEMPTS),
            )
            conn.commit()
        finally:
            conn.close()
    _audit(f"command:{act}", agent_id=aid, detail=blob, actor=actor)
    agent_protocol.bump_live("command", agent_id=aid, command_id=cid)
    return {"ok": True, "id": cid, "action": act, "status": "pending"}


def poll_commands(agent_id: str, *, limit: int = 10) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            # 只有声明 command.lease 的新 Agent 才会重投（它有本地回执去重）；旧 Agent 保持至多一次
            crow = conn.execute("SELECT capabilities_json FROM agents WHERE agent_id=?", (aid,)).fetchone()
            try:
                lease_ok = "command.lease" in json.loads((crow["capabilities_json"] if crow else "") or "[]")
            except Exception:
                lease_ok = False
            # 1) 过期：超过 deadline 仍未完成 → expired；租约耗尽且重试用完 → failed
            conn.execute(
                """UPDATE agent_commands SET status='expired', updated_at=?,
                          result_json=COALESCE(NULLIF(result_json,''), '{"error":"deadline exceeded"}')
                   WHERE agent_id=? AND status IN ('pending','sent') AND deadline<>'' AND deadline<?""",
                (now, aid, now),
            )
            conn.execute(
                """UPDATE agent_commands SET status='failed', updated_at=?,
                          result_json='{"error":"lease exhausted: agent never acked"}'
                   WHERE agent_id=? AND status='sent' AND lease_until<>'' AND lease_until<? AND attempts>=max_attempts
                     AND ?=1""",
                (now, aid, now, 1 if lease_ok else 0),
            )
            # 2) 取 pending，或租约已过期且仍有重试额度的 sent（Agent 崩溃/ack 丢失时重投）
            rows = conn.execute(
                """SELECT id, action, params_json, created_at, attempts, deadline FROM agent_commands
                   WHERE agent_id=? AND (status='pending'
                      OR (status='sent' AND lease_until<>'' AND lease_until<? AND attempts<max_attempts AND ?=1))
                   ORDER BY created_at ASC LIMIT ?""",
                (aid, now, 1 if lease_ok else 0, max(1, min(int(limit or 10), 50))),
            ).fetchall()
            items = []
            for r in rows:
                try:
                    params = json.loads(r["params_json"] or "{}")
                except Exception:
                    params = {}
                lease_sec = COMMAND_LEASE_SEC.get(r["action"], COMMAND_LEASE_DEFAULT_SEC)
                lease_until = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() + lease_sec))
                conn.execute(
                    """UPDATE agent_commands SET status='sent', updated_at=?, lease_until=?, attempts=attempts+1
                       WHERE id=?""",
                    (now, lease_until, r["id"]),
                )
                items.append({
                    "id": r["id"],
                    "action": r["action"],
                    "params": params,
                    "created_at": r["created_at"],
                    "attempt": int(r["attempts"] or 0) + 1,
                    "lease_sec": lease_sec,
                    "deadline": r["deadline"] or "",
                })
            conn.commit()
            return {"ok": True, "items": items}
        finally:
            conn.close()


def command_owner(command_id: str) -> str:
    ensure()
    with _lock:
        conn = _connect()
        try:
            r = conn.execute("SELECT agent_id FROM agent_commands WHERE id=?", (str(command_id or ""),)).fetchone()
            return str(r["agent_id"]) if r else ""
        finally:
            conn.close()


def ack_command(
    command_id: str,
    *,
    ok: bool,
    result: Optional[Dict[str, Any]] = None,
    caller_agent_id: str = "",
) -> Dict[str, Any]:
    """回执。caller_agent_id 非空时必须与命令所属 Agent 一致（凭据隔离）；重复回执幂等。"""
    ensure()
    cid = str(command_id or "").strip()
    if not cid:
        return {"ok": False, "error": "缺少 command_id"}
    st = "done" if ok else "failed"
    now = _now()
    store_result = dict(result or {})
    with _lock:
        conn_peek = _connect()
        try:
            peek = conn_peek.execute(
                "SELECT agent_id, action FROM agent_commands WHERE id=?", (cid,)
            ).fetchone()
        finally:
            conn_peek.close()
    if peek and peek["action"] == "collect_diagnostics" and ok:
        try:
            from . import agent_diagnostics as adiag

            slim = adiag.persist_from_command_result(str(peek["agent_id"]), cid, store_result)
            if isinstance(slim, dict):
                store_result = slim
        except Exception as e:
            print("[diagnostics] persist:", e)
            if "content_base64" in store_result:
                store_result = {k: v for k, v in store_result.items() if k != "content_base64"}
                store_result["stored"] = False
                store_result["error"] = str(e)[:200]
    blob = json.dumps(store_result, ensure_ascii=False)[:8000]
    with _lock:
        conn = _connect()
        try:
            cur_row = conn.execute(
                "SELECT agent_id, status, acked_at FROM agent_commands WHERE id=?", (cid,)
            ).fetchone()
            if not cur_row:
                return {"ok": False, "error": "指令不存在"}
            if caller_agent_id and cur_row["agent_id"] != caller_agent_id:
                return {"ok": False, "error": "指令不属于该 Agent", "forbidden": True}
            if cur_row["status"] in ("done", "failed") and cur_row["acked_at"]:
                # 重复回执（断网重传 / v2 重放）：保持首个结果，直接确认
                return {"ok": True, "id": cid, "status": cur_row["status"], "duplicate": True}
            conn.execute(
                """UPDATE agent_commands SET status=?, result_json=?, updated_at=?, acked_at=?
                   WHERE id=?""",
                (st, blob, now, now, cid),
            )
            conn.commit()
            row = conn.execute("SELECT agent_id, action FROM agent_commands WHERE id=?", (cid,)).fetchone()
        finally:
            conn.close()
    if row:
        _audit(f"ack:{row['action']}:{st}", agent_id=row["agent_id"], detail=blob)
        agent_protocol.bump_live("command_ack", agent_id=row["agent_id"], command_id=cid, status=st)
        if row["action"] == "scan_memory" and ok:
            _memscan_to_events(row["agent_id"], result or {})
    return {"ok": True, "id": cid, "status": st}


def _memscan_to_events(agent_id: str, result: Dict[str, Any]) -> int:
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    n = 0
    for f in findings[:20]:
        if not isinstance(f, dict):
            continue
        mod = "memory"
        if f.get("building_block"):
            mod = "building_block"
        detail = {
            "scan_mode": result.get("mode"),
            "yara_engine": result.get("yara_engine"),
            "rules_rev": result.get("rules_rev"),
            "engine": f.get("engine"),
            "rule_id": f.get("rule_id"),
            "rule_name": f.get("rule_name"),
            "type": f.get("type"),
            "pid": f.get("pid"),
            "name": f.get("name"),
            "address": f.get("address"),
            "matched_string": f.get("matched_string"),
            "matched_strings": f.get("matched_strings"),
            "mitre": f.get("mitre"),
            "building_block": bool(f.get("building_block")),
            "investigation": "打开进程树核对签名与路径；YARA 命中建议对该 PID 做隔离或内存转储复核。",
        }
        ev = agent_protocol.report_event({
            "agent_id": agent_id,
            "module": mod,
            "severity": str(f.get("severity") or "high"),
            "title": str(f.get("summary") or f.get("title") or f"内存可疑：{f.get('type')}")[:200],
            "detail": detail,
            "building_block": bool(f.get("building_block")),
        })
        if ev.get("ok") and not ev.get("deduped") and not ev.get("suppressed"):
            n += 1
    return n


def list_commands(agent_id: str = "", *, limit: int = 50) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            if agent_id:
                rows = conn.execute(
                    "SELECT * FROM agent_commands WHERE agent_id=? ORDER BY created_at DESC LIMIT ?",
                    (agent_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM agent_commands ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            items = [dict(r) for r in rows]
            return {"ok": True, "items": items}
        finally:
            conn.close()


def _is_agent_self_noise(etype: str, summary: str, detail: Dict[str, Any]) -> bool:
    """过滤端侧噪声：Agent 自写临时脚本 + Windows PowerShell 策略探针。"""
    detail = detail if isinstance(detail, dict) else {}
    parts = [
        str(etype or ""),
        str(summary or ""),
        str(detail.get("path") or ""),
        str(detail.get("name") or ""),
        str(detail.get("FileName") or ""),
        str(detail.get("image") or ""),
        str(detail.get("TargetFilename") or ""),
        str(detail.get("module") or ""),
        str(detail.get("module_name") or ""),
    ]
    blob = " ".join(parts).lower()
    for pre in ("fa-ps-", "fa-etw-", "fa-wevt-", "fa-watch-", "fa-upg-"):
        if pre in blob:
            return True
    # Windows Constrained Language / 执行策略探针（任意扩展中间段：.gfz.ps1 / .xla.ps1）
    if "psscriptpolicytest" in blob:
        return True
    return False


def purge_agent_self_noise_events() -> Dict[str, Any]:
    """清理历史误报：Agent 自写临时脚本晋升成的威胁事件 / 时间线。"""
    ensure()
    patterns = ("%fa-ps-%", "%fa-etw-%", "%fa-wevt-%", "%fa-watch-%", "%fa-upg-%", "%psscriptpolicytest%")
    n_ev = n_tl = 0
    with _lock:
        conn = _connect()
        try:
            for pat in patterns:
                cur = conn.execute(
                    "DELETE FROM agent_events WHERE lower(title) LIKE ? OR lower(detail) LIKE ?",
                    (pat, pat),
                )
                n_ev += int(cur.rowcount or 0)
                cur = conn.execute(
                    "DELETE FROM agent_timeline WHERE lower(summary) LIKE ? OR lower(detail_json) LIKE ?",
                    (pat, pat),
                )
                n_tl += int(cur.rowcount or 0)
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "events_deleted": n_ev, "timeline_deleted": n_tl}


def _apply_process_cmd_patch(
    conn: sqlite3.Connection,
    agent_id: str,
    detail: Dict[str, Any],
    ts: str,
) -> None:
    """Agent 迟到命令行：更新进程实体与近期时间线 detail。"""
    cmd = str(detail.get("command_line") or "").strip()
    if not cmd:
        return
    eid = str(detail.get("entity_id") or "").strip()[:64]
    pid = detail.get("pid")
    now = _now()
    if eid:
        conn.execute(
            """UPDATE agent_processes SET command_line=?, last_seen=?
               WHERE agent_id=? AND entity_id=? AND (command_line IS NULL OR command_line='')""",
            (cmd[:2000], now, agent_id, eid),
        )
    elif pid is not None:
        row = conn.execute(
            """SELECT entity_id FROM agent_processes WHERE agent_id=? AND pid=?
               AND (command_line IS NULL OR command_line='') ORDER BY last_seen DESC LIMIT 1""",
            (agent_id, int(pid)),
        ).fetchone()
        if row:
            conn.execute(
                """UPDATE agent_processes SET command_line=?, last_seen=?
                   WHERE agent_id=? AND entity_id=?""",
                (cmd[:2000], now, agent_id, str(row["entity_id"])),
            )
    rows = conn.execute(
        """SELECT id, detail_json FROM agent_timeline
           WHERE agent_id=? AND etype LIKE 'process_create%' AND ts >= datetime('now', '-2 hours')
           ORDER BY id DESC LIMIT 40""",
        (agent_id,),
    ).fetchall()
    for row in rows:
        try:
            dj = json.loads(row["detail_json"] or "{}")
        except Exception:
            continue
        if not isinstance(dj, dict):
            continue
        if pid is not None and int(dj.get("pid") or 0) != int(pid):
            continue
        if eid and str(dj.get("entity_id") or "") != eid:
            continue
        if str(dj.get("command_line") or "").strip():
            continue
        dj["command_line"] = cmd[:2000]
        dj["cmd_backfill"] = True
        conn.execute(
            "UPDATE agent_timeline SET detail_json=? WHERE id=?",
            (agent_protocol.fit_detail(dj), int(row["id"])),
        )


def ingest_timeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Agent 批量写入时间线条目。"""
    ensure()
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id:
        return {"ok": False, "error": "缺少 agent_id"}
    events = payload.get("events")
    if not isinstance(events, list):
        events = []
    # 单包上限放宽；超出的分批仍由 Agent 侧 drain 保留到下一轮，这里不再静默丢掉大半
    events = events[:800]
    host = str(payload.get("hostname") or "").strip()[:128] or agent_protocol._host_of(agent_id)
    now = _now()
    n = 0
    rows: List[Dict[str, Any]] = []
    tele: List[Any] = []
    detect_events: List[Dict[str, Any]] = []
    with _lock:
        conn = _connect()
        try:
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                etype = str(ev.get("etype") or ev.get("type") or "event")[:64]
                summary = str(ev.get("summary") or ev.get("title") or "")[:300]
                if not summary:
                    continue
                detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {"raw": ev.get("detail")}
                # Agent 自用临时脚本（fa-ps-*.ps1 等）不当作文件告警入库
                if _is_agent_self_noise(etype, summary, detail if isinstance(detail, dict) else {}):
                    continue
                if timeline_filter.is_collector_noise(agent_id, etype, detail) or \
                        timeline_filter.is_generated_script(etype, detail):
                    continue
                if etype == "process_cmd_patch" and isinstance(detail, dict):
                    try:
                        _apply_process_cmd_patch(conn, agent_id, detail, str(ev.get("ts") or now)[:32])
                    except Exception:
                        pass
                    tele.append((etype, detail, str(ev.get("ts") or now)[:32]))
                    continue
                # 重复源仍交给规则匹配：不同来源字段不全（如仅部分带命令行）
                detect_events.append(ev)
                # 进程实体 / DNS 聚合不受展示开关影响（关掉"进程退出"展示也要记录退出时间）
                tele.append((etype, detail, str(ev.get("ts") or now)[:32]))
                # 规则管理中关闭的内置传感器检出不再入库
                try:
                    from . import agent_rules as _ar
                    if not _ar.sensor_event_allowed(etype, summary, detail):
                        # 进程退出传感器默认关闭，但仍需入库供「进程退出」时间线分类展示
                        if timeline_filter.etype_kind(etype) != "exit":
                            continue
                except Exception:
                    pass
                if timeline_filter.is_duplicate(agent_id, etype, detail):
                    continue
                sev = str(ev.get("severity") or "info")[:16]
                ts = timeline_filter.fix_etw_ts(etype, str(ev.get("ts") or now)[:32], now)
                # 与告警详情同源：按字段收缩，绝不切坏 JSON（硬截断会导致详情页全空）
                detail_s = agent_protocol.fit_detail(detail or {})
                ent = str((detail or {}).get("entity_id") or "")[:64] if isinstance(detail, dict) else ""
                conn.execute(
                    """INSERT INTO agent_timeline(agent_id, hostname, etype, summary, detail_json, severity, ts, created_at, entity_id)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (agent_id, host, etype, summary, detail_s, sev, ts, now, ent),
                )
                rows.append({
                    "agent_id": agent_id, "hostname": host, "etype": etype, "summary": summary,
                    "detail_json": detail_s, "severity": sev, "ts": ts, "created_at": now,
                })
                try:
                    from . import elastic_detection_es as _edes
                    det = detail if isinstance(detail, dict) else {}
                    _edes.index_event_async(
                        agent_id=agent_id, hostname=host, etype=etype, summary=summary, detail=det, ts=ts,
                    )
                except Exception:
                    pass
                n += 1
            if tele:
                from . import agent_telemetry
                agent_telemetry.apply(conn, agent_id, tele)
            conn.commit()
        finally:
            conn.close()
    elastic_reported = 0
    if detect_events:
        try:
            from . import agent_rules as _ar
            from . import agent_sync as _asy
            from . import elastic_detection_import as _edi

            do_elastic = _asy.server_detection_enabled("elastic_evm_ingest")
            do_custom_evm = _asy.server_detection_enabled("evm_ingest")

            for ev in detect_events[:400]:
                if elastic_reported >= 12:
                    break
                if not isinstance(ev, dict):
                    continue
                det0 = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
                if str(ev.get("etype") or "").startswith("process_create"):
                    det0 = _ar.enrich_process_event_detail(
                        agent_id, det0, str(ev.get("summary") or ""),
                    )
                    ev = {**ev, "detail": det0}
                matched = False
                if do_elastic:
                    for r in _edi.match_timeline_event(ev):
                        title = str(r.get("title") or "Elastic 时间线命中")[:200]
                        src = str(r.get("source") or "elastic")
                        if src != "protections-artifacts" and str(r.get("id") or "").endswith(".prot.evm"):
                            src = "protections"
                        prefix = "Protections EVM" if src.startswith("protections") else "Elastic EVM"
                        agent_protocol.report_event({
                            "agent_id": agent_id,
                            "hostname": host,
                            "module": "timeline",
                            "severity": str(r.get("severity") or "medium"),
                            "title": f"{prefix}：{title}"[:200],
                            "detail": {
                                "rule_id": r.get("id"),
                                "rule_title": title,
                                "rule_source": src,
                                "elastic_rule_id": r.get("elastic_rule_id") or r.get("protections_rule_id"),
                                "etype": ev.get("etype"),
                                "summary": ev.get("summary"),
                                "building_block": True,
                            },
                        })
                        elastic_reported += 1
                        matched = True
                        break
                if not matched and do_custom_evm:
                    det = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
                    for r in _ar.match_live_evm_events(ev):
                        title = str(r.get("title") or "EVM 命中")[:200]
                        rid = str(r.get("id") or "")
                        src = "custom"
                        if rid.startswith("elastic-"):
                            src = "elastic"
                        elif ".prot.evm" in rid:
                            src = "protections"
                        cmd = str(det.get("command_line") or det.get("command") or "")
                        mod = "script" if cmd and re.search(
                            r"powershell|pwsh|wscript|cscript|mshta|scriptblock|\.ps1|\.vbs",
                            cmd,
                            re.I,
                        ) else "process"
                        agent_protocol.report_event({
                            "agent_id": agent_id,
                            "hostname": host,
                            "module": mod,
                            "severity": str(r.get("severity") or "high"),
                            "title": f"EVM：{title}"[:200],
                            "detail": {
                                "rule_id": rid,
                                "rule_title": title,
                                "rule_source": src,
                                "etype": ev.get("etype"),
                                "summary": ev.get("summary"),
                                "command_line": det.get("command_line"),
                                "command": det.get("command"),
                                "name": det.get("name"),
                                "path": det.get("path") or det.get("image"),
                                "parent_name": det.get("parent_name"),
                                "pid": det.get("pid"),
                                "matched": cmd[:400] if cmd else "",
                                "building_block": bool(r.get("building_block")),
                            },
                        })
                        elastic_reported += 1
                        break
        except Exception:
            pass
    if n:
        agent_protocol.bump_live("timeline", agent_id=agent_id, count=n)
        try:
            from . import agent_store
            threading.Thread(target=agent_store.write_timeline_batch, args=(rows,), daemon=True).start()
            agent_store.maybe_purge()
        except Exception:
            pass
    return {"ok": True, "inserted": n, "elastic_hits": elastic_reported, "_detect_events": detect_events}


def list_timeline(
    agent_id: str = "", *, etype: str = "", q: str = "", kind: str = "", limit: int = 100,
) -> Dict[str, Any]:
    ensure()
    limit = max(1, min(int(limit or 100), 500))
    clauses = []
    args: List[Any] = []
    if agent_id:
        clauses.append("agent_id=?")
        args.append(agent_id)
    if etype:
        clauses.append("etype=?")
        args.append(etype)
    if q:
        clauses.append("(summary LIKE ? OR detail_json LIKE ? OR hostname LIKE ?)")
        like = f"%{q}%"
        args.extend([like, like, like])
    kind = str(kind or "").strip().lower()
    with _lock:
        conn = _connect()
        try:
            base = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            kinds: Dict[str, int] = {k: 0 for k in timeline_filter.KIND_ORDER}
            etypes_by_kind: Dict[str, List[str]] = {}
            total = 0
            for et, cnt in conn.execute(f"SELECT etype, COUNT(*) FROM agent_timeline{base} GROUP BY etype", args):
                k = timeline_filter.etype_kind(et)
                kinds[k] = kinds.get(k, 0) + int(cnt)
                etypes_by_kind.setdefault(k, []).append(et)
                total += int(cnt)
            where_clauses, where_args = list(clauses), list(args)
            if kind:
                ets = etypes_by_kind.get(kind) or []
                if not ets:
                    return {"ok": True, "items": [], "kinds": kinds, "total": total}
                where_clauses.append(f"etype IN ({','.join('?' * len(ets))})")
                where_args.extend(ets)
            where = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            rows = conn.execute(
                f"SELECT * FROM agent_timeline{where} ORDER BY ts DESC, id DESC LIMIT ?",
                (*where_args, limit),
            ).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["detail"] = json.loads(d.pop("detail_json") or "{}")
                except Exception:
                    d["detail"] = {}
                items.append(d)
            return {"ok": True, "items": items, "kinds": kinds, "total": total}
        finally:
            conn.close()


def clean_timeline_history() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            stats = timeline_filter.clean_history(conn)
        finally:
            conn.close()
    return {"ok": True, **stats}


_THREAT_ETYPES = {
    "remote_thread_kernel", "protect_block_kernel",
}
_RISK_ETYPES = {
    "file_create", "file_write", "file_write_etw",
    "image_load_etw", "image_load_kernel",
    "network_connect", "network_connect_etw",
    "driver_load_kernel",
}
_SURFACE_ETYPES = {"protect_block_kernel", "sensor_status", "etw_status"}


def _log_nature(sev: str, etype: str, summary: str = "") -> str:
    """威胁 / 风险 / 细微 / 攻击面。"""
    et = str(etype or "")
    blob = f"{et} {summary or ''}".lower()
    if et in _SURFACE_ETYPES or "隔离" in blob or "quarantine" in blob:
        if et in _THREAT_ETYPES or str(sev).lower() in ("high", "critical"):
            return "threat"
        return "surface"
    if et in _THREAT_ETYPES or str(sev).lower() in ("high", "critical"):
        return "threat"
    if et in _RISK_ETYPES or str(sev).lower() == "medium" or any(
        k in blob for k in ("可疑", "临时", "public", "inject", "bypass", "dll", "文件创建", "落地")
    ):
        return "risk"
    return "minor"


def _parse_detail(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            o = json.loads(raw)
            return o if isinstance(o, dict) else {}
        except Exception:
            return {}
    return {}


def _timeline_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _parse_ts_any(s: str) -> Optional[datetime]:
    raw = str(s or "").strip().replace("T", " ").replace("Z", "")
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt)
        except ValueError:
            continue
    return None


_DROP_FILE_ETYPES = frozenset({
    "file_create", "file_write", "file_write_etw",
    "fim_add", "fim_modify", "fim_rename",
})
_DROP_PROC_ETYPES = frozenset({
    "process_create_etw", "process_create", "process_create_live", "process_create_kernel",
})


def _drop_edge_label(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if a.get("kind") == "proc" and b.get("kind") == "file":
        return "释放文件"
    if a.get("kind") == "file" and b.get("kind") == "proc":
        return "启动"
    if a.get("kind") == "proc" and b.get("kind") == "proc":
        if b.get("role") == "parent":
            return "父进程"
        if a.get("role") == "parent":
            return "运行"
        return "创建子进程"
    return "关联"


def _proc_step_from_entity(p: Dict[str, Any], *, role: str, is_hit: bool = False) -> Dict[str, Any]:
    eid = str(p.get("entity_id") or "").strip()
    return {
        "id": f"proc-{eid or p.get('pid')}",
        "kind": "proc",
        "role": role,
        "is_hit": is_hit,
        "name": p.get("name") or "?",
        "pid": p.get("pid"),
        "ppid": p.get("ppid"),
        "path": p.get("path") or "",
        "ts": p.get("last_seen") or p.get("first_seen") or "",
        "timeline_id": None,
    }


def _proc_step_from_timeline(row: Dict[str, Any], d: Dict[str, Any], *, role: str) -> Dict[str, Any]:
    path = str(d.get("path") or d.get("image") or "")
    name = d.get("name") or (os.path.basename(path) if path else "") or str(row.get("summary") or "?")[:80]
    pid = d.get("pid") or d.get("process_id")
    return {
        "id": f"tl-proc-{row.get('id')}",
        "kind": "proc",
        "role": role,
        "is_hit": False,
        "name": name,
        "pid": pid,
        "ppid": d.get("ppid"),
        "path": path,
        "command_line": str(d.get("command_line") or d.get("cmdline") or "")[:160],
        "ts": row.get("ts") or "",
        "timeline_id": row.get("id"),
        "etype": row.get("etype") or "",
    }


def _file_step_from_timeline(row: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    path = str(d.get("path") or d.get("file") or "").strip()
    name = os.path.basename(path) if path else str(row.get("summary") or "文件")[:80]
    return {
        "id": f"tl-file-{row.get('id')}",
        "kind": "file",
        "role": "dropped",
        "is_hit": False,
        "name": name,
        "path": path,
        "pid": d.get("pid") or d.get("process_id") or d.get("creator_pid"),
        "ts": row.get("ts") or "",
        "timeline_id": row.get("id"),
        "etype": row.get("etype") or "",
    }


def _build_threat_drop_chain(
    agent_id: str,
    ev: Optional[Dict[str, Any]],
    seed: Optional[Dict[str, Any]],
    chain: List[Dict[str, Any]],
    seed_pid: Any,
) -> Dict[str, Any]:
    """父进程 → 写文件 → 子进程：基于时间线窗口的释放/投递链。"""
    aid = str(agent_id or "").strip()
    if not aid:
        return {"steps": [], "edges": []}

    hit_pid = _timeline_int(seed.get("pid")) if seed else 0
    if not hit_pid and seed_pid not in (None, ""):
        hit_pid = _timeline_int(seed_pid)

    center_ts = ""
    if ev:
        center_ts = str(ev.get("created_at") or ev.get("ts") or "")
        raw = ev.get("detail_obj") or ev.get("detail") or {}
        if isinstance(raw, str):
            raw = _parse_detail(raw)
        if isinstance(raw, dict):
            evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else raw
            inner = evidence.get("evidence") if isinstance(evidence.get("evidence"), dict) else evidence
            if isinstance(inner, dict):
                center_ts = center_ts or str(inner.get("event_ts") or inner.get("ts") or "")
            center_ts = center_ts or str(raw.get("event_ts") or raw.get("ts") or "")

    dt = _parse_ts_any(center_ts) or datetime.utcnow()
    t0 = (dt - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    t1 = (dt + timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S")

    tl_rows: List[Dict[str, Any]] = []
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """SELECT id, etype, summary, detail_json, ts, severity
                   FROM agent_timeline WHERE agent_id=? AND ts >= ? AND ts <= ?
                   ORDER BY ts ASC LIMIT 500""",
                (aid, t0, t1),
            ).fetchall()
            tl_rows = [dict(r) for r in rows]
        finally:
            conn.close()

    steps: List[Dict[str, Any]] = []
    parent_p = chain[-2] if len(chain) >= 2 else None
    if not parent_p and seed:
        pp = _timeline_int(seed.get("ppid"))
        if pp:
            for row in reversed(tl_rows):
                et = str(row.get("etype") or "")
                if not et.startswith("process_create"):
                    continue
                d = _parse_detail(row.get("detail_json"))
                if _timeline_int(d.get("pid")) == pp:
                    steps.append(_proc_step_from_timeline(row, d, role="parent"))
                    break
    elif parent_p:
        steps.append(_proc_step_from_entity(parent_p, role="parent"))

    if seed:
        steps.append(_proc_step_from_entity(seed, role="hit", is_hit=True))
    elif hit_pid:
        title = str((ev or {}).get("title") or "").strip()
        steps.append({
            "id": f"proc-hit-{hit_pid}",
            "kind": "proc",
            "role": "hit",
            "is_hit": True,
            "name": title or f"PID {hit_pid}",
            "pid": hit_pid,
            "path": "",
            "ts": center_ts,
            "timeline_id": None,
        })

    files: List[tuple] = []
    children: List[tuple] = []
    for row in tl_rows:
        et = str(row.get("etype") or "")
        d = _parse_detail(row.get("detail_json"))
        if et in _DROP_FILE_ETYPES:
            cpid = _timeline_int(d.get("pid") or d.get("process_id") or d.get("creator_pid"))
            if hit_pid and cpid == hit_pid:
                files.append((row, d))
        if et in _DROP_PROC_ETYPES or et.startswith("process_create"):
            if hit_pid and _timeline_int(d.get("ppid")) == hit_pid:
                children.append((row, d))

    files.sort(key=lambda x: str(x[0].get("ts") or ""))
    children.sort(key=lambda x: str(x[0].get("ts") or ""))

    used_children: set = set()
    child_count = 0
    for row, d in files[:12]:
        fp = str(d.get("path") or "").strip()
        base = os.path.basename(fp).lower() if fp else ""
        steps.append(_file_step_from_timeline(row, d))
        for j, (crow, cd) in enumerate(children):
            if j in used_children:
                continue
            cp = str(cd.get("path") or cd.get("image") or "")
            cmd = str(cd.get("command_line") or cd.get("cmdline") or "")
            blob = f"{cp} {cmd}".lower()
            if fp and (fp.lower() in blob or (base and base in blob)):
                used_children.add(j)
                child_count += 1
                steps.append(_proc_step_from_timeline(crow, cd, role="child"))
                break

    for j, (crow, cd) in enumerate(children):
        if j in used_children or child_count >= 8:
            continue
        used_children.add(j)
        child_count += 1
        steps.append(_proc_step_from_timeline(crow, cd, role="child"))

    edges = [
        {"from": i, "to": i + 1, "label": _drop_edge_label(steps[i], steps[i + 1])}
        for i in range(len(steps) - 1)
    ]
    return {
        "steps": steps,
        "edges": edges,
        "window": {"from": t0, "to": t1},
        "hit_pid": hit_pid or None,
    }


def _hour_bucket(ts: str) -> str:
    s = str(ts or "").replace("T", " ")
    if len(s) >= 13:
        return s[:13] + ":00"
    return s[:10] + " 00:00" if len(s) >= 10 else "unknown"


def investigate_logs(
    *,
    q: str = "",
    agent_id: str = "",
    hostname: str = "",
    etype: str = "",
    nature: str = "",
    path: str = "",
    hash_q: str = "",
    range_key: str = "today",
    limit: int = 200,
    offset: int = 0,
    hide_proc_noise: bool = True,
) -> Dict[str, Any]:
    """日志调查：Agent 实时时间线检索 + 直方分布 + 分桶计数。"""
    ensure()
    limit = max(1, min(int(limit or 200), 500))
    offset = max(0, int(offset or 0))
    now = time.time()
    cut = ""
    rk = str(range_key or "today").lower()
    if rk in ("1h", "hour"):
        cut = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - 3600))
    elif rk in ("24h", "today", "day"):
        cut = time.strftime("%Y-%m-%dT00:00:00", time.localtime(now))
    elif rk in ("7d", "week"):
        cut = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - 7 * 86400))
    elif rk in ("30d", "month"):
        cut = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now - 30 * 86400))

    clauses: List[str] = []
    args: List[Any] = []
    if cut:
        clauses.append("ts >= ?")
        args.append(cut)
    if agent_id:
        clauses.append("agent_id=?")
        args.append(agent_id)
    if hostname:
        clauses.append("hostname LIKE ?")
        args.append(f"%{hostname}%")
    if etype:
        clauses.append("etype LIKE ?")
        args.append(f"%{etype}%")
    _PROC_NOISE_PRED = (
        "severity IN ('info','low') AND etype LIKE 'process_create%' "
        "AND IFNULL(summary,'') NOT LIKE '%可疑%'"
    )
    # 默认压掉「普通进程创建」噪声（显式按 etype 查时不压）
    if hide_proc_noise and not etype:
        clauses.append(f"NOT ({_PROC_NOISE_PRED})")
    if q:
        clauses.append("(summary LIKE ? OR detail_json LIKE ? OR hostname LIKE ? OR etype LIKE ?)")
        like = f"%{q}%"
        args.extend([like, like, like, like])
    if path:
        clauses.append("detail_json LIKE ?")
        args.append(f"%{path}%")
    if hash_q:
        clauses.append("detail_json LIKE ?")
        args.append(f"%{hash_q}%")
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    # 多取一些再按 nature 过滤；压噪时控制扫描量，避免「今天」全表扫卡死
    fetch_n = min(2500 if not hide_proc_noise else 900, max(limit + offset + 50, 400))
    _TL_COLS = (
        "id, agent_id, hostname, etype, summary, severity, detail_json, ts, created_at, entity_id"
    )
    with _lock:
        conn = _connect()
        try:
            if not hide_proc_noise and not etype:
                # 不压噪时分两路取数，避免海量 process_create 挤掉文件/网络等事件
                c_imp = [*clauses, f"NOT ({_PROC_NOISE_PRED})"]
                c_noise = [*clauses, _PROC_NOISE_PRED]
                w_imp = " WHERE " + " AND ".join(c_imp)
                w_noise = " WHERE " + " AND ".join(c_noise)
                imp_n = min(1800, fetch_n)
                noise_n = min(900, max(300, fetch_n // 2))
                rows_imp = conn.execute(
                    f"SELECT {_TL_COLS} FROM agent_timeline{w_imp} ORDER BY ts DESC, id DESC LIMIT ?",
                    (*args, imp_n),
                ).fetchall()
                rows_noise = conn.execute(
                    f"SELECT {_TL_COLS} FROM agent_timeline{w_noise} ORDER BY ts DESC, id DESC LIMIT ?",
                    (*args, noise_n),
                ).fetchall()
                by_id: Dict[int, Any] = {}
                for r in rows_imp:
                    by_id[int(r["id"])] = r
                for r in rows_noise:
                    by_id[int(r["id"])] = r
                rows = sorted(
                    by_id.values(),
                    key=lambda x: (str(x["ts"] or ""), int(x["id"] or 0)),
                    reverse=True,
                )[:fetch_n]
            else:
                rows = conn.execute(
                    f"SELECT {_TL_COLS} FROM agent_timeline{where} ORDER BY ts DESC, id DESC LIMIT ?",
                    (*args, fetch_n),
                ).fetchall()
        finally:
            conn.close()

    etype_set: Dict[str, int] = {}
    host_set: Dict[str, int] = {}
    hist: Dict[str, Dict[str, int]] = {}
    counts = {"all": 0, "threat": 0, "risk": 0, "minor": 0, "surface": 0}
    items: List[Dict[str, Any]] = []

    for r in rows:
        d = dict(r)
        detail = _parse_detail(d.pop("detail_json", None))
        d["detail"] = detail
        nat = _log_nature(d.get("severity") or "info", d.get("etype") or "", d.get("summary") or "")
        d["nature"] = nat
        counts["all"] += 1
        counts[nat] = counts.get(nat, 0) + 1
        et = str(d.get("etype") or "")
        if et:
            etype_set[et] = etype_set.get(et, 0) + 1
        hn = str(d.get("hostname") or d.get("agent_id") or "")
        if hn:
            host_set[hn] = host_set.get(hn, 0) + 1
        buck = _hour_bucket(d.get("ts") or "")
        hist.setdefault(buck, {"threat": 0, "risk": 0, "minor": 0, "surface": 0, "total": 0})
        hist[buck][nat] = hist[buck].get(nat, 0) + 1
        hist[buck]["total"] += 1
        if nature and nat != nature:
            continue
        items.append(d)

    items_page = items[offset: offset + limit]
    # 列表瘦身：摘要字段
    out_items = []
    for it in items_page:
        det = it.get("detail") or {}
        out_items.append({
            "id": it.get("id"),
            "agent_id": it.get("agent_id"),
            "hostname": it.get("hostname"),
            "etype": it.get("etype"),
            "summary": it.get("summary"),
            "severity": it.get("severity"),
            "nature": it.get("nature"),
            "ts": it.get("ts"),
            "pid": det.get("pid"),
            "ppid": det.get("ppid"),
            "name": det.get("name") or det.get("process_name"),
            "path": det.get("path") or det.get("image"),
            "user": det.get("user"),
            "command_line": (str(det.get("command_line") or "")[:180] or None),
            "sha256": det.get("sha256"),
            "source": det.get("source") or "",
        })

    hist_list = [{"ts": k, **v} for k, v in sorted(hist.items())]
    facets = {
        "etype": [{"id": k, "count": v} for k, v in sorted(etype_set.items(), key=lambda x: -x[1])[:40]],
        "hostname": [{"id": k, "count": v} for k, v in sorted(host_set.items(), key=lambda x: -x[1])[:40]],
    }
    return {
        "ok": True,
        "counts": counts,
        "histogram": hist_list,
        "facets": facets,
        "total": len(items),
        "offset": offset,
        "limit": limit,
        "items": out_items,
        "range": rk,
        "cut": cut,
    }


def get_log_detail(log_id: int) -> Dict[str, Any]:
    """单条日志详情：字段分组 + 进程链 + 原始 JSON。"""
    ensure()
    lid = int(log_id or 0)
    if lid <= 0:
        return {"ok": False, "error": "无效日志 ID"}
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_timeline WHERE id=?", (lid,)).fetchone()
            if not row:
                return {"ok": False, "error": "日志不存在"}
            item = dict(row)
            detail = _parse_detail(item.pop("detail_json", None))
            item["detail"] = detail
            item["nature"] = _log_nature(item.get("severity") or "info", item.get("etype") or "", item.get("summary") or "")
            aid = str(item.get("agent_id") or "")
            if aid and not str(item.get("hostname") or "").strip():
                try:
                    hr = conn.execute("SELECT hostname, ip FROM agents WHERE agent_id=?", (aid,)).fetchone()
                    if hr:
                        item["hostname"] = hr[0] or item.get("hostname")
                        item["agent_ip"] = hr[1] if len(hr) > 1 else ""
                except Exception:
                    pass
            if aid and not str(item.get("hostname") or "").strip():
                try:
                    hr = conn.execute("SELECT hostname, ip FROM agents WHERE agent_id=?", (aid,)).fetchone()
                    if hr:
                        item["hostname"] = hr[0] or item.get("hostname")
                        item["agent_ip"] = hr[1] if len(hr) > 1 else ""
                except Exception:
                    pass
            # 同主机近期时间线，用于拼进程链
            related = []
            if aid:
                related = conn.execute(
                    """SELECT id, etype, summary, detail_json, severity, ts, hostname
                       FROM agent_timeline WHERE agent_id=? ORDER BY ts DESC, id DESC LIMIT 400""",
                    (aid,),
                ).fetchall()
        finally:
            conn.close()

    # 字段分组
    prefer_groups = [
        ("进程", [
            "name", "process_name", "host_process", "pid", "ppid", "process_guid", "parent_guid",
            "parent_name", "parent_path", "user", "target_pid", "create_time",
            "elevated", "integrity",
        ]),
        ("模块 / 路径", [
            "module", "module_name", "path", "image", "command_line",
            "directory", "script_block", "payload", "process_path",
        ]),
        ("签名 / 哈希", ["signed", "signer", "sha256", "company", "file_version", "ext", "size", "size_kb"]),
        ("网络", ["remote", "local", "proto", "daddr", "dport", "saddr", "sport"]),
        ("其它", []),
    ]
    used = set()
    groups = []
    for title, keys in prefer_groups[:-1]:
        fields = []
        for k in keys:
            if k in detail and detail[k] not in (None, ""):
                fields.append({"k": k, "v": detail[k]})
                used.add(k)
        if fields:
            groups.append({"title": title, "fields": fields})
    rest = [{"k": k, "v": v} for k, v in detail.items() if k not in used and v not in (None, "")]
    if rest:
        groups.append({"title": "其它", "fields": rest})

    host_label = str(item.get("hostname") or "").strip() or agent_protocol._host_of(aid) or aid
    info = [
        {"k": "时间", "v": item.get("ts")},
        {"k": "主机名", "v": host_label},
        {"k": "Agent ID", "v": aid},
        {"k": "终端 IP", "v": item.get("agent_ip") or ""},
        {"k": "事件类型", "v": item.get("etype")},
        {"k": "级别", "v": item.get("severity")},
        {"k": "性质", "v": item.get("nature")},
        {"k": "摘要", "v": item.get("summary")},
    ]

    # 进程链：优先 process_guid（pid+创建时间），回退 PID（防复用错链）
    def _pid_of(dj: Dict[str, Any]) -> Any:
        return dj.get("pid") if dj.get("pid") not in (None, "") else None

    def _guid_of(dj: Dict[str, Any]) -> str:
        g = str(dj.get("process_guid") or "").strip()
        if g:
            return g
        pid = _pid_of(dj)
        ct = str(dj.get("create_time") or "").strip()
        if pid is not None and ct:
            return f"{pid}_{ct}"
        return ""

    self_pid = _pid_of(detail)
    self_ppid = detail.get("ppid")
    self_guid = _guid_of(detail)
    self_parent_guid = str(detail.get("parent_guid") or "").strip()
    nodes_by_guid: Dict[str, Dict[str, Any]] = {}
    nodes_by_pid: Dict[str, Dict[str, Any]] = {}
    for r in related:
        dj = _parse_detail(r["detail_json"])
        pid = _pid_of(dj)
        if pid is None and not _guid_of(dj):
            continue
        node = {
            "pid": pid,
            "ppid": dj.get("ppid"),
            "process_guid": _guid_of(dj),
            "parent_guid": str(dj.get("parent_guid") or "").strip(),
            "name": dj.get("name") or dj.get("process_name") or "",
            "path": dj.get("path") or dj.get("image") or "",
            "command_line": dj.get("command_line") or "",
            "user": dj.get("user") or "",
            "elevated": dj.get("elevated") or "",
            "integrity": dj.get("integrity") or "",
            "ts": r["ts"],
            "etype": r["etype"],
            "summary": r["summary"],
            "log_id": r["id"],
            "current": False,
        }
        gk = node["process_guid"]
        if gk:
            prev = nodes_by_guid.get(gk)
            if not prev or str(r["ts"] or "") >= str(prev.get("ts") or ""):
                nodes_by_guid[gk] = node
        if pid is not None:
            key = str(pid)
            prev = nodes_by_pid.get(key)
            if not prev or str(r["ts"] or "") >= str(prev.get("ts") or ""):
                nodes_by_pid[key] = node
    if self_pid is not None or self_guid:
        cur = {
            "pid": self_pid,
            "ppid": self_ppid,
            "process_guid": self_guid,
            "parent_guid": self_parent_guid,
            "name": detail.get("name") or detail.get("process_name") or "",
            "path": detail.get("path") or "",
            "command_line": detail.get("command_line") or "",
            "user": detail.get("user") or "",
            "elevated": detail.get("elevated") or "",
            "integrity": detail.get("integrity") or "",
            "ts": item.get("ts"),
            "etype": item.get("etype"),
            "summary": item.get("summary"),
            "log_id": item.get("id"),
            "current": True,
        }
        if self_guid:
            nodes_by_guid[self_guid] = {**(nodes_by_guid.get(self_guid) or {}), **cur, "current": True}
        if self_pid is not None:
            nodes_by_pid[str(self_pid)] = {**(nodes_by_pid.get(str(self_pid)) or {}), **cur, "current": True}

    def _resolve_parent(node: Dict[str, Any]) -> Dict[str, Any] | None:
        pg = str(node.get("parent_guid") or "").strip()
        if pg and pg in nodes_by_guid:
            return nodes_by_guid[pg]
        ppid = node.get("ppid")
        if ppid not in (None, "", 0, "0"):
            return nodes_by_pid.get(str(ppid))
        return None

    chain: List[Dict[str, Any]] = []
    self_node = (nodes_by_guid.get(self_guid) if self_guid else None) or (
        nodes_by_pid.get(str(self_pid)) if self_pid is not None else None
    )
    if self_node is not None:
        walk = []
        seen = set()
        cur_n = self_node
        depth = 0
        while depth < 8:
            parent = _resolve_parent(cur_n)
            if not parent:
                ppid = cur_n.get("ppid")
                if ppid not in (None, "", 0, "0"):
                    walk.append({
                        "pid": ppid,
                        "process_guid": cur_n.get("parent_guid") or "",
                        "name": detail.get("parent_name") or f"PID {ppid}",
                        "ppid": None,
                        "missing": True,
                    })
                break
            pk = parent.get("process_guid") or str(parent.get("pid"))
            if pk in seen:
                break
            seen.add(pk)
            walk.append(parent)
            cur_n = parent
            depth += 1
        chain.extend(reversed(walk))
        chain.append(self_node)
        # 子进程：优先 parent_guid，回退 ppid（按 guid/pid 去重）
        seen_child: set[str] = set()
        candidates = list(nodes_by_guid.values()) + [
            n for n in nodes_by_pid.values() if not n.get("process_guid")
        ]
        for n in candidates:
            if n.get("current"):
                continue
            hit = False
            if self_guid and str(n.get("parent_guid") or "") == self_guid:
                hit = True
            elif self_pid is not None and str(n.get("ppid")) == str(self_pid) and not n.get("parent_guid"):
                hit = True
            if not hit:
                continue
            ck = str(n.get("process_guid") or n.get("log_id") or n.get("pid") or id(n))
            if ck in seen_child:
                continue
            seen_child.add(ck)
            chain.append({**n, "child": True})

    raw = {
        "id": item.get("id"),
        "agent_id": item.get("agent_id"),
        "hostname": item.get("hostname"),
        "etype": item.get("etype"),
        "summary": item.get("summary"),
        "severity": item.get("severity"),
        "nature": item.get("nature"),
        "ts": item.get("ts"),
        "created_at": item.get("created_at"),
        "detail": detail,
    }
    return {
        "ok": True,
        "item": item,
        "info": info,
        "groups": groups,
        "chain": chain,
        "raw": raw,
    }


def hunt(q: str, *, limit: int = 100) -> Dict[str, Any]:
    """跨主机狩猎：时间线 + 快照 JSON + 威胁事件。"""
    ensure()
    query = str(q or "").strip()
    if len(query) < 2:
        return {"ok": False, "error": "请输入至少 2 个字符"}
    limit = max(1, min(int(limit or 100), 300))
    like = f"%{query}%"
    hits: List[Dict[str, Any]] = []
    with _lock:
        conn = _connect()
        try:
            for r in conn.execute(
                """SELECT id, agent_id, hostname, etype, summary, detail_json, severity, ts
                   FROM agent_timeline
                   WHERE summary LIKE ? OR detail_json LIKE ?
                   ORDER BY ts DESC LIMIT ?""",
                (like, like, limit),
            ).fetchall():
                hits.append({
                    "source": "timeline",
                    "id": r["id"],
                    "agent_id": r["agent_id"],
                    "hostname": r["hostname"],
                    "title": r["summary"],
                    "module": r["etype"],
                    "severity": r["severity"],
                    "ts": r["ts"],
                    "snippet": (r["detail_json"] or "")[:240],
                })
            for r in conn.execute(
                """SELECT agent_id, module, collected_at, payload_json FROM agent_snapshots
                   WHERE payload_json LIKE ? LIMIT ?""",
                (like, max(20, limit // 3)),
            ).fetchall():
                hits.append({
                    "source": "snapshot",
                    "agent_id": r["agent_id"],
                    "hostname": agent_protocol._host_of(r["agent_id"]),
                    "title": f"快照命中 · {r['module']}",
                    "module": r["module"],
                    "severity": "info",
                    "ts": r["collected_at"],
                    "snippet": _snip(r["payload_json"] or "", query),
                })
            for r in conn.execute(
                """SELECT id, agent_id, hostname, title, module, severity, detail, updated_at
                   FROM agent_events
                   WHERE title LIKE ? OR detail LIKE ?
                   ORDER BY id DESC LIMIT ?""",
                (like, like, max(20, limit // 3)),
            ).fetchall():
                hits.append({
                    "source": "event",
                    "id": r["id"],
                    "agent_id": r["agent_id"],
                    "hostname": r["hostname"],
                    "title": r["title"],
                    "module": r["module"],
                    "severity": r["severity"],
                    "ts": r["updated_at"],
                    "snippet": (r["detail"] or "")[:240],
                })
        finally:
            conn.close()
    hits = hits[:limit]
    return {"ok": True, "q": query, "count": len(hits), "items": hits}


def _snip(blob: str, q: str, radius: int = 80) -> str:
    low = blob.lower()
    i = low.find(q.lower())
    if i < 0:
        return blob[:160]
    a = max(0, i - radius)
    b = min(len(blob), i + len(q) + radius)
    return ("…" if a else "") + blob[a:b] + ("…" if b < len(blob) else "")


_DEFAULT_POLICY = {
    "intervals_sec": dict(agent_protocol.MODULE_INTERVAL_SEC),
    "heartbeat_sec": 3,
    "response_enabled": True,
    "timeline_process": True,
    "timeline_file": True,
    "timeline_network": True,
    "isolate_allow_server": True,
    "whitelist_skip_rules": True,
    "self_protect": False,
    "timeline_retain_days": 14,
    "events_retain_days": 90,
    "mysql_dual_write": True,
    # 文件完整性监控：内置关键目录 + 自定义目录（"D:\\app" 或 "D:\\app|r" 递归）
    "fim_enabled": True,
    "fim_paths": [],
    # 定向日志 tail（非 Filebeat filestream）；绝对路径白名单，如 C:\\Windows\\Temp\\app.log
    "log_tail_paths": [],
    # Winlog 通道：all | critical | custom；custom 时用 winevent_channels 列表（security/sysmon/…）
    "winevent_channel_mode": "all",
    "winevent_channels": [],
    "integrations": {
        "etw": True,
        "winevent": True,
        "fim": True,
        "registry": True,
        "persist": True,
        "device": True,
        "memory_scan": True,
        "evm": True,
        "ptm": True,
        "rootcheck": True,
        "sca": True,
    },
    "sca": {
        "policies": ["cis_win10_enterprise", "cis_win11_enterprise"],
        "max_checks_per_run": 48,
    },
    "active_response_enabled": True,
    "remote_ops_enabled": True,
    "remote_ops": {
        "enabled": True,
        "read_only": False,
        "run_cmd_enabled": True,
        "shell_enabled": True,
        "shell_max_minutes": 15,
        "run_cmd_whitelist": [
            "dir", "type", "reg", "ipconfig", "netstat", "tasklist", "systeminfo",
            "whoami", "hostname", "net", "sc", "cd", "echo", "where", "findstr",
            "powershell -noprofile -command",
        ],
    },
    "memory_scan": {
        "mode": "yara_triggered",
        "rules_rev": "2026.10.31.1",
        "max_processes_per_run": 20,
        "max_region_read_kb": 512,
        "schedule_interval_sec": 1800,
        "triggers": [
            "remote_thread_kernel",
            "process_access",
            "image_load_etw",
            "priv_escalation",
            "evm_hit",
            "api_amsi",
            "amsi_hit",
            "api_call",
            "api_hit",
        ],
        "exclude_signed_vendor": ["Microsoft Corporation", "Google LLC"],
    },
}


def get_policy(scope: str = "global") -> Dict[str, Any]:
    ensure()
    scope = str(scope or "global")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_policy WHERE scope=?", (scope,)).fetchone()
            if not row:
                now = _now()
                conn.execute(
                    "INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,1,?)",
                    (scope, json.dumps(_DEFAULT_POLICY, ensure_ascii=False), now),
                )
                conn.commit()
                return {"ok": True, "scope": scope, "rev": 1, "policy": dict(_DEFAULT_POLICY), "updated_at": now}
            try:
                pol = json.loads(row["policy_json"] or "{}")
            except Exception:
                pol = dict(_DEFAULT_POLICY)
            return {
                "ok": True,
                "scope": scope,
                "rev": int(row["rev"] or 1),
                "policy": pol,
                "updated_at": row["updated_at"],
            }
        finally:
            conn.close()


_POLICY_BOOL_KEYS = (
    "response_enabled", "timeline_process", "timeline_file", "timeline_network", "self_protect",
    "fim_enabled", "isolate_allow_server", "whitelist_skip_rules", "mysql_dual_write",
    "remote_ops_enabled",
)


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    return None


def validate_policy(p: Dict[str, Any]) -> List[str]:
    """与 Agent 侧 validatePolicy 同口径：任一项非法整份拒绝，避免终端出现"半生效"。"""
    errs: List[str] = []
    for k in _POLICY_BOOL_KEYS:
        if k in p and not isinstance(p[k], bool):
            errs.append(f"{k} 必须是布尔值")
    hb = _num(p.get("heartbeat_sec")) if "heartbeat_sec" in p else 5.0
    if hb is None or not 3 <= hb <= 120:
        errs.append("heartbeat_sec 必须在 3~120")
    iv = p.get("intervals_sec")
    if iv is not None:
        if not isinstance(iv, dict):
            errs.append("intervals_sec 必须是对象")
        else:
            for k in sorted(iv):
                n = _num(iv[k])
                if n is None or not 3 <= n <= 86400:
                    errs.append(f"intervals_sec.{k} 必须在 3~86400 秒")
    for k, lo, hi in (("timeline_retain_days", 1, 365), ("events_retain_days", 7, 730)):
        if k in p:
            n = _num(p[k])
            if n is None or not lo <= n <= hi:
                errs.append(f"{k} 必须在 {lo}~{hi}")
    fp = p.get("fim_paths")
    if fp is not None:
        if not isinstance(fp, list):
            errs.append("fim_paths 必须是数组")
        elif len(fp) > 50:
            errs.append("fim_paths 最多 50 项")
        else:
            for x in fp:
                s = str(x).strip() if isinstance(x, str) else ""
                path = s.rsplit("|", 1)[0].strip() if "|" in s else s
                if not re.match(r"^[A-Za-z]:\\", path) or len(path.rstrip("\\")) <= 2:
                    errs.append(f"fim_paths 非法路径（需绝对路径且不能是整个磁盘）: {x}")
    ltp = p.get("log_tail_paths")
    if ltp is not None:
        if not isinstance(ltp, list):
            errs.append("log_tail_paths 必须是数组")
        elif len(ltp) > 20:
            errs.append("log_tail_paths 最多 20 项")
        else:
            for x in ltp:
                s = str(x).strip() if isinstance(x, str) else ""
                if not re.match(r"^[A-Za-z]:\\", s) or len(s) <= 4 or s.endswith("\\"):
                    errs.append(f"log_tail_paths 需绝对文件路径（非盘符根/目录）: {x}")
    ms = p.get("memory_scan")
    if ms is not None:
        if not isinstance(ms, dict):
            errs.append("memory_scan 必须是对象")
        else:
            mode = str(ms.get("mode") or "").strip().lower()
            ok_modes = {
                "off", "heuristic", "yara_on_demand", "yara_triggered", "yara_scheduled",
            }
            if mode and mode not in ok_modes:
                errs.append(f"memory_scan.mode 非法: {mode}")
            for nk, lo, hi in (
                ("max_processes_per_run", 1, 80),
                ("max_region_read_kb", 64, 4096),
                ("schedule_interval_sec", 300, 86400),
            ):
                if nk in ms:
                    n = _num(ms[nk])
                    if n is None or not lo <= n <= hi:
                        errs.append(f"memory_scan.{nk} 必须在 {lo}~{hi}")
            tr = ms.get("triggers")
            if tr is not None and not isinstance(tr, list):
                errs.append("memory_scan.triggers 必须是数组")
    return errs


def set_policy(scope: str, policy: Dict[str, Any], *, actor: str = "", note: str = "") -> Dict[str, Any]:
    ensure()
    scope = str(scope or "global")
    if not isinstance(policy, dict):
        return {"ok": False, "error": "policy 必须是对象"}
    merged = dict(_DEFAULT_POLICY)
    merged.update(policy)
    errs = validate_policy(merged)
    if errs:
        return {"ok": False, "error": "；".join(errs), "errors": errs}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT rev FROM agent_policy WHERE scope=?", (scope,)).fetchone()
            rev = int(row["rev"] or 0) + 1 if row else 1
            conn.execute(
                """INSERT INTO agent_policy(scope, policy_json, rev, updated_at) VALUES(?,?,?,?)
                   ON CONFLICT(scope) DO UPDATE SET
                     policy_json=excluded.policy_json,
                     rev=excluded.rev,
                     updated_at=excluded.updated_at""",
                (scope, json.dumps(merged, ensure_ascii=False), rev, now),
            )
            conn.execute(
                """INSERT OR REPLACE INTO agent_policy_history(scope, rev, policy_json, actor, note, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (scope, rev, json.dumps(merged, ensure_ascii=False), actor[:64], note[:200], now),
            )
            conn.commit()
        finally:
            conn.close()
    _audit("policy_update", detail=json.dumps({"scope": scope, "rev": rev, "note": note}, ensure_ascii=False), actor=actor)
    agent_protocol.bump_live("policy", scope=scope, rev=rev)
    try:
        from . import agent_sync
        agent_sync.bump_sync("policy")
    except Exception:
        pass
    return {"ok": True, "scope": scope, "rev": rev, "policy": merged}


def list_policy_history(scope: str = "global", *, limit: int = 50) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT scope, rev, policy_json, actor, note, created_at FROM agent_policy_history "
                "WHERE scope=? ORDER BY rev DESC LIMIT ?",
                (str(scope or "global"), max(1, min(int(limit or 50), 200))),
            ).fetchall()
        finally:
            conn.close()
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["policy"] = json.loads(d.pop("policy_json") or "{}")
        except Exception:
            d["policy"] = {}
        items.append(d)
    return {"ok": True, "items": items}


def rollback_policy(scope: str, rev: int, *, actor: str = "") -> Dict[str, Any]:
    """回滚 = 以历史版本内容发布一个新 rev（rev 单调递增，终端按新 rev 原子生效）。"""
    ensure()
    scope = str(scope or "global")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT policy_json FROM agent_policy_history WHERE scope=? AND rev=?", (scope, int(rev))
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"ok": False, "error": f"历史版本 rev {rev} 不存在"}
    try:
        pol = json.loads(row["policy_json"] or "{}")
    except Exception:
        return {"ok": False, "error": "历史版本内容损坏"}
    return set_policy(scope, pol, actor=actor, note=f"回滚到 rev {int(rev)}")


def policy_rollout(scope: str = "global") -> Dict[str, Any]:
    """各终端对当前策略的生效情况（取自心跳 health.policy）。"""
    cur = get_policy(scope)
    rev = int(cur.get("rev") or 0)
    agents = agent_protocol.list_agents(online_within_sec=120).get("items") or []
    summary = {"total": 0, "applied": 0, "probation": 0, "rejected": 0, "rolled_back": 0, "pending": 0, "legacy": 0}
    problems: List[Dict[str, Any]] = []
    for a in agents:
        summary["total"] += 1
        st = (a.get("health") or {}).get("policy")
        if not isinstance(st, dict):
            summary["legacy"] += 1  # 旧 Agent 不回报策略状态
            continue
        status = str(st.get("status") or "")
        applied = int(st.get("applied_rev") or 0)
        if status in ("rejected", "rolled_back") and int(st.get("bad_rev") or 0) == rev:
            summary[status] += 1
            problems.append({
                "agent_id": a.get("agent_id"), "hostname": a.get("hostname"), "online": a.get("online"),
                "status": status, "applied_rev": applied, "lkg_rev": st.get("lkg_rev"), "error": st.get("error"),
            })
        elif applied == rev and status == "probation":
            summary["probation"] += 1
        elif applied == rev:
            summary["applied"] += 1
        else:
            summary["pending"] += 1
    return {"ok": True, "scope": scope, "rev": rev, "summary": summary, "problems": problems[:200]}


def list_whitelist() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_whitelist ORDER BY created_at DESC").fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def add_whitelist(
    kind: str,
    value: str,
    *,
    note: str = "",
    agent_id: str = "",
    rule: str = "",
    created_by: str = "",
    source_event_id: int = 0,
    apply_existing: bool = False,
) -> Dict[str, Any]:
    from . import alert_allow

    ensure()
    kind = str(kind or "").strip().lower()[:32]
    value = str(value or "").strip()[:500]
    rule = str(rule or "").strip()[:300]
    agent_id = str(agent_id or "").strip()[:64]
    if kind not in alert_allow.KINDS or not value:
        return {"ok": False, "error": "kind/value 无效"}
    if kind == "title" and value.strip("*? ") == "":
        return {"ok": False, "error": "标题通配过宽，会屏蔽全部告警"}
    wid = uuid.uuid4().hex
    entry = {"id": wid, "kind": kind, "value": value, "agent_id": agent_id, "rule": rule, "enabled": 1}
    ignored = 0
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_whitelist(id, kind, value, note, enabled, created_at,
                                               agent_id, rule, hits, last_hit_at, created_by, source_event_id)
                   VALUES(?,?,?,?,1,?,?,?,0,'',?,?)""",
                (wid, kind, value, note[:200], _now(), agent_id, rule, created_by[:64], int(source_event_id or 0)),
            )
            conn.commit()
            if apply_existing:
                ignored = alert_allow.apply_to_open_events(conn, entry)
        finally:
            conn.close()
    _audit("whitelist_add", agent_id=agent_id, actor=created_by,
           detail=json.dumps({"kind": kind, "value": value, "rule": rule, "ignored": ignored}, ensure_ascii=False))
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    if ignored:
        agent_protocol.bump_live("event")
    return {"ok": True, "id": wid, "ignored": ignored}


def set_whitelist_enabled(wid: str, enabled: bool) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("UPDATE agent_whitelist SET enabled=? WHERE id=?", (1 if enabled else 0, str(wid)))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "不存在"}
        finally:
            conn.close()
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    return {"ok": True}


def delete_whitelist(wid: str) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_whitelist WHERE id=?", (str(wid),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "不存在"}
        finally:
            conn.close()
    agent_protocol.bump_live("whitelist")
    try:
        from . import agent_sync
        agent_sync.bump_sync("whitelist")
    except Exception:
        pass
    return {"ok": True}


def list_groups() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_groups ORDER BY name").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["agent_ids"] = json.loads(d.pop("agent_ids_json") or "[]")
                except Exception:
                    d["agent_ids"] = []
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def upsert_group(gid: str, name: str, agent_ids: List[str], *, note: str = "") -> Dict[str, Any]:
    ensure()
    gid = str(gid or "").strip() or uuid.uuid4().hex
    name = str(name or "").strip()[:64] or gid
    ids = [str(x) for x in (agent_ids or []) if x][:500]
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_groups(id, name, agent_ids_json, note, updated_at) VALUES(?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name,
                     agent_ids_json=excluded.agent_ids_json,
                     note=excluded.note,
                     updated_at=excluded.updated_at""",
                (gid, name, json.dumps(ids, ensure_ascii=False), note[:200], _now()),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": gid, "name": name, "agent_ids": ids}


def list_audit(*, limit: int = 100) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT * FROM agent_audit ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def agent_side_bundle(agent_id: str, *, host_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """心跳附带：待执行指令 + 策略 + 白名单摘要。"""
    ensure()
    pol = get_policy("global")
    cmds = poll_commands(agent_id, limit=5)
    wl = list_whitelist()
    try:
        from . import agent_rules as _ar
        rule_fim = _ar.rule_fim_paths()
    except Exception:
        rule_fim = []
    mem_rev = ""
    try:
        from . import memory_yara
        mem_rev = str((memory_yara.bundle().get("rev") or ""))
    except Exception:
        mem_rev = ""
    policy_out = dict(pol.get("policy") or {})
    ms = policy_out.get("memory_scan")
    if isinstance(ms, dict) and mem_rev:
        ms = dict(ms)
        ms["rules_rev"] = mem_rev
        policy_out["memory_scan"] = ms
    return {
        "commands": cmds.get("items") or [],
        "rule_fim_paths": rule_fim,
        "policy": policy_out,
        "policy_rev": pol.get("rev") or 1,
        "memory_yara_rev": mem_rev,
        "whitelist": [
            {"kind": x.get("kind"), "value": x.get("value")}
            for x in (wl.get("items") or [])
            if x.get("enabled")
        ][:200],
        "self_protect": bool((pol.get("policy") or {}).get("self_protect")),
    }


# ---------- IOC ----------

def list_ioc() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_ioc ORDER BY created_at DESC").fetchall()
            return {"ok": True, "items": [dict(r) for r in rows]}
        finally:
            conn.close()


def add_ioc(ioc_type: str, value: str, *, severity: str = "high", note: str = "") -> Dict[str, Any]:
    ensure()
    ioc_type = str(ioc_type or "").strip().lower()[:32]
    value = str(value or "").strip()[:800]
    if ioc_type not in ("hash", "domain", "ip", "path", "process", "cmdline") or not value:
        return {"ok": False, "error": "ioc_type/value 无效"}
    iid = uuid.uuid4().hex
    now = _now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_ioc(id, ioc_type, value, severity, note, enabled, hits, created_at, updated_at)
                   VALUES(?,?,?,?,?,1,0,?,?)""",
                (iid, ioc_type, value, severity[:16], note[:200], now, now),
            )
            conn.commit()
        finally:
            conn.close()
    agent_protocol.bump_live("ioc")
    try:
        from . import agent_sync
        agent_sync.bump_sync("ioc")
    except Exception:
        pass
    return {"ok": True, "id": iid}


def import_iocs(text: str, *, ioc_type: str = "hash", severity: str = "high") -> Dict[str, Any]:
    """批量导入，每行一个 IOC。"""
    lines = [ln.strip() for ln in str(text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]
    n = 0
    for ln in lines[:2000]:
        # type:value 或纯值
        if ":" in ln and ln.split(":", 1)[0].lower() in ("hash", "domain", "ip", "path", "process", "cmdline"):
            t, v = ln.split(":", 1)
            r = add_ioc(t.strip(), v.strip(), severity=severity)
        else:
            r = add_ioc(ioc_type, ln, severity=severity)
        if r.get("ok"):
            n += 1
    return {"ok": True, "imported": n}


def delete_ioc(iid: str) -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_ioc WHERE id=?", (str(iid),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "不存在"}
        finally:
            conn.close()
    try:
        from . import agent_sync
        agent_sync.bump_sync("ioc")
    except Exception:
        pass
    return {"ok": True}


def _extract_ioc_candidates(events: List[Any], blob: str = "") -> List[Dict[str, str]]:
    """从时间线事件 / 文本提取可查 IOC 候选（hash/ip/domain）。"""
    import re

    import ipaddress

    out: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, value: str, src: str = "", ctx: Optional[Dict[str, Any]] = None) -> None:
        v = str(value or "").strip().lower().rstrip(".")
        if not v:
            return
        # ip 可能带端口
        if kind == "ip" and ":" in v:
            v = v.split(":", 1)[0]
        if kind == "ip":
            try:
                ip = ipaddress.ip_address(v)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                    return
            except ValueError:
                return
        key = f"{kind}|{v}"
        if key in seen or len(v) < 4:
            return
        seen.add(key)
        out.append({"ioc_type": kind, "value": v, "src": src, "ctx": ctx or {}})

    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
        ctx = {"etype": ev.get("etype"), "summary": str(ev.get("summary") or "")[:200]}
        for ck in ("pid", "process_name", "name", "path", "command_line", "remote", "domain", "query", "sha256"):
            if detail.get(ck) not in (None, ""):
                ctx[ck] = detail.get(ck)
        for hk in ("sha256", "sha1", "md5", "hash", "file_hash"):
            hv = str(detail.get(hk) or "").strip()
            if hv and re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", hv):
                add("file_hash", hv, hk, ctx)
        for ik in ("remote", "remote_ip", "ip", "dst", "dest"):
            rv = str(detail.get(ik) or "").strip()
            if not rv:
                continue
            # remote 常为 ip:port
            m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$", rv)
            if m:
                add("ip", m.group(1), ik, ctx)
            elif "." in rv and not rv.replace(".", "").isdigit():
                host = rv.split(":")[0].split("/")[0]
                if host and not host.replace(".", "").isdigit():
                    add("domain", host, ik, ctx)
        for dk in ("query", "domain"):
            dv = str(detail.get(dk) or "").strip()
            if "." in dv and not dv.replace(".", "").isdigit():
                add("domain", dv, dk, ctx)
        path = str(detail.get("path") or "")
        for m in re.finditer(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b", path):
            add("file_hash", m.group(1), "path", ctx)

    text = blob or ""
    for m in re.finditer(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b", text):
        add("file_hash", m.group(1), "blob")
    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
        add("ip", m.group(1), "blob")
    return out[:80]


_IOC_TYPE_CN = {"ip": "IP", "domain": "域名", "file_hash": "文件哈希", "url": "URL", "hash": "哈希"}


def match_iocs_against_text(agent_id: str, hostname: str, blob: str, *, module: str = "ioc") -> int:
    """本地 agent_ioc 子串 + ioc_data.db / MySQL 情报库精确匹配。"""
    return match_iocs(agent_id, hostname, blob=blob, events=None, module=module)


def match_iocs(
    agent_id: str,
    hostname: str,
    *,
    blob: str = "",
    events: Optional[List[Any]] = None,
    module: str = "ioc",
) -> int:
    """IOC 匹配：本地白名单式 agent_ioc + 情报库 ioc_data.db（经 ioc_db.lookup）。"""
    ensure()
    written = 0
    low = (blob or "").lower()
    local_hits: List[Dict[str, Any]] = []
    if low:
        with _lock:
            conn = _connect()
            try:
                rows = conn.execute("SELECT * FROM agent_ioc WHERE enabled=1").fetchall()
                for r in rows:
                    val = str(r["value"] or "").lower()
                    if val and val in low:
                        local_hits.append(dict(r))
                        conn.execute(
                            "UPDATE agent_ioc SET hits=hits+1, updated_at=? WHERE id=?",
                            (_now(), r["id"]),
                        )
                conn.commit()
            finally:
                conn.close()

    for h in local_hits[:20]:
        ev = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": hostname,
            "module": module,
            "severity": h.get("severity") or "high",
            "title": f"IOC 命中：{h.get('ioc_type')} {h.get('value')}",
            "detail": json.dumps({
                "ioc_id": h.get("id"),
                "ioc_type": h.get("ioc_type"),
                "value": h.get("value"),
                "note": h.get("note"),
                "source": "agent_ioc",
            }, ensure_ascii=False)[:1500],
        })
        if ev.get("ok") and not ev.get("deduped") and not ev.get("suppressed"):
            written += 1

    # 情报库精确查（ioc/ioc_data.db → MySQL/Redis/SQLite）
    candidates = _extract_ioc_candidates(events or [], blob)
    if not candidates:
        return written
    try:
        from . import ioc_db
    except Exception:
        return written

    lib_hits = 0
    for c in candidates:
        try:
            hits = ioc_db.lookup(c["value"], c["ioc_type"])
        except Exception:
            hits = []
        if not hits:
            # 哈希兼容：file_hash 再试无类型
            if c["ioc_type"] == "file_hash":
                try:
                    hits = ioc_db.lookup(c["value"], None)
                except Exception:
                    hits = []
        for hit in (hits or [])[:2]:
            malware = str(hit.get("malware") or hit.get("family") or "")[:80]
            src = str(hit.get("source") or "")[:80]
            val = str(hit.get("value") or c["value"])[:200]
            itype = str(hit.get("type") or hit.get("match_type") or c["ioc_type"])[:32]
            title = f"情报 IOC 命中：{val}（{_IOC_TYPE_CN.get(itype, itype)}）"
            fams = [x.strip() for x in malware.split(",") if x.strip()]
            if fams:
                title += f" · {fams[0]}" + (f" 等 {len(fams)} 个家族" if len(fams) > 1 else "")
            ctx = c.get("ctx") or {}
            ev = agent_protocol.report_event({
                "agent_id": agent_id,
                "hostname": hostname,
                "module": "ioc",
                "severity": "high",
                "title": title[:200],
                "detail": {
                    **{k: v for k, v in ctx.items() if k != "summary"},
                    "ioc_type": itype,
                    "ioc_value": val,
                    "malware": malware,
                    "intel_source": src,
                    "matched_from": c.get("src"),
                    "trigger": ctx.get("summary") or "",
                    "ioc_id": hit.get("id"),
                    "lib": "ioc_data",
                },
            })
            if ev.get("ok") and not ev.get("deduped") and not ev.get("suppressed"):
                written += 1
                lib_hits += 1
            if lib_hits >= 15:
                return written
    return written


def ioc_lib_status() -> Dict[str, Any]:
    """管理台展示：本地 agent_ioc + 情报库 ioc_data.db 状态。"""
    ensure()
    local_n = 0
    with _lock:
        conn = _connect()
        try:
            local_n = int(conn.execute("SELECT COUNT(*) AS c FROM agent_ioc WHERE enabled=1").fetchone()["c"])
        finally:
            conn.close()
    lib: Dict[str, Any] = {"ok": False, "path": "", "count": 0, "hint": ""}
    try:
        from . import ioc_db
        layout = ioc_db.source_layout() if hasattr(ioc_db, "source_layout") else {}
        info = ioc_db.file_info() if hasattr(ioc_db, "file_info") else {}
        st = ioc_db.stats(force=False) if hasattr(ioc_db, "stats") else {}
        lib = {
            "ok": True,
            "path": str((layout or {}).get("expected") or (info or {}).get("path") or ""),
            "count": int((st or {}).get("total") or (info or {}).get("count") or 0),
            "exists": bool((layout or {}).get("exists") or (info or {}).get("exists")),
            "mysql": (st or {}).get("mysql") if isinstance((st or {}).get("mysql"), dict) else {},
            "hint": (layout or {}).get("hint") or "",
        }
    except Exception as e:
        lib = {"ok": False, "path": str(Path(getattr(config, "IOC_DIR", "") or "") / "ioc_data.db"), "count": 0, "hint": str(e)}
    return {"ok": True, "local_enabled": local_n, "lib": lib}


# ---------- 标签 ----------

def set_agent_tags(agent_id: str, tags: List[str]) -> Dict[str, Any]:
    ensure()
    aid = str(agent_id or "").strip()
    tags = [str(t).strip()[:32] for t in (tags or []) if str(t).strip()][:20]
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM agent_tags WHERE agent_id=?", (aid,))
            for t in tags:
                conn.execute("INSERT OR IGNORE INTO agent_tags(agent_id, tag) VALUES(?,?)", (aid, t))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "agent_id": aid, "tags": tags}


def get_agent_tags(agent_id: str = "") -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            if agent_id:
                rows = conn.execute("SELECT tag FROM agent_tags WHERE agent_id=?", (agent_id,)).fetchall()
                return {"ok": True, "agent_id": agent_id, "tags": [r["tag"] for r in rows]}
            rows = conn.execute("SELECT agent_id, tag FROM agent_tags").fetchall()
            m: Dict[str, List[str]] = {}
            for r in rows:
                m.setdefault(r["agent_id"], []).append(r["tag"])
            return {"ok": True, "items": m}
        finally:
            conn.close()


# ---------- 行为序列 ----------

_DEFAULT_SEQ = [
    {
        "id": "seq-office-ps",
        "title": "办公进程后出现 PowerShell",
        "severity": "high",
        "window_sec": 180,
        "steps": [
            {"etype_contains": "process", "name_regex": r"(?i)(winword|excel|powerpnt|outlook)\.exe"},
            {"etype_contains": "process", "name_regex": r"(?i)(powershell|pwsh|cmd)\.exe"},
        ],
        "enabled": 1,
        "note": "宏/钓鱼常见链 · T1566→T1059",
    },
    {
        "id": "seq-temp-net",
        "title": "临时目录进程后外联",
        "severity": "high",
        "window_sec": 120,
        "steps": [
            {"summary_contains": "临时", "etype_contains": "process"},
            {"etype_contains": "network"},
        ],
        "enabled": 1,
        "note": "落地执行后外联 · T1105→T1071",
    },
    {
        "id": "seq-ps-net",
        "title": "PowerShell 后外联",
        "severity": "high",
        "window_sec": 90,
        "steps": [
            {"etype_contains": "process", "name_regex": r"(?i)(powershell|pwsh)\.exe"},
            {"etype_contains": "network"},
        ],
        "enabled": 1,
        "note": "脚本执行后 C2 · T1059→T1071",
    },
    {
        "id": "seq-file-proc",
        "title": "文件落地后进程创建",
        "severity": "medium",
        "window_sec": 120,
        "steps": [
            {"etype_contains": "file"},
            {"etype_contains": "process"},
        ],
        "enabled": 1,
        "note": "投放后执行 · T1105→T1204",
    },
]


def ensure_seq_rules() -> None:
    ensure()
    with _lock:
        conn = _connect()
        try:
            n = conn.execute("SELECT COUNT(*) AS c FROM agent_seq_rules").fetchone()["c"]
            if n:
                return
            for r in _DEFAULT_SEQ:
                conn.execute(
                    """INSERT INTO agent_seq_rules(id, title, severity, window_sec, steps_json, enabled, note, updated_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        r["id"], r["title"], r["severity"], r["window_sec"],
                        json.dumps(r["steps"], ensure_ascii=False), r["enabled"], r.get("note") or "", _now(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()


def list_seq_rules() -> Dict[str, Any]:
    ensure_seq_rules()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agent_seq_rules ORDER BY id").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["steps"] = json.loads(d.pop("steps_json") or "[]")
                except Exception:
                    d["steps"] = []
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def upsert_seq_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_seq_rules()
    rid = str(payload.get("id") or "").strip() or ("seq-" + uuid.uuid4().hex[:10])
    title = str(payload.get("title") or rid).strip()[:120]
    if not title:
        return {"ok": False, "error": "标题不能为空"}
    steps_in = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    steps: List[Dict[str, Any]] = []
    for s in steps_in[:8]:
        if not isinstance(s, dict):
            continue
        st = {
            "etype_contains": str(s.get("etype_contains") or "").strip()[:64],
            "summary_contains": str(s.get("summary_contains") or "").strip()[:120],
            "name_regex": str(s.get("name_regex") or "").strip()[:200],
        }
        if not any(st.values()):
            continue
        steps.append(st)
    if len(steps) < 2:
        return {"ok": False, "error": "至少需要 2 个有效步骤（A→B）"}
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_seq_rules(id, title, severity, window_sec, steps_json, enabled, note, updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     title=excluded.title, severity=excluded.severity, window_sec=excluded.window_sec,
                     steps_json=excluded.steps_json, enabled=excluded.enabled, note=excluded.note,
                     updated_at=excluded.updated_at""",
                (
                    rid, title, str(payload.get("severity") or "high")[:16],
                    max(10, min(int(payload.get("window_sec") or 120), 3600)),
                    json.dumps(steps, ensure_ascii=False),
                    1 if payload.get("enabled", True) else 0,
                    str(payload.get("note") or "")[:200], _now(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return {"ok": True, "id": rid}


def delete_seq_rule(rule_id: str) -> Dict[str, Any]:
    ensure_seq_rules()
    rid = str(rule_id or "").strip()
    if not rid:
        return {"ok": False, "error": "缺少 id"}
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("DELETE FROM agent_seq_rules WHERE id=?", (rid,))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "规则不存在"}
        finally:
            conn.close()
    return {"ok": True}


def _step_match(ev: Dict[str, Any], step: Dict[str, Any]) -> bool:
    import re
    et = str(ev.get("etype") or "")
    sm = str(ev.get("summary") or "")
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    name = str(detail.get("name") or "")
    if step.get("etype_contains") and str(step["etype_contains"]).lower() not in et.lower():
        return False
    if step.get("summary_contains") and str(step["summary_contains"]).lower() not in sm.lower():
        return False
    rx = step.get("name_regex")
    if rx:
        try:
            if not re.search(str(rx), name or sm):
                return False
        except re.error:
            return False
    return True


def match_sequences(agent_id: str, hostname: str = "") -> int:
    """在最近时间线上匹配行为序列。"""
    ensure_seq_rules()
    rules = [r for r in (list_seq_rules().get("items") or []) if r.get("enabled")]
    if not rules:
        return 0
    tl = list_timeline(agent_id, limit=80).get("items") or []
    # 时间升序
    tl = list(reversed(tl))
    written = 0
    for rule in rules:
        steps = rule.get("steps") or []
        if len(steps) < 2:
            continue
        win = int(rule.get("window_sec") or 120)
        # 找第一条命中
        for i, ev in enumerate(tl):
            if not _step_match(ev, steps[0]):
                continue
            t0 = _parse_ts(ev.get("ts"))
            idx = 1
            chain = [ev]
            for ev2 in tl[i + 1:]:
                t1 = _parse_ts(ev2.get("ts"))
                if t1 - t0 > win:
                    break
                if _step_match(ev2, steps[idx]):
                    chain.append(ev2)
                    idx += 1
                    if idx >= len(steps):
                        evr = agent_protocol.report_event({
                            "agent_id": agent_id,
                            "hostname": hostname or ev.get("hostname") or "",
                            "module": "sequence",
                            "severity": rule.get("severity") or "high",
                            "title": f"行为序列：{rule.get('title')}",
                            "detail": json.dumps({
                                "rule_id": rule.get("id"),
                                "steps": [
                                    {"etype": c.get("etype"), "summary": c.get("summary"), "ts": c.get("ts")}
                                    for c in chain
                                ],
                            }, ensure_ascii=False)[:1800],
                        })
                        if evr.get("ok") and not evr.get("deduped") and not evr.get("suppressed"):
                            written += 1
                        break
            if idx >= len(steps):
                break
    return written


def _parse_ts(s: Any) -> float:
    try:
        return time.mktime(time.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def _etype_to_rule_module(etype: str) -> str:
    et = str(etype or "").lower()
    if "file" in et or "image_load" in et or et.startswith("fim_"):
        return "file"
    if et.startswith("wmi_persist") or et.startswith("win_task") or et in ("win_bits", "win_smb", "persist_add", "persist_modify", "persist_delete"):
        return "file"
    if "network" in et:
        return "network"
    if "process" in et or et.endswith("_live"):
        return "process"
    if "driver" in et:
        return "file"
    return ""


def apply_timeline_rules(agent_id: str, host: str, events: List[Any]) -> int:
    """时间线实时事件也走 Agent 规则（保存规则后下一条即可命中，不必等快照）。"""
    try:
        from . import agent_rules
    except Exception:
        return 0
    by_mod: Dict[str, List[Dict[str, Any]]] = {}
    lol_items: List[Dict[str, Any]] = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("etype") or "")
        mod = _etype_to_rule_module(et)
        if not mod:
            continue
        detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
        if mod == "process" and "exit" not in et:
            detail = agent_rules.enrich_process_event_detail(
                agent_id, detail, str(ev.get("summary") or ""),
            )
        # 进程创建：所有进程都跑轻量 LOLBin 检测（只看进程名+命令行，量大也便宜）
        try:
            from . import agent_sync as _asy
            lol_on = _asy.server_detection_enabled("lolbin_ingest")
        except Exception:
            lol_on = True
        if lol_on and mod == "process" and "exit" not in et and (
            detail.get("command_line") or detail.get("parent_name") or detail.get("name")
        ):
            lol_items.append(dict(detail))
        # 普通 info 进程创建不跑全量规则，避免噪声刷威胁
        sev = str(ev.get("severity") or "info").lower()
        if mod == "process" and sev in ("info", "low") and "可疑" not in str(ev.get("summary") or ""):
            continue
        item = dict(detail)
        if not item.get("name") and ev.get("summary"):
            # 从摘要兜底一点可读字段
            item.setdefault("summary", ev.get("summary"))
        if et and not item.get("etype"):
            item["etype"] = et
        by_mod.setdefault(mod, []).append(item)
    written = 0
    for mod, items in by_mod.items():
        if not items:
            continue
        try:
            r = agent_rules.apply_snapshot_rules(agent_id, mod, items, hostname=host) or {}
            written += int(r.get("events") or 0)
        except Exception:
            continue
    if lol_items:
        # 非 info 的进程已在 apply_snapshot_rules(process) 里跑过 LOLBin；这里补 info 进程，dedup 由 report_event 处理
        try:
            r = agent_rules.apply_lolbin(agent_id, lol_items, hostname=host) or {}
            written += int(r.get("events") or 0)
        except Exception as e:
            print("[lolbin]", e)
    return written


# 挂钩：时间线入库后做 IOC + 序列 + 规则
_orig_ingest = ingest_timeline


def ingest_timeline(payload: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[no-redef]
    out = _orig_ingest(payload)
    events = out.pop("_detect_events", None)
    if not out.get("ok"):
        return out
    agent_id = str(payload.get("agent_id") or "").strip()
    host = str(payload.get("hostname") or "").strip()
    if events is None:
        events = payload.get("events") if isinstance(payload.get("events"), list) else []
    blob_parts = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        blob_parts.append(str(ev.get("summary") or ""))
        d = ev.get("detail")
        if isinstance(d, dict):
            blob_parts.append(json.dumps(d, ensure_ascii=False))
        elif d:
            blob_parts.append(str(d))
    ioc_n = match_iocs(agent_id, host, blob="\n".join(blob_parts), events=events, module="ioc")
    seq_n = match_sequences(agent_id, host)
    rule_n = apply_timeline_rules(agent_id, host, events)
    corr_n = 0
    try:
        from . import correlation_engine
        corr_n = correlation_engine.apply_correlations(agent_id, host, events)
    except Exception as e:
        print("[correlation_engine]", e)
    out["ioc_hits"] = ioc_n
    out["seq_hits"] = seq_n
    out["rule_hits"] = rule_n
    out["correlation_hits"] = corr_n
    out["sensor_alerts"] = _promote_sensor_alerts(agent_id, host, events)
    return out


# 允许晋升为威胁事件的传感器 etype（明确白名单；不在表内的一律只留时间线）
_ALERT_ETYPES = {
    "remote_thread_kernel", "protect_block_kernel", "remote_thread",
    "image_load_etw", "image_load_kernel", "driver_load_kernel",
    "persist_add", "persist_modify", "registry_set", "registry_delete", "registry_write",
    "fim_add", "fim_modify", "fim_rename",
    "dns_nx_burst", "win_audit_clear",
    "win_account_create", "win_group_add", "win_service_install", "win_task_create",
    "win_service_config",     "win_ps_scriptblock", "process_access",
    "file_create", "priv_escalation", "memory_scan_hit",
    "device_mount", "api_amsi", "amsi_hit", "api_call", "api_hit",
    "evm_hit", "ptm_hit", "memory_rule", "memory_yara",
}
_SCRIPT_DROP_EXTS = {".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".scr", ".wsf"}
_SIGNED_BAD = {"notsigned", "hashmismatch", "nottrusted", "incompatible"}
_SKIP_PROMOTE_ETYPES = {"sensor_status", "etw_status", "winevent_status"}
# 外联 / DNS：时间线照常入库，威胁事件只由 IOC 命中产出
_IOC_ONLY_ETYPES = {
    "network_connect", "network_connect_etw",
    "dns_query", "dns_summary",
}

# Windows 更新常改启动类型的系统服务（7040），不当作威胁
_WIN_SVC_NOISE = {
    "background intelligent transfer service", "bits",
    "windows update", "wuauserv",
    "update orchestrator service", "usosvc",
    "delivery optimization", "dosvc",
    "windows modules installer", "trustedinstaller",
    "waasmedicSvc", "waasmedicsvc",
    "microsoft account sign-in assistant", "wlidsvc",
    "system events broker", "systemeventsbroker",
    "connected user experiences and telemetry", "diagtrack",
    "windows push notifications system service", "wpnservice",
}


def _is_noisy_service_config(detail: Dict[str, Any], summary: str = "") -> bool:
    name = str(detail.get("name") or detail.get("service") or "").strip().lower()
    blob = f"{name} {summary}".lower()
    if not blob.strip():
        return False
    for n in _WIN_SVC_NOISE:
        if n in blob:
            return True
    return False


_MODULE_PREFIXES = (
    (("registry_", "persist_"), "registry"),
    (("image_load", "driver_load"), "image"),
    (("remote_thread", "process_access", "protect_block"), "inject"),
    (("process_",), "process"),
    (("file_", "fim_"), "file"),
    (("network_",), "network"),
    (("dns_",), "dns"),
    (("device_",), "file"),
    (("win_logon", "win_explicit_logon", "win_account", "win_password", "win_group", "win_special_priv"), "account"),
    (("win_service",), "service"),
    (("win_task",), "task"),
    (("win_ps_",), "script"),
    (("win_audit",), "audit"),
)


def alert_module_for(etype: str) -> str:
    """按事件语义归类告警模块（来源 etw/kernel/sysmon 保留在 detail.source）。"""
    et = str(etype or "").lower()
    for prefixes, mod in _MODULE_PREFIXES:
        if et.startswith(prefixes):
            return mod
    return "timeline"


def _detail_looks_registry(detail: Dict[str, Any]) -> bool:
    if not isinstance(detail, dict):
        return False
    if str(detail.get("source_etype") or "").startswith("registry"):
        return True
    chain = detail.get("chain")
    if isinstance(chain, list):
        for c in chain:
            if isinstance(c, dict) and str(c.get("etype") or "").startswith("registry"):
                return True
            if isinstance(c, dict) and (c.get("reg_key") or c.get("key")):
                return True
    return bool(detail.get("reg_key") or detail.get("key"))


def _ptm_detail_matched_hint(detail: Dict[str, Any]) -> str:
    if not isinstance(detail, dict):
        return ""
    if detail.get("matched"):
        return str(detail["matched"])[:500]
    chain = detail.get("chain")
    if not isinstance(chain, list):
        tr = detail.get("trigger")
        if isinstance(tr, dict):
            chain = [tr]
        else:
            return ""
    parts: List[str] = []
    for i, c in enumerate(chain[:6]):
        if not isinstance(c, dict):
            continue
        s = str(c.get("summary") or c.get("etype") or "").strip()
        rk = str(c.get("reg_key") or c.get("key") or c.get("path") or "").strip()
        if rk and rk not in s:
            s = f"{rk} {s}".strip()
        if s:
            parts.append(f"{i + 1}) {s}")
    return " | ".join(parts)[:500]


def _sensor_detail_matched_hint(detail: Dict[str, Any]) -> str:
    if not isinstance(detail, dict):
        return ""
    parts = [
        str(detail.get("source_summary") or "").strip(),
        str(detail.get("remote") or detail.get("remote_ip") or "").strip(),
        str(detail.get("domain") or "").strip(),
        str(detail.get("reg_key") or detail.get("key") or detail.get("path") or "").strip(),
        str(detail.get("command_line") or "").strip(),
    ]
    return " · ".join(p for p in parts if p)[:500]


def _promote_sensor_alerts(agent_id: str, host: str, events: List[Any]) -> int:
    n = 0
    for ev in events[:200]:
        if not isinstance(ev, dict):
            continue
        et = str(ev.get("etype") or "")
        sev = str(ev.get("severity") or "").lower()
        if et in _SKIP_PROMOTE_ETYPES or et in _IOC_ONLY_ETYPES:
            continue
        # 只晋升白名单 etype，且必须 medium+（不再把 info 抬成 medium）
        if et not in _ALERT_ETYPES:
            continue
        if sev not in ("medium", "high", "critical"):
            continue
        use_sev = sev
        detail_obj = {"etype": et}
        if isinstance(ev.get("detail"), dict):
            detail_obj.update(ev.get("detail") or {})
        title = str(ev.get("summary") or et)[:200]
        mod = alert_module_for(et)
        if et in ("evm_hit", "ptm_hit", "memory_rule", "memory_yara"):
            rt = str(detail_obj.get("rule_title") or detail_obj.get("title") or "").strip()
            if rt:
                prefix = "EVM" if et == "evm_hit" else "PTM" if et == "ptm_hit" else "内存规则"
                title = f"{prefix}：{rt}"[:200]
            detail_obj.setdefault("rule_title", rt or detail_obj.get("title"))
            if et == "evm_hit" and not detail_obj.get("matched"):
                detail_obj["matched"] = _sensor_detail_matched_hint(detail_obj)
            if et == "ptm_hit" and not detail_obj.get("matched"):
                detail_obj["matched"] = _ptm_detail_matched_hint(detail_obj)
            mod = "script" if et in ("evm_hit", "memory_rule", "memory_yara") else "process"
            if et == "ptm_hit" and _detail_looks_registry(detail_obj):
                mod = "registry"
            if et == "evm_hit" and str(detail_obj.get("source_etype") or "").startswith("network"):
                mod = "network"
        if ev.get("ts") and not detail_obj.get("event_ts"):
            detail_obj["event_ts"] = ev.get("ts")
        signed = str(detail_obj.get("signed") or "").strip().lower()
        # FIM：有签名字段时只认明确未签名/损坏；Valid 与未知均不晋升（hosts 等无签名字段的照常）
        if et.startswith("fim_") and signed and signed not in _SIGNED_BAD:
            continue
        # DLL / 内核模块：必须明确未签名
        if et in ("image_load_etw", "image_load_kernel") and signed not in _SIGNED_BAD:
            continue
        # 文件落地：仅投放区脚本类
        if et == "file_create":
            ext = str(detail_obj.get("ext") or "").lower()
            if ext not in _SCRIPT_DROP_EXTS:
                continue
        # BITS / Windows Update 等系统服务启动类型变更不晋升
        if et == "win_service_config" and _is_noisy_service_config(detail_obj, str(ev.get("summary") or "")):
            continue
        # 脚本块仅可疑特征（Agent 已标 high）
        if et == "win_ps_scriptblock" and sev != "high":
            continue
        # 规则管理里关闭的传感器不再晋升告警
        try:
            from . import agent_rules as _ar
            if not _ar.sensor_event_allowed(et, str(ev.get("summary") or ""), detail_obj):
                continue
        except Exception:
            pass
        try:
            from . import event_detail_enrich as _ede
            with agent_protocol._lock:
                conn = agent_protocol._connect()
                try:
                    detail_obj, _ = _ede.enrich_detail_from_timeline(
                        conn,
                        agent_id=agent_id,
                        title=title,
                        detail=detail_obj,
                        created_at=str(ev.get("ts") or ""),
                    )
                finally:
                    conn.close()
        except Exception:
            pass
        r = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": host,
            "module": mod,
            "severity": use_sev,
            "title": title,
            "detail": detail_obj,
        })
        if r.get("ok") and not r.get("deduped") and not r.get("suppressed"):
            n += 1
        if n >= 120:
            break
    return n


_LAST_THREAT_SYNC_AT = 0.0
_THREAT_SYNC_MIN_INTERVAL = 45.0


def sync_threats_from_timeline(*, limit: int = 300, force: bool = False) -> Dict[str, Any]:
    """把近期中危+时间线补晋升为威胁事件（修复首页有数据、威胁事件为空）。"""
    global _LAST_THREAT_SYNC_AT
    ensure()
    from . import agent_protocol as ap

    now_ts = time.time()
    if not force and (now_ts - _LAST_THREAT_SYNC_AT) < _THREAT_SYNC_MIN_INTERVAL:
        return {
            "ok": True,
            "skipped": True,
            "reason": "throttled",
            "retry_after_sec": int(_THREAT_SYNC_MIN_INTERVAL - (now_ts - _LAST_THREAT_SYNC_AT)),
        }
    _LAST_THREAT_SYNC_AT = now_ts

    purged = purge_agent_self_noise_events()
    orphans = purge_orphan_agent_data()
    lim = max(50, min(int(limit or 300), 800))
    with ap._lock:
        conn = ap._connect()
        try:
            rows = conn.execute(
                """SELECT t.agent_id, t.hostname, t.etype, t.summary, t.severity, t.detail_json, t.ts
                   FROM agent_timeline t JOIN agents a ON a.agent_id = t.agent_id
                   LEFT JOIN agent_event_deletions d ON d.agent_id = t.agent_id AND d.title = t.summary
                   WHERE lower(t.severity) IN ('medium','high','critical')
                     AND (d.deleted_at IS NULL OR t.created_at > d.deleted_at)
                     AND NOT EXISTS (
                         SELECT 1 FROM agent_events e
                         WHERE e.agent_id = t.agent_id AND e.title = substr(t.summary, 1, 200)
                     )
                   ORDER BY t.id DESC LIMIT ?""",
                (lim,),
            ).fetchall()
        finally:
            conn.close()
    by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        d = dict(r)
        aid = str(d.get("agent_id") or "")
        if not aid:
            continue
        detail = d.get("detail_json")
        if isinstance(detail, str):
            try:
                detail = json.loads(detail) if detail else {}
            except Exception:
                # 解析失败的旧截断数据不再包成 raw 晋升（会把告警详情盖成「命中对象 —」）
                continue
        if not isinstance(detail, dict):
            continue
        by_agent.setdefault(aid, []).append({
            "etype": d.get("etype"),
            "summary": d.get("summary"),
            "severity": d.get("severity"),
            "detail": detail,
            "ts": d.get("ts"),
        })
    total = 0
    for aid, evs in by_agent.items():
        host = ""
        try:
            host = ap._host_of(aid)
        except Exception:
            host = str((evs[0] or {}).get("hostname") or "")
        # hostname 在 timeline 行上
        if not host:
            for row in rows:
                if str(row["agent_id"]) == aid and row["hostname"]:
                    host = str(row["hostname"])
                    break
        # 晋升前再滤一遍自噪声，避免历史 fa-watch / fa-ps 回灌
        clean = [e for e in evs if not _is_agent_self_noise(
            str(e.get("etype") or ""), str(e.get("summary") or ""), e.get("detail") if isinstance(e.get("detail"), dict) else {}
        )]
        total += _promote_sensor_alerts(aid, host, clean)
    try:
        repaired = ap.repair_broken_event_details()
    except Exception:
        repaired = 0
    return {
        "ok": True,
        "promoted": total,
        "agents": len(by_agent),
        "scanned": len(rows),
        "purged": purged,
        "orphans": orphans,
        "repaired": repaired,
    }


# ---------- ATT&CK 看板 / 攻击故事 ----------

def _map_attck(text: str, module: str = "", etype: str = "") -> Dict[str, str]:
    if "LOLBin" in str(text or ""):
        try:
            from . import lolbin as _lb
            hit = _lb.technique_for_text(text)
            if hit:
                return hit
        except Exception:
            pass
    blob = f"{module} {etype} {text}".lower()
    if module == "memory" or "内存" in blob:
        if "mimikatz" in blob or "lsass" in blob:
            return {"technique": "T1003.001", "tactic": "credential_access"}
        return {"technique": "T1055", "tactic": "defense_evasion"}
    for keys, tid, tactic in _ATTCK_HINTS:
        if any(k.lower() in blob for k in keys):
            return {"technique": tid, "tactic": tactic}
    if module in ("startup", "task", "service"):
        return {"technique": "T1547.001" if module == "startup" else ("T1053.005" if module == "task" else "T1543.003"),
                "tactic": "persistence"}
    if module == "network" or "network" in etype:
        return {"technique": "T1071", "tactic": "command_and_control"}
    if module == "process" or "process" in etype:
        return {"technique": "T1059", "tactic": "execution"}
    return {"technique": "", "tactic": ""}


_TECH_NAME_CN = {
    "T1003": "凭证转储", "T1021": "远程服务", "T1053.005": "计划任务", "T1055": "进程注入",
    "T1059": "命令与脚本解释器", "T1071": "应用层协议通信", "T1105": "远程工具传入",
    "T1112": "修改注册表", "T1204": "用户执行", "T1543.003": "Windows 服务",
    "T1547.001": "注册表运行键 / 启动文件夹", "T1562.001": "禁用或篡改安全工具",
    "T1566": "钓鱼",     "T1574.002": "DLL 侧加载", "T1036.005": "匹配合法名称或位置",
    "T1070.001": "清除 Windows 事件日志", "T1136.001": "创建本地账号", "T1098": "账号操纵",
    "T1110": "暴力破解", "T1078": "有效账号", "T1003.001": "LSASS 内存读取", "T1568.002": "域名生成算法(DGA)",
    "T1059.001": "PowerShell",
}


def _tech_name(tid: str) -> str:
    if not tid:
        return ""
    if tid in _TECH_NAME_CN:
        return _TECH_NAME_CN[tid]
    try:
        from . import mitre
        meta = mitre.technique_meta(tid)
        return meta.get("name_cn") or meta.get("name_en") or ""
    except Exception:
        return ""


def _tech_label(tid: str) -> str:
    if not tid:
        return ""
    name = _tech_name(tid)
    return f"{tid} · {name}" if name else tid


def threat_process_tree(agent_id: str = "", *, event_id: int = 0, max_nodes: int = 56) -> Dict[str, Any]:
    """威胁视图：从告警证据 + 进程实体表还原进程树（祖先链 + 子进程展开）。"""
    ensure()
    aid = str(agent_id or "").strip()
    seed_eid = ""
    seed_pid: Any = None
    hit_title = ""
    event_item: Optional[Dict[str, Any]] = None

    if event_id:
        try:
            got = agent_protocol.get_event(int(event_id))
            ev = (got or {}).get("item") if (got or {}).get("ok") else None
        except Exception:
            ev = None
        if ev:
            event_item = ev
            aid = aid or str(ev.get("agent_id") or "")
            hit_title = str(ev.get("title") or "")
            raw = ev.get("detail_obj") or ev.get("detail") or {}
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = {}
            if not isinstance(raw, dict):
                raw = {}
            evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else raw
            inner = evidence.get("evidence") if isinstance(evidence.get("evidence"), dict) else evidence
            if isinstance(inner, dict):
                seed_eid = str(inner.get("entity_id") or evidence.get("entity_id") or "").strip()
                seed_pid = inner.get("pid") if inner.get("pid") not in (None, "") else evidence.get("pid")

    if not aid:
        return {"ok": False, "error": "缺少 agent_id 或无效事件"}

    max_nodes = max(8, min(int(max_nodes or 56), 120))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT * FROM agent_processes WHERE agent_id=? ORDER BY last_seen DESC LIMIT 800",
                (aid,),
            ).fetchall()
            procs = [dict(r) for r in rows]
        finally:
            conn.close()

    by_eid: Dict[str, Dict[str, Any]] = {}
    by_parent: Dict[str, List[Dict[str, Any]]] = {}
    for p in procs:
        eid = str(p.get("entity_id") or "").strip()
        if not eid:
            continue
        by_eid[eid] = p
        pe = str(p.get("parent_entity_id") or "").strip()
        if pe:
            by_parent.setdefault(pe, []).append(p)

    seed = by_eid.get(seed_eid) if seed_eid else None
    if not seed and seed_pid not in (None, ""):
        try:
            want = int(seed_pid)
            for p in procs:
                if int(p.get("pid") or 0) == want:
                    seed = p
                    seed_eid = str(p.get("entity_id") or "")
                    break
        except (TypeError, ValueError):
            pass

    if not seed:
        drop_chain = _build_threat_drop_chain(aid, event_item, None, [], seed_pid)
        return {
            "ok": True,
            "agent_id": aid,
            "nodes": [],
            "edges": [],
            "root_id": "",
            "hit_id": seed_eid,
            "title": hit_title,
            "drop_chain": drop_chain,
        }

    if not str(seed.get("command_line") or "").strip():
        try:
            from . import event_detail_enrich as _ede
            info = _ede._find_process_command(
                conn, aid,
                pid=int(seed.get("pid") or 0),
                entity_id=str(seed.get("entity_id") or ""),
            )
            if info and str(info.get("command_line") or "").strip():
                seed["command_line"] = info["command_line"]
        except Exception:
            pass
    if event_item and not str(seed.get("command_line") or "").strip():
        raw = event_item.get("detail_obj") or event_item.get("detail") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        if isinstance(raw, dict):
            cmd = str(raw.get("command_line") or raw.get("command") or "").strip()
            if cmd:
                seed["command_line"] = cmd

    chain: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = seed
    seen_chain: set = set()
    while cur and len(chain) < 14:
        eid = str(cur.get("entity_id") or "")
        if not eid or eid in seen_chain:
            break
        seen_chain.add(eid)
        chain.append(cur)
        pe = str(cur.get("parent_entity_id") or "").strip()
        cur = by_eid.get(pe) if pe else None
    chain.reverse()

    hit_id = str(seed.get("entity_id") or "")
    include: set = set()
    for p in chain:
        eid = str(p.get("entity_id") or "")
        if eid:
            include.add(eid)
    if hit_id:
        include.add(hit_id)
    # 命中进程的直接子进程 + 同父兄弟（避免把 explorer 下数百进程全拉进图）
    for child in by_parent.get(hit_id, [])[:20]:
        ce = str(child.get("entity_id") or "")
        if ce:
            include.add(ce)
    parent_eid = str(seed.get("parent_entity_id") or "").strip()
    if parent_eid:
        include.add(parent_eid)
        for sib in by_parent.get(parent_eid, [])[:14]:
            ce = str(sib.get("entity_id") or "")
            if ce:
                include.add(ce)
    # 祖先链上每层少量上下文子进程
    for p in chain:
        pe = str(p.get("entity_id") or "")
        for child in by_parent.get(pe, [])[:5]:
            ce = str(child.get("entity_id") or "")
            if ce and len(include) < max_nodes:
                include.add(ce)

    def _node_of(p: Dict[str, Any], *, is_hit: bool) -> Dict[str, Any]:
        eid = str(p.get("entity_id") or "")
        return {
            "id": eid,
            "name": p.get("name") or "?",
            "pid": p.get("pid"),
            "ppid": p.get("ppid"),
            "parent_id": str(p.get("parent_entity_id") or ""),
            "path": p.get("path") or "",
            "command_line": str(p.get("command_line") or "")[:2000],
            "is_hit": is_hit,
            "exit_time": p.get("exit_time") or "",
        }

    nodes = [_node_of(by_eid[eid], is_hit=(eid == hit_id)) for eid in include if eid in by_eid]
    edges = []
    node_ids = {n["id"] for n in nodes}
    by_pid: Dict[int, str] = {}
    for n in nodes:
        try:
            by_pid[int(n.get("pid") or 0)] = n["id"]
        except (TypeError, ValueError):
            pass
    for n in nodes:
        pid = n.get("parent_id")
        if pid and pid in node_ids:
            edges.append({"from": pid, "to": n["id"], "label": "子进程"})
    # PPID 补链 / 父进程不可见时插入占位节点
    for n in list(nodes):
        if n.get("parent_id") and n["parent_id"] in node_ids:
            continue
        ppid = n.get("ppid")
        try:
            pp = int(ppid) if ppid not in (None, "") else 0
        except (TypeError, ValueError):
            pp = 0
        if pp and pp in by_pid and by_pid[pp] != n["id"]:
            n["parent_id"] = by_pid[pp]
            n["link_repaired"] = True
            if n["parent_id"] not in node_ids:
                continue
            edges.append({"from": n["parent_id"], "to": n["id"], "label": "PPID 关联", "repaired": True})
        elif pp and n["id"] == hit_id:
            syn = f"syn-parent-{pp}"
            if syn not in node_ids:
                nodes.append({
                    "id": syn,
                    "name": f"父进程 PID {pp}",
                    "pid": pp,
                    "ppid": None,
                    "parent_id": "",
                    "path": "",
                    "command_line": "",
                    "is_hit": False,
                    "exit_time": "",
                    "synthetic": True,
                    "missing": True,
                })
                node_ids.add(syn)
            n["parent_id"] = syn
            n["link_repaired"] = True
            edges.append({"from": syn, "to": n["id"], "label": "断链推断", "repaired": True})
    for n in nodes:
        pid = n.get("parent_id")
        if pid and pid in node_ids and not any(e["from"] == pid and e["to"] == n["id"] for e in edges):
            edges.append({"from": pid, "to": n["id"], "label": "子进程"})
    root_id = str(chain[0].get("entity_id") or hit_id) if chain else hit_id
    if root_id.startswith("syn-parent-"):
        root_id = hit_id or root_id
    drop_chain = _build_threat_drop_chain(aid, event_item, seed, chain, seed_pid)
    return {
        "ok": True,
        "agent_id": aid,
        "root_id": root_id,
        "hit_id": hit_id,
        "nodes": nodes,
        "edges": edges,
        "title": hit_title,
        "drop_chain": drop_chain,
    }


def attack_story(agent_id: str = "", *, event_id: int = 0, limit: int = 80) -> Dict[str, Any]:
    """单主机 / 单事件的攻击故事链：时间升序节点 + ATT&CK 标注。"""
    ensure()
    aid = str(agent_id or "").strip()
    nodes: List[Dict[str, Any]] = []
    host = ""

    if event_id:
        try:
            got = agent_protocol.get_event(int(event_id))
            ev = (got or {}).get("item") if (got or {}).get("ok") else None
        except Exception:
            ev = None
        if ev and ev.get("id"):
            aid = aid or str(ev.get("agent_id") or "")
            host = str(ev.get("hostname") or "")
            mapped = _map_attck(str(ev.get("title") or ""), str(ev.get("module") or ""))
            nodes.append({
                "kind": "threat",
                "ts": ev.get("created_at") or ev.get("updated_at"),
                "title": ev.get("title"),
                "severity": ev.get("severity"),
                "module": ev.get("module"),
                "technique": mapped["technique"],
                "tactic": mapped["tactic"],
                "technique_label": _tech_label(mapped["technique"]),
                "id": ev.get("id"),
            })

    if aid:
        tl = list_timeline(aid, limit=limit).get("items") or []
        for t in reversed(tl):
            mapped = _map_attck(str(t.get("summary") or ""), etype=str(t.get("etype") or ""))
            host = host or str(t.get("hostname") or "")
            nodes.append({
                "kind": "timeline",
                "ts": t.get("ts") or t.get("created_at"),
                "title": t.get("summary"),
                "severity": t.get("severity"),
                "etype": t.get("etype"),
                "technique": mapped["technique"],
                "tactic": mapped["tactic"],
                "technique_label": _tech_label(mapped["technique"]),
                "detail": t.get("detail"),
            })
        try:
            evs = agent_protocol.list_events(agent_id=aid, limit=40)
            for e in (evs.get("items") or []):
                mapped = _map_attck(str(e.get("title") or ""), str(e.get("module") or ""))
                nodes.append({
                    "kind": "threat",
                    "ts": e.get("created_at"),
                    "title": e.get("title"),
                    "severity": e.get("severity"),
                    "module": e.get("module"),
                    "technique": mapped["technique"],
                    "tactic": mapped["tactic"],
                    "technique_label": _tech_label(mapped["technique"]),
                    "id": e.get("id"),
                })
        except Exception:
            pass

    nodes.sort(key=lambda x: str(x.get("ts") or ""))
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for n in nodes:
        k = (n.get("kind"), n.get("title"), n.get("ts"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
    techniques = []
    tseen = set()
    for n in uniq:
        tid = n.get("technique")
        if tid and tid not in tseen:
            tseen.add(tid)
            techniques.append({
                "id": tid,
                "label": n.get("technique_label") or tid,
                "tactic": n.get("tactic"),
            })
    return {
        "ok": True,
        "agent_id": aid,
        "hostname": host,
        "nodes": uniq[-limit:],
        "techniques": techniques,
        "tactics": [{"id": a, "name": b} for a, b in _ATTCK_TACTICS],
    }


def attck_board(*, limit_events: int = 2000, agent_id: str = "", days: int = 0) -> Dict[str, Any]:
    """全局 ATT&CK 看板：按战术聚合近期威胁；可按主机 / 天数过滤，附技术热力矩阵。"""
    ensure()
    cells: Dict[str, List[Dict[str, Any]]] = {t[0]: [] for t in _ATTCK_TACTICS}
    tech_count: Dict[str, int] = {}
    matrix: Dict[str, Dict[str, int]] = {t[0]: {} for t in _ATTCK_TACTICS}
    hosts: Dict[str, int] = {}
    tactic_names = dict(_ATTCK_TACTICS)
    tactic_count: Dict[str, int] = {t[0]: 0 for t in _ATTCK_TACTICS}
    tactic_high: Dict[str, int] = {t[0]: 0 for t in _ATTCK_TACTICS}
    tech_tactic: Dict[str, str] = {}
    host_aid: Dict[str, str] = {}
    rows: List[Dict[str, Any]] = []
    high = open_n = unmapped = 0
    items = _attck_source_events(agent_id=agent_id, days=days, limit=limit_events)
    for e in items:
        mapped = _map_attck(str(e.get("title") or ""), str(e.get("module") or ""))
        tid = mapped.get("technique") or ""
        tactic = mapped.get("tactic") or ""
        if tactic not in tactic_names:
            tactic = ""
        sev = str(e.get("severity") or "").lower()
        is_high = sev in ("high", "critical")
        high += is_high
        open_n += str(e.get("status") or "open") == "open"
        if tid and tactic:
            tech_count[tid] = tech_count.get(tid, 0) + 1
            tech_tactic.setdefault(tid, tactic)
            matrix[tactic][tid] = matrix[tactic].get(tid, 0) + 1
            tactic_count[tactic] += 1
            tactic_high[tactic] += is_high
        else:
            unmapped += 1
        hn = str(e.get("hostname") or e.get("agent_id") or "")
        if hn:
            hosts[hn] = hosts.get(hn, 0) + 1
            host_aid.setdefault(hn, str(e.get("agent_id") or ""))
        row = {
            "id": e.get("id"),
            "title": e.get("title"),
            "severity": e.get("severity"),
            "hostname": e.get("hostname"),
            "agent_id": e.get("agent_id"),
            "ts": e.get("created_at"),
            "technique": tid,
            "technique_label": _tech_label(tid) if tid else "",
            "technique_name": _tech_name(tid),
            "tactic": tactic,
            "tactic_name": tactic_names.get(tactic, "未映射"),
            "status": e.get("status"),
        }
        rows.append(row)
        if tactic:
            cells[tactic].append(row)

    columns = [
        {"id": tac, "name": name, "count": tactic_count[tac], "items": cells[tac][:30]}
        for tac, name in _ATTCK_TACTICS
    ]
    top_tech = sorted(
        [{"id": k, "count": v, "label": _tech_label(k), "name": _tech_name(k), "tactic": tech_tactic.get(k, ""),
          "tactic_name": tactic_names.get(tech_tactic.get(k, ""), "")} for k, v in tech_count.items()],
        key=lambda x: (-x["count"], x["id"]),
    )
    heat = []
    for tac, name in _ATTCK_TACTICS:
        techs = sorted(
            [{"id": k, "count": v, "label": _tech_label(k), "name": _tech_name(k)}
             for k, v in (matrix.get(tac) or {}).items()],
            key=lambda x: (-x["count"], x["id"]),
        )
        heat.append({"tactic": tac, "name": name, "count": tactic_count[tac],
                     "high": tactic_high[tac], "techniques": techs})
    top_hosts = sorted(
        [{"host": k, "agent_id": host_aid.get(k, ""), "count": v} for k, v in hosts.items()],
        key=lambda x: -x["count"],
    )[:10]
    covered = sum(1 for h in heat if h["techniques"])
    rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return {
        "ok": True,
        "columns": columns,
        "top_techniques": top_tech,
        "heat": heat,
        "top_hosts": top_hosts,
        "tactics_covered": covered,
        "event_total": len(items),
        "high_total": high,
        "open_total": open_n,
        "unmapped_total": unmapped,
        "items": rows,
    }


def _attck_source_events(*, agent_id: str = "", days: int = 0, limit: int = 2000) -> List[Dict[str, Any]]:
    """看板数据源：时间窗在 SQL 里过滤，避免先截断条数再按天筛导致漏数；已加白（无需处置）不计入。"""
    clauses = ["status != 'ignored'"]
    args: List[Any] = []
    if agent_id:
        clauses.append("agent_id=?")
        args.append(str(agent_id))
    if days and days > 0:
        clauses.append("created_at>=?")
        args.append(time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - int(days) * 86400)))
    args.append(max(1, min(int(limit or 2000), 5000)))
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                f"""SELECT id, agent_id, hostname, severity, title, module, status, created_at
                    FROM agent_events WHERE {' AND '.join(clauses)}
                    ORDER BY id DESC LIMIT ?""",
                args,
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()


# ---------- 灰度升级包 ----------

def _upgrade_dir() -> Path:
    root = Path(getattr(config, "DATA_ROOT", None) or getattr(config, "ROOT", Path(".")))
    d = root / "data" / "agent_upgrades"
    d.mkdir(parents=True, exist_ok=True)
    return d


def upgrade_sign_message(sha256_hex: str, version: str, size: int) -> bytes:
    """与 Agent upgradeSignMessage 一致。"""
    return f"FA-UPGRADE-V1\n{str(sha256_hex).lower().strip()}\n{str(version).strip()}\n{int(size)}".encode("utf-8")


def _upgrade_key_paths() -> tuple:
    d = _upgrade_dir()
    return d / "ed25519_priv.pem", d / "ed25519_pub.b64"


def ensure_upgrade_keypair() -> Dict[str, Any]:
    """首次调用时生成 Ed25519 密钥对；私钥仅留在服务端 data 目录。"""
    priv_path, pub_path = _upgrade_key_paths()
    if priv_path.is_file() and pub_path.is_file():
        return {"ok": True, "pubkey": pub_path.read_text(encoding="utf-8").strip(), "created": False}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception as e:
        return {"ok": False, "error": f"缺少 cryptography: {e}"}
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64

    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    priv_path.write_bytes(priv_pem)
    try:
        priv_path.chmod(0o600)
    except Exception:
        pass
    pub_path.write_text(pub_b64 + "\n", encoding="utf-8")
    return {"ok": True, "pubkey": pub_b64, "created": True}


def get_upgrade_pubkey() -> Dict[str, Any]:
    out = ensure_upgrade_keypair()
    if not out.get("ok"):
        return out
    return {"ok": True, "pubkey": out["pubkey"], "alg": "Ed25519"}


def sign_upgrade_package(sha256_hex: str, version: str, size: int) -> str:
    """返回 base64 签名；密钥不可用时返回空串。"""
    out = ensure_upgrade_keypair()
    if not out.get("ok"):
        return ""
    priv_path, _ = _upgrade_key_paths()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception:
        return ""
    try:
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            return ""
        sig = priv.sign(upgrade_sign_message(sha256_hex, version, size))
        import base64

        return base64.b64encode(sig).decode("ascii")
    except Exception as e:
        print("[upgrade] sign failed:", e)
        return ""


def list_upgrade_packages() -> Dict[str, Any]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, version, filename, sha256, size, note, created_by, created_at, "
                "COALESCE(sig_ed25519,'') AS sig_ed25519 FROM agent_upgrade_packages ORDER BY created_at DESC"
            ).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["signed"] = bool(d.get("sig_ed25519"))
                items.append(d)
            return {"ok": True, "items": items}
        finally:
            conn.close()


def save_upgrade_package(
    content: bytes,
    *,
    version: str,
    filename: str = "forensic-agent.exe",
    note: str = "",
    actor: str = "",
) -> Dict[str, Any]:
    ensure()
    import hashlib

    if not content or len(content) < 1024:
        return {"ok": False, "error": "包内容过小"}
    if len(content) > 80 * 1024 * 1024:
        return {"ok": False, "error": "包超过 80MB"}
    ver = str(version or "").strip()[:32] or time.strftime("%Y%m%d%H%M%S")
    pid = uuid.uuid4().hex
    sha = hashlib.sha256(content).hexdigest()
    safe_name = Path(filename or "forensic-agent.exe").name
    if not safe_name.lower().endswith(".exe"):
        safe_name += ".exe"
    dest = _upgrade_dir() / f"{pid}_{safe_name}"
    dest.write_bytes(content)
    sig = sign_upgrade_package(sha, ver, len(content))
    now = _now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_upgrade_packages(id, version, filename, sha256, size, note, created_by, created_at, sig_ed25519)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (pid, ver, dest.name, sha, len(content), note[:200], actor[:64], now, sig),
            )
            conn.commit()
        finally:
            conn.close()
    _audit("upgrade_upload", detail=f"version={ver} sha256={sha[:16]}… size={len(content)} signed={bool(sig)}", actor=actor)
    pub = get_upgrade_pubkey().get("pubkey") or ""
    return {"ok": True, "id": pid, "version": ver, "sha256": sha, "size": len(content), "sig_ed25519": sig, "pubkey": pub}


def get_upgrade_package(pid: str) -> Optional[Dict[str, Any]]:
    ensure()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_upgrade_packages WHERE id=?", (str(pid),)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def read_upgrade_package_bytes(pid: str) -> tuple:
    meta = get_upgrade_package(pid)
    if not meta:
        return None, None
    path = _upgrade_dir() / meta["filename"]
    if not path.is_file():
        return meta, None
    return meta, path.read_bytes()


def delete_upgrade_package(pid: str) -> Dict[str, Any]:
    ensure()
    meta = get_upgrade_package(pid)
    if not meta:
        return {"ok": False, "error": "不存在"}
    path = _upgrade_dir() / meta["filename"]
    try:
        if path.is_file():
            path.unlink()
    except Exception:
        pass
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM agent_upgrade_packages WHERE id=?", (str(pid),))
            conn.commit()
        finally:
            conn.close()
    return {"ok": True}


def push_upgrade(
    package_id: str,
    agent_ids: List[str],
    *,
    actor: str = "",
    base_url: str = "",
) -> Dict[str, Any]:
    """向指定终端下发 upgrade 指令（灰度）。"""
    meta = get_upgrade_package(package_id)
    if not meta:
        return {"ok": False, "error": "升级包不存在"}
    ids = [str(a).strip() for a in (agent_ids or []) if str(a).strip()]
    if not ids:
        return {"ok": False, "error": "未选择终端"}
    base = str(base_url or "").rstrip("/")
    url = f"{base}/api/agent/upgrade-packages/{meta['id']}/download" if base else f"/api/agent/upgrade-packages/{meta['id']}/download"
    sig = str(meta.get("sig_ed25519") or "")
    if not sig:
        sig = sign_upgrade_package(meta["sha256"], meta["version"], int(meta.get("size") or 0))
        if sig:
            with _lock:
                conn = _connect()
                try:
                    conn.execute(
                        "UPDATE agent_upgrade_packages SET sig_ed25519=? WHERE id=?",
                        (sig, meta["id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
    pub = get_upgrade_pubkey().get("pubkey") or ""
    results = []
    for aid in ids[:200]:
        params = {
            "package_id": meta["id"],
            "version": meta["version"],
            "sha256": meta["sha256"],
            "url": url,
            "size": meta["size"],
        }
        if sig:
            params["sig_ed25519"] = sig
        if pub:
            params["pubkey"] = pub  # 仅当 Agent 未钉扎公钥时作开发兜底
        r = create_command(aid, "upgrade", params, actor=actor)
        results.append({"agent_id": aid, **r})
    _audit(
        "upgrade_push",
        detail=json.dumps({"package_id": package_id, "version": meta["version"], "agents": len(ids)}, ensure_ascii=False),
        actor=actor,
    )
    return {"ok": True, "package_id": package_id, "version": meta["version"], "results": results}

