# -*- coding: utf-8 -*-
"""终端 Agent 协议（骨架）。

现状：平台主路径仍是离线 pack / 一次性 POST。
本模块定义实时 Agent 的模块集、心跳与增量快照存储，供后续 Windows 安装包对接。

工作量说明（务实）：
- MVP 心跳 + 在线列表：小
- 计划任务/服务/启动项/网络增量同步 + 变更 diff + 告警：中大
- 安装包、保活、权限、断线续传、多版本兼容：大

建议分阶段：heartbeat → snapshot(persist/network) → 变更事件 → 安装器。
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import secrets
import signal
import sqlite3
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from . import config

_pkg_lock = threading.Lock()

# Agent 默认同步模块（与 forensic 侧栏对齐，先做高价值轻量项）
AGENT_MODULES = (
    "sysinfo",
    "service",
    "task",
    "startup",
    "network",
    "process",
    "file",   # 高危目录近期文件
    "user",   # 本地用户 / 登录会话
    "software",  # 已装软件清单
    "hotfix",    # 补丁 KB
    "listen",    # 监听端口
    "driver",    # 内核/文件系统驱动
    "browser",   # 浏览器访问记录
)

# 采集周期（秒）——威胁相关模块尽量压到秒级，抓住黄金时间
# 实时威胁由 ETW/FIM/注册表/事件日志负责；周期快照只做资产与兜底，避免 PowerShell 拖慢终端
MODULE_INTERVAL_SEC = {
    "sysinfo": 300,
    "service": 600,
    "task": 900,
    "startup": 300,
    "network": 60,
    "process": 120,
    "file": 900,
    "user": 300,
    "software": 1800,
    "hotfix": 7200,
    "listen": 300,
    "driver": 1800,
    "browser": 900,
}

PROTOCOL_VERSION = 1
DB_NAME = "agents.db"

# 服务端支持的协议范围与能力。新增接口后同步上调 MAX 并追加能力名。
SERVER_PROTOCOL_MIN = 1
SERVER_PROTOCOL_MAX = 2
SERVER_CAPABILITIES = (
    "snapshot.v1",
    "timeline.v1",
    "command.ack.v1",
    "process.identity.v1",
    "sensor.etw",
    "sensor.wevt",
    "upgrade.replace",
    # 阶段1
    "ingest.v2",          # POST /api/agent/v2/events/batch 幂等批量上报
    "auth.agent_secret",  # 每 Agent 独立凭据
    "command.lease",      # 命令 lease/重试/截止
    "health.v1",          # 心跳健康指标
    # 阶段2
    "process.entity.v1",  # 进程实体 entity_id / 墓碑，服务端 agent_processes
    "registry.realtime",  # 实时注册表（persist_* / registry_*）
    "dns.aggregate",      # dns_query / dns_summary / dns_nx_burst，服务端 agent_dns
    "fim.v1",             # fim_add / fim_modify / fim_delete / fim_rename
    # 阶段3
    "inventory.delta",    # snapshot_delta：按 generation 链应用增量清单
    "policy.lkg",         # Agent 心跳回报策略生效/试用/拒绝/回滚状态
    "sync.v1",            # POST /api/agent/sync 统一配置/规则增量
)


def negotiate_protocol(payload: Dict[str, Any]) -> Dict[str, Any]:
    """按 Agent 声明的协议范围/能力与服务端取交集。旧 Agent 不带字段时视为 v1。"""
    def _i(v: Any, d: int) -> int:
        try:
            return max(1, int(v))
        except Exception:
            return d
    amin = _i(payload.get("protocol_min"), 1)
    amax = _i(payload.get("protocol_max"), amin)
    if amax < amin:
        amin, amax = amax, amin
    lo, hi = max(amin, SERVER_PROTOCOL_MIN), min(amax, SERVER_PROTOCOL_MAX)
    caps_in = payload.get("capabilities")
    if not isinstance(caps_in, list):
        caps_in = []
    caps = [str(c)[:48] for c in caps_in][:64]
    enabled = [c for c in caps if c in SERVER_CAPABILITIES]
    out: Dict[str, Any] = {
        "agent_min": amin, "agent_max": amax,
        "selected": hi if lo <= hi else 0,
        "agent_caps": caps, "enabled_caps": enabled,
    }
    if lo > hi:
        out["warning"] = (
            f"协议不兼容：Agent 支持 v{amin}-v{amax}，服务端支持 "
            f"v{SERVER_PROTOCOL_MIN}-v{SERVER_PROTOCOL_MAX}，请升级较旧的一方"
        )
    return out

# ---- 数据库迁移（PRAGMA user_version）----
# 迁移必须幂等，按版本号递增追加，禁止修改已发布的迁移。

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT DEFAULT '',
    os_family TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    version TEXT DEFAULT '',
    token_hint TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    status TEXT DEFAULT 'offline',
    meta_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS agent_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    module TEXT NOT NULL,
    collected_at TEXT DEFAULT '',
    item_count INTEGER DEFAULT 0,
    digest TEXT DEFAULT '',
    payload_json TEXT DEFAULT '',
    UNIQUE(agent_id, module)
);
CREATE TABLE IF NOT EXISTS agent_meta (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agent_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    title TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    module TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    hit_count INTEGER DEFAULT 1,
    created_at TEXT DEFAULT '',
    updated_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agents_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_snap_agent ON agent_snapshots(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON agent_events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_status ON agent_events(status);
"""

ENROLL_META_KEY = "enroll_key"

_lock = threading.RLock()

# 近实时推送：有心跳/快照/事件变更时递增，SSE 客户端据此拉取
_live_rev = 0
_live_cv = threading.Condition(_lock)
_live_hint: Dict[str, Any] = {"kind": "init"}


def bump_live(kind: str, **extra: Any) -> int:
    global _live_rev, _live_hint
    with _live_cv:
        _live_rev += 1
        _live_hint = {"kind": kind, "rev": _live_rev, **extra}
        _live_cv.notify_all()
        return _live_rev


_last_heartbeat_live_bump = 0.0


def bump_live_heartbeat(agent_id: str) -> None:
    """心跳节流推送（约 2s 一次），避免 SSE 被刷爆，仍能让概览及时看到上下线。"""
    global _last_heartbeat_live_bump
    now = time.time()
    if now - _last_heartbeat_live_bump < 2.0:
        return
    _last_heartbeat_live_bump = now
    bump_live("heartbeat", agent_id=str(agent_id or "")[:64])


def live_revision() -> int:
    with _lock:
        return int(_live_rev)


_live_shutdown = threading.Event()
_live_hooks_installed = False


def reset_live_shutdown() -> None:
    """进程启动时清除关闭标志（reload 子进程）。"""
    _live_shutdown.clear()


def shutdown_live() -> None:
    """服务关闭时唤醒并结束所有 SSE 生成器，避免 uvicorn 一直等长连接。"""
    _live_shutdown.set()
    with _live_cv:
        _live_cv.notify_all()


def install_live_shutdown_hooks() -> None:
    """在 SIGINT/SIGTERM 时先于 uvicorn 等待连接，唤醒 SSE（lifespan finally 可能被 CancelledError 跳过）。"""
    global _live_hooks_installed
    if _live_hooks_installed:
        return
    _live_hooks_installed = True

    import atexit

    atexit.register(shutdown_live)

    def _wrap(prev):
        def handler(signum, frame):
            shutdown_live()
            if callable(prev):
                prev(signum, frame)
            elif prev == signal.SIG_DFL:
                raise KeyboardInterrupt

        return handler

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _wrap(signal.getsignal(sig)))
        except (OSError, ValueError, RuntimeError):
            pass


def _live_snapshot(rev: int) -> Tuple[int, Optional[str]]:
    with _lock:
        cur = int(_live_rev)
        if cur <= rev:
            return cur, None
        hint = dict(_live_hint)
    return cur, f"data: {json.dumps(hint, ensure_ascii=False)}\n\n"


async def async_iter_live_sse(
    request: Any,
    last_rev: int = 0,
    *,
    timeout_sec: float = 15.0,
    poll_sec: float = 0.25,
):
    """异步 SSE：可响应客户端断开与服务关闭，避免 sync 生成器在 graceful shutdown 超时后被强杀。"""
    rev = int(last_rev or 0)
    idle = 0.0
    poll = max(0.05, min(float(poll_sec), 1.0))
    while not _live_shutdown.is_set():
        try:
            if await request.is_disconnected():
                return
        except Exception:
            return
        cur, chunk = _live_snapshot(rev)
        if chunk is not None:
            rev = cur
            idle = 0.0
            yield chunk
            continue
        idle += poll
        if idle >= timeout_sec:
            idle = 0.0
            yield ": ping\n\n"
        await asyncio.sleep(poll)
    yield 'data: {"kind":"server_shutdown"}\n\n'


def iter_live_sse(last_rev: int = 0, *, timeout_sec: float = 15.0):
    """SSE 事件生成器：data 为 JSON（rev/kind）。心跳注释保持连接。

    等待以 1 秒为片，随时响应关闭信号；客户端断开后下一次 yield 即退出。
    禁止在持有 Condition 锁时 yield：生成器被关闭时 __exit__ 可能在非持锁
    线程上 release，触发 RuntimeError: cannot release un-acquired lock。
    """
    rev = int(last_rev or 0)
    idle = 0.0
    while not _live_shutdown.is_set():
        to_yield: Optional[str] = None
        with _live_cv:
            if _live_rev <= rev:
                _live_cv.wait(timeout=0.25)
                if _live_shutdown.is_set():
                    return
                if _live_rev <= rev:
                    idle += 0.25
                    if idle >= timeout_sec:
                        idle = 0.0
                        to_yield = ": ping\n\n"
                else:
                    idle = 0.0
                    rev = _live_rev
                    to_yield = f"data: {json.dumps(dict(_live_hint), ensure_ascii=False)}\n\n"
            else:
                idle = 0.0
                rev = _live_rev
                to_yield = f"data: {json.dumps(dict(_live_hint), ensure_ascii=False)}\n\n"
        if to_yield is not None:
            yield to_yield


def db_path() -> Path:
    d = Path(getattr(config, "REPORTS_DIR", None) or (Path(config.ROOT) / "reports"))
    d.mkdir(parents=True, exist_ok=True)
    return d / DB_NAME


def _col_exists(conn: sqlite3.Connection, table: str, col: str) -> bool:
    return any(r[1] == col for r in conn.execute(f"PRAGMA table_info({table})").fetchall())


def _add_col(conn: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    if not _col_exists(conn, table, col):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


def _mig_001_agent_build_protocol(conn: sqlite3.Connection) -> None:
    """agents 增加构建号/源码指纹/协议协商/能力列。"""
    _add_col(conn, "agents", "build_id", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "source_rev", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "build_time", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "proto_min", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "proto_max", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "proto_selected", "INTEGER DEFAULT 1")
    _add_col(conn, "agents", "capabilities_json", "TEXT DEFAULT '[]'")


def _mig_002_credentials_health(conn: sqlite3.Connection) -> None:
    """每 Agent 独立凭据（仅存哈希）、吊销标记、健康指标。"""
    _add_col(conn, "agents", "secret_hash", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "secret_issued_at", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "secret_rev", "INTEGER DEFAULT 0")
    _add_col(conn, "agents", "revoked", "INTEGER DEFAULT 0")
    _add_col(conn, "agents", "health_json", "TEXT DEFAULT '{}'")
    _add_col(conn, "agents", "health_at", "TEXT DEFAULT ''")
    _add_col(conn, "agents", "clock_skew_sec", "REAL DEFAULT 0")


def _mig_003_ingest_commands(conn: sqlite3.Connection) -> None:
    """v2 幂等上报回执 + 命令 lease/截止/幂等键。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_receipts (
               agent_id TEXT NOT NULL,
               event_uuid TEXT NOT NULL,
               kind TEXT DEFAULT '',
               stream TEXT DEFAULT 'main',
               seq INTEGER DEFAULT 0,
               status TEXT DEFAULT 'ok',
               error TEXT DEFAULT '',
               received_at TEXT DEFAULT '',
               PRIMARY KEY(agent_id, event_uuid)
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_time ON agent_receipts(received_at)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_streams (
               agent_id TEXT NOT NULL,
               stream TEXT NOT NULL,
               high_seq INTEGER DEFAULT 0,
               received INTEGER DEFAULT 0,
               rejected INTEGER DEFAULT 0,
               updated_at TEXT DEFAULT '',
               PRIMARY KEY(agent_id, stream)
           )"""
    )
    _add_col(conn, "agent_commands", "lease_until", "TEXT DEFAULT ''")
    _add_col(conn, "agent_commands", "attempts", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_commands", "max_attempts", "INTEGER DEFAULT 3")
    _add_col(conn, "agent_commands", "deadline", "TEXT DEFAULT ''")
    _add_col(conn, "agent_commands", "idempotency_key", "TEXT DEFAULT ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cmd_idem ON agent_commands(agent_id, idempotency_key)"
    )


def _mig_004_entities_dns(conn: sqlite3.Connection) -> None:
    """进程实体（墓碑保留）+ DNS 域名聚合 + 时间线 entity_id 索引。"""
    from . import agent_telemetry
    agent_telemetry.migrate(conn)


def _mig_005_inventory_policy(conn: sqlite3.Connection) -> None:
    """增量清单（快照代号 + 条目键）+ 策略版本历史。"""
    _add_col(conn, "agent_snapshots", "generation", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_snapshots", "keys_json", "TEXT DEFAULT ''")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_policy_history (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               scope TEXT NOT NULL,
               rev INTEGER NOT NULL,
               policy_json TEXT DEFAULT '{}',
               actor TEXT DEFAULT '',
               note TEXT DEFAULT '',
               created_at TEXT DEFAULT ''
           )"""
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_hist ON agent_policy_history(scope, rev)")
    # 现有策略作为历史起点，便于回滚
    conn.execute(
        """INSERT OR IGNORE INTO agent_policy_history(scope, rev, policy_json, actor, note, created_at)
           SELECT scope, rev, policy_json, '', '迁移时的现行版本', updated_at FROM agent_policy"""
    )


def _mig_006_upgrade_ed25519(conn: sqlite3.Connection) -> None:
    """升级包 Ed25519 签名列。"""
    _add_col(conn, "agent_upgrade_packages", "sig_ed25519", "TEXT DEFAULT ''")


def _mig_007_alert_allow(conn: sqlite3.Connection) -> None:
    """告警加白：主机范围、告警标题限定、命中计数。"""
    _add_col(conn, "agent_whitelist", "agent_id", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "rule", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "hits", "INTEGER DEFAULT 0")
    _add_col(conn, "agent_whitelist", "last_hit_at", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "created_by", "TEXT DEFAULT ''")
    _add_col(conn, "agent_whitelist", "source_event_id", "INTEGER DEFAULT 0")


def _mig_008_agent_tombstones(conn: sqlite3.Connection) -> None:
    """删除终端时保留凭据哈希：仍在运行的 Agent 凭原凭据可自动恢复注册，不必重装。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_tombstones (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT DEFAULT '',
            secret_hash TEXT DEFAULT '',
            deleted_at TEXT DEFAULT ''
        )"""
    )


def _mig_009_event_deletions(conn: sqlite3.Connection) -> None:
    """记录被删除的告警，时间线补晋升时不再把它们恢复回来。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_event_deletions (
            agent_id TEXT NOT NULL,
            title TEXT NOT NULL,
            deleted_at TEXT DEFAULT '',
            PRIMARY KEY (agent_id, title)
        )"""
    )


def _mig_010_event_notes(conn: sqlite3.Connection) -> None:
    """威胁研判：评论 / 研判结论（真实威胁、误报、待观察）。"""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS agent_event_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            agent_id TEXT DEFAULT '',
            kind TEXT DEFAULT 'comment',
            verdict TEXT DEFAULT '',
            content TEXT DEFAULT '',
            author TEXT DEFAULT '',
            created_at TEXT DEFAULT ''
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_notes_event ON agent_event_notes(event_id, id)")


def _mig_011_event_hit_count(conn: sqlite3.Connection) -> None:
    """告警去重累计命中次数（同载荷/同标题合并时递增）。"""
    _add_col(conn, "agent_events", "hit_count", "INTEGER DEFAULT 1")
    conn.execute("UPDATE agent_events SET hit_count=1 WHERE hit_count IS NULL OR hit_count < 1")


_MIGRATIONS = (
    (1, "agent build/protocol columns", _mig_001_agent_build_protocol),
    (2, "per-agent credentials + health", _mig_002_credentials_health),
    (3, "v2 receipts + command lease", _mig_003_ingest_commands),
    (4, "process entities + dns aggregate", _mig_004_entities_dns),
    (5, "inventory delta + policy history", _mig_005_inventory_policy),
    (6, "upgrade package ed25519 sig", _mig_006_upgrade_ed25519),
    (7, "alert allowlist scope + hits", _mig_007_alert_allow),
    (8, "agent tombstones", _mig_008_agent_tombstones),
    (9, "event deletion marks", _mig_009_event_deletions),
    (10, "event triage notes", _mig_010_event_notes),
    (11, "event hit_count", _mig_011_event_hit_count),
)
SCHEMA_VERSION = _MIGRATIONS[-1][0]
_migrated_paths: set = set()


def _backup_db(conn: sqlite3.Connection, from_ver: int) -> Optional[Path]:
    """迁移前做一致性备份（sqlite backup API，含 WAL 内容），仅保留最近 5 份。"""
    try:
        bdir = db_path().parent / "db_backups"
        bdir.mkdir(parents=True, exist_ok=True)
        dst_path = bdir / f"agents_v{from_ver}_{time.strftime('%Y%m%d_%H%M%S')}.db"
        dst = sqlite3.connect(str(dst_path))
        try:
            conn.backup(dst)
        finally:
            dst.close()
        olds = sorted(bdir.glob("agents_v*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in olds[5:]:
            try:
                p.unlink()
            except OSError:
                pass
        return dst_path
    except Exception as e:
        print("[agent_db] 迁移前备份失败:", e)
        return None


def migrate(conn: sqlite3.Connection) -> int:
    """按 user_version 顺序执行未应用的迁移；每个迁移独立事务，失败则回滚并抛出。"""
    key = str(db_path())
    if key in _migrated_paths:
        return SCHEMA_VERSION
    cur = int(conn.execute("PRAGMA user_version").fetchone()[0])
    pending = [m for m in _MIGRATIONS if m[0] > cur]
    if pending:
        # 迁移可能涉及主表与 EDR 扩展表，先确保它们存在
        conn.executescript(_SCHEMA)
        try:
            from . import agent_edr
            conn.executescript(agent_edr._SCHEMA)
        except Exception as e:
            print("[agent_db] edr schema:", e)
        has_data = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0] > 0
        if has_data:
            conn.commit()
            bk = _backup_db(conn, cur)
            if bk:
                print(f"[agent_db] 迁移 v{cur}→v{SCHEMA_VERSION}，已备份 {bk.name}")
        for ver, name, fn in pending:
            try:
                conn.execute("BEGIN IMMEDIATE")
                fn(conn)
                conn.execute(f"PRAGMA user_version={int(ver)}")
                conn.commit()
                print(f"[agent_db] migration {ver} ok: {name}")
            except Exception:
                conn.rollback()
                raise
    _migrated_paths.add(key)
    return SCHEMA_VERSION


class _AmbientConn:
    """批量事务内共享的连接代理：commit/rollback/close 由外层 batch_tx 统一控制。"""

    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    def __getattr__(self, name: str) -> Any:
        return getattr(self._c, name)

    def commit(self) -> None:  # noqa: D401
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        return None

    def executescript(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("batch_tx 内禁止 executescript（会隐式提交）")


_ambient = threading.local()


def _real_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(_SCHEMA)
    migrate(conn)
    return conn


def ambient_conn() -> Optional[_AmbientConn]:
    return getattr(_ambient, "conn", None)


def _connect() -> sqlite3.Connection:
    a = ambient_conn()
    if a is not None:
        return a  # type: ignore[return-value]
    return _real_connect()


from contextlib import contextmanager  # noqa: E402


@contextmanager
def batch_tx():
    """把一批写入放进同一个 SQLite 事务：期间 agent_protocol/agent_edr 的 _connect() 都返回同一连接。

    锁顺序固定为 agent_edr._lock → agent_protocol._lock，与现有 edr→protocol 调用链一致。
    yield 真实连接，供调用方做 SAVEPOINT 与回执写入；正常退出统一提交，异常整体回滚。
    """
    from . import agent_edr
    with agent_edr._lock, _lock:
        if ambient_conn() is not None:
            raise RuntimeError("batch_tx 不可嵌套")
        conn = _real_connect()
        conn.execute("BEGIN IMMEDIATE")
        _ambient.conn = _AmbientConn(conn)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            _ambient.conn = None
            conn.close()


def ensure_db() -> Path:
    with _lock:
        conn = _connect()
        conn.close()
    return db_path()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def get_or_create_enroll_key(*, rotate: bool = False) -> str:
    """平台统一接入密钥：安装包内嵌此 key，终端无需再填账号密码。"""
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            if not rotate:
                row = conn.execute(
                    "SELECT value FROM agent_meta WHERE key=?", (ENROLL_META_KEY,)
                ).fetchone()
                if row and str(row["value"] or "").strip():
                    return str(row["value"]).strip()
            key = secrets.token_urlsafe(32)
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (ENROLL_META_KEY, key),
            )
            conn.commit()
            return key
        finally:
            conn.close()


def verify_enroll_key(token: str) -> bool:
    tok = str(token or "").strip()
    if not tok or len(tok) < 16:
        return False
    try:
        return secrets.compare_digest(tok, get_or_create_enroll_key())
    except Exception:
        return False


# ---- 每 Agent 独立凭据 ----
SECRET_PREFIX = "fa_"
SHARED_KEY_META = "allow_shared_key"


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _new_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(32)


def agent_auth_state(agent_id: str) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    if not aid:
        return {"exists": False, "has_secret": False, "revoked": False}
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"exists": False, "has_secret": False, "revoked": False}
    return {
        "exists": True,
        "has_secret": bool(str(row["secret_hash"] or "")),
        "revoked": bool(row["revoked"]),
    }


def verify_agent_secret(agent_id: str, token: str) -> str:
    """返回 ok | revoked | bad。常量时间比较，仅比较哈希。"""
    aid = str(agent_id or "").strip()
    tok = str(token or "").strip()
    if not aid or not tok.startswith(SECRET_PREFIX):
        return "bad"
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return "ok" if _restore_tombstoned_agent(aid, tok) else "bad"
    stored = str(row["secret_hash"] or "")
    ok = bool(stored) and secrets.compare_digest(stored, _hash_secret(tok))
    if not ok:
        return "bad"
    return "revoked" if row["revoked"] else "ok"


def _restore_tombstoned_agent(agent_id: str, token: str) -> bool:
    """被删除但仍在运行的终端带原凭据回连：校验哈希后恢复注册记录（历史数据不恢复）。"""
    with _lock:
        conn = _connect()
        try:
            try:
                tomb = conn.execute(
                    "SELECT hostname, secret_hash FROM agent_tombstones WHERE agent_id=?", (agent_id,)
                ).fetchone()
            except sqlite3.Error:
                return False
            stored = str(tomb["secret_hash"] or "") if tomb else ""
            if not stored or not secrets.compare_digest(stored, _hash_secret(token)):
                return False
            now = _now()
            conn.execute(
                """INSERT OR IGNORE INTO agents(agent_id, hostname, last_seen, status, meta_json, secret_hash, secret_issued_at)
                   VALUES(?,?,?, 'online', ?, ?, ?)""",
                (agent_id, str(tomb["hostname"] or ""), now,
                 json.dumps({"registered": now, "restored": True}, ensure_ascii=False), stored, now),
            )
            conn.execute("DELETE FROM agent_tombstones WHERE agent_id=?", (agent_id,))
            conn.commit()
        finally:
            conn.close()
    try:
        from . import agent_edr
        agent_edr._audit("agent_auto_restore", agent_id=agent_id, detail="已删除终端凭原凭据回连，自动恢复注册")
    except Exception:
        pass
    bump_live("agent", agent_id=agent_id)
    return True


def issue_agent_secret(agent_id: str, *, conn: Optional[sqlite3.Connection] = None) -> str:
    """签发（或轮换）凭据，明文只返回这一次，库里只存 SHA256。"""
    aid = str(agent_id or "").strip()
    secret = _new_secret()
    sql = "UPDATE agents SET secret_hash=?, secret_issued_at=?, secret_rev=COALESCE(secret_rev,0)+1 WHERE agent_id=?"
    args = (_hash_secret(secret), _now(), aid)
    if conn is not None:
        conn.execute(sql, args)
        return secret
    ensure_db()
    with _lock:
        c = _connect()
        try:
            c.execute(sql, args)
            c.commit()
        finally:
            c.close()
    return secret


def rotate_agent_secret(agent_id: str) -> Dict[str, Any]:
    st = agent_auth_state(agent_id)
    if not st["exists"]:
        return {"ok": False, "error": "Agent 不存在"}
    if st["revoked"]:
        return {"ok": False, "error": "Agent 已吊销"}
    secret = issue_agent_secret(agent_id)
    bump_live("credential", agent_id=agent_id)
    return {"ok": True, "agent_secret": secret}


def set_agent_revoked(agent_id: str, revoked: bool) -> Dict[str, Any]:
    aid = str(agent_id or "").strip()
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute("UPDATE agents SET revoked=? WHERE agent_id=?", (1 if revoked else 0, aid))
            if revoked:
                # 吊销时同时作废凭据，恢复后需重新注册换取新凭据
                conn.execute("UPDATE agents SET secret_hash='' WHERE agent_id=?", (aid,))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "Agent 不存在"}
        finally:
            conn.close()
    bump_live("credential", agent_id=aid)
    return {"ok": True, "agent_id": aid, "revoked": bool(revoked)}


def shared_key_allowed() -> bool:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT value FROM agent_meta WHERE key=?", (SHARED_KEY_META,)).fetchone()
        finally:
            conn.close()
    return not (row and str(row["value"]).strip() == "0")


def set_shared_key_allowed(allowed: bool) -> None:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                """INSERT INTO agent_meta(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (SHARED_KEY_META, "1" if allowed else "0"),
            )
            conn.commit()
        finally:
            conn.close()


def credential_summary() -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            r = conn.execute(
                """SELECT COUNT(*) AS total,
                          SUM(CASE WHEN secret_hash<>'' THEN 1 ELSE 0 END) AS with_secret,
                          SUM(CASE WHEN revoked=1 THEN 1 ELSE 0 END) AS revoked
                   FROM agents"""
            ).fetchone()
        finally:
            conn.close()
    return {
        "total": int(r["total"] or 0),
        "with_secret": int(r["with_secret"] or 0),
        "revoked": int(r["revoked"] or 0),
        "allow_shared_key": shared_key_allowed(),
    }


def agent_binary_path() -> Optional[Path]:
    """优先仓库编译产物，其次 tools 目录投放。"""
    candidates = [
        Path(config.ROOT) / "agent" / "forensic-agent.exe",
        Path(config.ROOT) / "tools" / "agent" / "forensic-agent.exe",
        Path(getattr(config, "REPORTS_DIR", config.ROOT / "reports")) / "agent" / "forensic-agent.exe",
    ]
    for p in candidates:
        if p.is_file() and p.stat().st_size > 100_000:
            return p
    return None


def _package_cache_dir() -> Path:
    d = Path(config.REPORTS_DIR) / "agent_packages"
    d.mkdir(parents=True, exist_ok=True)
    return d


def clear_install_package_cache() -> int:
    """删除已缓存的安装 zip（Agent/驱动更新后需重新打包容）。"""
    n = 0
    for p in _package_cache_dir().glob("pkg_*.zip"):
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n


def build_install_package(*, server_url: str) -> Tuple[Union[bytes, Path], str]:
    """生成开箱即用安装包：exe + agent.json + install 脚本。

    优化：
    - exe 用 ZIP_STORED（已压缩 PE，再 DEFLATE 又慢又几乎不缩小）
    - 按 exe mtime + 接入密钥 + 平台地址 磁盘缓存，二次下载近乎秒开
    返回 (Path 缓存文件 | bytes, 下载文件名)。
    """
    exe = agent_binary_path()
    if not exe:
        raise FileNotFoundError(
            "缺少 forensic-agent.exe，请先在服务器编译 agent/ 或放到 tools/agent/"
        )
    base = str(server_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("server_url 为空")
    # 去掉前端 path（/app、/a）
    for suf in ("/app", "/a"):
        if base.lower().endswith(suf):
            base = base[: -len(suf)].rstrip("/")
    key = get_or_create_enroll_key()
    from . import agent_release
    rel = agent_release.release_status(exe)
    manifest = agent_release.load_manifest(exe)
    from .agent_install_scripts import install_bat, install_vbs, readme_text, uninstall_bat

    cache_key = hashlib.sha1(
        f"{rel['exe_sha256']}|{base}|{key}|{rel.get('build_id','')}|v6-agent-only".encode("utf-8")
    ).hexdigest()[:20]
    tag = str(rel.get("build_id") or rel.get("source_version") or "unverified").replace("+", "-")
    name = f"ForensicAgent_{tag}_{time.strftime('%Y%m%d')}.zip"
    cache_path = _package_cache_dir() / f"pkg_{cache_key}.zip"

    with _pkg_lock:
        if cache_path.is_file() and cache_path.stat().st_size > 100_000:
            return cache_path, name

        cfg = {
            "server_url": base,
            "token": key,
            "modules": list(AGENT_MODULES),
            "intervals_sec": dict(MODULE_INTERVAL_SEC),
        }
        bat_main = install_bat()
        bat_vbs = install_vbs()
        bat_un = uninstall_bat()
        readme = readme_text(base=base, rel=rel)

        tmp = cache_path.with_suffix(".tmp")
        try:
            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
                zf.writestr("ForensicAgent/agent.json", json.dumps(cfg, ensure_ascii=False, indent=2))
                zf.writestr("ForensicAgent/install.bat", bat_main)
                zf.writestr("ForensicAgent/install.vbs", bat_vbs)
                zf.writestr("ForensicAgent/uninstall.bat", bat_un)
                zf.writestr("ForensicAgent/README.txt", readme)
                if manifest:
                    zf.writestr("ForensicAgent/build-manifest.json",
                                json.dumps(manifest, ensure_ascii=False, indent=2))
                # PE 再压缩收益极低，STORE 可把打包从数百毫秒～数秒降到接近拷贝
                zf.write(exe, arcname="ForensicAgent/forensic-agent.exe", compress_type=zipfile.ZIP_STORED)
            tmp.replace(cache_path)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            raise

        # 只保留最近几个缓存，避免占盘
        try:
            pkgs = sorted(_package_cache_dir().glob("pkg_*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in pkgs[8:]:
                try:
                    old.unlink()
                except Exception:
                    pass
        except Exception:
            pass

        return cache_path, name


def protocol_info() -> Dict[str, Any]:
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_min": SERVER_PROTOCOL_MIN,
        "protocol_max": SERVER_PROTOCOL_MAX,
        "capabilities": list(SERVER_CAPABILITIES),
        "schema_version": SCHEMA_VERSION,
        "modules": list(AGENT_MODULES),
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "has_binary": agent_binary_path() is not None,
        "endpoints": {
            "register": "POST /api/agent/register",
            "heartbeat": "POST /api/agent/heartbeat",
            "snapshot": "POST /api/agent/snapshot",
            "list": "GET /api/agent/list",
            "install_package": "GET /api/agent/install-package",
        },
        "notes": [
            "管理端下载安装包（已内嵌平台地址与接入密钥），目标机管理员运行 install.bat 即可。",
            "服务名 ForensicAgent：开机自启，心跳 + 按模块实时 snapshot。",
            "snapshot 只传精简 JSON，禁止整盘 files；完整取证仍用离线 pack。",
        ],
    }


def register_agent(payload: Dict[str, Any], *, cred: str = "user") -> Dict[str, Any]:
    """cred: enroll=共享接入密钥 | secret=每 Agent 凭据 | user=管理台会话。

    仅当 Agent 声明 auth.agent_secret 能力且是 enroll 注册时才签发新凭据，旧 Agent 不受影响。
    """
    ensure_db()
    hostname = str(payload.get("hostname") or "").strip()[:128]
    os_family = str(payload.get("os_family") or "").strip().lower()[:32]
    ip = str(payload.get("ip") or "").strip()[:64]
    version = str(payload.get("version") or "").strip()[:64]
    agent_id = str(payload.get("agent_id") or "").strip()
    now = _now()
    neg = negotiate_protocol(payload)
    build_id = str(payload.get("build_id") or "").strip()[:64]
    source_rev = str(payload.get("source_rev") or "").strip()[:32]
    build_time = str(payload.get("build_time") or "").strip()[:40]
    with _lock:
        conn = _connect()
        try:
            # 无 agent_id 时按主机名复用，避免重装/升级产生僵尸离线记录
            if not agent_id and hostname:
                row = conn.execute(
                    "SELECT agent_id FROM agents WHERE LOWER(hostname)=LOWER(?) ORDER BY last_seen DESC LIMIT 1",
                    (hostname,),
                ).fetchone()
                if row:
                    agent_id = str(row["agent_id"])
            if not agent_id:
                agent_id = uuid.uuid4().hex
            prev = conn.execute("SELECT revoked FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if prev and prev["revoked"]:
                return {"ok": False, "error": "该 Agent 已被吊销，请管理员恢复或删除记录后重新安装"}
            conn.execute(
                """INSERT INTO agents(agent_id, hostname, os_family, ip, version, last_seen, status, meta_json)
                   VALUES(?,?,?,?,?,?, 'online', ?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     hostname=excluded.hostname,
                     os_family=excluded.os_family,
                     ip=excluded.ip,
                     version=excluded.version,
                     last_seen=excluded.last_seen,
                     status='online'""",
                (agent_id, hostname, os_family, ip, version, now, json.dumps({"registered": now}, ensure_ascii=False)),
            )
            conn.execute(
                """UPDATE agents SET build_id=?, source_rev=?, build_time=?,
                       proto_min=?, proto_max=?, proto_selected=?, capabilities_json=?
                   WHERE agent_id=?""",
                (build_id, source_rev, build_time, neg["agent_min"], neg["agent_max"],
                 neg["selected"], json.dumps(neg["enabled_caps"], ensure_ascii=False), agent_id),
            )
            new_secret = ""
            if cred == "enroll" and "auth.agent_secret" in neg["enabled_caps"]:
                new_secret = issue_agent_secret(agent_id, conn=conn)
            conn.commit()
        finally:
            conn.close()
    bump_live("register", agent_id=agent_id)
    return {
        "ok": True,
        "agent_id": agent_id,
        **({"agent_secret": new_secret} if new_secret else {}),
        "protocol_version": PROTOCOL_VERSION,
        "protocol_selected": neg["selected"],
        "protocol_warning": neg.get("warning", ""),
        "server_capabilities": list(SERVER_CAPABILITIES),
        "enabled_capabilities": neg["enabled_caps"],
        "modules": list(AGENT_MODULES),
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "live_rev": live_revision(),
    }


def _host_meta_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    health = payload.get("health")
    if isinstance(health, dict):
        h = health.get("host")
        if isinstance(h, dict):
            return dict(h)
    top = payload.get("host")
    if isinstance(top, dict):
        return dict(top)
    return {}


def _store_health(conn: sqlite3.Connection, agent_id: str, payload: Dict[str, Any], now: str) -> None:
    """保存 Agent 自报健康（CPU/内存/spool/传感器），并按 agent_ts 估算时钟偏差。"""
    health = payload.get("health")
    if not isinstance(health, dict):
        health = {}
    fleet = {
        "policy_applied": bool(payload.get("policy_applied")),
        "local_sync_rev": int(payload.get("local_sync_rev") or 0),
        "local_policy_rev": int(payload.get("local_policy_rev") or 0),
    }
    if isinstance(health.get("fleet"), dict):
        fleet.update({k: health["fleet"][k] for k in health["fleet"] if k in (
            "server_sync_rev", "server_policy_rev", "fleet_state", "fleet_message",
        )})
    health = {**health, "fleet_report": fleet}
    skew = 0.0
    ats = str(payload.get("agent_ts") or "")
    try:
        skew = round(time.time() - float(ats), 1) if ats.replace(".", "", 1).isdigit() else 0.0
    except Exception:
        skew = 0.0
    blob = json.dumps(health, ensure_ascii=False)[:12000]
    conn.execute(
        "UPDATE agents SET health_json=?, health_at=?, clock_skew_sec=? WHERE agent_id=?",
        (blob, now, skew, agent_id),
    )


def heartbeat(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_db()
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id:
        return {"ok": False, "error": "缺少 agent_id"}
    now = _now()
    acked_ids: List[str] = []
    acks = payload.get("command_acks")
    if isinstance(acks, list):
        try:
            from . import agent_edr
            for item in acks[:20]:
                if not isinstance(item, dict):
                    continue
                cid = str(item.get("id") or "").strip()
                if not cid:
                    continue
                ok = bool(item.get("ok"))
                result = item.get("result") if isinstance(item.get("result"), dict) else {}
                r = agent_edr.ack_command(cid, ok=ok, result=result, caller_agent_id=agent_id)
                if r.get("ok"):
                    acked_ids.append(cid)
        except Exception as e:
            print("[agent] heartbeat command_acks:", e)
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE agents SET last_seen=?, status='online', ip=COALESCE(NULLIF(?, ''), ip) WHERE agent_id=?",
                (now, str(payload.get("ip") or "").strip()[:64], agent_id),
            )
            if cur.rowcount > 0:
                _store_health(conn, agent_id, payload, now)
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "未知 agent，请先 register"}
        finally:
            conn.close()
    out: Dict[str, Any] = {
        "ok": True,
        "server_time": now,
        # 热更新采集周期，无需重装 Agent
        "intervals_sec": dict(MODULE_INTERVAL_SEC),
        "heartbeat_sec": 3,
        "live_rev": live_revision(),
        "commands": [],
        "policy": {},
        "policy_rev": 0,
        "whitelist": [],
        "sync_rev": 0,
        "policy_applied": False,
        "acked_command_ids": acked_ids,
    }
    try:
        from . import agent_sync
        out["sync_rev"] = agent_sync.sync_revision()
        out["sync_manifest"] = agent_sync.manifest().get("parts")
    except Exception:
        pass
    try:
        from . import agent_edr
        bundle = agent_edr.agent_side_bundle(agent_id, host_meta=_host_meta_from_payload(payload))
        out.update(bundle)
        pol = bundle.get("policy") or {}
        if isinstance(pol.get("intervals_sec"), dict):
            out["intervals_sec"] = {**MODULE_INTERVAL_SEC, **pol["intervals_sec"]}
        if isinstance(pol.get("heartbeat_sec"), int) and 3 <= pol["heartbeat_sec"] <= 120:
            out["heartbeat_sec"] = int(pol["heartbeat_sec"])
    except Exception as e:
        print("[agent_edr] heartbeat bundle:", e)
    srv_sync = int(out.get("sync_rev") or 0)
    local_sync = int(payload.get("local_sync_rev") or 0)
    agent_pa = bool(payload.get("policy_applied"))
    out["policy_applied"] = agent_pa and (srv_sync <= 0 or local_sync >= srv_sync)
    out["server_policy_rev"] = int(out.get("policy_rev") or 0)
    out["server_sync_rev"] = srv_sync
    bump_live_heartbeat(agent_id)
    return out


def list_agents(*, online_within_sec: int = 45) -> Dict[str, Any]:
    ensure_db()
    # 默认心跳 3s，超过约 15s 无上报视为离线（调用方可传更大窗口）
    online_within_sec = max(12, min(int(online_within_sec or 15), 3600))
    cutoff = time.time() - online_within_sec
    try:
        from . import agent_release
        rel = agent_release.release_status()
    except Exception:
        agent_release, rel = None, {}
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
            items = []
            for r in rows:
                d = dict(r)
                try:
                    d["capabilities"] = json.loads(d.pop("capabilities_json", "") or "[]")
                except Exception:
                    d["capabilities"] = []
                try:
                    d["health"] = json.loads(d.pop("health_json", "") or "{}")
                except Exception:
                    d["health"] = {}
                d["has_secret"] = bool(d.pop("secret_hash", ""))  # 绝不外泄哈希
                d["revoked"] = bool(d.get("revoked"))
                d["outdated"] = bool(agent_release and rel.get("build_id") and agent_release.agent_outdated(d, rel))
                last = str(d.get("last_seen") or "")
                try:
                    ts = time.mktime(time.strptime(last, "%Y-%m-%dT%H:%M:%S"))
                except Exception:
                    ts = 0
                online = ts >= cutoff
                d["online"] = online
                d["status"] = "online" if online else "offline"
                items.append(d)
            release = {k: rel.get(k) for k in (
                "status", "is_latest", "version", "build_id", "build_time", "exe_sha256",
            )} if rel else {}
            return {"ok": True, "items": items, "online_within_sec": online_within_sec, "release": release}
        finally:
            conn.close()


def get_snapshot(agent_id: str, module: str) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM agent_snapshots WHERE agent_id=? AND module=?",
                (str(agent_id), str(module).lower()),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "无快照"}
            d = dict(row)
            try:
                d["items"] = json.loads(d.pop("payload_json") or "[]")
            except Exception:
                d["items"] = []
            return {"ok": True, "item": d}
        finally:
            conn.close()


def delete_agent(agent_id: str) -> Dict[str, Any]:
    ensure_db()
    aid = str(agent_id or "").strip()
    if not aid:
        return {"ok": False, "error": "缺少 agent_id"}
    with _lock:
        conn = _connect()
        try:
            prev = conn.execute(
                "SELECT hostname, secret_hash, revoked FROM agents WHERE agent_id=?", (aid,)
            ).fetchone()
            if prev and str(prev["secret_hash"] or "") and not prev["revoked"]:
                conn.execute(
                    """INSERT INTO agent_tombstones(agent_id, hostname, secret_hash, deleted_at) VALUES(?,?,?,?)
                       ON CONFLICT(agent_id) DO UPDATE SET hostname=excluded.hostname,
                         secret_hash=excluded.secret_hash, deleted_at=excluded.deleted_at""",
                    (aid, str(prev["hostname"] or ""), str(prev["secret_hash"]), _now()),
                )
            cur = conn.execute("DELETE FROM agents WHERE agent_id=?", (aid,))
            deleted = cur.rowcount > 0
            if deleted:
                conn.execute("DELETE FROM agent_snapshots WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_events WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_receipts WHERE agent_id=?", (aid,))
                conn.execute("DELETE FROM agent_streams WHERE agent_id=?", (aid,))
            conn.commit()
        finally:
            conn.close()
    # 时间线 / 指令 / 标签在 edr 扩展库，一并清掉，避免「主机删了告警还在」
    try:
        from . import agent_edr
        agent_edr.purge_agent_data(aid)
    except Exception:
        pass
    if not deleted:
        return {"ok": False, "error": "主机不存在"}
    bump_live("agent_deleted", agent_id=aid)
    return {"ok": True, "deleted": aid}


def _host_of(agent_id: str) -> str:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT hostname FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            return str(row["hostname"] if row else "") or ""
        finally:
            conn.close()


_DETAIL_MAX = 4000


def _shrink(obj: Any, cap: int) -> Any:
    if isinstance(obj, str):
        return obj if len(obj) <= cap else obj[:cap] + "…"
    if isinstance(obj, dict):
        return {k: _shrink(v, cap) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shrink(v, cap) for v in obj[:50]]
    return obj


def fit_detail(raw: Any) -> str:
    """告警详情统一存 JSON：dict/list 正常序列化，超长时逐级收缩字符串字段而不是硬截断（硬截断会破坏 JSON）。"""
    if raw is None or raw == "":
        return ""
    obj = raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s.startswith(("{", "[")):
            return json.dumps({"message": s[:_DETAIL_MAX - 40]}, ensure_ascii=False)
        try:
            obj = json.loads(s)
        except ValueError:
            return json.dumps({"message": s[:_DETAIL_MAX - 40], "truncated": True}, ensure_ascii=False)
    try:
        out = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return json.dumps({"message": str(raw)[:_DETAIL_MAX - 40]}, ensure_ascii=False)
    for cap in (1500, 800, 300, 120):
        if len(out) <= _DETAIL_MAX:
            return out
        out = json.dumps(_shrink(obj, cap), ensure_ascii=False, default=str)
    if len(out) <= _DETAIL_MAX:
        return out
    return json.dumps({"truncated": True, "preview": out[:_DETAIL_MAX - 60]}, ensure_ascii=False)


def _detail_score(s: str) -> int:
    if not s:
        return 0
    try:
        o = json.loads(s) if s.lstrip().startswith(("{", "[")) else None
    except ValueError:
        return max(1, len(s) // 10)
    if not isinstance(o, dict):
        return max(1, len(s) // 10)
    # 只有 raw/etype 的截断残骸视为几乎无信息
    if "raw" in o and len(o) <= 2:
        return 1
    n = 0
    for k, v in o.items():
        if v in (None, "", [], {}):
            continue
        n += 2
        if isinstance(v, dict):
            n += sum(1 for x in v.values() if x not in (None, "", [], {}))
        elif isinstance(v, str) and len(v) > 20:
            n += 1
    return n


def _detail_richer(new: str, old: str) -> bool:
    return _detail_score(new) >= _detail_score(old) and bool(new)


_REMOTE_OPS_ACTIONS = frozenset({
    "reg_read", "fs_list", "fs_stat", "fs_read", "fs_volumes", "run_cmd",
    "shell_open", "shell_write", "shell_poll", "shell_close",
})


def _suppress_response_ops_event(module: str, title: str) -> bool:
    """远程运维/只读指令的结果不写威胁事件（见 Agent 指令记录）。"""
    if str(module or "").strip().lower() != "response":
        return False
    t = str(title or "").strip()
    for prefix in ("处置成功：", "处置失败：", "远程运维失败："):
        if not t.startswith(prefix):
            continue
        act = t[len(prefix):].strip().lower()
        if act in _REMOTE_OPS_ACTIONS:
            return True
        if prefix == "处置成功：" and act == "refresh_modules":
            return True
    return False


_REMOTE_OPS_NOISE_PREFIXES = (
    "处置成功：fs_list", "处置成功：fs_stat", "处置成功：fs_read", "处置成功：fs_volumes",
    "处置成功：reg_read", "处置成功：run_cmd",
    "处置成功：shell_open", "处置成功：shell_write", "处置成功：shell_poll", "处置成功：shell_close",
    "处置失败：fs_volumes",
)


def _is_remote_ops_noise(title: str) -> bool:
    t = str(title or "").strip()
    return any(t == p or t.startswith(p) for p in _REMOTE_OPS_NOISE_PREFIXES)


def _event_payload_key(detail: Any) -> str:
    """从告警 detail 提取可合并键：任务/快捷方式/服务真实载荷路径。"""
    import json as _json
    d: Any = detail
    if isinstance(d, str) and d.strip():
        try:
            d = _json.loads(d)
        except Exception:
            return ""
    if not isinstance(d, dict):
        return ""
    for k in (
        "task_execute", "payload_path", "shortcut_target", "service_exe",
        "local_path", "image", "matched",
    ):
        v = str(d.get(k) or "").strip().lower()
        if v and (":\\" in v or v.startswith("\\\\") or v.endswith((".exe", ".dll", ".bat", ".ps1", ".cmd", ".scr"))):
            return v.replace("/", "\\")
    return ""


def report_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """终端或平台写入威胁/采集异常事件。"""
    ensure_db()
    agent_id = str(payload.get("agent_id") or "").strip()
    title = str(payload.get("title") or "").strip()[:200]
    if not agent_id or not title:
        return {"ok": False, "error": "缺少 agent_id 或 title"}
    if _is_remote_ops_noise(title):
        return {"ok": True, "suppressed": True, "reason": "remote_ops_noise"}
    module = str(payload.get("module") or "").strip().lower()[:32]
    if _suppress_response_ops_event(module, title):
        return {"ok": True, "suppressed": True, "ops_audit": True}
    severity = str(payload.get("severity") or "medium").strip().lower()[:16]
    if severity not in ("info", "low", "medium", "high", "critical"):
        severity = "medium"
    detail = fit_detail(payload.get("detail"))
    building_block = bool(payload.get("building_block")) or (
        isinstance(detail, dict) and detail.get("building_block") is True
    )
    if building_block:
        module = module or "building_block"
        if module not in ("building_block", "correlation"):
            module = "building_block"
        if severity in ("high", "critical"):
            severity = "medium"
    hostname = str(payload.get("hostname") or "").strip()[:128] or _host_of(agent_id)
    now = _now()
    from . import alert_allow
    with _lock:
        conn = _connect()
        try:
            # 已删除 / 未注册的终端不再产生告警，避免「主机删了告警还在」
            if not conn.execute("SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)).fetchone():
                return {"ok": False, "error": "终端未注册或已删除", "orphan": True}
            allow = alert_allow.find_match(conn, agent_id, title, detail)
            if allow is not None:
                alert_allow.record_hit(conn, allow["id"])
                return {"ok": True, "suppressed": True, "allow_id": allow["id"]}
            # 同主机同载荷路径（task_execute/payload_path）2 小时内合并 FIM+EVM 等双告警
            payload_key = _event_payload_key(detail)
            row = None
            if payload_key:
                since2h = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 7200))
                cand = conn.execute(
                    """SELECT id, title, detail, severity FROM agent_events
                       WHERE agent_id=? AND status='open' AND created_at>=?
                       ORDER BY id DESC LIMIT 40""",
                    (agent_id, since2h),
                ).fetchall()
                for c in cand or []:
                    if _event_payload_key(c["detail"]) == payload_key:
                        row = c
                        break
            # 同主机同标题 10 分钟内不重复刷屏
            if row is None:
                row = conn.execute(
                    """SELECT id FROM agent_events
                       WHERE agent_id=? AND title=? AND status='open'
                         AND created_at>=?
                       ORDER BY id DESC LIMIT 1""",
                    (agent_id, title, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - 600))),
                ).fetchone()
            if row:
                # 只在新详情信息量不少于旧值时覆盖，避免补晋升/字段更少的重复源把完整证据盖空
                old = conn.execute(
                    "SELECT detail, severity, hit_count FROM agent_events WHERE id=?",
                    (row["id"],),
                ).fetchone()
                old_detail = str((old["detail"] if old else "") or "")
                old_sev = str((old["severity"] if old else "") or severity)
                richer = _detail_richer(detail, old_detail)
                sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                bump_sev = sev_rank.get(severity, 0) > sev_rank.get(old_sev, 0)
                prev_hits = int((old["hit_count"] if old else 1) or 1)
                new_hits = max(1, prev_hits) + 1
                conn.execute(
                    """UPDATE agent_events SET detail=?, severity=?, module=?, hit_count=?, updated_at=?
                       WHERE id=?""",
                    (
                        detail if richer else old_detail,
                        severity if bump_sev else old_sev,
                        module or "",
                        new_hits,
                        now,
                        row["id"],
                    ),
                )
                conn.commit()
                eid = row["id"]
                deduped = True
            else:
                cur = conn.execute(
                    """INSERT INTO agent_events(agent_id, hostname, severity, title, detail, module, status,
                                                hit_count, created_at, updated_at)
                       VALUES(?,?,?,?,?,?, 'open', 1, ?, ?)""",
                    (agent_id, hostname, severity, title, detail, module, now, now),
                )
                conn.commit()
                eid = cur.lastrowid
                deduped = False
        finally:
            conn.close()
    bump_live("event", agent_id=agent_id, event_id=eid)
    if not deduped:
        row = {
            "id": eid, "agent_id": agent_id, "hostname": hostname, "severity": severity,
            "title": title, "detail": detail, "module": module, "status": "open",
            "created_at": now, "updated_at": now, "deduped": False,
        }
        if not building_block:
            try:
                from . import agent_notify
                agent_notify.notify_event(row)
            except Exception:
                pass
        try:
            from . import agent_store
            threading.Thread(target=agent_store.write_event, args=(row,), daemon=True).start()
        except Exception:
            pass
        try:
            from . import elastic_detection_es as _edes
            import json as _json
            det = {}
            if detail:
                try:
                    det = _json.loads(detail) if isinstance(detail, str) else (detail if isinstance(detail, dict) else {})
                except Exception:
                    det = {}
            _edes.index_event_async(
                agent_id=agent_id,
                hostname=hostname,
                etype=str(det.get("etype") or module or "event"),
                summary=title,
                detail=det if isinstance(det, dict) else {},
                ts=now,
            )
        except Exception:
            pass
    return {"ok": True, "id": eid, "deduped": deduped}


_QUIET_AT = 0.0


def _quiet_open_alerts(conn: sqlite3.Connection) -> int:
    """已加白的未处置告警、以及远程运维成功回执，不再留在威胁列表。"""
    global _QUIET_AT
    now_ts = time.time()
    if now_ts - _QUIET_AT < 15:
        return 0
    _QUIET_AT = now_ts
    now = _now()
    cur = conn.execute(
        """UPDATE agent_events SET status='ignored', updated_at=?
           WHERE status='open' AND (
             title LIKE '处置成功：fs_%' OR title LIKE '处置成功：reg_read%'
             OR title LIKE '处置成功：run_cmd%' OR title LIKE '处置成功：shell_%'
             OR title LIKE '处置失败：fs_volumes%'
           )""",
        (now,),
    )
    n = int(cur.rowcount or 0)
    try:
        from . import alert_allow
        n += alert_allow.apply_all_enabled(conn)
    except Exception:
        pass
    if n:
        conn.commit()
    return n


def related_events_by_payload(
    event_id: int,
    *,
    limit: int = 20,
) -> Dict[str, Any]:
    """按 task_execute/payload_path 等载荷键关联同主机告警（FIM↔EVM↔进程产品化边）。"""
    ensure_db()
    limit = max(1, min(int(limit or 20), 50))
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM agent_events WHERE id=?", (int(event_id),)).fetchone()
            if not row:
                return {"ok": False, "error": "事件不存在"}
            detail = row["detail"]
            key = _event_payload_key(detail)
            edges = []
            dobj = None
            try:
                import json as _json
                dobj = _json.loads(detail) if isinstance(detail, str) else detail
            except Exception:
                dobj = detail if isinstance(detail, dict) else {}
            if isinstance(dobj, dict):
                for label, field in (
                    ("task_def", "task_def_path"),
                    ("payload", "task_execute"),
                    ("payload", "payload_path"),
                    ("shortcut", "shortcut_target"),
                    ("service", "service_exe"),
                    ("process", "image"),
                    ("process", "path"),
                    ("network", "remote_ip"),
                ):
                    v = str(dobj.get(field) or "").strip()
                    if v:
                        edges.append({"kind": label, "field": field, "value": v})
            items = []
            if key:
                aid = row["agent_id"]
                cand = conn.execute(
                    """SELECT id, title, module, severity, status, created_at, detail
                       FROM agent_events WHERE agent_id=? AND id<>?
                       ORDER BY id DESC LIMIT 80""",
                    (aid, int(event_id)),
                ).fetchall()
                for c in cand or []:
                    if _event_payload_key(c["detail"]) != key:
                        continue
                    items.append({
                        "id": c["id"], "title": c["title"], "module": c["module"],
                        "severity": c["severity"], "status": c["status"],
                        "created_at": c["created_at"], "payload_key": key,
                    })
                    if len(items) >= limit:
                        break
            return {
                "ok": True,
                "event_id": int(event_id),
                "payload_key": key,
                "edges": edges,
                "items": items,
            }
        finally:
            conn.close()


def _event_detail_obj_light(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """列表接口用：只解析 JSON，不做时间线回填（回填留给 get_event）。"""
    raw = item.get("detail") or ""
    if not str(raw).lstrip().startswith("{"):
        return None
    try:
        d = json.loads(raw)
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def list_events(
    *,
    status: str = "",
    agent_id: str = "",
    limit: int = 100,
) -> Dict[str, Any]:
    ensure_db()
    limit = max(1, min(int(limit or 100), 500))
    clauses = []
    args: List[Any] = []
    st = str(status or "").strip().lower()
    if st in ("open", "closed", "ignored"):
        clauses.append("status=?")
        args.append(st)
    aid = str(agent_id or "").strip()
    if aid:
        clauses.append("agent_id=?")
        args.append(aid)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with _lock:
        conn = _connect()
        try:
            _quiet_open_alerts(conn)
            rows = conn.execute(
                f"""SELECT id, agent_id, hostname, severity, title, detail, module, status,
                           hit_count, created_at, updated_at
                    FROM agent_events{where} ORDER BY id DESC LIMIT ?""",
                (*args, limit),
            ).fetchall()
            items = []
            for r in rows:
                it = dict(r)
                obj = _event_detail_obj_light(it)
                if obj is not None:
                    it["detail_obj"] = obj
                items.append(it)
            open_n = conn.execute("SELECT COUNT(*) AS c FROM agent_events WHERE status='open'").fetchone()["c"]
            return {"ok": True, "items": items, "open_count": int(open_n or 0)}
        finally:
            conn.close()


def update_event(event_id: int, *, status: str = "") -> Dict[str, Any]:
    ensure_db()
    st = str(status or "").strip().lower()
    if st not in ("open", "closed", "ignored"):
        return {"ok": False, "error": "status 无效"}
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE agent_events SET status=?, updated_at=? WHERE id=?",
                (st, _now(), int(event_id)),
            )
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "事件不存在"}
            return {"ok": True}
        finally:
            conn.close()


def delete_event(event_id: int) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            _mark_deleted(conn, "id=?", [int(event_id)])
            cur = conn.execute("DELETE FROM agent_events WHERE id=?", (int(event_id),))
            conn.commit()
            if cur.rowcount <= 0:
                return {"ok": False, "error": "事件不存在"}
            return {"ok": True, "deleted": int(event_id)}
        finally:
            conn.close()


def delete_events(*, status: str = "", agent_id: str = "", severity: str = "") -> Dict[str, Any]:
    """按筛选条件批量删除告警（不带条件即全部）。"""
    ensure_db()
    clauses, args = [], []
    st = str(status or "").strip().lower()
    if st in ("open", "closed", "ignored"):
        clauses.append("status=?")
        args.append(st)
    if agent_id:
        clauses.append("agent_id=?")
        args.append(str(agent_id))
    sev = str(severity or "").strip().lower()
    if sev in ("info", "low", "medium", "high", "critical"):
        clauses.append("lower(severity)=?")
        args.append(sev)
    where = " AND ".join(clauses) or "1=1"
    with _lock:
        conn = _connect()
        try:
            _mark_deleted(conn, where, args)
            cur = conn.execute(f"DELETE FROM agent_events WHERE {where}", args)
            conn.commit()
            n = int(cur.rowcount or 0)
        finally:
            conn.close()
    bump_live("event")
    return {"ok": True, "deleted": n}


def _mark_deleted(conn: sqlite3.Connection, where: str, args: List[Any]) -> None:
    conn.execute(
        f"""INSERT INTO agent_event_deletions(agent_id, title, deleted_at)
            SELECT agent_id, title, ? FROM agent_events WHERE {where}
            ON CONFLICT(agent_id, title) DO UPDATE SET deleted_at=excluded.deleted_at""",
        (_now(), *args),
    )


def _repair_event_detail(conn: sqlite3.Connection, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = str(item.get("title") or "")
    aid = str(item.get("agent_id") or "")
    if not title or not aid:
        return None
    raw = item.get("detail") or ""
    try:
        cur = json.loads(raw) if str(raw).lstrip().startswith("{") else {}
    except ValueError:
        cur = {}
    if not isinstance(cur, dict):
        cur = {}
    try:
        from . import event_detail_enrich as ede
        out, changed = ede.enrich_detail_from_timeline(
            conn, agent_id=aid, title=title, detail=cur,
            created_at=str(item.get("created_at") or ""),
        )
        if changed:
            detail_s = fit_detail(out)
            conn.execute(
                "UPDATE agent_events SET detail=?, updated_at=? WHERE id=?",
                (detail_s, _now(), int(item["id"])),
            )
            conn.commit()
            return out
    except Exception:
        pass
    try:
        tl = conn.execute(
            """SELECT etype, detail_json FROM agent_timeline
               WHERE agent_id=? AND summary=? ORDER BY id DESC LIMIT 1""",
            (aid, title),
        ).fetchone()
    except sqlite3.Error:
        return None
    if not tl:
        return None
    try:
        d = json.loads(tl["detail_json"] or "{}")
    except Exception:
        return None
    if not isinstance(d, dict) or not d:
        return None
    out = {"etype": tl["etype"] or ""}
    out.update(d)
    try:
        conn.execute(
            "UPDATE agent_events SET detail=? WHERE id=?",
            (fit_detail(out), int(item["id"])),
        )
        conn.commit()
    except sqlite3.Error:
        pass
    return out


def enrich_event_details(*, limit: int = 500) -> Dict[str, Any]:
    """从时间线回填缺详情的威胁事件（PTM/EVM/SCA 等）。"""
    ensure_db()
    from . import event_detail_enrich as ede
    with _lock:
        conn = _connect()
        try:
            return ede.backfill_agent_events(conn, limit=limit, write=True)
        finally:
            conn.close()


def _event_detail_obj(conn: sqlite3.Connection, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = item.get("detail") or ""
    if not str(raw).lstrip().startswith("{"):
        return None
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    try:
        from . import event_detail_enrich as ede
        out, _ = ede.enrich_detail_from_timeline(
            conn,
            agent_id=str(item.get("agent_id") or ""),
            title=str(item.get("title") or ""),
            detail=d,
            created_at=str(item.get("created_at") or ""),
        )
        return out
    except Exception:
        return d


def repair_broken_event_details(limit: int = 500) -> int:
    ensure_db()
    fixed = 0
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                """SELECT id, agent_id, title, detail FROM agent_events
                   WHERE detail LIKE '{%' AND detail NOT LIKE '%}' ORDER BY id DESC LIMIT ?""",
                (int(limit),),
            ).fetchall()
            for r in rows:
                if _repair_event_detail(conn, dict(r)) is not None:
                    fixed += 1
        finally:
            conn.close()
    return fixed


def get_event(event_id: int) -> Dict[str, Any]:
    ensure_db()
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT * FROM agent_events WHERE id=?",
                (int(event_id),),
            ).fetchone()
            if not row:
                return {"ok": False, "error": "事件不存在"}
            item = dict(row)
            # 解析 detail JSON（规则命中证据）
            detail_obj = None
            raw = item.get("detail") or ""
            if raw.startswith("{"):
                try:
                    detail_obj = json.loads(raw)
                except Exception:
                    detail_obj = None
            # 旧版晋升时 detail 被截断成非法 JSON：按同主机同标题从时间线回填原始证据
            if not isinstance(detail_obj, dict) or len(detail_obj) <= 1:
                repaired = _repair_event_detail(conn, item)
                if repaired is not None:
                    detail_obj = repaired
                    item["detail"] = fit_detail(repaired)
            elif detail_obj and isinstance(detail_obj, dict):
                try:
                    from . import event_detail_enrich as ede
                    enriched, changed = ede.enrich_detail_from_timeline(
                        conn,
                        agent_id=str(item.get("agent_id") or ""),
                        title=str(item.get("title") or ""),
                        detail=detail_obj,
                        created_at=str(item.get("created_at") or ""),
                    )
                    if changed:
                        detail_obj = enriched
                    if changed:
                        item["detail"] = fit_detail(detail_obj)
                        conn.execute(
                            "UPDATE agent_events SET detail=?, updated_at=? WHERE id=?",
                            (item["detail"], _now(), int(event_id)),
                        )
                        conn.commit()
                except Exception:
                    pass
            item["detail_obj"] = detail_obj or _event_detail_obj(conn, item)
            return {"ok": True, "item": item}
        finally:
            conn.close()


def _blob_has_mojibake(text: str) -> bool:
    if not text:
        return False
    # UTF-8 替换符或连续问号菱形在 JSON 里常表现为 \ufffd
    return ("\ufffd" in text) or (text.count("?") >= 8 and "DisplayName" in text)


def upsert_snapshot(payload: Dict[str, Any]) -> Dict[str, Any]:
    """写入某模块最新快照（覆盖式）。payload.items 建议 ≤500 条精简对象。"""
    ensure_db()
    agent_id = str(payload.get("agent_id") or "").strip()
    module = str(payload.get("module") or "").strip().lower()
    if not agent_id or module not in AGENT_MODULES:
        return {"ok": False, "error": "agent_id 或 module 无效"}
    items = payload.get("items")
    if not isinstance(items, list):
        items = []
    items = items[:500]
    keys = payload.get("keys")
    # 增量清单需要与条目一一对应的键；旧 Agent 不带 keys，代号记 0（之后的增量会被拒并触发全量）
    if not (isinstance(keys, list) and len(keys) >= len(items)):
        keys = []
    keys = [str(k)[:300] for k in keys[:len(items)]]
    try:
        generation = int(payload.get("generation") or 0) if keys else 0
    except (TypeError, ValueError):
        generation = 0
    digest = str(payload.get("digest") or "").strip()[:128]
    collected_at = str(payload.get("collected_at") or _now())[:32]
    blob = json.dumps(items, ensure_ascii=False)
    if len(blob) > 1_500_000:
        return {"ok": False, "error": "snapshot 过大，请精简字段"}
    now = _now()
    with _lock:
        conn = _connect()
        try:
            conn.execute(
                "UPDATE agents SET last_seen=?, status='online' WHERE agent_id=?",
                (now, agent_id),
            )
            conn.execute(
                """INSERT INTO agent_snapshots(agent_id, module, collected_at, item_count, digest, payload_json,
                                               generation, keys_json)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(agent_id, module) DO UPDATE SET
                     collected_at=excluded.collected_at,
                     item_count=excluded.item_count,
                     digest=excluded.digest,
                     payload_json=excluded.payload_json,
                     generation=excluded.generation,
                     keys_json=excluded.keys_json""",
                (agent_id, module, collected_at, len(items), digest, blob, generation,
                 json.dumps(keys, ensure_ascii=False) if keys else ""),
            )
            conn.commit()
        finally:
            conn.close()
    return _post_snapshot(agent_id, module, items, blob, total=len(items))


def _post_snapshot(agent_id: str, module: str, items: List[Any], blob: str, *, total: int,
                   extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """快照入库后的质量检查与规则匹配；增量时 items 只含新增/变化条目。"""
    # 采集质量异常 → 威胁事件
    if _blob_has_mojibake(blob):
        report_event({
            "agent_id": agent_id,
            "module": module,
            "severity": "medium",
            "title": f"采集编码异常（{module}）",
            "detail": "快照中出现乱码字符，请升级终端 Agent 后重新上报",
        })
    if module in ("service", "process", "network") and total == 0:
        report_event({
            "agent_id": agent_id,
            "module": module,
            "severity": "low",
            "title": f"模块采集为空（{module}）",
            "detail": "本次快照 0 条，可能权限不足或采集失败",
        })
    # 实时规则命中 → 威胁事件（增量只评估新增/变化条目）
    rule_stats = {"hits": 0}
    host = _host_of(agent_id)
    if items:
        try:
            from . import agent_rules
            rule_stats = agent_rules.apply_snapshot_rules(agent_id, module, items, hostname=host) or {}
        except Exception as e:
            print("[agent_rules]", e)
    # 浏览器访问记录：域名走 IOC 匹配才告警
    if module == "browser" and items:
        try:
            from . import agent_edr
            parts = []
            for it in items[:300]:
                if not isinstance(it, dict):
                    continue
                parts.append(str(it.get("domain") or ""))
                parts.append(str(it.get("url") or ""))
            agent_edr.match_iocs(agent_id, host, blob="\n".join(parts), events=None, module="ioc")
        except Exception as e:
            print("[agent_ioc browser]", e)
    bump_live("snapshot", agent_id=agent_id, module=module)
    out = {
        "ok": True,
        "module": module,
        "item_count": total,
        "rule_hits": int(rule_stats.get("hits") or 0),
        "live_rev": live_revision(),
    }
    if extra:
        out.update(extra)
    return out


DELTA_MAX_ITEMS = 1000


def apply_snapshot_delta(payload: Dict[str, Any]) -> Dict[str, Any]:
    """按 generation 链应用增量清单。服务端代号与 base_generation 不一致、或应用后条数与 Agent
    声明不符时拒绝（generation_mismatch），Agent 收到拒绝后改发全量，不做"猜测式合并"。"""
    ensure_db()
    agent_id = str(payload.get("agent_id") or "").strip()
    module = str(payload.get("module") or "").strip().lower()
    if not agent_id or module not in AGENT_MODULES:
        return {"ok": False, "error": "agent_id 或 module 无效"}
    try:
        base = int(payload.get("base_generation") or 0)
        gen = int(payload.get("generation") or 0)
        want_n = int(payload.get("item_count")) if payload.get("item_count") is not None else -1
    except (TypeError, ValueError):
        return {"ok": False, "error": "generation 无效"}
    ups = payload.get("upserts") if isinstance(payload.get("upserts"), list) else []
    rms = payload.get("removes") if isinstance(payload.get("removes"), list) else []
    if base <= 0 or gen <= base:
        return {"ok": False, "error": "generation_mismatch"}
    collected_at = str(payload.get("collected_at") or _now())[:32]
    digest = str(payload.get("digest") or "").strip()[:128]
    now = _now()
    changed: List[Dict[str, Any]] = []
    with _lock:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT generation, keys_json, payload_json FROM agent_snapshots WHERE agent_id=? AND module=?",
                (agent_id, module),
            ).fetchone()
            if not row or int(row["generation"] or 0) != base or not row["keys_json"]:
                return {"ok": False, "error": "generation_mismatch"}
            try:
                keys = json.loads(row["keys_json"] or "[]")
                items = json.loads(row["payload_json"] or "[]")
            except Exception:
                return {"ok": False, "error": "generation_mismatch"}
            if len(keys) != len(items):
                return {"ok": False, "error": "generation_mismatch"}
            rmset = {str(k) for k in rms}
            new_keys: List[str] = []
            new_items: List[Any] = []
            for k, it in zip(keys, items):
                if k not in rmset:
                    new_keys.append(k)
                    new_items.append(it)
            pos = {k: i for i, k in enumerate(new_keys)}
            for u in ups:
                if not isinstance(u, dict) or not isinstance(u.get("item"), dict):
                    continue
                k = str(u.get("k") or "")[:300]
                if not k:
                    continue
                if k in pos:
                    new_items[pos[k]] = u["item"]
                else:
                    pos[k] = len(new_keys)
                    new_keys.append(k)
                    new_items.append(u["item"])
                changed.append(u["item"])
            if len(new_items) > DELTA_MAX_ITEMS or (want_n >= 0 and len(new_items) != want_n):
                return {"ok": False, "error": "generation_mismatch"}
            blob = json.dumps(new_items, ensure_ascii=False)
            if len(blob) > 1_500_000:
                return {"ok": False, "error": "snapshot 过大，请精简字段"}
            conn.execute("UPDATE agents SET last_seen=?, status='online' WHERE agent_id=?", (now, agent_id))
            conn.execute(
                """UPDATE agent_snapshots SET collected_at=?, item_count=?, digest=?, payload_json=?,
                       generation=?, keys_json=? WHERE agent_id=? AND module=?""",
                (collected_at, len(new_items), digest, blob, gen, json.dumps(new_keys, ensure_ascii=False),
                 agent_id, module),
            )
            conn.commit()
            total = len(new_items)
        finally:
            conn.close()
    changed_blob = json.dumps(changed, ensure_ascii=False) if changed else ""
    return _post_snapshot(agent_id, module, changed, changed_blob, total=total,
                          extra={"delta": True, "upserts": len(changed), "removes": len(rmset), "generation": gen})
