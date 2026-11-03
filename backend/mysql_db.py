"""MySQL 连接（phpstudy / 本机）。主机台账等管理数据优先走 MySQL，失败回退 SQLite。

配置优先级：环境变量 > db_config.json > 安全默认（禁用且无密码）
"""
from __future__ import annotations
import json
import os
import threading
import time
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional, Tuple

from . import config

def _db_config_path() -> Path:
    try:
        from .cache_config import db_config_path
        return db_config_path()
    except Exception:
        return config.resolve_config_file("db_config.json")


DB_CONFIG_PATH = config.resolve_config_file("db_config.json")

# 新安装默认禁用；必须显式配置数据库和强密码。
_DEFAULTS = {
    "enabled": False,
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",
    "database": "forensic_platform",
    "charset": "utf8mb4",
    "pool_size": 20,  # 20～50 人：与分析并发匹配；可在 db_config.json 覆盖
}

_status: Dict[str, Any] = {
    "ok": False,
    "backend": "sqlite",
    "error": "",
    "database": "",
    "version": "",
}


def load_db_config() -> Dict[str, Any]:
    cfg = dict(_DEFAULTS)
    path = _db_config_path()
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                cfg.update({k: data[k] for k in data if k in cfg or k in ("enabled",)})
        except Exception as e:
            print(f"[mysql] read db_config.json failed: {e}")
    # 环境变量覆盖
    if os.getenv("FORENSIC_MYSQL_ENABLED") is not None:
        cfg["enabled"] = os.getenv("FORENSIC_MYSQL_ENABLED", "").strip().lower() in ("1", "true", "yes")
    if os.getenv("FORENSIC_MYSQL_HOST"):
        cfg["host"] = os.getenv("FORENSIC_MYSQL_HOST", "").strip()
    if os.getenv("FORENSIC_MYSQL_PORT"):
        try:
            cfg["port"] = int(os.getenv("FORENSIC_MYSQL_PORT", "3306"))
        except ValueError:
            pass
    if os.getenv("FORENSIC_MYSQL_USER"):
        cfg["user"] = os.getenv("FORENSIC_MYSQL_USER", "").strip()
    if os.getenv("FORENSIC_MYSQL_PASSWORD") is not None:
        cfg["password"] = os.getenv("FORENSIC_MYSQL_PASSWORD", "")
    if os.getenv("FORENSIC_MYSQL_DATABASE"):
        cfg["database"] = os.getenv("FORENSIC_MYSQL_DATABASE", "").strip()
    return cfg


def save_db_config_example() -> Path:
    """写出示例配置（不含强制覆盖已有文件）。"""
    example = config.resolve_config_file("db_config.example.json", for_write=True)
    # 若根目录仍有示例且 config/ 尚无，迁移即可
    old = config.ROOT / "db_config.example.json"
    if old.is_file() and not example.is_file():
        try:
            import shutil
            shutil.move(str(old), str(example))
        except Exception:
            pass
    if not example.exists():
        with open(example, "w", encoding="utf-8") as f:
            json.dump(_DEFAULTS, f, ensure_ascii=False, indent=2)
    return example


def ensure_db_config_file() -> Path:
    """不自动创建含凭据的 db_config.json；仅确保示例文件存在。"""
    path = _db_config_path()
    save_db_config_example()
    if not path.exists():
        print(f"[mysql] db_config.json 不存在，MySQL 默认禁用；请复制 db_config.example.json 或使用环境变量 FORENSIC_MYSQL_*")
    return path


def _import_pymysql():
    try:
        import pymysql
        from pymysql.cursors import DictCursor
        return pymysql, DictCursor
    except ImportError:
        return None, None


def probe_mysql(cfg: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """仅探测能否登录（不要求库已存在）。"""
    cfg = cfg or load_db_config()
    if not cfg.get("enabled", False):
        return False, "disabled"
    pymysql, DictCursor = _import_pymysql()
    if not pymysql:
        return False, "pymysql not installed (pip install pymysql)"
    try:
        conn = pymysql.connect(
            host=cfg["host"],
            port=int(cfg["port"]),
            user=cfg["user"],
            password=cfg["password"],
            charset=cfg.get("charset") or "utf8mb4",
            connect_timeout=5,
            cursorclass=DictCursor,
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT VERSION() AS v")
                row = cur.fetchone() or {}
                ver = row.get("v") or ""
            return True, str(ver)
        finally:
            conn.close()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def connect_mysql(database: Optional[str] = "", use_cfg_db: bool = True):
    """返回 pymysql 连接（DictCursor）。默认走连接池；建库等场景可直连。

    - database='' 且 use_cfg_db=True：使用配置里的库名
    - database='' 且 use_cfg_db=False：不选库（用于 CREATE DATABASE）
    - database='xxx'：强制使用该库
    """
    try:
        if database or not use_cfg_db:
            return _raw_connect_mysql(database=database, use_cfg_db=use_cfg_db)
        return _pool_acquire()
    except Exception as e:
        # 池/直连失败均降级，避免后续请求继续撞墙
        try:
            mark_mysql_down(f"{type(e).__name__}: {e}")
        except Exception:
            pass
        raise


def _raw_connect_mysql(database: Optional[str] = "", use_cfg_db: bool = True):
    cfg = load_db_config()
    pymysql, DictCursor = _import_pymysql()
    if not pymysql:
        raise RuntimeError("pymysql not installed")
    kw: Dict[str, Any] = dict(
        host=cfg["host"],
        port=int(cfg["port"]),
        user=cfg["user"],
        password=cfg["password"],
        charset=cfg.get("charset") or "utf8mb4",
        connect_timeout=8,
        cursorclass=DictCursor,
        autocommit=False,
    )
    if database:
        kw["database"] = database
    elif use_cfg_db and cfg.get("database"):
        kw["database"] = cfg["database"]
    return pymysql.connect(**kw)


class _PooledConn:
    """包装真实连接：close() 归还连接池而非断开。"""

    __slots__ = ("_conn", "_released")

    def __init__(self, conn):
        self._conn = conn
        self._released = False

    def close(self):
        if self._released:
            return
        self._released = True
        _pool_release(self._conn)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
        finally:
            self.close()
        return False


_pool_q: Optional[Queue] = None
_pool_lock = threading.Lock()
_pool_created = 0
_pool_max = 8


def _pool_key(cfg: Dict[str, Any]) -> Tuple:
    return (
        cfg.get("host"),
        int(cfg.get("port") or 3306),
        cfg.get("user"),
        cfg.get("password"),
        cfg.get("database"),
        cfg.get("charset") or "utf8mb4",
    )


_pool_ident: Optional[Tuple] = None


def _ensure_pool():
    global _pool_q, _pool_created, _pool_max, _pool_ident
    cfg = load_db_config()
    ident = _pool_key(cfg)
    with _pool_lock:
        if _pool_q is None or _pool_ident != ident:
            _pool_q = Queue(maxsize=32)
            _pool_created = 0
            _pool_ident = ident
            try:
                _pool_max = max(2, min(32, int(cfg.get("pool_size") or 20)))
            except Exception:
                _pool_max = 20


def _pool_live(conn):
    """空闲连接复用时不必每次 ping；超过 20s 再探测，避免每次点按钮都打 MySQL。"""
    last = float(getattr(conn, "_forensic_last_ping", 0) or 0)
    if time.time() - last >= 20:
        conn.ping(reconnect=True)
    conn._forensic_last_ping = time.time()
    return _PooledConn(conn)


def _pool_acquire():
    global _pool_created
    _ensure_pool()
    assert _pool_q is not None
    # 先尝试取空闲连接
    try:
        conn = _pool_q.get_nowait()
        try:
            return _pool_live(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            with _pool_lock:
                _pool_created = max(0, _pool_created - 1)
    except Empty:
        pass

    # 新建（受上限约束）
    can_create = False
    with _pool_lock:
        if _pool_created < _pool_max:
            _pool_created += 1
            can_create = True
    if can_create:
        try:
            conn = _raw_connect_mysql()
            conn._forensic_last_ping = time.time()
            return _PooledConn(conn)
        except Exception:
            with _pool_lock:
                _pool_created = max(0, _pool_created - 1)
            raise

    # 已满：阻塞等待空闲连接
    conn = _pool_q.get(timeout=12)
    try:
        return _pool_live(conn)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        with _pool_lock:
            _pool_created = max(0, _pool_created - 1)
        with _pool_lock:
            _pool_created += 1
        try:
            conn = _raw_connect_mysql()
            conn._forensic_last_ping = time.time()
            return _PooledConn(conn)
        except Exception:
            with _pool_lock:
                _pool_created = max(0, _pool_created - 1)
            raise


def _pool_release(conn) -> None:
    global _pool_created
    if _pool_q is None:
        try:
            conn.close()
        except Exception:
            pass
        return
    try:
        conn.rollback()
    except Exception:
        pass
    try:
        _pool_q.put_nowait(conn)
    except Full:
        try:
            conn.close()
        except Exception:
            pass
        with _pool_lock:
            _pool_created = max(0, _pool_created - 1)


def reset_mysql_pool() -> None:
    """配置变更或重启时清空池。"""
    global _pool_q, _pool_created, _pool_ident
    with _pool_lock:
        q = _pool_q
        _pool_q = None
        _pool_created = 0
        _pool_ident = None
    if not q:
        return
    while True:
        try:
            c = q.get_nowait()
        except Empty:
            break
        try:
            c.close()
        except Exception:
            pass


def mark_mysql_down(error: str = "") -> None:
    """连接失败时降级为 sqlite，避免 sticky ok 导致整站挂死。"""
    global _status
    prev = bool(_status.get("ok"))
    _status["ok"] = False
    _status["backend"] = "sqlite"
    if error:
        _status["error"] = str(error)[:400]
    if prev:
        print(f"[mysql] marked down → sqlite: {_status.get('error')}")
        try:
            reset_mysql_pool()
        except Exception:
            pass


def ensure_database_and_schema() -> Dict[str, Any]:
    """自动建库 + hosts 表。成功则 status.ok=True。"""
    global _status, _last_reprobe_ts
    ensure_db_config_file()
    cfg = load_db_config()
    _status = {
        "ok": False,
        "backend": "sqlite",
        "error": "",
        "database": cfg.get("database") or "",
        "version": "",
        "host": cfg.get("host"),
        "port": cfg.get("port"),
        "user": cfg.get("user"),
        "config_file": str(_db_config_path()),
    }
    if not cfg.get("enabled", True):
        _status["error"] = "MySQL disabled in config"
        return dict(_status)

    ok, msg = probe_mysql(cfg)
    if not ok:
        _status["error"] = msg
        return dict(_status)
    _status["version"] = msg

    dbname = cfg.get("database") or "forensic_platform"
    try:
        # 不选库，先 CREATE DATABASE
        conn = connect_mysql(use_cfg_db=False)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{dbname}` "
                    "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            conn.commit()
        finally:
            conn.close()

        conn = connect_mysql(database=dbname, use_cfg_db=False)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS hosts (
                        id VARCHAR(32) NOT NULL PRIMARY KEY,
                        name VARCHAR(128) NOT NULL,
                        ip VARCHAR(255) DEFAULT '',
                        note VARCHAR(512) DEFAULT '',
                        created_at DOUBLE,
                        updated_at DOUBLE,
                        UNIQUE KEY uk_hosts_name (name)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                    """
                )
            conn.commit()
            from .mysql_store import ensure_analysis_tables
            ensure_analysis_tables(conn)
            from .users import ensure_users_table
            ensure_users_table(conn)
            from .audit import ensure_audit_table
            ensure_audit_table(conn)
            from .jobs import ensure_jobs_table
            ensure_jobs_table(conn)
            from .rule_index import ensure_mysql_table
            ensure_mysql_table(conn)
            from .platform_store import ensure_platform_tables
            ensure_platform_tables(conn)
        finally:
            conn.close()

        _status["ok"] = True
        _status["backend"] = "mysql"
        _status["database"] = dbname
        _status["error"] = ""
        _last_reprobe_ts = time.time()
        print(f"[mysql] connected {cfg['host']}:{cfg['port']}/{dbname} ver={msg}")
    except Exception as e:
        _status["ok"] = False
        _status["backend"] = "sqlite"
        _status["error"] = f"{type(e).__name__}: {e}"
        print(f"[mysql] setup failed, fallback sqlite: {e}")
        try:
            reset_mysql_pool()
        except Exception:
            pass
    return dict(_status)


_last_reprobe_ts = 0.0
_REPROBE_SEC = 12.0
_catchup_running = False
_catchup_lock = threading.Lock()


def _catchup_after_mysql_recovery() -> None:
    """MySQL 从降级恢复后：本地缺项补迁报告，并以 MySQL 对齐用户/主机镜像。"""
    global _catchup_running
    with _catchup_lock:
        if _catchup_running:
            return
        _catchup_running = True
    try:
        try:
            from .hosts import sync_hosts_mysql_to_sqlite
            sync_hosts_mysql_to_sqlite()
        except Exception as e:
            print(f"[mysql] recovery sync hosts: {e}")
        try:
            from .users import sync_users_mysql_to_sqlite
            sync_users_mysql_to_sqlite()
        except Exception as e:
            print(f"[mysql] recovery sync users: {e}")
        try:
            from .mysql_store import migrate_index_sqlite_to_mysql
            n = migrate_index_sqlite_to_mysql()
            if n:
                print(f"[mysql] recovery catch-up reports: {n}")
        except Exception as e:
            print(f"[mysql] recovery catch-up reports: {e}")
        try:
            from . import platform_store
            from .settings import get_settings
            from . import config as cfgmod
            from . import system_updates as sumod
            platform_store.catchup_all(
                runtime=get_settings(),
                ai={
                    "model": cfgmod.AI_MODEL,
                    "base_url": cfgmod.AI_BASE_URL,
                    "api_key": cfgmod.AI_API_KEY,
                },
                updates=sumod.peek_local(),
            )
            cfgmod.reload_ai_config()
        except Exception as e:
            print(f"[mysql] recovery platform_store: {e}")
    finally:
        _catchup_running = False


def mysql_ready() -> bool:
    """当前是否可用。若已降级，周期性轻量重探，MySQL 事后启动可自动恢复。"""
    global _last_reprobe_ts
    if _status.get("ok"):
        return True
    cfg = load_db_config()
    if not cfg.get("enabled", True):
        return False
    now = time.time()
    if now - _last_reprobe_ts < _REPROBE_SEC:
        return False
    _last_reprobe_ts = now
    ok, msg = probe_mysql(cfg)
    if not ok:
        _status["error"] = msg
        return False
    try:
        st = ensure_database_and_schema()
        if st.get("ok"):
            print("[mysql] recovered from downtime")
            _catchup_after_mysql_recovery()
        return bool(st.get("ok"))
    except Exception as e:
        _status["error"] = f"{type(e).__name__}: {e}"
        return False


def get_status() -> Dict[str, Any]:
    return dict(_status)


def init_on_startup() -> Dict[str, Any]:
    """服务启动时调用。"""
    st = ensure_database_and_schema()
    if st.get("ok"):
        try:
            from .hosts import migrate_hosts_sqlite_to_mysql, sync_hosts_mysql_to_sqlite
            n = migrate_hosts_sqlite_to_mysql()
            if n:
                print(f"[mysql] migrated {n} hosts from sqlite")
            sync_hosts_mysql_to_sqlite()
        except Exception as e:
            print(f"[mysql] migrate hosts:", e)
        try:
            from .users import migrate_users_sqlite_to_mysql, sync_users_mysql_to_sqlite
            n = migrate_users_sqlite_to_mysql()
            if n:
                print(f"[mysql] migrated {n} users from sqlite")
            # MySQL 为准：覆盖本地 users.db，避免改密后回退仍用旧默认密码
            sync_users_mysql_to_sqlite()
        except Exception as e:
            print(f"[mysql] migrate users:", e)
        try:
            from .mysql_store import migrate_index_sqlite_to_mysql, table_counts
            n = migrate_index_sqlite_to_mysql()
            if n:
                print(f"[mysql] migrated {n} report index rows from sqlite")
            print(f"[mysql] tables: {table_counts()}")
        except Exception as e:
            print(f"[mysql] migrate reports:", e)
        try:
            from .auth import ensure_bootstrap_admin
            ensure_bootstrap_admin()
        except Exception as e:
            print("[auth] bootstrap:", e)
        try:
            from . import platform_store
            from .settings import get_settings
            from . import config as cfgmod
            from . import system_updates as sumod
            platform_store.catchup_all(
                runtime=get_settings(),
                ai={
                    "model": cfgmod.AI_MODEL,
                    "base_url": cfgmod.AI_BASE_URL,
                    "api_key": cfgmod.AI_API_KEY,
                },
                updates=sumod.peek_local(),
            )
            cfgmod.reload_ai_config()
        except Exception as e:
            print("[platform_store] seed:", e)
        try:
            from .settings import apply_runtime
            apply_runtime()
        except Exception as e:
            print("[settings] apply:", e)
        try:
            from .jobs import recover_jobs_on_startup
            recover_jobs_on_startup()
        except Exception as e:
            print("[jobs] recover:", e)
        try:
            from . import ip_catalog
            info = ip_catalog.reload_from_files(persist=True)
            print(
                f"[ip_catalog] domestic={info.get('domestic_cidrs')} "
                f"cloud={info.get('cloud_cidrs')} mysql={info.get('mysql')} sqlite={info.get('sqlite')}"
            )
        except Exception as e:
            print("[ip_catalog] load:", e)
        try:
            from . import ioc_mysql
            ioc_st = ioc_mysql.start_sync_async(only_if_empty=True)
            if ioc_st.get("started"):
                print("[ioc_mysql] background sync started (table empty)")
            elif ioc_st.get("skipped"):
                print(f"[ioc_mysql] table ready count={ioc_st.get('mysql_count')}")
            elif ioc_st.get("error"):
                print(f"[ioc_mysql] skip sync: {ioc_st.get('error')}")
        except Exception as e:
            print("[ioc_mysql] startup:", e)
    else:
        print(f"[mysql] not used ({st.get('error') or 'unavailable'}), hosts use sqlite")
        try:
            from .auth import ensure_bootstrap_admin
            ensure_bootstrap_admin()
        except Exception as e:
            print("[auth] bootstrap:", e)
        try:
            from .settings import apply_runtime
            apply_runtime()
        except Exception as e:
            print("[settings] apply:", e)
        try:
            from .jobs import recover_jobs_on_startup
            recover_jobs_on_startup()
        except Exception as e:
            print("[jobs] recover:", e)
        try:
            from . import ip_catalog
            info = ip_catalog.reload_from_files(persist=True)
            print(
                f"[ip_catalog] domestic={info.get('domestic_cidrs')} "
                f"cloud={info.get('cloud_cidrs')} mysql={info.get('mysql')} sqlite={info.get('sqlite')}"
            )
        except Exception as e:
            print("[ip_catalog] load:", e)
        try:
            from . import ioc_es
            ioc_st = ioc_es.start_sync_async(only_if_empty=True)
            if ioc_st.get("started"):
                print("[ioc_es] background sync started (index empty)")
            elif ioc_st.get("skipped"):
                print(f"[ioc_es] index ready count={ioc_st.get('es_count')}")
        except Exception as e:
            print("[ioc_es] startup:", e)
    return st
