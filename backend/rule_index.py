"""规则文件索引：磁盘是工作副本，数据库存清单 + 正文快照 + 删除墓碑。

匹配仍读本地 JSON；库用于：
- 多进程/多实例同步启用/禁用/已删除
- 删了就不再跑（墓碑优先于磁盘残留）
- 正文快照便于核对和恢复
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_SQLITE = None
# 整个模块共用一条 check_same_thread=False 的连接，24 个 worker 会并发打它。
# 无锁时两个隐患：懒初始化可能被并发执行两遍（建表 + 迁移竞态），以及
# execute/commit 在线程间交错——A 的 commit 会把 B 尚未写完的语句一起提交。
_SQLITE_LOCK = threading.RLock()
_BODY_LIMIT = 2 * 1024 * 1024
_GEN_FILE = ".rules_gen"


def _sqlite_path() -> Path:
    # 运行时索引放到 config/，避免污染仓库根目录
    cfg = Path(getattr(config, "CONFIG_DIR", None) or (Path(getattr(config, "ROOT", Path("."))) / "config"))
    cfg.mkdir(parents=True, exist_ok=True)
    new_p = cfg / "rule_index.db"
    # 兼容：若根目录仍有旧库且新位置没有，迁过去
    root = Path(getattr(config, "DATA_ROOT", None) or config.ROOT)
    old_p = root / "rule_index.db"
    if old_p.is_file() and not new_p.is_file():
        try:
            import shutil
            shutil.move(str(old_p), str(new_p))
        except Exception as e:
            print(f"[rule_index] migrate db failed: {e}")
            return old_p
    elif old_p.is_file() and new_p.is_file():
        try:
            old_p.unlink()
        except Exception:
            pass
    return new_p


def _sqlite():
    global _SQLITE
    with _SQLITE_LOCK:
        if _SQLITE is None:
            p = _sqlite_path()
            conn = sqlite3.connect(str(p), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute(
                """CREATE TABLE IF NOT EXISTS rule_files (
                    file TEXT PRIMARY KEY,
                    name TEXT,
                    status TEXT,
                    description TEXT,
                    path TEXT,
                    size INTEGER,
                    mtime TEXT,
                    sha1 TEXT,
                    loaded INTEGER,
                    enabled INTEGER,
                    updated_at TEXT,
                    body TEXT,
                    deleted INTEGER DEFAULT 0,
                    deleted_at TEXT DEFAULT ''
                )"""
            )
            conn.commit()
            _migrate_sqlite(conn)
            _SQLITE = conn
        return _SQLITE


def _migrate_sqlite(conn) -> None:
    cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(rule_files)").fetchall()}
    for col, spec in (
        ("body", "TEXT"),
        ("deleted", "INTEGER DEFAULT 0"),
        ("deleted_at", "TEXT DEFAULT ''"),
    ):
        if col not in cols:
            try:
                conn.execute(f"ALTER TABLE rule_files ADD COLUMN {col} {spec}")
            except Exception:
                pass
    conn.commit()


def _mysql_ready() -> bool:
    try:
        from .mysql_db import mysql_ready
        return bool(mysql_ready())
    except Exception:
        return False


def ensure_mysql_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_files (
                file VARCHAR(191) NOT NULL PRIMARY KEY,
                name VARCHAR(255) DEFAULT '',
                status VARCHAR(32) DEFAULT '',
                description TEXT,
                path VARCHAR(512) DEFAULT '',
                size BIGINT DEFAULT 0,
                mtime VARCHAR(32) DEFAULT '',
                sha1 VARCHAR(40) DEFAULT '',
                loaded TINYINT DEFAULT 0,
                enabled TINYINT DEFAULT 1,
                updated_at VARCHAR(32) DEFAULT '',
                body MEDIUMTEXT,
                deleted TINYINT DEFAULT 0,
                deleted_at VARCHAR(32) DEFAULT ''
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        )
        for col, spec in (
            ("body", "MEDIUMTEXT"),
            ("deleted", "TINYINT DEFAULT 0"),
            ("deleted_at", "VARCHAR(32) DEFAULT ''"),
        ):
            try:
                cur.execute(f"ALTER TABLE rule_files ADD COLUMN {col} {spec}")
            except Exception:
                pass
    conn.commit()


def _file_sha1(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            left = limit
            while left > 0:
                chunk = f.read(min(65536, left))
                if not chunk:
                    break
                h.update(chunk)
                left -= len(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def scan_disk() -> List[Dict[str, Any]]:
    """只列出磁盘上真实存在的 rules-*.json（含 rules/linux/）。"""
    roots = []
    rd = Path(config.RULES_DIR)
    if rd not in roots:
        roots.append(rd)
    if config.ROOT not in roots:
        roots.append(Path(config.ROOT))
    found: Dict[str, Path] = {}
    for base in roots:
        try:
            if not base.is_dir():
                continue
            for p in base.glob("rules-*.json"):
                if p.name not in found:
                    found[p.name] = p
            linux_dir = base / "linux"
            if linux_dir.is_dir():
                for p in linux_dir.glob("rules-*.json"):
                    # 子目录包用 basename 作为 inventory 主键（与 RuleStore._load 一致）
                    if p.name not in found:
                        found[p.name] = p
        except Exception:
            continue

    disabled = set()
    for base in roots:
        p = base / ".disabled.json"
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            files = data.get("files") if isinstance(data, dict) else data
            for x in files or []:
                n = str(x or "").strip()
                if n.startswith("rules-") and n.endswith(".json"):
                    disabled.add(n)
        except Exception:
            pass

    rows = []
    for fname, path in sorted(found.items()):
        meta: Dict[str, Any] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("meta"), dict):
                meta = data["meta"]
        except Exception:
            data = {}
        st = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
        try:
            from .rules_loader import PIPELINE_STATUS
            status = PIPELINE_STATUS.get(fname) or "active"
        except Exception:
            status = "active"
        if fname in disabled:
            status = "disabled"
        rows.append({
            "file": fname,
            "name": meta.get("name") or fname,
            "status": status,
            "description": meta.get("description") or "",
            "path": str(path),
            "dir": str(path.parent),
            "size": path.stat().st_size,
            "mtime": st,
            "sha1": _file_sha1(path),
            "loaded": bool(data),
            "enabled": fname not in disabled,
            "exists": True,
            "os_family": str(meta.get("os_family") or ("linux" if "linux" in fname else "")),
        })
    return rows


def _gen_path() -> Path:
    root = Path(getattr(config, "RULES_DIR", None) or config.ROOT)
    try:
        root.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return root / _GEN_FILE


def current_gen() -> int:
    try:
        from .redis_client import get_client, prefix
        r = get_client()
        if r:
            raw = r.get(prefix() + "rules_gen")
            if raw is not None:
                return int(raw)
    except Exception:
        pass
    p = _gen_path()
    try:
        if p.is_file():
            return int((p.read_text(encoding="utf-8") or "0").strip() or 0)
    except Exception:
        pass
    return 0


def bump_gen() -> int:
    n = 0
    try:
        from .redis_client import get_client, prefix
        r = get_client()
        if r:
            n = int(r.incr(prefix() + "rules_gen"))
    except Exception:
        n = 0
    if not n:
        n = current_gen() + 1
    try:
        _gen_path().write_text(str(n), encoding="utf-8")
    except Exception:
        pass
    return n


def _read_body(path: Path) -> str:
    try:
        if not path.is_file() or path.stat().st_size > _BODY_LIMIT:
            return ""
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _upsert_row(r: Dict[str, Any], now: str, body: str, deleted: int = 0, deleted_at: str = "") -> None:
    args = (
        r["file"], r.get("name") or "", r.get("status") or "",
        r.get("description") or "", r.get("path") or "",
        int(r.get("size") or 0), r.get("mtime") or "",
        r.get("sha1") or "", 1 if r.get("loaded") else 0,
        1 if r.get("enabled", True) else 0, now, body or "",
        int(deleted), deleted_at or "",
    )
    if _mysql_ready():
        try:
            from .mysql_db import connect_mysql
            conn = connect_mysql()
            try:
                ensure_mysql_table(conn)
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO rule_files(file,name,status,description,path,size,mtime,sha1,loaded,enabled,updated_at,body,deleted,deleted_at)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON DUPLICATE KEY UPDATE
                          name=VALUES(name), status=VALUES(status), description=VALUES(description),
                          path=VALUES(path), size=VALUES(size), mtime=VALUES(mtime), sha1=VALUES(sha1),
                          loaded=VALUES(loaded), enabled=VALUES(enabled), updated_at=VALUES(updated_at),
                          body=VALUES(body), deleted=VALUES(deleted), deleted_at=VALUES(deleted_at)
                        """,
                        args,
                    )
                conn.commit()
                return
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as e:
            print(f"[rule_index] mysql upsert: {e}")
    db = _sqlite()
    with _SQLITE_LOCK:
        db.execute(
            """INSERT INTO rule_files(file,name,status,description,path,size,mtime,sha1,loaded,enabled,updated_at,body,deleted,deleted_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(file) DO UPDATE SET
                 name=excluded.name, status=excluded.status, description=excluded.description,
                 path=excluded.path, size=excluded.size, mtime=excluded.mtime, sha1=excluded.sha1,
                 loaded=excluded.loaded, enabled=excluded.enabled, updated_at=excluded.updated_at,
                 body=excluded.body, deleted=excluded.deleted, deleted_at=excluded.deleted_at
            """,
            args,
        )
        db.commit()


def tombstone_file(fname: str, reason: str = "deleted") -> None:
    """标记规则已删除：即使磁盘残留/内存未刷新也不再匹配。"""
    n = str(fname or "").strip()
    if not (n.startswith("rules-") and n.endswith(".json")):
        return
    if n in set(list_tombstones()):
        return
    now = datetime.now().isoformat(timespec="seconds")
    row = {
        "file": n, "name": n, "status": "deleted", "description": reason,
        "path": "", "size": 0, "mtime": "", "sha1": "", "loaded": False, "enabled": False,
    }
    _upsert_row(row, now, "", deleted=1, deleted_at=now)
    bump_gen()


def list_tombstones() -> List[str]:
    names: List[str] = []
    if _mysql_ready():
        try:
            from .mysql_db import connect_mysql
            conn = connect_mysql()
            try:
                ensure_mysql_table(conn)
                with conn.cursor() as cur:
                    cur.execute("SELECT file FROM rule_files WHERE deleted=1")
                    names = []
                    for r in (cur.fetchall() or []):
                        if isinstance(r, dict):
                            names.append(str(r.get("file") or ""))
                        else:
                            names.append(str((r[0] if r else "") or ""))
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            return [x for x in names if x]
        except Exception as e:
            print(f"[rule_index] mysql tombstones: {e}")
    try:
        with _SQLITE_LOCK:
            rows = _sqlite().execute("SELECT file FROM rule_files WHERE deleted=1").fetchall()
        return [str(r["file"] if isinstance(r, sqlite3.Row) else r[0]) for r in rows]
    except Exception:
        return []


def is_tombstoned(fname: str) -> bool:
    n = str(fname or "").strip()
    if not n:
        return False
    return n in set(list_tombstones())


def clear_tombstone(fname: str) -> None:
    """管理员重新启用/恢复文件时去掉墓碑。"""
    n = str(fname or "").strip()
    if not n:
        return
    now = datetime.now().isoformat(timespec="seconds")
    row = {
        "file": n, "name": n, "status": "active", "description": "",
        "path": "", "size": 0, "mtime": "", "sha1": "", "loaded": False, "enabled": True,
    }
    _upsert_row(row, now, "", deleted=0, deleted_at="")
    bump_gen()


def sync_index(rows: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """同步磁盘规则到库：在盘的写快照；不在盘的保留墓碑，不再 DELETE 掉。"""
    rows = rows if rows is not None else scan_disk()
    now = datetime.now().isoformat(timespec="seconds")
    dead = set(list_tombstones())
    out = []
    for r in rows:
        fname = r.get("file") or ""
        if fname in dead:
            # 墓碑优先：磁盘残留也不复活，避免删了还在跑
            r["enabled"] = False
            r["loaded"] = False
            r["status"] = "deleted"
            r["deleted"] = True
            out.append(r)
            continue
        body = _read_body(Path(r.get("path") or ""))
        _upsert_row(r, now, body, deleted=0, deleted_at="")
        out.append(r)
    return out


def list_indexed() -> List[Dict[str, Any]]:
    """优先返回刚扫的磁盘清单（并写库）。"""
    return sync_index()
