"""用户管理：增删改查，优先 MySQL，失败回退 SQLite。"""
from __future__ import annotations
import hashlib
import hmac
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence

from . import config
from .cache_policy import capacity, ttl
from .db_store import _connect

USERS_DB = config.REPORTS_DIR / "users.db"

ROLES = ("admin", "analyst", "readonly")

# 角色说明：当前三类覆盖管理 / 研判 / 查阅；暂不拆「采集员」等，避免权限矩阵膨胀
ROLE_LABELS = {
    "admin": "管理员",
    "analyst": "分析员",
    "readonly": "来宾",
}
ROLE_HINTS = {
    "admin": "用户与设置、审计、控制中心、全部报告与主机台账",
    "analyst": "上传/分析、本人报告；可查看并维护主机台账；不可进控制中心",
    "readonly": "来宾：查看授权数据与主机台账（只读）；不可上传、分析、改台账或进控制中心",
}


_PBKDF2_ROUNDS = 180_000


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """返回 pbkdf2$rounds$salt$hex；旧登录仍接受 salt$sha256。"""
    if salt is None:
        salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _PBKDF2_ROUNDS,
    )
    return f"pbkdf2${_PBKDF2_ROUNDS}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        return False
    if stored.startswith("pbkdf2$"):
        try:
            _, rounds_s, salt, digest = stored.split("$", 3)
            rounds = int(rounds_s)
            if rounds < 10_000 or rounds > 2_000_000:
                return False
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt),
                rounds,
            )
            return hmac.compare_digest(dk.hex(), digest)
        except Exception:
            return False
    # 旧格式 salt$sha256
    salt, _ = stored.split("$", 1)
    old = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(f"{salt}${old}", stored)


def upgrade_password_hash(user_id: str, password: str) -> None:
    """登录成功后把旧 sha256 散列升级为 PBKDF2。"""
    uid = str(user_id or "").strip()
    if not uid or not password:
        return
    new_hash = _hash_password(password)
    now = time.time()
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
        if not row:
            return
        store.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (new_hash, now, uid),
        )
        store.commit()
        if store.mysql:
            _mirror_user_to_sqlite({
                "id": uid,
                "username": row["username"],
                "password_hash": new_hash,
                "display_name": row.get("display_name") or "",
                "role": row.get("role") or "analyst",
                "enabled": 1 if row.get("enabled", 1) else 0,
                "note": row.get("note") or "",
                "created_at": row.get("created_at") or now,
                "updated_at": now,
            })
    finally:
        store.close()
    invalidate_user_cache()


def _init_users_sqlite(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            display_name TEXT DEFAULT '',
            role TEXT DEFAULT 'analyst',
            enabled INTEGER DEFAULT 1,
            note TEXT DEFAULT '',
            org TEXT DEFAULT '',
            last_login_at REAL,
            last_login_ip TEXT DEFAULT '',
            created_at REAL,
            updated_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """
    )
    _ensure_user_columns_sqlite(conn)


def _ensure_user_columns_sqlite(conn) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    alters = []
    if "org" not in cols:
        alters.append("ALTER TABLE users ADD COLUMN org TEXT DEFAULT ''")
    if "last_login_at" not in cols:
        alters.append("ALTER TABLE users ADD COLUMN last_login_at REAL")
    if "last_login_ip" not in cols:
        alters.append("ALTER TABLE users ADD COLUMN last_login_ip TEXT DEFAULT ''")
    for sql in alters:
        try:
            conn.execute(sql)
        except Exception:
            pass
    if alters:
        try:
            conn.commit()
        except Exception:
            pass


USERS_MYSQL_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL DEFAULT '',
    display_name VARCHAR(128) DEFAULT '',
    role VARCHAR(32) DEFAULT 'analyst',
    enabled TINYINT DEFAULT 1,
    note VARCHAR(512) DEFAULT '',
    org VARCHAR(128) DEFAULT '',
    last_login_at DOUBLE NULL,
    last_login_ip VARCHAR(64) DEFAULT '',
    created_at DOUBLE,
    updated_at DOUBLE,
    UNIQUE KEY uk_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def _ensure_user_columns_mysql(cur) -> None:
    for col, ddl in (
        ("org", "ALTER TABLE users ADD COLUMN org VARCHAR(128) DEFAULT ''"),
        ("last_login_at", "ALTER TABLE users ADD COLUMN last_login_at DOUBLE NULL"),
        ("last_login_ip", "ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(64) DEFAULT ''"),
    ):
        try:
            cur.execute(ddl)
        except Exception:
            pass


def ensure_users_table(conn=None) -> None:
    """在已有 MySQL 连接上建表；或独立连接。"""
    from . import mysql_db
    own = conn is None
    if own:
        if not mysql_db.mysql_ready():
            return
        conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(USERS_MYSQL_SQL)
            try:
                cur.execute("ALTER TABLE users MODIFY password_hash VARCHAR(255) NOT NULL DEFAULT ''")
            except Exception:
                pass
            _ensure_user_columns_mysql(cur)
        conn.commit()
    finally:
        if own:
            conn.close()


class UserStore:
    def __init__(self):
        from . import mysql_db
        self.mysql = False
        self.cur = None
        if mysql_db.mysql_ready():
            try:
                # 建表只在启动 init_on_startup 做；这里仅补列，避免旧库缺 org/last_login
                self.conn = mysql_db.connect_mysql()
                self.cur = self.conn.cursor()
                try:
                    _ensure_user_columns_mysql(self.cur)
                    self.conn.commit()
                except Exception:
                    pass
                self.mysql = True
                return
            except Exception as e:
                try:
                    mysql_db.mark_mysql_down(str(e))
                except Exception:
                    pass
                print(f"[users] mysql unavailable → sqlite: {e}")
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = _connect(USERS_DB)
        _init_users_sqlite(self.conn)
        self.cur = None

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.mysql else sql

    def execute(self, sql: str, params: Sequence[Any] = ()):
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
        else:
            self.conn.execute(q, tuple(params))
        return self

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
            row = self.cur.fetchone()
            return dict(row) if row else None
        row = self.conn.execute(q, tuple(params)).fetchone()
        return {k: row[k] for k in row.keys()} if row else None

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
            return [dict(r) for r in (self.cur.fetchall() or [])]
        rows = self.conn.execute(q, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            if self.mysql and self.cur:
                self.cur.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


def _public(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row.get("display_name") or "",
        "role": row.get("role") or "analyst",
        "enabled": bool(row.get("enabled", 1)),
        "note": row.get("note") or "",
        "org": row.get("org") or "",
        "last_login_at": row.get("last_login_at"),
        "last_login_ip": row.get("last_login_ip") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "has_password": bool(row.get("password_hash")),
    }


def _validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise ValueError("用户名不能为空")
    if len(username) > 64:
        raise ValueError("用户名过长")
    if any(c in username for c in ' <>:"/\\|?*'):
        raise ValueError("用户名含非法字符")
    return username


def _validate_role(role: str) -> str:
    role = (role or "analyst").strip().lower()
    if role not in ROLES:
        raise ValueError(f"角色无效，可选: {', '.join(ROLES)}")
    return role


def list_users() -> List[Dict[str, Any]]:
    store = UserStore()
    try:
        rows = store.query_all("SELECT * FROM users ORDER BY username")
        out = [_public(r) for r in rows]
        out.sort(key=lambda x: (x["username"] or "").lower())
        return out
    finally:
        store.close()


_USER_CACHE: Dict[tuple, tuple] = {}
_USER_CACHE_LOCK = threading.Lock()
_USER_CACHE_TTL = ttl("user", 20.0, minimum=2.0, maximum=120.0)
_USER_CACHE_MAX = capacity("user", 2000)


def invalidate_user_cache() -> None:
    with _USER_CACHE_LOCK:
        _USER_CACHE.clear()
    try:
        from .auth import invalidate_auth_cache
        invalidate_auth_cache()
    except Exception:
        pass


def _user_cache_put(pub: Optional[Dict[str, Any]], *, uid: str = "", username: str = "") -> None:
    now = time.time()
    with _USER_CACHE_LOCK:
        if uid:
            _USER_CACHE[("id", uid)] = (now, dict(pub) if pub else None)
        if username:
            _USER_CACHE[("name", username)] = (now, dict(pub) if pub else None)
        if pub:
            pid = str(pub.get("id") or uid or "").strip()
            pname = str(pub.get("username") or username or "").strip()
            if pid:
                _USER_CACHE[("id", pid)] = (now, dict(pub))
            if pname:
                _USER_CACHE[("name", pname)] = (now, dict(pub))
        if len(_USER_CACHE) > _USER_CACHE_MAX:
            for key, _ in sorted(_USER_CACHE.items(), key=lambda x: x[1][0])[:max(1, _USER_CACHE_MAX // 4)]:
                _USER_CACHE.pop(key, None)


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    uid = str(user_id or "").strip()
    if not uid:
        return None
    with _USER_CACHE_LOCK:
        hit = _USER_CACHE.get(("id", uid))
        if hit and time.time() - float(hit[0]) < _USER_CACHE_TTL:
            return dict(hit[1]) if isinstance(hit[1], dict) else None
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
        pub = _public(row) if row else None
        _user_cache_put(pub, uid=uid, username=(pub or {}).get("username") or "")
        return pub
    finally:
        store.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    username = (username or "").strip()
    if not username:
        return None
    with _USER_CACHE_LOCK:
        hit = _USER_CACHE.get(("name", username))
        if hit and time.time() - float(hit[0]) < _USER_CACHE_TTL:
            return dict(hit[1]) if isinstance(hit[1], dict) else None
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE username=?", (username,))
        pub = _public(row) if row else None
        _user_cache_put(pub, uid=(pub or {}).get("id") or "", username=username)
        return pub
    finally:
        store.close()


def verify_user_password(user_id: str, password: str) -> None:
    """校验指定用户当前密码；失败抛 ValueError。"""
    uid = str(user_id or "").strip()
    if not uid:
        raise ValueError("未登录")
    if not str(password or ""):
        raise ValueError("请输入管理员密码")
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
        if not row:
            raise ValueError("当前登录用户无效")
        if not row.get("enabled", 1):
            raise ValueError("账号已禁用")
        if not _verify_password(str(password), row.get("password_hash") or ""):
            raise ValueError("管理员密码不正确")
    finally:
        store.close()


def create_user(
    username: str,
    password: str = "",
    display_name: str = "",
    role: str = "analyst",
    note: str = "",
    enabled: bool = True,
    org: str = "",
) -> Dict[str, Any]:
    username = _validate_username(username)
    role = _validate_role(role)
    if get_user_by_username(username):
        raise ValueError(f"用户已存在: {username}")
    uid = uuid.uuid4().hex[:12]
    now = time.time()
    if password and len(password) < 8:
        raise ValueError("密码至少 8 位")
    pwd_hash = _hash_password(password) if password else ""
    row = {
        "id": uid,
        "username": username,
        "password_hash": pwd_hash,
        "display_name": (display_name or "").strip(),
        "role": role,
        "enabled": 1 if enabled else 0,
        "note": (note or "").strip(),
        "org": (org or "").strip()[:128],
        "last_login_at": None,
        "last_login_ip": "",
        "created_at": now,
        "updated_at": now,
    }
    store = UserStore()
    try:
        store.execute(
            """
            INSERT INTO users(id,username,password_hash,display_name,role,enabled,note,org,last_login_at,last_login_ip,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                row["id"], row["username"], row["password_hash"], row["display_name"],
                row["role"], row["enabled"], row["note"], row.get("org") or "",
                row.get("last_login_at"), row.get("last_login_ip") or "",
                row["created_at"], row["updated_at"],
            ),
        )
        store.commit()
        if store.mysql:
            _mirror_user_to_sqlite(row)
    finally:
        store.close()
    invalidate_user_cache()
    return get_user(uid) or {"id": uid, "username": username}


def reset_user_password(
    user_id: str,
    new_password: str,
    operator_password: str,
    operator_id: str,
) -> Dict[str, Any]:
    """用当前登录者密码核验后，重置目标用户密码。"""
    new_password = (new_password or "").strip()
    operator_password = operator_password or ""
    if not new_password:
        raise ValueError("请填写新密码")
    if len(new_password) < 8:
        raise ValueError("新密码至少 8 位")
    if not operator_id:
        raise ValueError("未登录")
    store = UserStore()
    try:
        op = store.query_one("SELECT * FROM users WHERE id=?", (operator_id,))
        if not op:
            raise ValueError("当前登录用户无效")
        if not _verify_password(operator_password, op.get("password_hash") or ""):
            raise ValueError("当前密码不正确")
        row = store.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise ValueError("用户不存在")
        new_hash = _hash_password(new_password)
        now = time.time()
        store.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (new_hash, now, user_id),
        )
        store.commit()
        if store.mysql:
            _mirror_user_to_sqlite({
                "id": user_id,
                "username": row["username"],
                "password_hash": new_hash,
                "display_name": row.get("display_name") or "",
                "role": row.get("role") or "analyst",
                "enabled": 1 if row.get("enabled", 1) else 0,
                "note": row.get("note") or "",
                "created_at": row.get("created_at") or now,
                "updated_at": now,
            })
    finally:
        store.close()
    invalidate_user_cache()
    out = get_user(user_id)
    if not out:
        raise ValueError("重置失败")
    return out


def update_user(
    user_id: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    display_name: Optional[str] = None,
    role: Optional[str] = None,
    note: Optional[str] = None,
    enabled: Optional[bool] = None,
    org: Optional[str] = None,
) -> Dict[str, Any]:
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE id=?", (user_id,))
        if not row:
            raise ValueError("用户不存在")
        new_username = row["username"]
        if username is not None:
            new_username = _validate_username(username)
            other = store.query_one("SELECT id FROM users WHERE username=?", (new_username,))
            if other and other["id"] != user_id:
                raise ValueError(f"用户名已被占用: {new_username}")
        new_role = row.get("role") or "analyst"
        if role is not None:
            new_role = _validate_role(role)
        new_display = row.get("display_name") or ""
        if display_name is not None:
            new_display = (display_name or "").strip()
        new_note = row.get("note") or ""
        if note is not None:
            new_note = (note or "").strip()
        new_org = row.get("org") or ""
        if org is not None:
            new_org = (org or "").strip()[:128]
        new_enabled = 1 if row.get("enabled", 1) else 0
        if enabled is not None:
            new_enabled = 1 if enabled else 0
        new_hash = row.get("password_hash") or ""
        if password is not None and str(password).strip() != "":
            new_hash = _hash_password(str(password))

        store.execute(
            """
            UPDATE users SET username=?, password_hash=?, display_name=?, role=?,
                             enabled=?, note=?, org=?, updated_at=? WHERE id=?
            """,
            (new_username, new_hash, new_display, new_role, new_enabled, new_note, new_org, time.time(), user_id),
        )
        store.commit()
        if store.mysql:
            _mirror_user_to_sqlite({
                "id": user_id,
                "username": new_username,
                "password_hash": new_hash,
                "display_name": new_display,
                "role": new_role,
                "enabled": new_enabled,
                "note": new_note,
                "org": new_org,
                "last_login_at": row.get("last_login_at"),
                "last_login_ip": row.get("last_login_ip") or "",
                "created_at": row.get("created_at") or time.time(),
                "updated_at": time.time(),
            })
    finally:
        store.close()
    invalidate_user_cache()
    out = get_user(user_id)
    if not out:
        raise ValueError("更新失败")
    return out


def touch_login(user_id: str, ip: str = "") -> None:
    """记录最近登录时间与 IP。"""
    uid = str(user_id or "").strip()
    if not uid:
        return
    now = time.time()
    lip = str(ip or "").strip()[:64]
    store = UserStore()
    try:
        store.execute(
            "UPDATE users SET last_login_at=?, last_login_ip=?, updated_at=? WHERE id=?",
            (now, lip, now, uid),
        )
        store.commit()
        if store.mysql:
            row = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
            if row:
                _mirror_user_to_sqlite(dict(row))
    except Exception as e:
        print("[users] touch_login:", e)
    finally:
        store.close()
    invalidate_user_cache()


def change_own_password(user_id: str, current_password: str, new_password: str) -> Dict[str, Any]:
    """用户本人修改密码（需校验当前密码）。"""
    uid = str(user_id or "").strip()
    if not uid:
        raise ValueError("未登录")
    new_password = (new_password or "").strip()
    if len(new_password) < 8:
        raise ValueError("新密码至少 8 位")
    store = UserStore()
    try:
        row = store.query_one("SELECT * FROM users WHERE id=?", (uid,))
        if not row:
            raise ValueError("用户不存在")
        if not row.get("enabled", 1):
            raise ValueError("账号已禁用")
        if not _verify_password(str(current_password or ""), row.get("password_hash") or ""):
            raise ValueError("当前密码不正确")
        new_hash = _hash_password(new_password)
        now = time.time()
        store.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (new_hash, now, uid),
        )
        store.commit()
        if store.mysql:
            mirrored = dict(row)
            mirrored["password_hash"] = new_hash
            mirrored["updated_at"] = now
            _mirror_user_to_sqlite(mirrored)
    finally:
        store.close()
    invalidate_user_cache()
    try:
        from .auth import revoke_user_sessions
        revoke_user_sessions(user_id=uid)
    except Exception:
        pass
    return {"ok": True, "id": uid}


def delete_user(user_id: str) -> Dict[str, Any]:
    user = get_user(user_id)
    if not user:
        raise ValueError("用户不存在")
    if str(user.get("role") or "").lower() == "admin":
        others = [u for u in list_users() if str(u.get("role") or "").lower() == "admin" and u.get("id") != user_id and u.get("enabled")]
        if not others:
            raise ValueError("不能删除最后一个管理员")
    store = UserStore()
    try:
        store.execute("DELETE FROM users WHERE id=?", (user_id,))
        store.commit()
        if store.mysql:
            try:
                config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                conn = _connect(USERS_DB)
                try:
                    _init_users_sqlite(conn)
                    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
                    # 同时清同名残留（历史双库漂移）
                    conn.execute("DELETE FROM users WHERE username=?", (user["username"],))
                    conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                print("[users] mirror delete sqlite:", e)
    finally:
        store.close()
    invalidate_user_cache()
    return {"deleted": True, "id": user_id, "username": user["username"]}


def _mirror_user_to_sqlite(row: Dict[str, Any]) -> None:
    """MySQL 写入后镜像到本地，保证 MySQL 宕机仍可登录。

    注意：历史数据可能存在「同用户名、不同 id」的漂移（bootstrap 分别写过
    SQLite / MySQL）。必须先清掉冲突用户名，否则 UNIQUE(username) 会导致
    镜像失败，改密只落在 MySQL，回退登录仍用旧默认密码。
    """
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect(USERS_DB)
        try:
            _init_users_sqlite(conn)
            uid = row.get("id")
            uname = (row.get("username") or "").strip()
            if uname and uid:
                conn.execute(
                    "DELETE FROM users WHERE username=? AND id!=?",
                    (uname, uid),
                )
            _ensure_user_columns_sqlite(conn)
            conn.execute(
                """
                INSERT INTO users(id,username,password_hash,display_name,role,enabled,note,org,last_login_at,last_login_ip,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  username=excluded.username, password_hash=excluded.password_hash,
                  display_name=excluded.display_name, role=excluded.role,
                  enabled=excluded.enabled, note=excluded.note, org=excluded.org,
                  last_login_at=excluded.last_login_at, last_login_ip=excluded.last_login_ip,
                  updated_at=excluded.updated_at
                """,
                (
                    uid, uname, row.get("password_hash") or "",
                    row.get("display_name") or "", row.get("role") or "analyst",
                    1 if row.get("enabled", 1) else 0, row.get("note") or "",
                    row.get("org") or "",
                    row.get("last_login_at"), row.get("last_login_ip") or "",
                    row.get("created_at") or time.time(), row.get("updated_at") or time.time(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print("[users] mirror sqlite:", e)


def sync_users_mysql_to_sqlite() -> int:
    """用 MySQL 用户表全量覆盖本地 users.db，消除双库漂移。"""
    from . import mysql_db
    if not mysql_db.mysql_ready():
        return 0
    store = UserStore()
    try:
        if not store.mysql:
            return 0
        rows = store.query_all("SELECT * FROM users")
    finally:
        store.close()
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect(USERS_DB)
        try:
            _init_users_sqlite(conn)
            conn.execute("DELETE FROM users")
            for r in rows:
                conn.execute(
                    """
                    INSERT INTO users(id,username,password_hash,display_name,role,enabled,note,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        r["id"], r["username"], r.get("password_hash") or "",
                        r.get("display_name") or "", r.get("role") or "analyst",
                        1 if r.get("enabled", 1) else 0, r.get("note") or "",
                        r.get("created_at") or time.time(),
                        r.get("updated_at") or time.time(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        if rows:
            print(f"[users] synced {len(rows)} users mysql → sqlite")
        return len(rows)
    except Exception as e:
        print("[users] sync mysql→sqlite:", e)
        return 0


def migrate_users_sqlite_to_mysql() -> int:
    """MySQL users 为空时，从本地 users.db 迁入。"""
    from . import mysql_db
    if not mysql_db.mysql_ready() or not USERS_DB.exists():
        return 0
    store = UserStore()
    try:
        if store.query_all("SELECT id FROM users LIMIT 1"):
            return 0
    finally:
        store.close()
    src = _connect(USERS_DB)
    try:
        _init_users_sqlite(src)
        rows = src.execute("SELECT * FROM users").fetchall()
        if not rows:
            return 0
        dst = UserStore()
        n = 0
        try:
            for r in rows:
                try:
                    dst.execute(
                        """
                        INSERT INTO users(id,username,password_hash,display_name,role,enabled,note,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            r["id"], r["username"], r["password_hash"] or "",
                            r["display_name"] or "", r["role"] or "analyst",
                            1 if r["enabled"] else 0, r["note"] or "",
                            r["created_at"], r["updated_at"],
                        ),
                    )
                    n += 1
                except Exception as e:
                    print("[users] migrate row:", e)
            dst.commit()
        finally:
            dst.close()
        if n:
            print(f"[users] migrated {n} users sqlite → mysql")
        return n
    finally:
        src.close()


def backend_info() -> Dict[str, Any]:
    from . import mysql_db
    return {
        "users_backend": "mysql" if mysql_db.mysql_ready() else "sqlite",
        "sqlite_path": str(USERS_DB),
        "roles": list(ROLES),
    }
