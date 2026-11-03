"""EDR 后台独立账号体系：用户、会话与分析平台完全隔离。

用户库：reports/edr_users.db（不复用分析平台 users.db）
会话：SQLite 只存 token 的 SHA256；浏览器拿 HttpOnly Cookie `edr_sid`
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

COOKIE_NAME = "edr_sid"
ROLES = ("admin", "analyst", "readonly")
ROLE_LABELS = {"admin": "管理员", "analyst": "分析员", "readonly": "只读"}

SESSION_TTL = int(os.environ.get("EDR_SESSION_TTL_HOURS") or "12") * 3600
SESSION_IDLE = int(os.environ.get("EDR_SESSION_IDLE_MINUTES") or "120") * 60
_PBKDF2_ROUNDS = 200_000
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

_lock = threading.Lock()
_touch_at: Dict[str, float] = {}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS edr_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT DEFAULT '',
    role TEXT NOT NULL DEFAULT 'analyst',
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    must_change INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_login_at REAL,
    last_login_ip TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS edr_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_edr_sessions_user ON edr_sessions(user_id);
"""


def db_path() -> Path:
    d = Path(getattr(config, "REPORTS_DIR", None) or (Path(config.ROOT) / "reports"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "edr_users.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


# ---------- 密码 ----------

def _hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return f"pbkdf2${_PBKDF2_ROUNDS}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds_s, salt, digest = str(stored or "").split("$", 3)
        if algo != "pbkdf2":
            return False
        rounds = int(rounds_s)
        if not 10_000 <= rounds <= 2_000_000:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), rounds)
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def _check_password_strength(password: str) -> None:
    pw = password or ""
    if len(pw) < 8:
        raise ValueError("密码至少 8 位")
    if len(pw) > 128:
        raise ValueError("密码过长")
    kinds = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if kinds < 2:
        raise ValueError("密码需包含字母、数字、符号中的至少两类")


def _validate_username(username: str) -> str:
    u = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-@]{2,64}", u):
        raise ValueError("用户名需 2-64 位，仅限字母、数字和 _ . - @")
    return u


def _validate_role(role: str) -> str:
    r = (role or "analyst").strip().lower()
    if r not in ROLES:
        raise ValueError("角色无效")
    return r


def _public(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"] or "",
        "role": row["role"],
        "role_label": ROLE_LABELS.get(row["role"], row["role"]),
        "enabled": bool(row["enabled"]),
        "must_change": bool(row["must_change"]),
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "last_login_ip": row["last_login_ip"] or "",
    }


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


# ---------- 用户 ----------

def list_users() -> List[Dict[str, Any]]:
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute("SELECT * FROM edr_users ORDER BY created_at").fetchall()
            return [_public(r) for r in rows]
        finally:
            conn.close()


def _count_admins(conn: sqlite3.Connection, exclude_id: str = "") -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM edr_users WHERE role='admin' AND enabled=1 AND id<>?", (exclude_id,)
    ).fetchone()
    return int(row[0] or 0)


def create_user(username: str, password: str, *, role: str = "analyst",
                display_name: str = "", must_change: bool = True) -> Dict[str, Any]:
    username = _validate_username(username)
    role = _validate_role(role)
    _check_password_strength(password)
    now = time.time()
    uid = uuid.uuid4().hex
    with _lock:
        conn = _connect()
        try:
            if conn.execute("SELECT 1 FROM edr_users WHERE username=?", (username,)).fetchone():
                raise ValueError("用户名已存在")
            conn.execute(
                """INSERT INTO edr_users(id, username, display_name, role, password_hash, enabled,
                   must_change, created_at, updated_at) VALUES(?,?,?,?,?,1,?,?,?)""",
                (uid, username, str(display_name or "")[:64], role, _hash_password(password),
                 1 if must_change else 0, now, now),
            )
            conn.commit()
            return _public(conn.execute("SELECT * FROM edr_users WHERE id=?", (uid,)).fetchone())
        finally:
            conn.close()


def update_user(user_id: str, *, role: Optional[str] = None, enabled: Optional[bool] = None,
                display_name: Optional[str] = None) -> Dict[str, Any]:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM edr_users WHERE id=?", (user_id,)).fetchone()
            if not row:
                raise ValueError("用户不存在")
            new_role = _validate_role(role) if role is not None else row["role"]
            new_enabled = bool(enabled) if enabled is not None else bool(row["enabled"])
            if row["role"] == "admin" and (new_role != "admin" or not new_enabled):
                if _count_admins(conn, exclude_id=user_id) == 0:
                    raise ValueError("至少保留一个启用的管理员")
            conn.execute(
                "UPDATE edr_users SET role=?, enabled=?, display_name=?, updated_at=? WHERE id=?",
                (new_role, 1 if new_enabled else 0,
                 str(display_name if display_name is not None else row["display_name"] or "")[:64],
                 time.time(), user_id),
            )
            if not new_enabled or new_role != row["role"]:
                conn.execute("DELETE FROM edr_sessions WHERE user_id=?", (user_id,))
            conn.commit()
            return _public(conn.execute("SELECT * FROM edr_users WHERE id=?", (user_id,)).fetchone())
        finally:
            conn.close()


def reset_password(user_id: str, new_password: str, *, must_change: bool = True) -> None:
    _check_password_strength(new_password)
    with _lock:
        conn = _connect()
        try:
            cur = conn.execute(
                "UPDATE edr_users SET password_hash=?, must_change=?, updated_at=? WHERE id=?",
                (_hash_password(new_password), 1 if must_change else 0, time.time(), user_id),
            )
            if not cur.rowcount:
                raise ValueError("用户不存在")
            conn.execute("DELETE FROM edr_sessions WHERE user_id=?", (user_id,))
            conn.commit()
        finally:
            conn.close()


def delete_user(user_id: str) -> None:
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM edr_users WHERE id=?", (user_id,)).fetchone()
            if not row:
                raise ValueError("用户不存在")
            if row["role"] == "admin" and _count_admins(conn, exclude_id=user_id) == 0:
                raise ValueError("至少保留一个启用的管理员")
            conn.execute("DELETE FROM edr_sessions WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM edr_users WHERE id=?", (user_id,))
            conn.commit()
        finally:
            conn.close()


def change_own_password(user_id: str, current: str, new_password: str, *, keep_token: str = "") -> None:
    _check_password_strength(new_password)
    if current == new_password:
        raise ValueError("新密码不能与当前密码相同")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM edr_users WHERE id=?", (user_id,)).fetchone()
            if not row or not _verify_password(current or "", row["password_hash"]):
                raise ValueError("当前密码不正确")
            conn.execute(
                "UPDATE edr_users SET password_hash=?, must_change=0, updated_at=? WHERE id=?",
                (_hash_password(new_password), time.time(), user_id),
            )
            # 其他会话全部下线，仅保留当前会话
            keep = _token_hash(keep_token) if _TOKEN_RE.fullmatch(keep_token or "") else ""
            conn.execute("DELETE FROM edr_sessions WHERE user_id=? AND token_hash<>?", (user_id, keep))
            conn.commit()
        finally:
            conn.close()


# ---------- 会话 ----------

def login(username: str, password: str, *, ip: str = "") -> Dict[str, Any]:
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("请输入用户名和密码")
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT * FROM edr_users WHERE username=?", (username,)).fetchone()
            # 用户不存在时也做一次哈希，避免按响应时间枚举用户名
            if not row:
                _verify_password(password, "pbkdf2$200000$" + "00" * 16 + "$" + "00" * 32)
                raise ValueError("用户名或密码错误")
            if not _verify_password(password, row["password_hash"]):
                raise ValueError("用户名或密码错误")
            if not row["enabled"]:
                raise ValueError("账号已禁用")
            token = secrets.token_hex(32)
            now = time.time()
            conn.execute(
                "INSERT INTO edr_sessions(token_hash, user_id, created_at, last_seen, ip) VALUES(?,?,?,?,?)",
                (_token_hash(token), row["id"], now, now, str(ip or "")[:64]),
            )
            conn.execute(
                "UPDATE edr_users SET last_login_at=?, last_login_ip=? WHERE id=?",
                (now, str(ip or "")[:64], row["id"]),
            )
            conn.execute("DELETE FROM edr_sessions WHERE created_at<?", (now - SESSION_TTL,))
            conn.commit()
            user = _public(conn.execute("SELECT * FROM edr_users WHERE id=?", (row["id"],)).fetchone())
            return {"token": token, "user": user}
        finally:
            conn.close()


def logout(token: str) -> None:
    if not _TOKEN_RE.fullmatch(token or ""):
        return
    with _lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM edr_sessions WHERE token_hash=?", (_token_hash(token),))
            conn.commit()
        finally:
            conn.close()


def me(token: str) -> Optional[Dict[str, Any]]:
    if not _TOKEN_RE.fullmatch(token or ""):
        return None
    th = _token_hash(token)
    now = time.time()
    with _lock:
        conn = _connect()
        try:
            s = conn.execute("SELECT * FROM edr_sessions WHERE token_hash=?", (th,)).fetchone()
            if not s:
                return None
            if now - s["created_at"] > SESSION_TTL or now - s["last_seen"] > SESSION_IDLE:
                conn.execute("DELETE FROM edr_sessions WHERE token_hash=?", (th,))
                conn.commit()
                return None
            u = conn.execute("SELECT * FROM edr_users WHERE id=?", (s["user_id"],)).fetchone()
            if not u or not u["enabled"]:
                conn.execute("DELETE FROM edr_sessions WHERE token_hash=?", (th,))
                conn.commit()
                return None
            # last_seen 每分钟最多写一次
            if now - _touch_at.get(th, 0) > 60:
                _touch_at[th] = now
                conn.execute("UPDATE edr_sessions SET last_seen=? WHERE token_hash=?", (now, th))
                conn.commit()
                if len(_touch_at) > 5000:
                    _touch_at.clear()
            return _public(u)
        finally:
            conn.close()


def token_from_request(cookie_header: str, authorization: str = "") -> str:
    from http.cookies import SimpleCookie
    jar = SimpleCookie()
    try:
        jar.load(str(cookie_header or ""))
    except Exception:
        jar = SimpleCookie()
    m = jar.get(COOKIE_NAME)
    tok = str(m.value).strip() if m else ""
    if _TOKEN_RE.fullmatch(tok):
        return tok
    auth = str(authorization or "").strip()
    if auth.lower().startswith("bearer "):
        auth = auth[7:].strip()
    return auth if _TOKEN_RE.fullmatch(auth) else ""


# ---------- 初始化 ----------

def ensure_bootstrap_admin() -> None:
    """首次启动没有任何 EDR 账号时创建 admin，密码只打印到控制台。"""
    with _lock:
        conn = _connect()
        try:
            n = int(conn.execute("SELECT COUNT(*) FROM edr_users").fetchone()[0] or 0)
        finally:
            conn.close()
    if n:
        return
    env_pwd = os.environ.get("EDR_BOOTSTRAP_ADMIN_PASSWORD") or ""
    pwd = env_pwd or (secrets.token_urlsafe(12) + "A1")
    create_user("admin", pwd, role="admin", display_name="EDR 管理员", must_change=True)
    if env_pwd:
        print("[edr-auth] bootstrap admin created from EDR_BOOTSTRAP_ADMIN_PASSWORD", file=sys.stderr)
    else:
        print("[edr-auth] ===== EDR 后台首次启动 · 管理员账号（首次登录须改密）=====", file=sys.stderr)
        print("[edr-auth] username: admin", file=sys.stderr)
        print(f"[edr-auth] password: {pwd}", file=sys.stderr)
        print("[edr-auth] ===========================================================", file=sys.stderr)


def reset_admin_cli() -> str:
    """命令行重置 admin 密码（忘记密码时用）。"""
    pwd = secrets.token_urlsafe(12) + "A1"
    with _lock:
        conn = _connect()
        try:
            row = conn.execute("SELECT id FROM edr_users WHERE username='admin'").fetchone()
        finally:
            conn.close()
    if row:
        reset_password(row["id"], pwd, must_change=True)
        update_user(row["id"], role="admin", enabled=True)
    else:
        create_user("admin", pwd, role="admin", display_name="EDR 管理员", must_change=True)
    return pwd
