"""账号注册申请：仅建申请单，人工审核通过后才 create_user。

安全要点：
- 所有写库字段经消毒（去控制字符 / HTML / 空字节）
- SQL 一律参数化绑定
- 注册路径禁止开 admin
- 申请 ID 限制为十六进制，防路径/注入式越权
"""
from __future__ import annotations

import re
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

from . import config
from .users import ROLES, _hash_password, create_user, get_user_by_username

REG_DB = config.REPORTS_DIR / "registration.db"

_STATUSES = ("pending", "approved", "rejected")
# 允许 Unicode 字母数字、._- ；长度 2-32
_USERNAME_RE = re.compile(r"^[\w.\-]{2,32}$", re.UNICODE)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}$")
_RID_RE = re.compile(r"^[a-fA-F0-9]{16,64}$")
_HTML_TAG_RE = re.compile(r"<[^>]*>")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# 明显脚本/事件注入痕迹（消毒后仍保留可读文本）
_SCRIPT_RE = re.compile(
    r"(?is)(?:javascript\s*:|vbscript\s*:|data\s*:text/html|<\s*script|on\w+\s*=|expression\s*\()"
)
# 注册审核允许的角色（禁止 admin）
_REG_ROLES = frozenset({"analyst", "readonly"})


def _connect() -> sqlite3.Connection:
    REG_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(REG_DB), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registration_requests (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            org TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            email TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            review_note TEXT DEFAULT '',
            reviewer TEXT DEFAULT '',
            created_at REAL,
            updated_at REAL,
            reviewed_at REAL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reg_status ON registration_requests(status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reg_user ON registration_requests(username)"
    )
    conn.commit()
    return conn


def _strip_ctrl(s: str) -> str:
    return _CTRL_RE.sub("", s or "")


def _sanitize_text(value: Any, max_len: int, *, field: str = "字段") -> str:
    """去控制字符 / HTML 标签 / 脚本痕迹，截断长度。不做反引号执行，也不拼进 shell。"""
    s = _strip_ctrl(str(value if value is not None else ""))
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # 去掉 HTML 标签，保留纯文本
    s = _HTML_TAG_RE.sub("", s)
    s = s.replace("<", "").replace(">", "")
    if _SCRIPT_RE.search(s):
        raise ValueError(f"{field}含有不允许的脚本内容")
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _sanitize_username(username: Any) -> str:
    s = _strip_ctrl(str(username or "")).strip()
    if not s:
        raise ValueError("用户名不能为空")
    if len(s) < 2 or len(s) > 32:
        raise ValueError("用户名长度需 2-32")
    if any(c in s for c in ' \t\r\n/@<>:"\\|?*`$();|&{}[]'):
        raise ValueError("用户名含非法字符")
    if not _USERNAME_RE.match(s):
        raise ValueError("用户名仅允许字母数字、下划线、点、连字符")
    if s.lower() in ("admin", "root", "administrator", "system", "null", "undefined"):
        raise ValueError("该用户名不可用")
    return s


def _sanitize_email(email: Any) -> str:
    s = _sanitize_text(email, 120, field="邮箱")
    if not s:
        return ""
    if len(s) > 120 or not _EMAIL_RE.match(s):
        raise ValueError("邮箱格式不正确")
    return s.lower()


def _validate_password(password: Any) -> str:
    if password is None:
        raise ValueError("请填写密码")
    if not isinstance(password, str):
        raise ValueError("密码格式无效")
    if "\x00" in password:
        raise ValueError("密码含非法字符")
    if len(password) < 8:
        raise ValueError("密码至少 8 位")
    if len(password) > 128:
        raise ValueError("密码过长")
    # 拒绝全空白
    if not password.strip():
        raise ValueError("密码不能为空白")
    return password


def _validate_rid(rid: Any) -> str:
    s = _strip_ctrl(str(rid or "")).strip()
    if not _RID_RE.match(s):
        raise ValueError("无效的申请编号")
    return s


def _safe_reg_role(role: Any) -> str:
    r = _strip_ctrl(str(role or "analyst")).strip().lower()
    if r == "admin" or r not in _REG_ROLES:
        return "analyst"
    return r


def _row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d.pop("password_hash", None)
    # 出库再消毒一遍，防历史脏数据 XSS
    for k in ("username", "display_name", "org", "reason", "email", "review_note", "reviewer", "status"):
        if k in d and d[k] is not None:
            try:
                d[k] = _sanitize_text(d[k], 500 if k == "reason" else 120, field=k)
            except ValueError:
                d[k] = _HTML_TAG_RE.sub("", _strip_ctrl(str(d[k])))[:120]
    return d


def submit_registration(
    username: str,
    password: str,
    display_name: str = "",
    org: str = "",
    reason: str = "",
    email: str = "",
) -> Dict[str, Any]:
    username = _sanitize_username(username)
    password = _validate_password(password)
    display_name = _sanitize_text(display_name, 80, field="显示名")
    org = _sanitize_text(org, 120, field="单位")
    reason = _sanitize_text(reason, 500, field="申请事由")
    email = _sanitize_email(email)

    if get_user_by_username(username):
        raise ValueError("用户名已存在")
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, status FROM registration_requests WHERE username=? AND status='pending'",
            (username,),
        ).fetchone()
        if row:
            raise ValueError("该用户名已有待审申请")
        now = time.time()
        rid = uuid.uuid4().hex
        ph = _hash_password(password)
        conn.execute(
            """INSERT INTO registration_requests
               (id, username, display_name, org, reason, email, password_hash, status, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,'pending',?,?)""",
            (rid, username, display_name, org, reason, email, ph, now, now),
        )
        conn.commit()
        return {
            "id": rid,
            "username": username,
            "status": "pending",
            "hint": "已提交，等待管理员审核通过后方可登录。",
        }
    finally:
        conn.close()


def list_registrations(status: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        limit = max(1, min(200, int(limit or 100)))
        st = _strip_ctrl(str(status or "")).strip().lower()
        if st in _STATUSES:
            rows = conn.execute(
                "SELECT id, username, display_name, org, reason, email, status, review_note, reviewer, "
                "created_at, updated_at, reviewed_at FROM registration_requests "
                "WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (st, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, display_name, org, reason, email, status, review_note, reviewer, "
                "created_at, updated_at, reviewed_at FROM registration_requests "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row(r) for r in rows]
    finally:
        conn.close()


def count_pending() -> int:
    conn = _connect()
    try:
        r = conn.execute(
            "SELECT COUNT(*) AS c FROM registration_requests WHERE status='pending'"
        ).fetchone()
        return int(r["c"] if r else 0)
    finally:
        conn.close()


def get_registration(rid: str) -> Optional[Dict[str, Any]]:
    rid = _validate_rid(rid)
    conn = _connect()
    try:
        r = conn.execute(
            "SELECT * FROM registration_requests WHERE id=?", (rid,)
        ).fetchone()
        if not r:
            return None
        return _row(r)
    finally:
        conn.close()


def approve_registration(
    rid: str,
    reviewer: str = "",
    role: str = "analyst",
    note: str = "",
) -> Dict[str, Any]:
    rid = _validate_rid(rid)
    role = _safe_reg_role(role)
    reviewer = _sanitize_text(reviewer, 64, field="审核人")
    note = _sanitize_text(note, 300, field="审核备注")
    conn = _connect()
    try:
        r = conn.execute(
            "SELECT * FROM registration_requests WHERE id=?", (rid,)
        ).fetchone()
        if not r:
            raise ValueError("申请不存在")
        if r["status"] != "pending":
            raise ValueError("申请已处理")
        username = _sanitize_username(r["username"])
        if get_user_by_username(username):
            raise ValueError("用户名已被占用，请驳回")
        display_name = _sanitize_text(r["display_name"] or username, 80, field="显示名")
        reason_note = _sanitize_text(r["reason"] or "", 200, field="事由")
        user = _create_user_with_hash(
            username=username,
            password_hash=str(r["password_hash"] or ""),
            display_name=display_name,
            role=role,
            note=_sanitize_text(f"注册审核通过 · {note or reason_note}", 200, field="备注"),
        )
        now = time.time()
        conn.execute(
            """UPDATE registration_requests
               SET status='approved', reviewer=?, review_note=?, reviewed_at=?, updated_at=?,
                   password_hash=''
               WHERE id=? AND status='pending'""",
            (reviewer, note, now, now, rid),
        )
        if conn.total_changes < 1:
            raise ValueError("申请状态已变更，请刷新")
        conn.commit()
        return {"ok": True, "user": user, "request_id": rid}
    finally:
        conn.close()


def reject_registration(rid: str, reviewer: str = "", note: str = "") -> Dict[str, Any]:
    rid = _validate_rid(rid)
    reviewer = _sanitize_text(reviewer, 64, field="审核人")
    note = _sanitize_text(note, 300, field="驳回原因")
    conn = _connect()
    try:
        r = conn.execute(
            "SELECT id, status FROM registration_requests WHERE id=?", (rid,)
        ).fetchone()
        if not r:
            raise ValueError("申请不存在")
        if r["status"] != "pending":
            raise ValueError("申请已处理")
        now = time.time()
        conn.execute(
            """UPDATE registration_requests
               SET status='rejected', reviewer=?, review_note=?, reviewed_at=?, updated_at=?,
                   password_hash=''
               WHERE id=? AND status='pending'""",
            (reviewer, note, now, now, rid),
        )
        if conn.total_changes < 1:
            raise ValueError("申请状态已变更，请刷新")
        conn.commit()
        return {"ok": True, "request_id": rid, "status": "rejected"}
    finally:
        conn.close()


def _create_user_with_hash(
    username: str,
    password_hash: str,
    display_name: str = "",
    role: str = "analyst",
    note: str = "",
) -> Dict[str, Any]:
    """用申请时已计算的 password_hash 建号，避免二次哈希。"""
    from .users import UserStore, _public, _mirror_user_to_sqlite, ensure_users_table

    username = _sanitize_username(username)
    display_name = _sanitize_text(display_name, 80, field="显示名")
    note = _sanitize_text(note, 200, field="备注")
    role = _safe_reg_role(role)
    ph = str(password_hash or "")
    if not ph or "\x00" in ph or len(ph) > 256:
        raise ValueError("申请凭证无效，请驳回后让用户重提")

    ensure_users_table()
    now = time.time()
    uid = uuid.uuid4().hex[:12]
    store = UserStore()
    try:
        store.execute(
            """INSERT INTO users(id, username, password_hash, display_name, role, enabled, note, created_at, updated_at)
               VALUES(?,?,?,?,?,1,?,?,?)""",
            (uid, username, ph, display_name, role, note, now, now),
        )
        store.commit()
        row = {
            "id": uid,
            "username": username,
            "password_hash": ph,
            "display_name": display_name,
            "role": role,
            "enabled": 1,
            "note": note,
            "created_at": now,
            "updated_at": now,
        }
        if store.mysql:
            try:
                _mirror_user_to_sqlite(row)
            except Exception:
                pass
        return _public(row)
    finally:
        store.close()
