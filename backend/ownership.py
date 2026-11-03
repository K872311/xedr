"""报告归属：按平台登录用户隔离；admin 可看全部。"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Optional

_owner_ctx: ContextVar[Optional[Dict[str, str]]] = ContextVar("report_owner", default=None)


def set_owner_context(user: Optional[Dict[str, Any]]) -> None:
    if not user or not isinstance(user, dict):
        _owner_ctx.set(None)
        return
    uid = str(user.get("id") or "").strip()
    uname = str(user.get("username") or "").strip()
    if not uid and not uname:
        _owner_ctx.set(None)
        return
    _owner_ctx.set({"owner_id": uid, "owner_username": uname, "role": str(user.get("role") or "")})


def clear_owner_context() -> None:
    _owner_ctx.set(None)


@contextmanager
def owner_context(user: Optional[Dict[str, Any]]) -> Iterator[None]:
    token = _owner_ctx.set(None)
    try:
        set_owner_context(user)
        yield
    finally:
        _owner_ctx.reset(token)


def current_owner() -> Dict[str, str]:
    return dict(_owner_ctx.get() or {})


def resolve_owner_fields(row: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """优先用显式 row，其次上下文。"""
    row = row or {}
    oid = str(row.get("owner_id") or "").strip()
    oun = str(row.get("owner_username") or "").strip()
    if oid or oun:
        return {"owner_id": oid, "owner_username": oun}
    ctx = current_owner()
    return {
        "owner_id": str(ctx.get("owner_id") or ""),
        "owner_username": str(ctx.get("owner_username") or ""),
    }


def is_admin(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and str(user.get("role") or "").lower() == "admin")


def is_readonly(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and str(user.get("role") or "").lower() == "readonly")


def is_analyst(user: Optional[Dict[str, Any]]) -> bool:
    return bool(user and str(user.get("role") or "").lower() == "analyst")


def can_view_hosts(user: Optional[Dict[str, Any]]) -> bool:
    """主机台账：管理员、分析员、来宾均可查看。"""
    if not user:
        return False
    if is_admin(user) or is_analyst(user) or is_readonly(user):
        return True
    return False


def can_manage_hosts(user: Optional[Dict[str, Any]]) -> bool:
    """主机台账增删改：管理员与分析员；来宾只读。"""
    if not user:
        return False
    return is_admin(user) or is_analyst(user)


def can_access_report(user: Optional[Dict[str, Any]], owner_id: str = "", owner_username: str = "") -> bool:
    """无归属的历史报告仅 admin 可见；有归属则本人或 admin。"""
    if not user:
        return False
    if is_admin(user):
        return True
    oid = (owner_id or "").strip()
    oun = (owner_username or "").strip()
    uid = str(user.get("id") or "").strip()
    uname = str(user.get("username") or "").strip()
    if oid:
        return bool(uid and oid == uid)
    if oun:
        return bool(uname and oun == uname)
    return False
