"""实体键归一化：ip / domain / hash / account。

- ip / domain / hash → scope=global（跨主机可比对）
- account → scope=host_scoped（需带主机名才有意义）
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from .iputil import parse_ip_list, is_weak_ip

_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d))$"
)

GLOBAL_KINDS = frozenset({"ip", "domain", "hash"})
HOST_SCOPED_KINDS = frozenset({"account"})
ALL_KINDS = GLOBAL_KINDS | HOST_SCOPED_KINDS


def scope_for_kind(kind: str) -> str:
    k = (kind or "").strip().lower()
    if k in HOST_SCOPED_KINDS:
        return "host_scoped"
    return "global"


def normalize_hash(value: str) -> Optional[str]:
    v = (value or "").strip().lower()
    if v.startswith("sha256:") or v.startswith("md5:") or v.startswith("sha1:"):
        v = v.split(":", 1)[1].strip()
    if not _HASH_RE.match(v):
        return None
    return v


def normalize_ip(value: str) -> Optional[str]:
    parts = parse_ip_list(value) or [(value or "").strip()]
    for raw in parts:
        ip = (raw or "").strip().strip("[]").split("%")[0]
        if not ip:
            continue
        if _IPV4_RE.match(ip):
            if is_weak_ip(ip):
                continue
            return ip
        # 简易 IPv6：含冒号且非链路本地
        if ":" in ip and not ip.lower().startswith("fe80:"):
            return ip.lower()
    return None


def normalize_domain(value: str) -> Optional[str]:
    v = (value or "").strip().lower().rstrip(".")
    if not v or " " in v or "/" in v or "\\" in v:
        return None
    if v.startswith("http://") or v.startswith("https://"):
        try:
            host = urlparse(v).hostname or ""
        except Exception:
            host = ""
        v = host.lower().rstrip(".")
    if not v or _IPV4_RE.match(v) or ":" in v:
        return None
    if not _DOMAIN_RE.match(v):
        return None
    # 过滤本机/常见噪声
    if v in ("localhost", "local", "localdomain") or v.endswith(".local"):
        return None
    return v


def normalize_account(value: str) -> Optional[str]:
    v = (value or "").strip()
    if not v or len(v) > 256:
        return None
    # DOMAIN\user 或 user@domain
    if "\\" in v:
        dom, _, user = v.partition("\\")
        user = user.strip()
        dom = dom.strip()
        if not user:
            return None
        return f"{dom}\\{user}".lower() if dom else user.lower()
    if "@" in v and " " not in v:
        return v.lower()
    # 纯用户名
    if re.match(r"^[\w.\-$]{1,128}$", v, re.UNICODE):
        low = v.lower()
        if low in ("root", "administrator", "admin", "guest", "nobody", "www-data"):
            return low  # 仍保留，但属 host_scoped
        return low
    return None


def normalize(kind: str, value: Any) -> Optional[Tuple[str, str]]:
    """返回 (kind, normalized) 或 None。"""
    k = (kind or "").strip().lower()
    if k in ("md5", "sha1", "sha256", "file_hash", "sha128"):
        k = "hash"
    if k not in ALL_KINDS:
        return None
    raw = str(value or "").strip()
    if not raw:
        return None
    if k == "hash":
        n = normalize_hash(raw)
    elif k == "ip":
        n = normalize_ip(raw)
    elif k == "domain":
        n = normalize_domain(raw)
    elif k == "account":
        n = normalize_account(raw)
    else:
        n = None
    if not n:
        return None
    return k, n


def detect_kind(value: str) -> Optional[str]:
    """从裸值猜类型。"""
    v = (value or "").strip()
    if not v:
        return None
    if normalize_hash(v):
        return "hash"
    if normalize_ip(v):
        return "ip"
    if normalize_domain(v):
        return "domain"
    if "\\" in v or ("@" in v and " " not in v):
        if normalize_account(v):
            return "account"
    return None


def entity_key(kind: str, value: str, *, hostname: str = "") -> Optional[str]:
    """稳定键：global 为 kind:value；host_scoped 为 kind:host:value。"""
    norm = normalize(kind, value)
    if not norm:
        return None
    k, n = norm
    if scope_for_kind(k) == "host_scoped":
        host = (hostname or "").strip().lower() or "_"
        return f"{k}:{host}:{n}"
    return f"{k}:{n}"


def to_dict(kind: str, value: str, *, hostname: str = "") -> Optional[Dict[str, Any]]:
    norm = normalize(kind, value)
    if not norm:
        return None
    k, n = norm
    return {
        "kind": k,
        "value": n,
        "scope": scope_for_kind(k),
        "key": entity_key(k, n, hostname=hostname),
        "hostname": (hostname or "").strip() if scope_for_kind(k) == "host_scoped" else "",
    }
