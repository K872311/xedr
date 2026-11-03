"""匹配工具：边界命中，避免 grep 式短子串误报"""
from __future__ import annotations
import re


def is_private_ip(ip: str) -> bool:
    ip = (ip or "").split("%")[0].strip().strip("[]")
    if not ip:
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "198.18.", "::1", "fc", "fd")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except Exception:
            return False
    return False


def conn_remote(c: dict | None) -> str:
    """统一取连接远端：兼容 Win remote_addr 与 Linux remote_address / remote_ip。"""
    if not isinstance(c, dict):
        return ""
    for k in ("remote_addr", "remote_address", "RemoteAddr", "peer", "remote"):
        v = c.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    rip = str(c.get("remote_ip") or "").strip()
    if rip:
        rp = str(c.get("remote_port") or "").strip()
        return f"{rip}:{rp}" if rp else rip
    return ""


def conn_local(c: dict | None) -> str:
    """统一取连接本端：兼容 Win local_addr 与 Linux local_address。"""
    if not isinstance(c, dict):
        return ""
    for k in ("local_addr", "local_address", "LocalAddr", "local"):
        v = c.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def conn_remote_ip(c: dict | None) -> str:
    """从连接记录提取纯 IP（去端口 / 括号）。"""
    if not isinstance(c, dict):
        return ""
    rip = str(c.get("remote_ip") or "").strip().strip("[]")
    if rip:
        return rip.split("%")[0]
    raw = conn_remote(c)
    if not raw:
        return ""
    host = raw.split("%")[0].strip().strip("[]")
    if host.count(":") == 1 and not host.startswith(":"):
        # ipv4:port
        return host.split(":", 1)[0]
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    # bare ipv4 / ipv6 without port
    if host.count(":") > 1:
        # ipv6 — if trailing :digits treat as port
        m = re.match(r"^(.+):(\d+)$", host)
        if m:
            return m.group(1).strip("[]")
        return host.strip("[]")
    return host


def basename(path: str) -> str:
    p = (path or "").replace("/", "\\")
    return p.rsplit("\\", 1)[-1]


def strip_ext(name: str) -> str:
    return re.sub(r"\.(exe|msi|dll|lnk|sys|bat|cmd|ps1)$", "", (name or ""), flags=re.I)


def pat_hit(text: str, pat: str) -> bool:
    t = (text or "").lower().strip()
    p = (pat or "").lower().strip()
    if not t or not p:
        return False
    p = strip_ext(p).strip()
    if not p or len(p) < 3:
        return False
    base = strip_ext(basename(t)).strip()
    if not base:
        return False
    if base == p:
        return True
    if len(p) >= 4 and base.startswith(p) and (len(base) == len(p) or not base[len(p)].isalnum()):
        return True
    if re.search(r"(^|[^a-z0-9])" + re.escape(p) + r"([^a-z0-9]|$)", t):
        return True
    if len(p) >= 6:
        if re.search(r"[\\/]" + re.escape(p) + r"([\\/]|$)", t):
            return True
        if re.search(r"(^|[\\/])" + re.escape(p) + r"\.", t):
            return True
    return False


def expand_env_path(p: str) -> str:
    p = (p or "").replace("/", "\\")
    for env in ("%APPDATA%", "%LOCALAPPDATA%", "%ProgramData%", "%PROGRAMDATA%",
                "%ProgramFiles%", "%PROGRAMFILES%", "%SYSTEMROOT%", "%USERPROFILE%"):
        p = p.replace(env, "")
    return p.strip("\\").lower()
