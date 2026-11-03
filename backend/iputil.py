"""从采集端多网卡 IP 列表中挑选展示用主 IP。"""
from __future__ import annotations
import re
from typing import Iterable, List, Optional

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def parse_ip_list(raw: str) -> List[str]:
    """拆分采集端 ip 字段（逗号 / 换行 / 分号）。"""
    text = (raw or "").strip()
    if not text:
        return []
    parts = re.split(r"[\s,;|/]+", text)
    out: List[str] = []
    seen = set()
    for p in parts:
        ip = p.strip().strip("[]").split("%")[0].strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def _is_ipv4(ip: str) -> bool:
    return bool(_IPV4_RE.match(ip or ""))


def _rfc1918_score(ip: str) -> int:
    """越大越优先。负分表示应尽量不用。"""
    if not _is_ipv4(ip):
        # IPv6：仅作兜底
        low = (ip or "").lower()
        if low in ("::1",) or low.startswith("fe80:"):
            return -80
        if low.startswith(("fc", "fd")):
            return 20
        return 5
    parts = [int(x) for x in ip.split(".")]
    a, b = parts[0], parts[1]
    if ip in ("0.0.0.0", "255.255.255.255"):
        return -100
    if a == 127:
        return -90
    if a == 169 and b == 254:
        return -50  # APIPA / 链路本地，多网卡时常排第一但不可用
    if a == 10:
        return 100
    if a == 192 and b == 168:
        return 100
    if a == 172 and 16 <= b <= 31:
        return 100
    if a == 198 and b == 18:
        return 10
    # 公网
    return 40


def pick_primary_ip(raw: Optional[str], prefer: Optional[Iterable[str]] = None) -> str:
    """
    从多网卡列表选主 IP：优先 RFC1918 局域网，避开 169.254 / 127 / 0.0.0.0。
    prefer: 可选候选优先集合（如已有手工填写）。
    """
    cands = parse_ip_list(raw or "")
    if prefer:
        for p in prefer:
            p = (p or "").strip()
            if p and p not in cands:
                cands.insert(0, p)
    if not cands:
        return ""
    scored = sorted(
        cands,
        key=lambda ip: (-_rfc1918_score(ip), 0 if _is_ipv4(ip) else 1, ip),
    )
    return scored[0]


def is_weak_ip(ip: str) -> bool:
    """是否为不可靠展示 IP（空 / 回环 / APIPA）。"""
    ip = (ip or "").strip()
    if not ip:
        return True
    return _rfc1918_score(ip) < 0
