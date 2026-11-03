"""Redis 热缓存：报告列表 / 检索结果 / 任务快照 / 失效广播。不可用时全部静默失败。"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from .cache_policy import CACHE_VERSION, ttl as cache_ttl
from .redis_client import get_client, prefix, rget, rjson_get, rjson_set

# 检索结果包：一次扫完后切片翻页；分析写库会 bump() 换代，避免脏读。
# 冷查询默认按页取一小包（见 search.py），上限仍受此常量约束。
SEARCH_PACK_CAP = 1200
SEARCH_PACK_COLD = 500
_SEARCH_TTL = int(cache_ttl("search", 90.0, minimum=15.0, maximum=300.0))


def _gen() -> int:
    try:
        raw = rget(prefix() + "cache:gen")
        return int(raw or 0)
    except Exception:
        return 0


def bump() -> None:
    try:
        r = get_client()
        if r:
            r.incr(prefix() + "cache:gen")
    except Exception:
        pass



def put_job(job: Dict[str, Any]) -> None:
    jid = str(job.get("id") or "")
    if not jid:
        return
    rjson_set(prefix() + "job:" + jid, job, ex=7200)
    try:
        r = get_client()
        if r:
            r.publish(
                prefix() + "jobs",
                __import__("json").dumps(
                    {
                        "id": jid,
                        "status": job.get("status"),
                        "phase": job.get("phase"),
                        "progress": job.get("progress"),
                        "message": job.get("message"),
                        "issues": job.get("issues"),
                    },
                    ensure_ascii=False,
                ),
            )
    except Exception:
        pass


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    val = rjson_get(prefix() + "job:" + str(job_id))
    return val if isinstance(val, dict) else None


def set_jg(status: Dict[str, Any]) -> None:
    rjson_set(prefix() + "jg:status", status, ex=30)


def get_jg() -> Optional[Dict[str, Any]]:
    val = rjson_get(prefix() + "jg:status")
    return val if isinstance(val, dict) else None


def set_stats(stats: Dict[str, Any]) -> None:
    rjson_set(prefix() + "jobs:stats", stats, ex=3)


def get_stats() -> Optional[Dict[str, Any]]:
    val = rjson_get(prefix() + "jobs:stats")
    return val if isinstance(val, dict) else None


def findings_search_digest(
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    owner_id: str = "",
    exclude: Optional[str] = None,
) -> str:
    raw = "|".join([
        (q or "").strip().lower(),
        (hostname or "").strip(),
        (severity or "").strip().lower(),
        str(owner_id or ""),
        (exclude or "").strip().lower(),
    ])
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]


def search_pack_key(digest: str) -> str:
    return f"{prefix()}cache:{CACHE_VERSION}:search:{_gen()}:{digest}"


def get_search_pack(digest: str) -> Optional[Dict[str, Any]]:
    val = rjson_get(search_pack_key(digest))
    return val if isinstance(val, dict) else None


def set_search_pack(digest: str, payload: Dict[str, Any], ttl: Optional[int] = None) -> None:
    if not digest or not isinstance(payload, dict):
        return
    rjson_set(search_pack_key(digest), payload, ex=max(15, int(ttl or _SEARCH_TTL)))


def slice_search_pack(
    pack: Optional[Dict[str, Any]],
    offset: int,
    size: int,
) -> Optional[Tuple[List[Dict[str, Any]], int]]:
    """能完整切出本页则返回 (items, total)，否则 None（需回源）。"""
    if not isinstance(pack, dict):
        return None
    items = pack.get("items")
    if not isinstance(items, list):
        return None
    try:
        total = int(pack.get("total") or 0)
    except (TypeError, ValueError):
        total = len(items)
    off = max(0, int(offset))
    lim = max(1, int(size))
    if off >= total:
        return [], total
    end = off + lim
    if end > len(items) and total > len(items):
        return None
    return items[off:off + lim], total
