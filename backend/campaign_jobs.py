"""战役聚合异步任务：后台扫描 + 进度查询。"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, Optional

_lock = threading.RLock()
_JOBS: Dict[str, Dict[str, Any]] = {}
_TTL_SEC = 1800
# 同轨道结果缓存：进入页面复用，点「刷新」才强制重扫
_RESULT_CACHE: Dict[str, Dict[str, Any]] = {}
_RESULT_TTL_SEC = 600
_COMPUTE_LOCKS: Dict[str, threading.Lock] = {}


def _purge() -> None:
    now = time.time()
    dead = [k for k, v in _JOBS.items() if now - float(v.get("updated") or 0) > _TTL_SEC]
    for k in dead:
        _JOBS.pop(k, None)
    dead_c = [
        k for k, v in _RESULT_CACHE.items()
        if now - float(v.get("ts") or 0) > _RESULT_TTL_SEC
    ]
    for k in dead_c:
        _RESULT_CACHE.pop(k, None)


def _norm_os_family(os_family: str = "") -> str:
    fam = str(os_family or "").strip().lower()
    if fam in ("windows", "linux"):
        return fam
    return ""


def _cache_key(limit_hosts: int, os_family: str) -> str:
    return f"{os_family or 'all'}|{int(limit_hosts)}"


def build_campaign_sync(limit_hosts: int = 80, os_family: str = "") -> Dict[str, Any]:
    """兼容同步接口，并合并同参数并发扫描。

    旧前端可能同时发出多个 GET /campaign；过去每个请求都会独立全量扫描。
    现在同一轨道只允许一个计算，其余请求等待并复用结果。
    """
    from .ir_analysis import analyze_campaign

    fam = _norm_os_family(os_family)
    limit_hosts = int(limit_hosts)
    ckey = _cache_key(limit_hosts, fam)
    with _lock:
        _purge()
        cached = _RESULT_CACHE.get(ckey)
        if cached and cached.get("result"):
            return dict(cached["result"])
        compute_lock = _COMPUTE_LOCKS.setdefault(ckey, threading.Lock())

    with compute_lock:
        with _lock:
            _purge()
            cached = _RESULT_CACHE.get(ckey)
            if cached and cached.get("result"):
                return dict(cached["result"])
        result = analyze_campaign(limit_hosts=limit_hosts, os_family=fam)
        with _lock:
            _RESULT_CACHE[ckey] = {
                "ts": time.time(),
                "job_id": "",
                "result": result,
            }
        return dict(result)


def start_campaign(
    limit_hosts: int = 80,
    os_family: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    """启动扫描。

    - 同轨道+limit 的 running 任务可复用
    - 未 force 时：10 分钟内完成的结果直接复用（进入页面不重复全量扫）
    - force=True（点刷新）：忽略缓存，重新扫描
    """
    fam = _norm_os_family(os_family)
    limit_hosts = int(limit_hosts)
    ckey = _cache_key(limit_hosts, fam)
    with _lock:
        _purge()
        if not force:
            cached = _RESULT_CACHE.get(ckey)
            if cached and cached.get("result"):
                job_id = str(cached.get("job_id") or "") or uuid.uuid4().hex[:16]
                job = {
                    "id": job_id,
                    "status": "done",
                    "progress": 100,
                    "message": "缓存结果",
                    "error": "",
                    "result": cached["result"],
                    "created": float(cached.get("ts") or time.time()),
                    "updated": time.time(),
                    "limit_hosts": limit_hosts,
                    "os_family": fam,
                    "cached": True,
                }
                _JOBS[job_id] = job
                # 缓存命中时直接带回完整结果，前端进入页面即可展示，无需再点检索/轮询。
                out = {
                    "ok": True,
                    "job_id": job_id,
                    "reused": True,
                    "cached": True,
                    **_public(job),
                }
                if isinstance(cached.get("result"), dict):
                    out.update(cached["result"])
                return out
        for jid, j in _JOBS.items():
            if (
                j.get("status") == "running"
                and int(j.get("limit_hosts") or 0) == limit_hosts
                and str(j.get("os_family") or "") == fam
            ):
                return {"ok": True, "job_id": jid, "reused": True, "cached": False, **_public(j)}
        job_id = uuid.uuid4().hex[:16]
        job = {
            "id": job_id,
            "status": "running",
            "progress": 0,
            "message": "排队…",
            "error": "",
            "result": None,
            "created": time.time(),
            "updated": time.time(),
            "limit_hosts": limit_hosts,
            "os_family": fam,
            "cached": False,
        }
        _JOBS[job_id] = job

    def _run() -> None:
        from .ir_analysis import analyze_campaign

        def cb(pct: int, msg: str) -> None:
            with _lock:
                j = _JOBS.get(job_id)
                if not j:
                    return
                j["progress"] = pct
                j["message"] = msg
                j["updated"] = time.time()

        try:
            result = analyze_campaign(limit_hosts=limit_hosts, progress_cb=cb, os_family=fam)
            with _lock:
                j = _JOBS.get(job_id)
                if j:
                    j["status"] = "done"
                    j["progress"] = 100
                    j["message"] = "完成"
                    j["result"] = result
                    j["updated"] = time.time()
                _RESULT_CACHE[ckey] = {
                    "ts": time.time(),
                    "job_id": job_id,
                    "result": result,
                }
        except Exception as e:
            with _lock:
                j = _JOBS.get(job_id)
                if j:
                    j["status"] = "error"
                    j["error"] = str(e)
                    j["message"] = "失败"
                    j["updated"] = time.time()

    threading.Thread(target=_run, name=f"campaign-{job_id}", daemon=True).start()
    with _lock:
        return {"ok": True, "job_id": job_id, "reused": False, "cached": False, **_public(_JOBS[job_id])}


def get_campaign(job_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        _purge()
        j = _JOBS.get(job_id)
        if not j:
            return None
        out = {"ok": True, "job_id": job_id, **_public(j)}
        if j.get("status") == "done" and j.get("result"):
            out.update(j["result"])
        return out


def _public(j: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": j.get("status"),
        "progress": int(j.get("progress") or 0),
        "message": j.get("message") or "",
        "error": j.get("error") or "",
        "os_family": j.get("os_family") or "all",
        "cached": bool(j.get("cached")),
    }
