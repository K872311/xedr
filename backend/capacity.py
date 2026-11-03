"""控制中心容量快照：队列 / 磁盘 / 并发策略（20～50 人运维看板）。"""
from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from . import config
from . import paths as P


def _bytes_h(n: int) -> str:
    v = float(max(0, int(n or 0)))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(v)} {unit}"
            return f"{v:.1f} {unit}"
        v /= 1024.0
    return f"{int(n)} B"


_DIR_SIZE_CACHE: Dict[str, Any] = {}
_DIR_SIZE_CACHE_TTL = 60.0


def _dir_size(path: Path, *, limit_files: int = 80_000) -> Dict[str, Any]:
    key = str(path)
    now = time.time()
    hit = _DIR_SIZE_CACHE.get(key)
    if isinstance(hit, dict) and (now - float(hit.get("_at") or 0)) < _DIR_SIZE_CACHE_TTL:
        out = {k: v for k, v in hit.items() if k != "_at"}
        out["cached"] = True
        return out
    total = 0
    files = 0
    if not path.exists():
        return {"bytes": 0, "files": 0, "truncated": False}
    try:
        for p in path.rglob("*"):
            if not p.is_file():
                continue
            try:
                total += p.stat().st_size
                files += 1
            except OSError:
                continue
            if files >= limit_files:
                result = {"bytes": total, "files": files, "truncated": True}
                _DIR_SIZE_CACHE[key] = {**result, "_at": now}
                return result
    except Exception as e:
        return {"bytes": total, "files": files, "truncated": False, "error": str(e)}
    result = {"bytes": total, "files": files, "truncated": False}
    _DIR_SIZE_CACHE[key] = {**result, "_at": now}
    return result


def _disk_usage(path: Path) -> Dict[str, Any]:
    try:
        u = shutil.disk_usage(str(path if path.exists() else path.parent))
        return {
            "total": u.total,
            "used": u.used,
            "free": u.free,
            "used_pct": round(100.0 * u.used / u.total, 1) if u.total else 0,
            "total_h": _bytes_h(u.total),
            "used_h": _bytes_h(u.used),
            "free_h": _bytes_h(u.free),
            "path": str(path),
        }
    except Exception as e:
        return {"error": str(e), "path": str(path)}


def _report_counts() -> Dict[str, Any]:
    try:
        ids = P.iter_report_ids(5000)
    except Exception:
        ids = []
    return {"reports": len(ids), "sample_cap": 5000}


def capacity_snapshot(*, with_reports_size: bool = True) -> Dict[str, Any]:
    from .settings import get_settings
    from .jobs import queue_stats

    cfg = get_settings()
    qs = queue_stats()
    reports_dir = Path(config.REPORTS_DIR)
    disk = _disk_usage(reports_dir)
    size = _dir_size(reports_dir) if with_reports_size else {"bytes": 0, "files": 0, "skipped": True}
    counts = _report_counts()

    mysql_pool = 20
    mysql_ok = False
    try:
        from .mysql_db import load_db_config, mysql_ready
        mysql_ok = bool(mysql_ready())
        mysql_pool = max(2, min(32, int((load_db_config() or {}).get("pool_size") or 20)))
    except Exception:
        pass

    redis_ok = False
    try:
        from .redis_client import is_available
        redis_ok = bool(is_available())
    except Exception:
        pass

    es_ok = False
    es_enabled = False
    try:
        from .es_client import probe_status as es_probe
        est = es_probe(reprobe=False) or {}
        es_enabled = bool(est.get("enabled"))
        es_ok = bool(est.get("connected"))
    except Exception:
        pass

    soft = int(cfg.get("job_queue_soft_limit") or 60)
    hard = int(cfg.get("job_queue_hard_limit") or 150)
    qdepth = int(qs.get("queued") or 0) + int(qs.get("running") or 0)
    warn: List[str] = []
    if qdepth >= hard:
        warn.append("分析队列已达硬限，新上传会被拒绝")
    elif qdepth >= soft:
        warn.append("分析队列接近软限，建议错峰导入")
    if float(disk.get("used_pct") or 0) >= 85:
        warn.append("磁盘占用 ≥ 85%，请清理过期报告")
    elif float(disk.get("used_pct") or 0) >= 70:
        warn.append("磁盘占用 ≥ 70%，建议执行保留清理")

    return {
        "ok": True,
        "generated_at": time.time(),
        "queue": qs,
        "limits": {
            "job_max_workers": int(cfg.get("job_max_workers") or 10),
            "job_heavy_max": int(cfg.get("job_heavy_max") or 3),
            "job_per_user_max": int(cfg.get("job_per_user_max") or 5),
            "upload_max_concurrent": int(cfg.get("upload_max_concurrent") or 8),
            "job_queue_soft_limit": soft,
            "job_queue_hard_limit": hard,
            "report_retention_days": int(cfg.get("report_retention_days") or 0),
            "mysql_pool": mysql_pool,
        },
        "disk": disk,
        "reports_dir": {
            "path": str(reports_dir),
            "size_bytes": int(size.get("bytes") or 0),
            "size_h": _bytes_h(int(size.get("bytes") or 0)),
            "files": int(size.get("files") or 0),
            "truncated": bool(size.get("truncated")),
            "report_count": int(counts.get("reports") or 0),
        },
        "backends": {
            "mysql": mysql_ok,
            "redis": redis_ok,
            "elasticsearch": es_ok,
            "elasticsearch_enabled": es_enabled,
        },
        "warnings": warn,
        "queue_depth": qdepth,
    }
