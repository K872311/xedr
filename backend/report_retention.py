"""按保留天数清理过期报告（控制中心一键清理）。"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config
from . import paths as P


def _mtime_for_rid(rid: str) -> float:
    """取报告目录/文件最近修改时间作为「年龄」依据。"""
    candidates: List[Path] = []
    try:
        d = P.report_dir(rid)
        if d.is_dir():
            candidates.append(d)
            for name in ("report.json", "result.json", "analysis.db", "collect.json"):
                p = d / name
                if p.exists():
                    candidates.append(p)
    except Exception:
        pass
    for fn in (
        getattr(P, "resolve_report_json", lambda _x: None)(rid),
        getattr(P, "resolve_analysis_db", lambda _x: None)(rid),
    ):
        if fn and Path(fn).exists():
            candidates.append(Path(fn))
    best = 0.0
    for p in candidates:
        try:
            best = max(best, float(p.stat().st_mtime))
        except OSError:
            continue
    return best


def list_expired_reports(
    days: Optional[int] = None,
    *,
    limit: int = 2000,
) -> Dict[str, Any]:
    from .settings import get_settings

    cfg_days = int(days) if days is not None else int((get_settings() or {}).get("report_retention_days") or 0)
    if cfg_days <= 0:
        return {
            "ok": True,
            "days": 0,
            "cutoff": 0,
            "expired": [],
            "count": 0,
            "message": "保留天数为 0（不自动清理），请先在系统设置中设置天数",
        }
    cutoff = time.time() - cfg_days * 86400
    expired: List[Dict[str, Any]] = []
    try:
        ids = P.iter_report_ids(max(1, int(limit)))
    except Exception:
        ids = []
    for rid in ids:
        mt = _mtime_for_rid(rid)
        if mt <= 0:
            continue
        if mt < cutoff:
            expired.append({
                "file": rid,
                "mtime": mt,
                "age_days": round((time.time() - mt) / 86400, 1),
            })
    expired.sort(key=lambda x: float(x.get("mtime") or 0))
    return {
        "ok": True,
        "days": cfg_days,
        "cutoff": cutoff,
        "expired": expired,
        "count": len(expired),
        "reports_root": str(config.REPORTS_DIR),
    }


def purge_expired_reports(
    days: Optional[int] = None,
    *,
    dry_run: bool = True,
    limit: int = 500,
) -> Dict[str, Any]:
    preview = list_expired_reports(days, limit=limit)
    items = list(preview.get("expired") or [])
    if dry_run or not items:
        return {
            **preview,
            "dry_run": True,
            "deleted": 0,
            "errors": [],
            "message": "预览完成" if items else (preview.get("message") or "没有过期报告"),
        }

    from .report_delete import delete_one_report

    deleted = 0
    errors: List[Dict[str, str]] = []
    for it in items:
        rid = str(it.get("file") or "")
        if not rid:
            continue
        try:
            delete_one_report(rid)
            deleted += 1
        except FileNotFoundError:
            deleted += 1
        except Exception as e:
            errors.append({"file": rid, "error": str(e)})
    return {
        **preview,
        "dry_run": False,
        "deleted": deleted,
        "errors": errors,
        "message": f"已删除 {deleted} 份过期报告" + (f"，失败 {len(errors)}" if errors else ""),
    }
