"""把最终分析结果同步到 MySQL / Elasticsearch / Redis。

本地 analysis.db + result.json 仍是工作副本；远程副本用于跨主机检索和多端查看。
"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import paths as P

_lock = threading.Lock()
_last: Dict[str, Any] = {}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load_local_bundle(rid: str) -> Optional[Dict[str, Any]]:
    """从本地 analysis.db / result.json 取出可同步的报告元数据 + 分析结论。"""
    rid = P.report_id(rid)
    report: Dict[str, Any] = {}
    analysis: Dict[str, Any] = {}

    dbp = P.resolve_analysis_db(rid)
    if dbp and dbp.exists():
        try:
            from .db_store import _connect, _init_schema, _jload, _load_findings_from_conn
            conn = _connect(dbp)
            try:
                _init_schema(conn)
                meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
                blobs = {}
                for row in conn.execute("SELECT name,data FROM blobs"):
                    blobs[row["name"]] = _jload(row["data"])
                findings = _load_findings_from_conn(conn)
                report = {
                    "hostname": meta.get("hostname") or "",
                    "ip": meta.get("ip") or "",
                    "collect_time": meta.get("collect_time") or "",
                    "processes": blobs.get("processes") if isinstance(blobs.get("processes"), list) else [],
                    "services": blobs.get("services") if isinstance(blobs.get("services"), list) else [],
                    "_files_count": int(meta.get("count_file_scans") or 0),
                }
                analysis = {
                    "summary": blobs.get("summary") or {},
                    "summary_aggregated": blobs.get("summary_aggregated") or {},
                    "pipeline": blobs.get("pipeline") or {},
                    "timeline": blobs.get("timeline") or [],
                    "findings_by_module": blobs.get("findings_by_module") or {},
                    "meta": blobs.get("analysis_meta") or {},
                    "findings_aggregated": findings,
                    "findings": blobs.get("findings_raw_sample") or findings,
                    "ai": blobs.get("ai"),
                    "analyzed_at": meta.get("analyzed_at") or _now(),
                }
            finally:
                conn.close()
        except Exception as e:
            print(f"[result_sync] load db {rid}: {e}")

    rp = P.resolve_result_json(rid)
    if rp and rp.exists():
        try:
            with open(rp, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                if isinstance(data.get("report"), dict):
                    report.setdefault("hostname", data["report"].get("hostname") or "")
                    report.setdefault("collect_time", data["report"].get("time") or "")
                an = data.get("analysis")
                if isinstance(an, dict):
                    if not analysis:
                        analysis = an
                    else:
                        rj = an.get("findings_aggregated") or an.get("findings") or []
                        loc = analysis.get("findings_aggregated") or []
                        if isinstance(rj, list) and len(rj) > len(loc):
                            analysis["findings_aggregated"] = rj
                            if an.get("summary_aggregated"):
                                analysis["summary_aggregated"] = an.get("summary_aggregated")
                            if an.get("pipeline"):
                                analysis["pipeline"] = an.get("pipeline")
                        for k in ("summary", "timeline", "findings_by_module", "ai", "meta"):
                            if not analysis.get(k) and an.get(k):
                                analysis[k] = an.get(k)
        except Exception as e:
            print(f"[result_sync] load result.json {rid}: {e}")

    jp = P.resolve_report_json(rid)
    if jp and jp.exists() and not report.get("hostname"):
        try:
            with open(jp, encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                report["hostname"] = raw.get("hostname") or report.get("hostname") or ""
                report["ip"] = raw.get("ip") or report.get("ip") or ""
                report["collect_time"] = raw.get("collect_time") or report.get("collect_time") or ""
        except Exception:
            pass

    if not analysis:
        return None
    return {"file": rid, "report": report, "analysis": analysis}


def _sync_mysql(rid: str, report: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    out = {"ok": False, "findings": 0, "error": ""}
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import ensure_analysis_tables, save_analysis_mysql
        if not mysql_ready():
            out["error"] = "mysql_unavailable"
            return out
        ensure_analysis_tables()
        ok = bool(save_analysis_mysql(report, analysis, rid))
        out["ok"] = ok
        out["findings"] = len(analysis.get("findings_aggregated") or [])
        if not ok:
            out["error"] = "save_failed"
    except Exception as e:
        out["error"] = str(e)
        print(f"[result_sync] mysql {rid}: {e}")
    return out


def _sync_es(rid: str, report: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    out = {"ok": False, "indexed": 0, "error": ""}
    findings = analysis.get("findings_aggregated") or analysis.get("findings") or []
    if not findings:
        out["ok"] = True
        return out
    try:
        from .es_client import delete_findings_for_report, index_findings, is_available
        if not is_available():
            out["error"] = "es_unavailable"
            return out
        try:
            delete_findings_for_report(rid)
        except Exception:
            pass
        n = index_findings(
            rid,
            report.get("hostname") or "",
            analysis.get("analyzed_at") or _now(),
            findings if isinstance(findings, list) else [],
        )
        out["ok"] = n > 0 or not findings
        out["indexed"] = int(n or 0)
        if n <= 0 and findings:
            out["error"] = "index_zero"
    except Exception as e:
        out["error"] = str(e)
        print(f"[result_sync] es {rid}: {e}")
    return out


def _sync_redis(rid: str, report: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    out = {"ok": False, "error": ""}
    try:
        from .redis_client import is_available, prefix, rjson_set
        if not is_available():
            out["error"] = "redis_unavailable"
            return out
        agg = analysis.get("findings_aggregated") or []
        slim = []
        for x in agg[:200]:
            if not isinstance(x, dict):
                continue
            ev = x.get("evidence")
            if isinstance(ev, list):
                ev_s = "；".join(str(i) for i in ev[:3])
            else:
                ev_s = str(ev or "")
            slim.append({
                "title": x.get("title") or x.get("name") or "",
                "category": x.get("category") or "",
                "severity": x.get("severity") or "medium",
                "evidence": ev_s[:400],
                "rule_id": x.get("rule_id") or "",
                "matcher": x.get("matcher") or "",
            })
        payload = {
            "file": rid,
            "hostname": report.get("hostname") or "",
            "issues": len(slim),
            "findings": slim,
            "synced_at": _now(),
        }
        ok = rjson_set(prefix() + "cache:analysis:" + rid, payload, ex=86400 * 7)
        out["ok"] = bool(ok)
        if not ok:
            out["error"] = "set_failed"
    except Exception as e:
        out["error"] = str(e)
    return out


def search_findings_redis(
    needle: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """从 Redis cache:analysis:* 补检索（ES/本地不足时）。"""
    from backend.search_sql import text_matches_query

    needle = (needle or "").strip()
    if not needle:
        return []
    out: List[Dict[str, Any]] = []
    try:
        from .redis_client import is_available, prefix, rjson_get
        from .db_store import list_index
        if not is_available():
            return []
        rows = list_index(80, user=user) or []
        hn_filter = (hostname or "").strip().lower()
        sev_filter = (severity or "").strip().lower()
        for row in rows:
            rid = str((row or {}).get("file") or "")
            if not rid:
                continue
            hn = str((row or {}).get("hostname") or "")
            if hn_filter and hn_filter not in hn.lower():
                continue
            pack = rjson_get(prefix() + "cache:analysis:" + rid)
            if not isinstance(pack, dict):
                continue
            for x in pack.get("findings") or []:
                if not isinstance(x, dict):
                    continue
                sev = str(x.get("severity") or "medium").lower()
                if sev_filter and sev != sev_filter and not (
                    sev_filter == "high" and sev in ("high", "critical")
                ):
                    continue
                blob = " ".join([
                    str(x.get("title") or ""),
                    str(x.get("category") or ""),
                    str(x.get("evidence") or ""),
                    str(x.get("rule_id") or ""),
                    hn,
                    rid,
                ])
                if not text_matches_query(blob, needle):
                    continue
                out.append({
                    "hostname": hn or pack.get("hostname") or "",
                    "report_id": rid,
                    "file": rid,
                    "title": x.get("title") or "",
                    "evidence": x.get("evidence") or "",
                    "severity": x.get("severity") or "medium",
                    "category": x.get("category") or "",
                    "rule_id": x.get("rule_id") or "",
                    "matcher": x.get("matcher") or "",
                    "_source": "redis",
                })
                if len(out) >= size:
                    return out
    except Exception as e:
        print(f"[result_sync] redis search: {e}")
    return out


def sync_one(
    rid: str,
    report: Optional[Dict[str, Any]] = None,
    analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """把一份报告的最终分析同步到 MySQL + ES + Redis。"""
    rid = P.report_id(rid)
    if not (isinstance(report, dict) and isinstance(analysis, dict) and analysis):
        bundle = load_local_bundle(rid)
        if not bundle:
            return {"ok": False, "file": rid, "error": "no_local_analysis"}
        report = bundle["report"]
        analysis = bundle["analysis"]
    mysql = _sync_mysql(rid, report or {}, analysis or {})
    es = _sync_es(rid, report or {}, analysis or {})
    redis = _sync_redis(rid, report or {}, analysis or {})
    result = {
        "ok": bool(mysql.get("ok") or es.get("ok") or redis.get("ok")),
        "file": rid,
        "hostname": (report or {}).get("hostname") or "",
        "findings": len((analysis or {}).get("findings_aggregated") or []),
        "mysql": mysql,
        "es": es,
        "redis": redis,
    }
    with _lock:
        _last[rid] = {"at": _now(), "ok": result["ok"], "findings": result["findings"]}
    return result


def backfill_all(limit: int = 80) -> Dict[str, Any]:
    """把磁盘上已有分析结果补同步到 MySQL/ES（启动或手动触发）。"""
    from .paths import iter_report_ids
    synced = 0
    failed = 0
    skipped = 0
    details: List[Dict[str, Any]] = []
    for rid in iter_report_ids(max(1, int(limit))):
        bundle = load_local_bundle(rid)
        if not bundle or not (bundle["analysis"].get("findings_aggregated") or bundle["analysis"].get("findings")):
            skipped += 1
            continue
        r = sync_one(rid, bundle["report"], bundle["analysis"])
        if r.get("ok"):
            synced += 1
        else:
            failed += 1
        if len(details) < 20:
            details.append({"file": rid, "ok": r.get("ok"), "findings": r.get("findings"), "es": (r.get("es") or {}).get("indexed")})
    out = {
        "ok": True,
        "synced": synced,
        "failed": failed,
        "skipped": skipped,
        "details": details,
    }
    print(f"[result_sync] backfill synced={synced} failed={failed} skipped={skipped}")
    return out


def last_status() -> Dict[str, Any]:
    with _lock:
        return dict(_last)


def purge_remote(
    rids: Optional[List[str]] = None,
    hostname: Optional[str] = None,
    background: bool = True,
) -> Dict[str, Any]:
    """删远程副本：MySQL 已由调用方批量处理时，这里清 ES + Redis。

    ES delete_by_query 可能上百毫秒，默认丢后台，避免拖住删除接口。
    """
    ids = [P.report_id(x) for x in (rids or []) if str(x or "").strip()]
    hn = (hostname or "").strip()

    def _run() -> Dict[str, Any]:
        es_n = 0
        redis_n = 0
        try:
            from .es_client import delete_findings_for_hostname, delete_findings_for_reports
            if hn:
                es_n = delete_findings_for_hostname(hn)
            if ids and (not hn or es_n == 0):
                es_n += delete_findings_for_reports(ids)
        except Exception as e:
            print(f"[result_sync] purge es: {e}")
        try:
            from .redis_client import prefix, rdel
            from .hot_cache import bump
            keys = [prefix() + "cache:analysis:" + rid for rid in ids]
            if keys:
                redis_n = rdel(*keys)
            bump()
        except Exception as e:
            print(f"[result_sync] purge redis: {e}")
        out = {"es": es_n, "redis": redis_n, "files": len(ids)}
        print(f"[result_sync] purge remote {out}")
        return out

    if background:
        threading.Thread(target=_run, daemon=True, name="purge-remote").start()
        return {"ok": True, "queued": True, "files": len(ids), "hostname": hn}
    return {"ok": True, "queued": False, **_run()}
