"""报告 / 分析结果落盘（每报告一目录 + SQLite 主读）"""
from __future__ import annotations
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from . import config
from . import paths as P
from .db_store import save_report_db, upsert_ai_blob


def result_path_for_report(report_file: str) -> Path:
    """写入用：reports/<stem>/result.json；读时请用 resolve。"""
    return P.result_json_path(report_file, create_dir=True)


def save_report(
    report: Dict[str, Any],
    fname: str,
    *,
    ingest_heavy: bool = True,
    timer=None,
) -> Path:
    """落盘 report.json。默认先把 file_scans/event_logs 写入 SQLite 再写瘦身 JSON。

    timer: 可选 StageTimer，用于把「写盘 / 存证」拆开计时。
    """
    from .stage_timer import null_timer
    t = timer if timer is not None else null_timer()
    rid = P.report_id(fname)
    if ingest_heavy:
        with t.step("save_ingest"):
            try:
                from .db_store import detach_and_ingest_heavy
                detach_and_ingest_heavy(rid, report)
            except Exception as e:
                print(f"[store] ingest heavy before save_report: {e}")
    path = P.report_json_path(rid, create_dir=True)
    with t.step("write_json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, separators=(",", ":"))
    with t.step("seal"):
        try:
            from .vault import seal_report
            seal_report(rid, source="save_report")
        except Exception as e:
            print(f"[store] vault seal: {e}")
    # 清理旧扁平文件（若仍存在）
    legacy = P.legacy_flat_report(rid)
    if legacy.exists() and legacy.resolve() != path.resolve():
        try:
            legacy.unlink()
        except OSError:
            pass
    return path


def save_analysis(
    report: Dict[str, Any],
    analysis: Dict[str, Any],
    fname: str,
    *,
    persist: str = "full",
) -> Dict[str, Any]:
    """保存分析结果。

    persist:
      - light: 只写 result.json（快速阶段用，避免整库重写）
      - full: result.json + analysis.db + MySQL/ES 同步
    """
    rid = P.report_id(fname)
    hostname = report.get("hostname", "unknown")
    analysis_slim = dict(analysis)
    raw = analysis_slim.get("findings") or []
    analysis_slim["findings"] = raw[:100]
    analysis_slim["_findings_total"] = len(raw)
    # 与 DB 一致：模块只留样本，count/high 保留全量，避免 result.json 膨胀且导出误用样本长度
    fbm = analysis_slim.get("findings_by_module") or {}
    if isinstance(fbm, dict) and fbm:
        _mod_sample = 300
        slim_fbm = {}
        for k, block in fbm.items():
            if not isinstance(block, dict):
                continue
            items = block.get("findings") or []
            if not isinstance(items, list):
                items = []
            slim_fbm[k] = {
                "matcher": block.get("matcher") or k,
                "count": int(block.get("count") or len(items) or 0),
                "high": int(block.get("high") or 0),
                "findings": items[:_mod_sample],
                "truncated": bool(block.get("truncated")) or len(items) > _mod_sample,
            }
        analysis_slim["findings_by_module"] = slim_fbm
    pipe = dict(analysis_slim.get("pipeline") or {})
    pipe.pop("rules_inventory", None)
    analysis_slim["pipeline"] = pipe
    if analysis_slim.get("timeline") and len(analysis_slim["timeline"]) > 400:
        analysis_slim["timeline"] = analysis_slim["timeline"][:400]

    files_n = len(report.get("file_scans") or []) or int(report.get("_files_count") or 0)
    result = {
        "report": {
            "hostname": hostname,
            "time": report.get("collect_time"),
            "processes": len(report.get("processes") or []),
            "services": len(report.get("services") or []),
            "tasks": len(report.get("scheduled_tasks") or []),
            "programs": len(report.get("installed_programs") or []),
            "files": files_n,
            "event_logs": int(report.get("_event_logs_count") or len(report.get("event_logs") or []) or 0),
        },
        "analysis": analysis_slim,
        "file": rid,
        "folder": P.report_stem(rid),
        "persist": persist,
    }
    rp = P.result_json_path(rid, create_dir=True)
    with open(rp, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, separators=(",", ":"))
    legacy_r = P.legacy_flat_result(rid)
    if legacy_r.exists() and legacy_r.resolve() != rp.resolve():
        try:
            legacy_r.unlink()
        except OSError:
            pass

    if str(persist or "full").lower() == "light":
        # 快速阶段不重写 analysis.db；但告警数必须立刻进索引，否则台账一直显示 0
        try:
            from .db_store import upsert_index
            from .iputil import pick_primary_ip
            summary = analysis.get("summary") or {}
            summary_agg = analysis.get("summary_aggregated") or {}
            meta = analysis.get("meta") if isinstance(analysis.get("meta"), dict) else {}
            upsert_index({
                "file": rid,
                "hostname": hostname,
                "collect_time": report.get("collect_time"),
                "ip": pick_primary_ip(report.get("ip") or ""),
                "issues": (summary_agg.get("total") if summary_agg else None) or summary.get("total") or 0,
                "raw_issues": summary.get("total") or 0,
                "analyzed": True,
                "os_family": report.get("os_family") or meta.get("os_family") or "",
                "os": report.get("os") or "",
            })
        except Exception as e:
            print(f"[store] light index upsert: {e}")
        # 同步把本次告警写入 MySQL，避免「分析结果」页仍读到上一次的误报
        try:
            from .mysql_store import save_analysis_mysql
            save_analysis_mysql(report, analysis_slim, rid)
        except Exception as e:
            print(f"[store] light save_analysis_mysql: {e}")
        # 同步刷新 analysis.db 的 findings_agg（不碰采集大表），与 result.json 对齐
        try:
            from .db_store import sync_findings_to_analysis_db
            sync_findings_to_analysis_db(rid, analysis_slim)
        except Exception as e:
            print(f"[store] light sync_findings_to_analysis_db: {e}")
        return result

    try:
        save_report_db(report, analysis, rid)
    except Exception as e:
        print(f"[store] save_report_db failed: {e}")

    if analysis.get("ai"):
        try:
            save_ai_result(rid, analysis["ai"], report=report)
        except Exception as e:
            print(f"[store] save_ai_result failed: {e}")

    # ES：由 result_sync.sync_one 统一写，避免与异步队列双写竞态
    # _es_enqueue(rid, hostname, analysis)

    # 最终结论同步一份到 MySQL / ES / Redis，供跨主机检索
    try:
        from .result_sync import sync_one
        sync_one(rid, report, analysis)
    except Exception as e:
        print(f"[store] result_sync: {e}")

    return result


_es_q = None  # type: ignore
_es_started = False
_es_lock = threading.Lock()


def _es_enqueue(rid: str, hostname: str, analysis: Dict[str, Any]) -> None:
    import queue
    global _es_q, _es_started
    findings = analysis.get("findings_aggregated") or analysis.get("findings") or []
    if not findings:
        return
    with _es_lock:
        if _es_q is None:
            _es_q = queue.Queue(maxsize=64)
        if not _es_started:
            _es_started = True
            threading.Thread(target=_es_worker, daemon=True, name="es-index-worker").start()
        q = _es_q
    item = {
        "rid": rid,
        "hostname": hostname,
        "analyzed_at": analysis.get("analyzed_at") or datetime.now().isoformat(timespec="seconds"),
        "findings": findings,
    }
    try:
        q.put_nowait(item)
    except Exception:
        # 队列满：丢弃最旧再试一次，避免无界线程爆炸
        try:
            q.get_nowait()
        except Exception:
            pass
        try:
            q.put_nowait(item)
        except Exception as e:
            print(f"[store] es queue full, drop {rid}: {e}")


def _es_worker() -> None:
    from .es_client import index_findings, is_available as es_ok
    assert _es_q is not None
    while True:
        item = _es_q.get()
        try:
            if not es_ok():
                continue
            n = index_findings(
                item.get("rid") or "",
                item.get("hostname") or "",
                item.get("analyzed_at") or "",
                item.get("findings") or [],
            )
            if n:
                print(f"[store] es indexed {n} findings for {item.get('rid')}")
        except Exception as e:
            print(f"[store] es index {item.get('rid')}: {e}")
        finally:
            try:
                _es_q.task_done()
            except Exception:
                pass


def _es_index_async(rid: str, hostname: str, analysis: Dict[str, Any]) -> None:
    """兼容旧调用：改走有界队列。"""
    _es_enqueue(rid, hostname, analysis)


def save_ai_result(report_file: str, ai: Dict[str, Any], report: Optional[Dict[str, Any]] = None) -> Path:
    """单独写出 AI 研判结果（不覆盖规则匹配 result.json 的主体）。"""
    rid = P.report_id(report_file)
    P.report_dir(rid, create=True)
    payload = {
        "file": rid,
        "folder": P.report_stem(rid),
        "hostname": (report or {}).get("hostname") or "",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ai": ai,
    }
    path = P.ai_result_json_path(rid, create_dir=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    # 同步进 result.json 的 analysis.ai（若存在）
    rp = P.result_json_path(rid)
    if rp.exists():
        try:
            with open(rp, encoding="utf-8") as f:
                result = json.load(f)
            if not isinstance(result, dict):
                result = {}
            analysis = result.get("analysis") if isinstance(result.get("analysis"), dict) else {}
            analysis["ai"] = ai
            result["analysis"] = analysis
            with open(rp, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, separators=(",", ":"))
        except Exception as e:
            print(f"[store] merge ai into result.json failed: {e}")

    try:
        upsert_ai_blob(rid, ai)
    except Exception as e:
        print(f"[store] upsert_ai_blob failed: {e}")

    try:
        from .mysql_store import upsert_ai_mysql
        upsert_ai_mysql(rid, ai, hostname=payload.get("hostname") or "")
    except Exception as e:
        print(f"[store] upsert_ai_mysql failed: {e}")

    return path


def load_ai_result(report_file: str) -> Optional[Dict[str, Any]]:
    rid = P.report_id(report_file)
    # 本地专用结果文件是最便宜、也是 save_ai_result 的主落点；避免每次先等 MySQL。
    path = P.ai_result_json_path(rid)
    if not path.exists():
        # 本地文件不存在时 MySQL 里几乎不会有（save_ai_result 先写本地再写 MySQL），
        # 直接跳过阻塞查询，把 7-27s 的慢 404 变成即时返回。
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass
    # 文件存在但解析失败时才尝试 MySQL 兜底。
    try:
        from .mysql_store import load_ai_from_mysql
        m = load_ai_from_mysql(rid)
        if m:
            return m
    except Exception:
        pass
    return None


def save_section_ai_result(
    report_file: str,
    section: str,
    ai: Dict[str, Any],
    *,
    scope: str = "all",
    item_count: int = 0,
    hostname: str = "",
) -> Path:
    """落盘模块级 AI 结果（本地文件，不进 Redis）。"""
    rid = P.report_id(report_file)
    payload = {
        "file": rid,
        "section": str(section or "").strip().lower(),
        "scope": str(scope or "all").strip() or "all",
        "item_count": int(item_count or 0),
        "hostname": hostname or "",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ai": ai,
    }
    path = P.ai_section_result_path(rid, section, payload["scope"], create_dir=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def load_section_ai_result(
    report_file: str,
    section: str,
    scope: str = "all",
) -> Optional[Dict[str, Any]]:
    rid = P.report_id(report_file)
    path = P.ai_section_result_path(rid, section, scope or "all")
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None
