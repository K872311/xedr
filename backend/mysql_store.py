"""MySQL 报告索引 / 分析摘要 / findings / AI 读写。"""
from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional

from . import config
from . import paths as P
from . import mysql_db
from .iputil import pick_primary_ip

SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS reports (
        file VARCHAR(255) NOT NULL PRIMARY KEY,
        host_id VARCHAR(32) DEFAULT NULL,
        hostname VARCHAR(128) DEFAULT '',
        collect_time VARCHAR(64) DEFAULT '',
        ip VARCHAR(255) DEFAULT '',
        issues INT DEFAULT 0,
        raw_issues INT DEFAULT 0,
        analyzed TINYINT DEFAULT 0,
        processes INT DEFAULT 0,
        services INT DEFAULT 0,
        files INT DEFAULT 0,
        folder VARCHAR(255) DEFAULT '',
        db_path VARCHAR(512) DEFAULT '',
        report_path VARCHAR(512) DEFAULT '',
        owner_id VARCHAR(64) DEFAULT '',
        owner_username VARCHAR(128) DEFAULT '',
        updated_at DOUBLE,
        KEY idx_reports_host_id (host_id),
        KEY idx_reports_hostname (hostname),
        KEY idx_reports_time (collect_time),
        KEY idx_reports_owner (owner_id),
        KEY idx_reports_host_time (hostname, collect_time, file),
        KEY idx_reports_owner_time (owner_id, collect_time, file)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS report_analysis (
        file VARCHAR(255) NOT NULL PRIMARY KEY,
        summary MEDIUMTEXT,
        summary_aggregated MEDIUMTEXT,
        pipeline MEDIUMTEXT,
        timeline MEDIUMTEXT,
        findings_by_module MEDIUMTEXT,
        analysis_meta MEDIUMTEXT,
        raw_findings_total INT DEFAULT 0,
        updated_at DOUBLE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS findings_agg (
        file VARCHAR(255) NOT NULL,
        id VARCHAR(255) NOT NULL,
        category VARCHAR(128) DEFAULT '',
        severity VARCHAR(32) DEFAULT 'medium',
        title VARCHAR(512) DEFAULT '',
        count INT DEFAULT 1,
        evidence MEDIUMTEXT,
        sources MEDIUMTEXT,
        rule_id VARCHAR(128) DEFAULT '',
        matcher VARCHAR(128) DEFAULT '',
        extra MEDIUMTEXT,
        PRIMARY KEY (file, id),
        KEY idx_findings_severity (severity),
        KEY idx_findings_category (category),
        KEY idx_findings_file_severity (file, severity),
        KEY idx_findings_file_category (file, category)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
    """
    CREATE TABLE IF NOT EXISTS ai_results (
        file VARCHAR(255) NOT NULL PRIMARY KEY,
        hostname VARCHAR(128) DEFAULT '',
        generated_at VARCHAR(64) DEFAULT '',
        ai MEDIUMTEXT,
        updated_at DOUBLE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """,
]


def _jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _jload(s: Optional[str], default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def ensure_analysis_tables(conn=None) -> None:
    own = conn is None
    if own:
        if not mysql_db.mysql_ready():
            return
        conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            for sql in SCHEMA_SQL:
                cur.execute(sql)
            # 旧表补列
            for col, ddl in (
                ("owner_id", "VARCHAR(64) DEFAULT ''"),
                ("owner_username", "VARCHAR(128) DEFAULT ''"),
                ("os_family", "VARCHAR(16) DEFAULT ''"),
                ("os", "VARCHAR(200) DEFAULT ''"),
            ):
                try:
                    cur.execute(f"ALTER TABLE reports ADD COLUMN {col} {ddl}")
                except Exception:
                    pass
            # 旧库补组合索引；放在启动迁移，不进入任何 GET 读路径。
            for table, name, columns in (
                ("reports", "idx_reports_host_time", "hostname,collect_time,file"),
                ("reports", "idx_reports_owner_time", "owner_id,collect_time,file"),
                ("findings_agg", "idx_findings_file_severity", "file,severity"),
                ("findings_agg", "idx_findings_file_category", "file,category"),
            ):
                try:
                    cur.execute(f"CREATE INDEX {name} ON {table}({columns})")
                except Exception:
                    pass
        conn.commit()
    finally:
        if own:
            conn.close()


def upsert_report_row(row: Dict[str, Any]) -> bool:
    """写入/更新 reports 索引行（含 host_id / owner）。"""
    if not mysql_db.mysql_ready():
        return False
    from .ownership import resolve_owner_fields
    rid = P.report_id(row["file"])
    hostname = (row.get("hostname") or "").strip()
    host_id = row.get("host_id") or ""
    if not host_id and hostname and hostname != "unknown":
        try:
            from .hosts import ensure_host
            h = ensure_host(hostname, row.get("ip") or "")
            host_id = h.get("id") or ""
        except Exception as e:
            print("[mysql_store] ensure_host:", e)

    folder = row.get("folder") or P.report_stem(rid)
    db_path = row.get("db_path") or ""
    report_path = row.get("report_path") or ""
    if not report_path:
        jp = P.resolve_report_json(rid) or P.report_json_path(rid)
        try:
            report_path = str(jp.relative_to(config.REPORTS_DIR)).replace("\\", "/")
        except Exception:
            report_path = str(jp)
    owner = resolve_owner_fields(row)

    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports(
                    file, host_id, hostname, collect_time, ip, issues, raw_issues,
                    analyzed, processes, services, files, folder, db_path, report_path,
                    owner_id, owner_username, os_family, os, updated_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    host_id=VALUES(host_id), hostname=VALUES(hostname),
                    collect_time=VALUES(collect_time), ip=VALUES(ip),
                    issues=VALUES(issues), raw_issues=VALUES(raw_issues),
                    analyzed=VALUES(analyzed), processes=VALUES(processes),
                    services=VALUES(services), files=VALUES(files),
                    folder=VALUES(folder), db_path=VALUES(db_path),
                    report_path=VALUES(report_path),
                    owner_id=IF(VALUES(owner_id)<>'', VALUES(owner_id), owner_id),
                    owner_username=IF(VALUES(owner_username)<>'', VALUES(owner_username), owner_username),
                    os_family=IF(VALUES(os_family)<>'', VALUES(os_family), os_family),
                    os=IF(VALUES(os)<>'', VALUES(os), os),
                    updated_at=VALUES(updated_at)
                """,
                (
                    rid,
                    host_id or None,
                    hostname,
                    row.get("collect_time") or "",
                    row.get("ip") or "",
                    int(row.get("issues") or 0),
                    int(row.get("raw_issues") or 0),
                    1 if row.get("analyzed") else 0,
                    int(row.get("processes") or 0),
                    int(row.get("services") or 0),
                    int(row.get("files") or 0),
                    folder,
                    db_path,
                    report_path,
                    owner.get("owner_id") or "",
                    owner.get("owner_username") or "",
                    str(row.get("os_family") or "").strip().lower(),
                    str(row.get("os") or "").strip()[:200],
                    time.time(),
                ),
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[mysql_store] upsert_report_row: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()


def delete_report_row(report_file: str) -> None:
    if not mysql_db.mysql_ready():
        return
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM findings_agg WHERE file=%s", (rid,))
            cur.execute("DELETE FROM report_analysis WHERE file=%s", (rid,))
            cur.execute("DELETE FROM ai_results WHERE file=%s", (rid,))
            cur.execute("DELETE FROM reports WHERE file=%s", (rid,))
        conn.commit()
    except Exception as e:
        print(f"[mysql_store] delete_report_row: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        conn.close()


def delete_reports_by_hostname(hostname: str) -> int:
    if not mysql_db.mysql_ready():
        return 0
    hostname = (hostname or "").strip()
    if not hostname:
        return 0
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT file FROM reports WHERE hostname=%s", (hostname,))
            files = [r["file"] for r in (cur.fetchall() or []) if r.get("file")]
            if not files:
                return 0
            cur.execute(
                "DELETE f FROM findings_agg f INNER JOIN reports r ON r.file=f.file WHERE r.hostname=%s",
                (hostname,),
            )
            cur.execute(
                "DELETE a FROM report_analysis a INNER JOIN reports r ON r.file=a.file WHERE r.hostname=%s",
                (hostname,),
            )
            cur.execute(
                "DELETE a FROM ai_results a INNER JOIN reports r ON r.file=a.file WHERE r.hostname=%s",
                (hostname,),
            )
            cur.execute("DELETE FROM reports WHERE hostname=%s", (hostname,))
        conn.commit()
        return len(files)
    except Exception as e:
        print(f"[mysql_store] delete_reports_by_hostname: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def delete_report_files(files: List[str]) -> int:
    """按报告 ID 批量删 MySQL 分析副本（一次连接）。"""
    if not mysql_db.mysql_ready():
        return 0
    rids = [P.report_id(x) for x in (files or []) if str(x or "").strip()]
    rids = list(dict.fromkeys(rids))
    if not rids:
        return 0
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            chunk = 200
            for i in range(0, len(rids), chunk):
                part = rids[i:i + chunk]
                ph = ",".join(["%s"] * len(part))
                cur.execute(f"DELETE FROM findings_agg WHERE file IN ({ph})", part)
                cur.execute(f"DELETE FROM report_analysis WHERE file IN ({ph})", part)
                cur.execute(f"DELETE FROM ai_results WHERE file IN ({ph})", part)
                cur.execute(f"DELETE FROM reports WHERE file IN ({ph})", part)
        conn.commit()
        return len(rids)
    except Exception as e:
        print(f"[mysql_store] delete_report_files: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rename_reports_hostname(old_name: str, new_name: str) -> int:
    if not mysql_db.mysql_ready():
        return 0
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE reports SET hostname=%s, updated_at=%s WHERE hostname=%s",
                (new_name, time.time(), old_name),
            )
            n = cur.rowcount
            cur.execute(
                "UPDATE ai_results SET hostname=%s WHERE hostname=%s",
                (new_name, old_name),
            )
        conn.commit()
        return int(n or 0)
    except Exception as e:
        print(f"[mysql_store] rename_reports_hostname: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return 0
    finally:
        conn.close()


def save_analysis_mysql(report: Dict[str, Any], analysis: Dict[str, Any], fname: str) -> bool:
    """写入 report_analysis + findings_agg，并更新 reports 索引。"""
    if not mysql_db.mysql_ready():
        return False
    try:
        ensure_analysis_tables()
    except Exception:
        pass
    rid = P.report_id(fname)
    summary = analysis.get("summary") or {}
    summary_agg = analysis.get("summary_aggregated") or {}
    pipe = analysis.get("pipeline") or {}
    pipe_slim = {
        "matchers": pipe.get("matchers") or [],
        "rules_used": pipe.get("rules_used") or [],
    }
    timeline = (analysis.get("timeline") or [])[:500]
    fbm = analysis.get("findings_by_module") or {}
    fbm_slim = {}
    _mod_sample = 300
    for k, block in fbm.items():
        if not isinstance(block, dict):
            continue
        items = block.get("findings") or []
        fbm_slim[k] = {
            "matcher": block.get("matcher") or k,
            "count": block.get("count") or len(items),
            "high": block.get("high") or 0,
            "findings": items[:_mod_sample],
            "truncated": len(items) > _mod_sample,
        }
    raw = analysis.get("findings") or []
    agg_items = analysis.get("findings_aggregated") or []

    dbp = P.db_path_for_write(rid)
    try:
        db_rel = str(dbp.relative_to(config.REPORTS_DIR)).replace("\\", "/")
    except Exception:
        db_rel = str(dbp)
    jp = P.report_json_path(rid)
    try:
        report_rel = str(jp.relative_to(config.REPORTS_DIR)).replace("\\", "/")
    except Exception:
        report_rel = str(jp)

    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO report_analysis(
                    file, summary, summary_aggregated, pipeline, timeline,
                    findings_by_module, analysis_meta, raw_findings_total, updated_at
                ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    summary=VALUES(summary), summary_aggregated=VALUES(summary_aggregated),
                    pipeline=VALUES(pipeline), timeline=VALUES(timeline),
                    findings_by_module=VALUES(findings_by_module),
                    analysis_meta=VALUES(analysis_meta),
                    raw_findings_total=VALUES(raw_findings_total),
                    updated_at=VALUES(updated_at)
                """,
                (
                    rid,
                    _jdump(summary),
                    _jdump(summary_agg),
                    _jdump(pipe_slim),
                    _jdump(timeline),
                    _jdump(fbm_slim),
                    _jdump(analysis.get("meta") or {}),
                    len(raw),
                    time.time(),
                ),
            )
            cur.execute("DELETE FROM findings_agg WHERE file=%s", (rid,))
            batch = []
            for item in agg_items:
                if not isinstance(item, dict):
                    continue
                fid = item.get("id") or f"{item.get('category')}|{item.get('title')}"
                batch.append((
                    rid,
                    str(fid)[:255],
                    (item.get("category") or "")[:128],
                    (item.get("severity") or "medium")[:32],
                    (item.get("title") or "")[:512],
                    int(item.get("count") or 1),
                    _jdump(item.get("evidence") or []),
                    _jdump(item.get("sources") or []),
                    (item.get("rule_id") or "")[:128],
                    (item.get("matcher") or "")[:128],
                    _jdump({k: item.get(k) for k in ("type", "name", "reason") if k in item}),
                ))
            if batch:
                cur.executemany(
                    """
                    INSERT INTO findings_agg(
                        file, id, category, severity, title, count,
                        evidence, sources, rule_id, matcher, extra
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    batch,
                )
            if analysis.get("ai"):
                cur.execute(
                    """
                    INSERT INTO ai_results(file, hostname, generated_at, ai, updated_at)
                    VALUES(%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                        hostname=VALUES(hostname), generated_at=VALUES(generated_at),
                        ai=VALUES(ai), updated_at=VALUES(updated_at)
                    """,
                    (
                        rid,
                        report.get("hostname") or "",
                        time.strftime("%Y-%m-%dT%H:%M:%S"),
                        _jdump(analysis["ai"]),
                        time.time(),
                    ),
                )
        conn.commit()
    except Exception as e:
        print(f"[mysql_store] save_analysis_mysql: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()

    upsert_report_row({
        "file": rid,
        "hostname": report.get("hostname"),
        "collect_time": report.get("collect_time"),
        "ip": pick_primary_ip(report.get("ip") or ""),
        "issues": (summary_agg.get("total") if summary_agg else None) or summary.get("total") or 0,
        "raw_issues": summary.get("total") or len(raw),
        "analyzed": True,
        "processes": len(report.get("processes") or []),
        "services": len(report.get("services") or []),
        "files": len(report.get("file_scans") or []),
        "folder": P.report_stem(rid),
        "db_path": db_rel,
        "report_path": report_rel,
        "os_family": report.get("os_family") or "",
        "os": report.get("os") or "",
    })
    return True


def upsert_ai_mysql(report_file: str, ai: Dict[str, Any], hostname: str = "") -> bool:
    if not mysql_db.mysql_ready():
        return False
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ai_results(file, hostname, generated_at, ai, updated_at)
                VALUES(%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    hostname=VALUES(hostname), generated_at=VALUES(generated_at),
                    ai=VALUES(ai), updated_at=VALUES(updated_at)
                """,
                (
                    rid,
                    hostname or "",
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    _jdump(ai),
                    time.time(),
                ),
            )
        conn.commit()
        return True
    except Exception as e:
        print(f"[mysql_store] upsert_ai_mysql: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()


def list_reports_mysql(limit: int = 100, user: Optional[Dict[str, Any]] = None) -> Optional[List[Dict[str, Any]]]:
    """返回报告列表。user 非 admin 时按归属过滤。失败返回 []；表不存在等返回 None 以便回退 SQLite。"""
    if not mysql_db.mysql_ready():
        return None
    from .ownership import is_admin
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            if user and not is_admin(user):
                uid = str(user.get("id") or "")
                uname = str(user.get("username") or "")
                cur.execute(
                    """
                    SELECT * FROM reports
                    WHERE (owner_id<>'' AND owner_id=%s)
                       OR (owner_username<>'' AND owner_username=%s)
                    ORDER BY collect_time DESC, file DESC
                    LIMIT %s
                    """,
                    (uid, uname, int(limit)),
                )
            else:
                cur.execute(
                    """
                    SELECT * FROM reports
                    ORDER BY collect_time DESC, file DESC
                    LIMIT %s
                    """,
                    (int(limit),),
                )
            rows = cur.fetchall() or []
        out = []
        for r in rows:
            rid = r["file"]
            out.append({
                "file": rid,
                "db": r.get("db_path") or "",
                "hostname": r.get("hostname") or "",
                "time": r.get("collect_time") or "",
                "ip": r.get("ip") or "",
                "issues": r.get("issues") or 0,
                "raw_issues": r.get("raw_issues") or 0,
                "analyzed": bool(r.get("analyzed")),
                "processes": r.get("processes") or 0,
                "services": r.get("services") or 0,
                "files": r.get("files") or 0,
                "host_id": r.get("host_id") or "",
                "folder": r.get("folder") or P.report_stem(rid),
                "owner_id": r.get("owner_id") or "",
                "owner_username": r.get("owner_username") or "",
                "os_family": r.get("os_family") or "",
                "os": r.get("os") or "",
            })
        return out
    except Exception as e:
        print(f"[mysql_store] list_reports_mysql: {e}")
        return None
    finally:
        conn.close()


def get_report_owner_mysql(report_file: str) -> Optional[Dict[str, str]]:
    if not mysql_db.mysql_ready():
        return None
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT owner_id, owner_username FROM reports WHERE file=%s", (rid,)
            )
            row = cur.fetchone()
            if not row:
                return {"owner_id": "", "owner_username": ""}
            return {
                "owner_id": row.get("owner_id") or "",
                "owner_username": row.get("owner_username") or "",
            }
    except Exception as e:
        print(f"[mysql_store] get_report_owner_mysql: {e}")
        return None
    finally:
        conn.close()


def load_finding_row_mysql(report_file: str, finding_id: str) -> Optional[Dict[str, Any]]:
    """按 id 取单条聚合告警（含完整 evidence）。"""
    if not mysql_db.mysql_ready():
        return None
    rid = P.report_id(report_file)
    fid = str(finding_id or "").strip()
    if not fid:
        return None
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, title, count, evidence, extra FROM findings_agg WHERE file=%s AND id=%s",
                (rid, fid),
            )
            row = cur.fetchone()
            if not row:
                return None
            item = {
                "id": row.get("id") or fid,
                "title": row.get("title") or "",
                "count": row.get("count") or 1,
                "evidence": _jload(row.get("evidence"), []),
                "extra": _jload(row.get("extra"), {}) or {},
            }
            if isinstance(item["extra"], dict):
                if item["extra"].get("evidence_total") is not None:
                    item["evidence_total"] = item["extra"].get("evidence_total")
            return item
    except Exception as e:
        print(f"[mysql_store] load_finding_row_mysql: {e}")
        return None
    finally:
        conn.close()


def get_report_meta_mysql(report_file: str) -> Optional[Dict[str, Any]]:
    """索引元数据：hostname + 归属。找不到返回空壳；查询失败返回 None。"""
    if not mysql_db.mysql_ready():
        return None
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT file, hostname, owner_id, owner_username FROM reports WHERE file=%s",
                (rid,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "file": row.get("file") or rid,
                "hostname": row.get("hostname") or "",
                "owner_id": row.get("owner_id") or "",
                "owner_username": row.get("owner_username") or "",
            }
    except Exception as e:
        print(f"[mysql_store] get_report_meta_mysql: {e}")
        return None
    finally:
        conn.close()


def load_analysis_from_mysql(report_file: str) -> Optional[Dict[str, Any]]:
    """返回 analysis 片段：summary / findings_aggregated / ai / timeline 等。"""
    if not mysql_db.mysql_ready():
        return None
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM report_analysis WHERE file=%s", (rid,))
            ra = cur.fetchone()
            if not ra:
                return None
            cur.execute("SELECT * FROM findings_agg WHERE file=%s", (rid,))
            findings_rows = cur.fetchall() or []
            cur.execute("SELECT ai FROM ai_results WHERE file=%s", (rid,))
            ai_row = cur.fetchone()
        findings = []
        for r in findings_rows:
            item = {
                "id": r["id"],
                "category": r.get("category") or "",
                "severity": r.get("severity") or "medium",
                "title": r.get("title") or "",
                "count": r.get("count") or 1,
                "evidence": _jload(r.get("evidence"), []),
                "sources": _jload(r.get("sources"), []),
                "rule_id": r.get("rule_id") or "",
                "matcher": r.get("matcher") or "",
                "type": r.get("category") or "",
                "name": r.get("title") or "",
            }
            extra = _jload(r.get("extra"), {}) or {}
            item.update(extra)
            if not item.get("reason"):
                ev = item.get("evidence")
                item["reason"] = ev[0] if isinstance(ev, list) and ev else item["title"]
            findings.append(item)
        analysis = {
            "summary": _jload(ra.get("summary"), {}) or {},
            "summary_aggregated": _jload(ra.get("summary_aggregated"), {}) or {},
            "pipeline": _jload(ra.get("pipeline"), {}) or {},
            "timeline": _jload(ra.get("timeline"), []) or [],
            "findings_by_module": _jload(ra.get("findings_by_module"), {}) or {},
            "meta": _jload(ra.get("analysis_meta"), {}) or {},
            "findings_aggregated": findings,
            "findings": findings,
            "_findings_total": ra.get("raw_findings_total") or len(findings),
            "_source": "mysql",
        }
        if ai_row and ai_row.get("ai"):
            analysis["ai"] = _jload(ai_row["ai"], {}) or {}
        return analysis
    except Exception as e:
        print(f"[mysql_store] load_analysis_from_mysql: {e}")
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


#: None 表示还没探测过；探测一次后缓存结果
_FT_READY: Optional[bool] = None
#: ngram 分词器默认 token 长度为 2，短于此长度的词建不进索引
_NGRAM_MIN = 2


def ensure_findings_fulltext() -> bool:
    """给 findings_agg 建生成列 + ngram 全文索引；返回是否可用。

    原来的 CONCAT_WS(...) LIKE '%x%' 无法用任何索引，只能全表扫。
    改成 STORED 生成列上的 FULLTEXT，中文要用 ngram 解析器
    （默认解析器按空白切词，切不开中文）。
    虚拟生成列不支持 FULLTEXT，必须 STORED。
    """
    global _FT_READY
    if _FT_READY is not None:
        return _FT_READY
    if not mysql_db.mysql_ready():
        return False
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT COUNT(*) AS c FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings_agg'
                     AND INDEX_NAME='ft_findings_blob'"""
            )
            if int((cur.fetchone() or {}).get("c") or 0) > 0:
                _FT_READY = True
                return True
            cur.execute(
                """SELECT COUNT(*) AS c FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='findings_agg'
                     AND COLUMN_NAME='search_blob'"""
            )
            if int((cur.fetchone() or {}).get("c") or 0) == 0:
                cur.execute(
                    """ALTER TABLE findings_agg
                       ADD COLUMN search_blob MEDIUMTEXT
                       GENERATED ALWAYS AS (CONCAT_WS(' ',
                           IFNULL(title,''), IFNULL(evidence,''), IFNULL(category,''),
                           IFNULL(rule_id,''), IFNULL(extra,''), IFNULL(matcher,''),
                           IFNULL(file,'')
                       )) STORED"""
                )
            cur.execute(
                "ALTER TABLE findings_agg "
                "ADD FULLTEXT KEY ft_findings_blob (search_blob) WITH PARSER ngram"
            )
        conn.commit()
        _FT_READY = True
    except Exception as e:
        print(f"[mysql_store] findings fulltext unavailable, fallback to LIKE: {e}")
        _FT_READY = False
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return _FT_READY


def _boolean_phrase(needle: str) -> str:
    """转成 BOOLEAN MODE 的短语检索，语义等价于原来的子串匹配。"""
    return '"' + needle.replace('"', " ").strip() + '"'


def search_findings_mysql(
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
    offset: int = 0,
) -> tuple[List[Dict[str, Any]], int]:
    """在 findings_agg 里搜告警标题 / 证据 / 分类 / 规则。

    返回 (本页, 命中总数)。总数不再用 COUNT(*) 精确统计，而是多取一条判断
    还有没有下一页；结果能一页装下时总数仍然是准的。
    """
    needle = (q or "").strip()
    if not needle or not mysql_db.mysql_ready():
        return [], 0

    from backend.search_sql import LIKE_ESCAPE, glob_to_like, has_glob_meta

    use_glob = has_glob_meta(needle)
    use_ft = (not use_glob) and len(needle) >= _NGRAM_MIN and ensure_findings_fulltext()
    args: List[Any] = []
    if use_ft:
        # 生成列只能取 findings_agg 自身的列，取不到 r.hostname；
        # 主机名一般已包含在 f.file 里（报告 id 以主机名开头），仍可命中。
        from_sql = """
            FROM findings_agg f
            LEFT JOIN reports r ON r.file=f.file
            WHERE MATCH(f.search_blob) AGAINST (%s IN BOOLEAN MODE)
        """
        args.append(_boolean_phrase(needle))
    elif use_glob:
        like = glob_to_like(needle).lower()
        from_sql = f"""
            FROM findings_agg f
            LEFT JOIN reports r ON r.file=f.file
            WHERE LOWER(CONCAT_WS(' ',
                IFNULL(f.title,''), IFNULL(f.evidence,''), IFNULL(f.category,''),
                IFNULL(f.rule_id,''), IFNULL(f.extra,''), IFNULL(f.matcher,''),
                IFNULL(r.hostname,''), IFNULL(f.file,'')
            )) LIKE %s ESCAPE '{LIKE_ESCAPE}'
        """
        args.append(like)
    else:
        from_sql = """
            FROM findings_agg f
            LEFT JOIN reports r ON r.file=f.file
            WHERE LOWER(CONCAT_WS(' ',
                IFNULL(f.title,''), IFNULL(f.evidence,''), IFNULL(f.category,''),
                IFNULL(f.rule_id,''), IFNULL(f.extra,''), IFNULL(f.matcher,''),
                IFNULL(r.hostname,''), IFNULL(f.file,'')
            )) LIKE %s
        """
        args.append(f"%{needle.lower()}%")
    if hostname:
        from_sql += " AND r.hostname=%s"
        args.append(hostname)
    if severity:
        from_sql += " AND f.severity=%s"
        args.append(severity)
    try:
        from .ownership import is_admin
        if user and not is_admin(user):
            uid = str(user.get("id") or "").strip()
            from_sql += " AND r.owner_id<>'' AND r.owner_id=%s"
            args.append(uid)
    except Exception:
        pass
    size_v = max(1, int(size))
    offset_v = max(0, int(offset))
    list_sql = (
        "SELECT f.file, f.category, f.severity, f.title, f.evidence, f.matcher, f.rule_id, f.extra, "
        "r.hostname, IFNULL(r.os_family,'') AS os_family "
        + from_sql
        + " ORDER BY f.severity='high' DESC, f.file, f.rule_id, f.title LIMIT %s OFFSET %s"
    )
    # 多取一条用来判断是否还有下一页，省掉一次全量 COUNT(*)
    list_args = list(args) + [size_v + 1, offset_v]
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(list_sql, list_args)
            rows = cur.fetchall() or []
        has_more = len(rows) > size_v
        rows = rows[:size_v]
        total = offset_v + len(rows) + (1 if has_more else 0)
        out = []
        for r in rows:
            ev = _jload(r.get("evidence"), [])
            if isinstance(ev, list):
                ev_s = "；".join(str(x) for x in ev[:4])
            else:
                ev_s = str(ev or "")
            extra = _jload(r.get("extra"), {}) or {}
            out.append({
                "report_id": r.get("file") or "",
                "hostname": r.get("hostname") or "",
                "severity": r.get("severity") or "medium",
                "category": r.get("category") or "",
                "title": r.get("title") or extra.get("name") or "",
                "evidence": ev_s or extra.get("reason") or "",
                "matcher": r.get("matcher") or "",
                "rule_id": r.get("rule_id") or "",
                "_source": "mysql",
                "os_family": str(r.get("os_family") or "").strip().lower(),
                "extra": extra if isinstance(extra, dict) else {},
                "path": str(extra.get("path") or ""),
                "command": str(extra.get("command") or extra.get("image_path") or extra.get("path") or ""),
                "image_path": str(extra.get("image_path") or ""),
                "md5": str(extra.get("md5") or ""),
                "sha1": str(extra.get("sha1") or ""),
                "sha256": str(extra.get("sha256") or ""),
            })
        return out, total
    except Exception as e:
        print(f"[mysql_store] search_findings_mysql: {e}")
        return [], 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


def load_ai_from_mysql(report_file: str) -> Optional[Dict[str, Any]]:
    if not mysql_db.mysql_ready():
        return None
    rid = P.report_id(report_file)
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM ai_results WHERE file=%s", (rid,))
            row = cur.fetchone()
        if not row or not row.get("ai"):
            return None
        return {
            "file": rid,
            "hostname": row.get("hostname") or "",
            "generated_at": row.get("generated_at") or "",
            "ai": _jload(row["ai"], {}) or {},
            "source": "mysql",
        }
    except Exception as e:
        print(f"[mysql_store] load_ai_from_mysql: {e}")
        return None
    finally:
        conn.close()


def migrate_index_sqlite_to_mysql() -> int:
    """把 SQLite index 中 MySQL 尚缺的报告补迁入。

    MySQL 为主：已有记录不覆盖；仅补宕机期间只写到本地的条目（恢复后补迁）。
    """
    if not mysql_db.mysql_ready():
        return 0
    from .db_store import INDEX_DB, _connect, _init_index

    if not INDEX_DB.exists():
        return 0

    existing: set = set()
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT file FROM reports")
            existing = {r["file"] for r in (cur.fetchall() or []) if r.get("file")}
    except Exception as e:
        print(f"[mysql_store] list reports for catch-up: {e}")
        return 0
    finally:
        conn.close()

    src = _connect(INDEX_DB)
    n = 0
    try:
        _init_index(src)
        rows = src.execute("SELECT * FROM reports").fetchall()
        for r in rows:
            rid = r["file"]
            if not rid or rid in existing:
                continue
            ok = upsert_report_row({
                "file": rid,
                "db_path": r["db_path"] or "",
                "hostname": r["hostname"] or "",
                "collect_time": r["collect_time"] or "",
                "ip": r["ip"] or "",
                "issues": r["issues"] or 0,
                "raw_issues": r["raw_issues"] or 0,
                "analyzed": bool(r["analyzed"]),
                "processes": r["processes"] or 0,
                "services": r["services"] or 0,
                "files": r["files"] or 0,
                "folder": P.report_stem(rid),
                "owner_id": r["owner_id"] if "owner_id" in r.keys() else "",
                "owner_username": r["owner_username"] if "owner_username" in r.keys() else "",
                "os_family": r["os_family"] if "os_family" in r.keys() else "",
                "os": r["os"] if "os" in r.keys() else "",
            })
            if ok:
                n += 1
                existing.add(rid)
                try:
                    _migrate_one_analysis_db(rid)
                except Exception as e:
                    print(f"[mysql_store] migrate analysis {rid}: {e}")
    finally:
        src.close()
    if n:
        print(f"[mysql_store] catch-up {n} report index rows sqlite → mysql")
    return n


def _migrate_one_analysis_db(report_file: str) -> bool:
    """从本地 analysis.db 抽出摘要/findings 写入 MySQL。"""
    from .db_store import _connect as sqlite_connect, _init_schema, _jload as sjload

    dbp = P.resolve_analysis_db(report_file)
    if not dbp or not dbp.exists():
        return False
    rid = P.report_id(report_file)
    conn = sqlite_connect(dbp)
    try:
        _init_schema(conn)
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
        blobs = {r["name"]: sjload(r["data"]) for r in conn.execute("SELECT name,data FROM blobs")}
        findings_rows = list(conn.execute("SELECT * FROM findings_agg"))
        try:
            files_count = int(conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] or 0)
        except Exception:
            files_count = 0
    finally:
        conn.close()

    analysis = {
        "summary": blobs.get("summary") or {},
        "summary_aggregated": blobs.get("summary_aggregated") or {},
        "pipeline": blobs.get("pipeline") or {},
        "timeline": blobs.get("timeline") or [],
        "findings_by_module": blobs.get("findings_by_module") or {},
        "meta": blobs.get("analysis_meta") or {},
        "findings": blobs.get("findings_raw_sample") or [],
        "findings_aggregated": [],
        "ai": blobs.get("ai"),
    }
    for r in findings_rows:
        item = {
            "id": r["id"],
            "category": r["category"],
            "severity": r["severity"],
            "title": r["title"],
            "count": r["count"],
            "evidence": sjload(r["evidence"], []),
            "sources": sjload(r["sources"], []),
            "rule_id": r["rule_id"],
            "matcher": r["matcher"],
        }
        extra = sjload(r["extra"], {}) or {}
        item.update(extra)
        analysis["findings_aggregated"].append(item)

    processes = blobs.get("processes") if isinstance(blobs.get("processes"), list) else []
    services = blobs.get("services") if isinstance(blobs.get("services"), list) else []
    report = {
        "hostname": meta.get("hostname") or "",
        "ip": meta.get("ip") or "",
        "collect_time": meta.get("collect_time") or "",
        "processes": processes,
        "services": services,
        "file_scans": [{}] * files_count,  # 仅用于计数
    }
    return save_analysis_mysql(report, analysis, rid)


def table_counts() -> Dict[str, int]:
    if not mysql_db.mysql_ready():
        return {}
    conn = mysql_db.connect_mysql()
    out = {}
    try:
        with conn.cursor() as cur:
            for t in ("hosts", "reports", "report_analysis", "findings_agg", "ai_results", "users"):
                try:
                    cur.execute(f"SELECT COUNT(*) AS c FROM `{t}`")
                    out[t] = int((cur.fetchone() or {}).get("c") or 0)
                except Exception:
                    out[t] = -1
        return out
    finally:
        conn.close()
