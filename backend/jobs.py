"""分析任务队列：持久化 + 分阶段进度（load → fast → full），重启可恢复。"""
from __future__ import annotations
import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import config
from . import paths as P
from .db_store import _connect
from .ingest import slim_report
from .pipeline import JobCancelled, analyze_report
from .store import save_analysis

JOBS_DB = config.REPORTS_DIR / "jobs.db"

_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}
_queue: List[str] = []
_worker_started = False
_max_workers = 10
_active = 0
_recovered = False
# 大报告（事件日志/文件扫描上万条）同时跑会占满 GIL 和 MySQL 连接池，
# 批量上传时把其它接口一起拖死。轻任务仍可并行，重任务单独限流。
_heavy_active = 0
_heavy_max = 3


class QueueRejected(Exception):
    """入队被容量策略拒绝（单用户上限等）。"""

    def __init__(self, detail: str, code: int = 429):
        super().__init__(detail)
        self.detail = detail
        self.code = int(code or 429)
_HEAVY_EVENTS = 20_000
_HEAVY_FILES = 8_000
_HEAVY_JSON_BYTES = 40 * 1024 * 1024
_HEAVY_PARK_EVENTS_BYTES = 8 * 1024 * 1024
_HEAVY_PARK_FILES_BYTES = 16 * 1024 * 1024

# 对外状态（用于 pill / 去重）
# queued | load | fast | full | partial | done | error | cancelled | skipped
_TERMINAL = frozenset({"done", "error", "cancelled", "skipped"})
_ACTIVE = frozenset({"load", "fast", "full", "partial", "save_fast", "save_full"})
_BUSY = _ACTIVE | frozenset({"queued"})

PHASE_LABELS = {
    "queued": "排队中",
    "load": "加载报告",
    "fast": "快速匹配",
    "save_fast": "保存快匹配",
    "full": "全量匹配",
    "partial": "局部重跑",
    "save_full": "保存结果",
    "done": "已完成",
    "error": "失败",
    "cancelled": "已取消",
    "skipped": "已跳过",
}

JOBS_MYSQL_SQL = """
CREATE TABLE IF NOT EXISTS analyze_jobs (
    id VARCHAR(32) NOT NULL PRIMARY KEY,
    file VARCHAR(255) NOT NULL DEFAULT '',
    hostname VARCHAR(128) DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    phase VARCHAR(32) DEFAULT '',
    message VARCHAR(512) DEFAULT '',
    error TEXT,
    issues INT DEFAULT 0,
    progress INT DEFAULT 0,
    force_flag TINYINT DEFAULT 0,
    cancel_flag TINYINT DEFAULT 0,
    retry_count INT DEFAULT 0,
    steps_json TEXT,
    workflow VARCHAR(64) DEFAULT '',
    created_at VARCHAR(40) DEFAULT '',
    updated_at VARCHAR(40) DEFAULT '',
    finished_at VARCHAR(40) DEFAULT '',
    KEY idx_jobs_status (status),
    KEY idx_jobs_file (file),
    KEY idx_jobs_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def set_max_workers(n: int) -> int:
    global _max_workers
    _max_workers = max(1, min(64, int(n or 1)))
    return _max_workers


def get_max_workers() -> int:
    return _max_workers


def set_heavy_max(n: int) -> int:
    global _heavy_max
    _heavy_max = max(1, min(8, int(n or 1)))
    return _heavy_max


def report_is_heavy(
    rid: str = "",
    *,
    events: int = 0,
    files: int = 0,
    json_bytes: int = 0,
) -> bool:
    """按事件数 / 文件扫描数 / 落盘体积判断是否占用「重任务」槽。"""
    if int(events or 0) >= _HEAVY_EVENTS or int(files or 0) >= _HEAVY_FILES:
        return True
    if int(json_bytes or 0) >= _HEAVY_JSON_BYTES:
        return True
    name = str(rid or "").strip()
    if not name:
        return False
    try:
        d = P.report_dir(name)
        pe = d / "_park_event_logs.pkl"
        pf = d / "_park_file_scans.pkl"
        if pe.is_file() and pe.stat().st_size >= _HEAVY_PARK_EVENTS_BYTES:
            return True
        if pf.is_file() and pf.stat().st_size >= _HEAVY_PARK_FILES_BYTES:
            return True
        jp = P.resolve_report_json(name)
        if jp and jp.exists() and jp.stat().st_size >= _HEAVY_JSON_BYTES:
            return True
    except Exception:
        return False
    return False


def _pick_next_job_locked() -> tuple:
    """调用方必须持有 _lock。返回 (job_id, is_heavy)；无合适任务则 (None, False)。

    重任务槽满时跳过队头的大报告，让小报告先跑，避免十份 100MB+ 结果把接口卡死。
    """
    global _active, _heavy_active
    if _active >= _max_workers or not _queue:
        return None, False
    heavy_full = _heavy_active >= _heavy_max
    pick_idx = None
    pick_heavy = False
    for i, jid in enumerate(_queue):
        job = _jobs.get(jid) or {}
        is_heavy = bool(job.get("heavy")) or report_is_heavy(job.get("file") or "")
        if is_heavy and heavy_full:
            continue
        pick_idx = i
        pick_heavy = is_heavy
        break
    if pick_idx is None:
        return None, False
    jid = _queue.pop(pick_idx)
    _active += 1
    if pick_heavy:
        _heavy_active += 1
        job = _jobs.get(jid)
        if job is not None:
            job["heavy"] = True
    return jid, pick_heavy


def queue_stats() -> Dict[str, Any]:
    """队列深度 / 运行中 / 上限，供上传回执与 UI。"""
    global _active, _heavy_active
    recover_jobs_on_startup()
    with _lock:
        by: Dict[str, int] = {}
        for j in _jobs.values():
            s = j.get("status") or "?"
            by[s] = by.get(s, 0) + 1
        running = sum(1 for j in _jobs.values() if (j.get("status") or "") in _ACTIVE)
        # 纠正幽灵 active：任务已不在内存但 _active 未减，避免 UI「运行1、列表空」
        if _active != running:
            _active = running
        heavy_running = sum(
            1 for j in _jobs.values()
            if (j.get("status") or "") in _ACTIVE and j.get("heavy")
        )
        if _heavy_active != heavy_running:
            _heavy_active = heavy_running
        return {
            "queued": len(_queue),
            "running": running,
            "active": running,
            "active_workers": _active,
            "max_workers": _max_workers,
            "heavy_running": _heavy_active,
            "heavy_max": _heavy_max,
            "queue_len": len(_queue),
            "capacity": _max_workers,
            "by_status": by,
            "done": by.get("done", 0),
            "error": by.get("error", 0),
            "cancelled": by.get("cancelled", 0),
            "total": len(_jobs),
            "persisted": True,
        }


def queue_position(job_id: str) -> int:
    """1-based 排队位置；已在跑或结束返回 0。"""
    with _lock:
        if job_id in _queue:
            try:
                return _queue.index(job_id) + 1
            except ValueError:
                return 0
        j = _jobs.get(job_id)
        if j and (j.get("status") or "") in _ACTIVE:
            return 0
        return 0


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _init_jobs_sqlite(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS analyze_jobs (
            id TEXT PRIMARY KEY,
            file TEXT NOT NULL DEFAULT '',
            hostname TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'queued',
            phase TEXT DEFAULT '',
            message TEXT DEFAULT '',
            error TEXT DEFAULT '',
            issues INTEGER DEFAULT 0,
            progress INTEGER DEFAULT 0,
            force_flag INTEGER DEFAULT 0,
            cancel_flag INTEGER DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            steps_json TEXT DEFAULT '',
            workflow TEXT DEFAULT '',
            created_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT '',
            finished_at TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON analyze_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_file ON analyze_jobs(file);
        """
    )
    # 旧库补列
    for col, typ in (("steps_json", "TEXT DEFAULT ''"), ("workflow", "TEXT DEFAULT ''")):
        try:
            conn.execute(f"ALTER TABLE analyze_jobs ADD COLUMN {col} {typ}")
            conn.commit()
        except Exception:
            pass


def ensure_jobs_table(conn=None) -> None:
    from . import mysql_db
    own = conn is None
    if own:
        if not mysql_db.mysql_ready():
            return
        conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(JOBS_MYSQL_SQL)
            for col, typ in (("steps_json", "TEXT"), ("workflow", "VARCHAR(64) DEFAULT ''")):
                try:
                    cur.execute(f"ALTER TABLE analyze_jobs ADD COLUMN {col} {typ}")
                except Exception:
                    pass
        conn.commit()
    finally:
        if own:
            conn.close()


class _JobDb:
    """优先 MySQL，失败回退 SQLite reports/jobs.db。"""

    def __init__(self):
        from . import mysql_db
        self.mysql = False
        self.cur = None
        if mysql_db.mysql_ready():
            try:
                ensure_jobs_table()
                self.conn = mysql_db.connect_mysql()
                self.cur = self.conn.cursor()
                self.mysql = True
                return
            except Exception as e:
                try:
                    mysql_db.mark_mysql_down(str(e))
                except Exception:
                    pass
                print(f"[jobs] mysql unavailable → sqlite: {e}")
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = _connect(JOBS_DB)
        _init_jobs_sqlite(self.conn)
        self.cur = None

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.mysql else sql

    def execute(self, sql: str, params: Sequence[Any] = ()):
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
        else:
            self.conn.execute(q, tuple(params))
        return self

    def query_all(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        q = self._q(sql)
        if self.mysql:
            self.cur.execute(q, tuple(params))
            return [dict(r) for r in (self.cur.fetchall() or [])]
        rows = self.conn.execute(q, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            if self.mysql and self.cur:
                self.cur.close()
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass


def _parse_steps(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if not raw:
        return []
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
    except Exception:
        pass
    return []


def _row_from_db(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": r.get("id") or "",
        "file": r.get("file") or "",
        "hostname": r.get("hostname") or "",
        "status": r.get("status") or "queued",
        "phase": r.get("phase") or "",
        "message": r.get("message") or "",
        "error": r.get("error") or "",
        "issues": int(r.get("issues") or 0),
        "progress": int(r.get("progress") or 0),
        "force": bool(r.get("force_flag") or r.get("force")),
        "cancel": bool(r.get("cancel_flag") or r.get("cancel")),
        "retry_count": int(r.get("retry_count") or 0),
        "only_matchers": _parse_steps(r.get("steps_json")),
        "workflow": r.get("workflow") or "",
        "created_at": r.get("created_at") or "",
        "updated_at": r.get("updated_at") or "",
        "finished_at": r.get("finished_at") or None,
    }


def _persist_params(job: Dict[str, Any]) -> tuple:
    steps = job.get("only_matchers") or []
    steps_json = json.dumps(steps, ensure_ascii=False) if steps else ""
    return (
        job.get("id"),
        job.get("file") or "",
        job.get("hostname") or "",
        job.get("status") or "queued",
        job.get("phase") or "",
        (job.get("message") or "")[:500],
        job.get("error") or "",
        int(job.get("issues") or 0),
        int(job.get("progress") or 0),
        1 if job.get("force") else 0,
        1 if job.get("cancel") else 0,
        int(job.get("retry_count") or 0),
        steps_json,
        job.get("workflow") or "",
        job.get("created_at") or "",
        job.get("updated_at") or "",
        job.get("finished_at") or "",
    )


def _persist(job: Dict[str, Any]) -> None:
    """写入当前可用库；MySQL 时再镜像到本地 jobs.db。"""
    params = _persist_params(job)
    try:
        db = _JobDb()
        try:
            if db.mysql:
                db.execute(
                    """
                    INSERT INTO analyze_jobs(
                        id,file,hostname,status,phase,message,error,issues,progress,
                        force_flag,cancel_flag,retry_count,steps_json,workflow,
                        created_at,updated_at,finished_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON DUPLICATE KEY UPDATE
                        file=VALUES(file), hostname=VALUES(hostname), status=VALUES(status),
                        phase=VALUES(phase), message=VALUES(message), error=VALUES(error),
                        issues=VALUES(issues), progress=VALUES(progress),
                        force_flag=VALUES(force_flag), cancel_flag=VALUES(cancel_flag),
                        retry_count=VALUES(retry_count), steps_json=VALUES(steps_json),
                        workflow=VALUES(workflow), updated_at=VALUES(updated_at),
                        finished_at=VALUES(finished_at)
                    """,
                    params,
                )
            else:
                db.execute(
                    """
                    INSERT INTO analyze_jobs(
                        id,file,hostname,status,phase,message,error,issues,progress,
                        force_flag,cancel_flag,retry_count,steps_json,workflow,
                        created_at,updated_at,finished_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        file=excluded.file, hostname=excluded.hostname, status=excluded.status,
                        phase=excluded.phase, message=excluded.message, error=excluded.error,
                        issues=excluded.issues, progress=excluded.progress,
                        force_flag=excluded.force_flag, cancel_flag=excluded.cancel_flag,
                        retry_count=excluded.retry_count, steps_json=excluded.steps_json,
                        workflow=excluded.workflow, updated_at=excluded.updated_at,
                        finished_at=excluded.finished_at
                    """,
                    params,
                )
            db.commit()
            if db.mysql:
                _mirror_job_sqlite(job)
        finally:
            db.close()
    except Exception as e:
        print(f"[jobs] persist: {e}")


def _mirror_job_sqlite(job: Dict[str, Any]) -> None:
    try:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect(JOBS_DB)
        try:
            _init_jobs_sqlite(conn)
            conn.execute(
                """
                INSERT INTO analyze_jobs(
                    id,file,hostname,status,phase,message,error,issues,progress,
                    force_flag,cancel_flag,retry_count,steps_json,workflow,
                    created_at,updated_at,finished_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    file=excluded.file, hostname=excluded.hostname, status=excluded.status,
                    phase=excluded.phase, message=excluded.message, error=excluded.error,
                    issues=excluded.issues, progress=excluded.progress,
                    force_flag=excluded.force_flag, cancel_flag=excluded.cancel_flag,
                    retry_count=excluded.retry_count, steps_json=excluded.steps_json,
                    workflow=excluded.workflow, updated_at=excluded.updated_at,
                    finished_at=excluded.finished_at
                """,
                _persist_params(job),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[jobs] mirror sqlite: {e}")


def _delete_persisted(job_id: str) -> None:
    try:
        db = _JobDb()
        try:
            db.execute("DELETE FROM analyze_jobs WHERE id=?", (job_id,))
            db.commit()
            if db.mysql and JOBS_DB.exists():
                conn = _connect(JOBS_DB)
                try:
                    _init_jobs_sqlite(conn)
                    conn.execute("DELETE FROM analyze_jobs WHERE id=?", (job_id,))
                    conn.commit()
                finally:
                    conn.close()
        finally:
            db.close()
    except Exception as e:
        print(f"[jobs] delete persist: {e}")


def _load_all_from_db() -> List[Dict[str, Any]]:
    try:
        db = _JobDb()
        try:
            rows = db.query_all("SELECT * FROM analyze_jobs ORDER BY created_at DESC LIMIT 500")
            return [_row_from_db(r) for r in rows]
        finally:
            db.close()
    except Exception as e:
        print(f"[jobs] load db: {e}")
        return []


def recover_jobs_on_startup() -> int:
    """启动时从库恢复任务；中断的运行中任务重新入队。"""
    global _recovered
    with _lock:
        if _recovered:
            return 0
        _recovered = True
        rows = _load_all_from_db()
        recovered = 0
        _jobs.clear()
        _queue.clear()
        for j in rows:
            jid = j.get("id") or ""
            if not jid:
                continue
            st = j.get("status") or ""
            # 进程被杀时卡在 load/fast/full：重新排队
            if st in _ACTIVE:
                j["status"] = "queued"
                j["phase"] = "queued"
                j["progress"] = 0
                j["cancel"] = False
                j["message"] = "服务重启，已重新排队…"
                j["updated_at"] = _now()
                j["finished_at"] = None
                recovered += 1
            _jobs[jid] = j
            if j.get("status") == "queued":
                _queue.append(jid)
                _persist(j)
        # 按创建时间排队
        _queue.sort(key=lambda x: (_jobs.get(x) or {}).get("created_at") or "")
        if _queue:
            _ensure_worker()
        if rows:
            print(f"[jobs] recovered {len(rows)} jobs from db (re-queued {recovered})")
        return len(rows)


def _job_public(j: Dict[str, Any]) -> Dict[str, Any]:
    phase = j.get("phase") or j.get("status") or ""
    only = j.get("only_matchers") or []
    jid = j["id"]
    pos = 0
    st = j.get("status") or ""
    if st == "queued":
        try:
            pos = _queue.index(jid) + 1
        except ValueError:
            pos = 0
    os_family = str(j.get("os_family") or "").strip().lower()
    return {
        "id": jid,
        "file": j.get("file") or "",
        "hostname": j.get("hostname") or "",
        "status": st,
        "phase": phase,
        "phase_label": PHASE_LABELS.get(phase, phase),
        "message": j.get("message") or "",
        "error": j.get("error") or "",
        "issues": j.get("issues") or 0,
        "progress": int(j.get("progress") or 0),
        "retry_count": int(j.get("retry_count") or 0),
        "only_matchers": list(only) if only else [],
        "workflow": j.get("workflow") or "",
        "created_at": j.get("created_at"),
        "updated_at": j.get("updated_at"),
        "finished_at": j.get("finished_at"),
        "force": bool(j.get("force")),
        "cancel": bool(j.get("cancel")),
        "queue_position": pos,
        "max_workers": _max_workers,
        "owner_id": j.get("owner_id") or "",
        "owner_username": j.get("owner_username") or "",
        "os_family": os_family,
    }



def list_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    # 列表接口尽量轻：不在每次轮询时做 recover（启动时已做）
    with _lock:
        items = sorted(_jobs.values(), key=lambda x: x.get("created_at") or "", reverse=True)
        return [_job_public(j) for j in items[:limit]]


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    recover_jobs_on_startup()
    with _lock:
        j = _jobs.get(job_id)
        return _job_public(j) if j else None


def get_job_by_file(report_file: str) -> Optional[Dict[str, Any]]:
    recover_jobs_on_startup()
    rid = P.report_id(report_file)
    with _lock:
        for j in sorted(_jobs.values(), key=lambda x: x.get("created_at") or "", reverse=True):
            if j.get("file") == rid:
                return _job_public(j)
    return None


def enqueue_analyze(
    report_file: str,
    hostname: str = "",
    force: bool = False,
    only_matchers: Optional[List[str]] = None,
    workflow: str = "",
    heavy: Optional[bool] = None,
) -> Dict[str, Any]:
    """入队分析任务。

    force=True（覆盖重分析）：取消同文件进行中/排队任务后新建。
    force=False：同文件已 busy 则返回已有任务。
    """
    recover_jobs_on_startup()
    rid = P.report_id(report_file)
    steps = [str(x).strip() for x in (only_matchers or []) if str(x).strip()]
    wf = (workflow or "").strip()
    to_persist: List[Dict[str, Any]] = []
    with _lock:
        if force:
            for j in list(_jobs.values()):
                if j.get("file") != rid:
                    continue
                st = j.get("status") or ""
                if st not in _BUSY:
                    continue
                jid = j.get("id") or ""
                if st == "queued":
                    try:
                        _queue.remove(jid)
                    except ValueError:
                        pass
                    j["status"] = "cancelled"
                    j["phase"] = "cancelled"
                    j["progress"] = 0
                    j["message"] = "已被覆盖上传取消，将重新分析"
                    j["finished_at"] = _now()
                    j["updated_at"] = _now()
                    j["cancel"] = False
                    to_persist.append(dict(j))
                else:
                    j["cancel"] = True
                    j["status"] = "cancelled"
                    j["phase"] = "cancelled"
                    j["message"] = "已被新任务取消"
                    j["finished_at"] = _now()
                    j["updated_at"] = _now()
                    j["rev"] = int(j.get("rev") or 0) + 1
                    to_persist.append(dict(j))
        else:
            for j in _jobs.values():
                if j.get("file") == rid and (j.get("status") or "") in _BUSY:
                    return _job_public(j)

        jid = uuid.uuid4().hex[:12]
        qlen = len(_queue)
        is_heavy = bool(heavy) if heavy is not None else report_is_heavy(rid)
        if steps:
            msg = f"已排队，局部重跑：{', '.join(steps)}"
        elif wf:
            msg = f"已排队（工作流 {wf}）…"
        else:
            msg = f"已排队，等待分析…（前方约 {qlen} 个）" if qlen else "已排队，等待分析…"
        if is_heavy:
            msg = (msg + " · 大报告串行分析，避免卡死其它页面") if qlen else "已排队，大报告将单独分析…"
        try:
            from .ownership import current_owner
            own = current_owner()
        except Exception:
            own = {}
        oid = str(own.get("owner_id") or "")
        # 单用户同时排队+运行上限（管理员可在设置里调；0=不限）
        try:
            from .settings import get_settings
            per_user = int((get_settings() or {}).get("job_per_user_max") or 0)
        except Exception:
            per_user = 5
        if oid and per_user > 0:
            busy_n = sum(
                1 for j in _jobs.values()
                if str(j.get("owner_id") or "") == oid and (j.get("status") or "") in _BUSY
            )
            if busy_n >= per_user:
                raise QueueRejected(
                    f"您当前进行中的分析已达上限（{busy_n}/{per_user}），"
                    f"请等待完成或取消部分任务后再试",
                    429,
                )
        os_family = ""
        try:
            from .db_store import get_index_meta
            meta = get_index_meta(rid) or {}
            os_family = str(meta.get("os_family") or "").strip().lower()
        except Exception:
            os_family = ""
        job = {
            "id": jid,
            "file": rid,
            "hostname": hostname or "",
            "status": "queued",
            "phase": "queued",
            "message": msg,
            "error": "",
            "issues": 0,
            "progress": 0,
            "force": force,
            "cancel": False,
            "retry_count": 0,
            "only_matchers": steps,
            "workflow": wf,
            "created_at": _now(),
            "updated_at": _now(),
            "finished_at": None,
            "owner_id": oid,
            "owner_username": str(own.get("owner_username") or ""),
            "os_family": os_family,
            "heavy": is_heavy,
        }
        _jobs[jid] = job
        _queue.append(jid)
        snap = dict(job)
        _ensure_worker()
        pub = _job_public(job)
    for old in to_persist:
        _persist(old)
    _persist(snap)
    return pub


def cancel_jobs(job_ids: List[str]) -> Dict[str, Any]:
    """批量取消；已结束的任务跳过。"""
    ok = 0
    errors: List[Dict[str, str]] = []
    for jid in job_ids or []:
        if not jid:
            continue
        try:
            cancel_job(str(jid))
            ok += 1
        except Exception as e:
            errors.append({"id": str(jid), "error": str(e)})
    return {"cancelled": ok, "errors": errors}


def cancel_job(job_id: str) -> Dict[str, Any]:
    snap = None
    with _lock:
        j = _jobs.get(job_id)
        if not j:
            raise KeyError("job not found")
        st = j.get("status") or ""
        if st in _TERMINAL:
            raise ValueError("任务已结束，无法取消")
        if st == "queued":
            try:
                _queue.remove(job_id)
            except ValueError:
                pass
            j["cancel"] = False
            j["status"] = "cancelled"
            j["phase"] = "cancelled"
            j["progress"] = 0
            j["message"] = "已取消（未开始）"
            j["finished_at"] = _now()
            j["updated_at"] = _now()
            j["rev"] = int(j.get("rev") or 0) + 1
        else:
            j["cancel"] = True
            j["status"] = "cancelled"
            j["phase"] = "cancelled"
            j["progress"] = int(j.get("progress") or 0)
            j["message"] = "已取消"
            j["finished_at"] = _now()
            j["updated_at"] = _now()
            j["rev"] = int(j.get("rev") or 0) + 1
        snap = dict(j)
    if snap:
        _persist_current(snap)
        try:
            from .hot_cache import put_job, set_stats
            put_job(_job_public(snap))
            set_stats(queue_stats())
        except Exception:
            pass
    return _job_public(snap)


def delete_job(job_id: str) -> Dict[str, Any]:
    with _lock:
        j = _jobs.get(job_id)
        if not j:
            raise KeyError("job not found")
        st = j.get("status") or ""
        if st not in _TERMINAL:
            raise ValueError("仅可删除已结束任务（先取消或等完成）")
        if job_id in _queue:
            try:
                _queue.remove(job_id)
            except ValueError:
                pass
        pub = _job_public(j)
        del _jobs[job_id]
    _delete_persisted(job_id)
    return pub


def purge_jobs_for_files(files: List[str]) -> int:
    """取消并删除这些报告相关的任务记录（删除报告时调用）。"""
    want = set()
    for x in files or []:
        try:
            want.add(P.safe_report_id(x))
        except Exception:
            continue
    if not want:
        return 0
    ids: List[str] = []
    with _lock:
        for jid, j in list(_jobs.items()):
            fn = str(j.get("file") or "")
            if fn not in want:
                continue
            st = j.get("status") or ""
            if st in _BUSY:
                j["cancel"] = True
                j["status"] = "cancelled"
                j["phase"] = "cancelled"
                j["message"] = "报告已删除"
                j["finished_at"] = _now()
                j["updated_at"] = _now()
                if jid in _queue:
                    try:
                        _queue.remove(jid)
                    except ValueError:
                        pass
            ids.append(jid)
            del _jobs[jid]
    for jid in ids:
        _delete_persisted(jid)
    return len(ids)


def clear_terminal_jobs(statuses: Optional[List[str]] = None) -> int:
    want = set(statuses or list(_TERMINAL))
    ids: List[str] = []
    with _lock:
        ids = [jid for jid, j in _jobs.items() if (j.get("status") or "") in want]
        for jid in ids:
            del _jobs[jid]
    for jid in ids:
        _delete_persisted(jid)
    return len(ids)


def retry_job(job_id: str, force: bool = True) -> Dict[str, Any]:
    with _lock:
        j = _jobs.get(job_id)
        if not j:
            raise KeyError("job not found")
        st = j.get("status") or ""
        if st not in _TERMINAL:
            raise ValueError("任务仍在进行，请先取消或等待完成")
        rid = j.get("file") or ""
        hostname = j.get("hostname") or ""
        retry_n = int(j.get("retry_count") or 0) + 1
        # 原地复活为排队，保留同一 id，便于追踪
        for other in _jobs.values():
            if other.get("id") != job_id and other.get("file") == rid and (other.get("status") or "") in _BUSY:
                raise ValueError("该报告已有进行中的任务")
        j["status"] = "queued"
        j["phase"] = "queued"
        j["progress"] = 0
        j["message"] = f"重试入队（第 {retry_n} 次）…"
        j["error"] = ""
        j["cancel"] = False
        j["force"] = force
        j["retry_count"] = retry_n
        j["finished_at"] = None
        j["updated_at"] = _now()
        if job_id not in _queue:
            _queue.append(job_id)
        snap = dict(j)
    _persist(snap)
    _ensure_worker()
    return _job_public(snap)


def _cancelled(job_id: str) -> bool:
    with _lock:
        return _is_cancelled(_jobs.get(job_id))


def _mark_cancelled(job_id: str, msg: str = "已取消") -> None:
    _update(
        job_id,
        status="cancelled",
        phase="cancelled",
        progress=0,
        message=msg,
        cancel=False,
        finished_at=_now(),
    )


def _is_cancelled(j: Optional[Dict[str, Any]]) -> bool:
    if not j:
        return True
    if j.get("cancel"):
        return True
    return (j.get("status") or "") == "cancelled"


def _update(job_id: str, **kw) -> None:
    snap = None
    with _lock:
        j = _jobs.get(job_id)
        if not j:
            return
        # 已取消：只允许巩固为 cancelled，禁止进度/完成把任务写活
        if _is_cancelled(j) and kw.get("status") != "cancelled":
            return
        j.update(kw)
        if kw.get("status") == "cancelled":
            j["status"] = "cancelled"
            j["phase"] = "cancelled"
            j["cancel"] = True
            j["finished_at"] = j.get("finished_at") or _now()
        j["updated_at"] = _now()
        j["rev"] = int(j.get("rev") or 0) + 1
        snap = dict(j)
    if snap:
        _persist_current(snap)
        try:
            from .hot_cache import put_job, set_stats
            put_job(_job_public(snap))
            set_stats(queue_stats())
        except Exception:
            pass


def _persist_current(snap: Dict[str, Any]) -> None:
    """过期快照不落库，避免取消后又被 worker 旧进度覆盖。"""
    jid = snap.get("id") or ""
    rev = int(snap.get("rev") or 0)
    with _lock:
        cur = _jobs.get(jid)
        if not cur:
            return
        if int(cur.get("rev") or 0) > rev:
            return
        if _is_cancelled(cur) and (snap.get("status") or "") != "cancelled":
            return
    _persist(snap)


def _ensure_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    # 调度启动前再应用一次设置，避免仅默认 _max_workers=1
    try:
        from .settings import apply_runtime
        apply_runtime()
    except Exception:
        pass
    _worker_started = True
    t = threading.Thread(target=_dispatcher_loop, daemon=True, name="analyze-dispatcher")
    t.start()


def _dispatch_one(job_id: str, is_heavy: bool = False) -> None:
    """单任务执行线程：真正并行跑到 max_workers。"""
    global _active, _heavy_active
    try:
        _run_job(job_id)
    except Exception as e:
        print(f"[jobs] worker crash {job_id}: {e}")
        _update(
            job_id,
            status="error",
            phase="error",
            progress=0,
            error=str(e),
            message=f"失败: {e}",
            finished_at=_now(),
        )
    finally:
        with _lock:
            _active = max(0, _active - 1)
            if is_heavy:
                _heavy_active = max(0, _heavy_active - 1)


def _dispatcher_loop() -> None:
    """调度器：按 max_workers 为每个任务开独立线程；大报告占用单独的重任务槽。"""
    while True:
        job_id = None
        is_heavy = False
        with _lock:
            job_id, is_heavy = _pick_next_job_locked()
        if not job_id:
            time.sleep(0.15)
            continue
        t = threading.Thread(
            target=_dispatch_one,
            args=(job_id, is_heavy),
            daemon=True,
            name=f"analyze-{job_id[:8]}",
        )
        t.start()


def _load_report(rid: str, cancel_check=None, *, heavy: bool = True) -> Optional[Dict[str, Any]]:
    path = P.resolve_report_json(rid)
    if not path or not path.exists():
        return None
    if cancel_check and cancel_check():
        raise JobCancelled()
    from .stage_timer import StageTimer
    t = StageTimer("job_timing", "load_report", rid=rid)
    with t.step("read_json"):
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig", errors="replace")
        report = slim_report(json.loads(text))
    if cancel_check and cancel_check():
        raise JobCancelled()
    report["_rid"] = rid
    report["_files_rid"] = rid
    if not heavy:
        parked = bool(report.get("_pack") or report.get("_heavy_parked")
                      or report.get("_event_logs_count") or report.get("_files_count"))
        if parked:
            report["file_scans"] = []
            report["event_logs"] = []
        report["_files_ingested"] = False
        report["_event_logs_ingested"] = False
        t.emit(files=report.get("_files_count"), events=report.get("_event_logs_count"))
        return report
    try:
        from .db_store import ensure_heavy_ready
        with t.step("heavy"):
            stats = ensure_heavy_ready(rid, report, cancel_check=cancel_check)
        report["_rid"] = rid
        report["_files_rid"] = rid
        report["_files_count"] = int(stats.get("files") or report.get("_files_count") or 0)
        report["_files_ingested"] = True
        report["_event_logs_count"] = int(stats.get("event_logs") or report.get("_event_logs_count") or 0)
        report["_event_logs_ingested"] = True
        # 匹配阶段不持有大数组
        report["file_scans"] = []
        report["event_logs"] = []
    except InterruptedError:
        raise JobCancelled()
    except JobCancelled:
        raise
    except Exception as e:
        print(f"[jobs] ensure heavy: {e}")
        try:
            from .db_store import ingest_file_scans
            files = report.get("file_scans") or []
            n = ingest_file_scans(rid, files, cancel_check=cancel_check)
            report["_rid"] = rid
            report["_files_rid"] = rid
            report["_files_count"] = n
            report["_files_ingested"] = True
            if n >= 3000:
                report["file_scans"] = []
        except InterruptedError:
            raise JobCancelled()
        except Exception as e2:
            print(f"[jobs] ingest files: {e2}")
    t.emit(files=report.get("_files_count"), events=report.get("_event_logs_count"))
    return report


def _load_base_analysis(rid: str) -> Optional[Dict[str, Any]]:
    rp = P.result_json_path(rid)
    if not rp.exists():
        return None
    try:
        with open(rp, encoding="utf-8") as fh:
            data = json.load(fh)
        an = data.get("analysis") if isinstance(data, dict) else None
        return an if isinstance(an, dict) else None
    except Exception:
        return None


def _ingest_heavy_for_match(rid: str, report: Dict[str, Any], cancel_check=None) -> Dict[str, int]:
    """匹配前统一准备：pack 轻量补全 → 文件/事件入库 → 覆盖面标记。

    顺序硬约束（勿再挪到 fast 之后）：
    - windows_process / persistence 需 files 表回填模块签名
    - eventlog / files / aux_rules 需 event_logs / files 已入库
    """
    try:
        from .collect_pack import hydrate_report_from_pack, match_data_coverage
        hydrate_report_from_pack(rid, report)
    except Exception as e:
        print(f"[jobs] hydrate pack: {e}")

    try:
        from .matchers.persistence import _ensure_persist_report_context
        _ensure_persist_report_context(report)
    except Exception as e:
        print(f"[jobs] persist context: {e}")

    from .db_store import ensure_heavy_ready

    stats = ensure_heavy_ready(rid, report, cancel_check=cancel_check)
    report["_rid"] = rid
    report["_files_rid"] = rid
    report["_files_count"] = int(stats.get("files") or report.get("_files_count") or 0)
    report["_event_logs_count"] = int(stats.get("event_logs") or report.get("_event_logs_count") or 0)
    report["_files_ingested"] = True
    report["_event_logs_ingested"] = True
    report["file_scans"] = []
    report["event_logs"] = []
    try:
        from .collect_pack import match_data_coverage
        report["_match_ready"] = match_data_coverage(report)
        cov = report["_match_ready"]
        print(
            f"[jobs] match_ready {rid} "
            f"proc={cov.get('processes')} startup={cov.get('startup_items')} "
            f"tasks={cov.get('scheduled_tasks')} svc={cov.get('services')} "
            f"files={cov.get('files_count')} events={cov.get('event_logs_count')} "
            f"dirsnap={cov.get('dir_snapshots')}"
        )
    except Exception:
        pass

    # 采集覆盖度：mapped vs unmapped → reports/<rid>/coverage.json
    try:
        from .coverage_map import write_coverage
        write_coverage(rid, report)
    except Exception as e:
        print(f"[jobs] coverage_map: {e}")

    # 实体出现记录（跨主机）
    try:
        from . import entity_occurrences as EO
        n = EO.ingest_report_entities(report, rid=rid)
        n2 = EO.ingest_file_hashes_from_db(rid, hostname=str(report.get("hostname") or ""))
        print(f"[jobs] entity_occurrences rid={rid} report={n} files={n2}")
    except Exception as e:
        print(f"[jobs] entity_occurrences: {e}")

    return stats


def _run_job(job_id: str) -> None:
    with _lock:
        job = dict(_jobs.get(job_id) or {})
    if not job:
        return
    if job.get("cancel") or job.get("status") == "cancelled":
        _mark_cancelled(job_id, "已取消（未开始）")
        return
    rid = job["file"]
    only = list(job.get("only_matchers") or [])
    t_job = time.perf_counter()
    # 长驻进程可能还钉着旧 matcher/规则；任务开始前按磁盘 mtime 热加载
    try:
        from .hot_reload import ensure_fresh_analysis
        hr = ensure_fresh_analysis()
        if hr.get("reloaded_code") or hr.get("reloaded_rules"):
            print(f"[jobs] using fresh analysis code for {rid}: {hr.get('fingerprint', {}).get('stamp')}")
    except Exception as e:
        print(f"[jobs] hot_reload: {e}")
    print(f"[jobs] start {job_id} {rid} steps={only or 'full'}")

    _update(
        job_id,
        status="load",
        phase="load",
        progress=8,
        message="加载报告…",
    )
    try:
        t0 = time.perf_counter()
        report = _load_report(rid, cancel_check=lambda: _cancelled(job_id), heavy=False)
        print(f"[jobs] load {rid} ms={int((time.perf_counter() - t0) * 1000)}")
        try:
            from . import applog
            applog.info("jobs", f"load {rid} ms={int((time.perf_counter() - t0) * 1000)}", rid=rid)
        except Exception:
            pass
    except JobCancelled:
        _mark_cancelled(job_id, "已取消（加载中止）")
        return
    if not report:
        _update(
            job_id,
            status="error",
            phase="error",
            progress=0,
            error="report not found",
            message="找不到报告文件",
            finished_at=_now(),
        )
        return
    if _cancelled(job_id):
        _mark_cancelled(job_id, "已取消（加载后）")
        return

    hostname = report.get("hostname") or job.get("hostname") or ""

    # —— 局部重跑：只跑指定 matcher，合并进已有结果 ——
    if only:
        _update(
            job_id,
            hostname=hostname,
            status="partial",
            phase="partial",
            progress=30,
            message=f"局部重跑：{', '.join(only)}…",
        )
        try:
            _update(job_id, progress=18, message="准备文件/事件日志数据…")
            _ingest_heavy_for_match(rid, report, cancel_check=lambda: _cancelled(job_id))
            base = _load_base_analysis(rid)
            a_part = analyze_report(
                report,
                with_ai=False,
                stage="full",
                only_matchers=only,
                base_analysis=base,
                cancel_check=lambda: _cancelled(job_id),
            )
            if _cancelled(job_id):
                _mark_cancelled(job_id, "已取消（局部结果未落库）")
                return
            _update(job_id, phase="save_full", progress=85, message="保存局部分析结果…")
            save_analysis(report, a_part, rid, persist="full")
            issues = (a_part.get("summary_aggregated") or a_part.get("summary") or {}).get("total") or 0
            _update(
                job_id,
                issues=issues,
                status="done",
                phase="done",
                progress=100,
                message=f"局部重跑完成（{', '.join(only)}），聚合告警 {issues}",
                finished_at=_now(),
            )
            print(f"[jobs] partial done {rid} {only} issues={issues}")
            _maybe_finish_workflow(job_id, rid, report, a_part)
        except JobCancelled:
            _mark_cancelled(job_id, "已取消（局部匹配中止）")
            return
        except Exception as e:
            _update(
                job_id,
                status="error",
                phase="error",
                progress=0,
                error=str(e),
                message=f"局部重跑失败: {e}",
                finished_at=_now(),
            )
            print(f"[jobs] partial fail {rid}: {e}")
        return

    try:
        _update(
            job_id,
            hostname=hostname,
            status="load",
            phase="ingest",
            progress=15,
            message="入库文件/事件日志（供进程、持久化、日志规则）…",
        )
        _ingest_heavy_for_match(rid, report, cancel_check=lambda: _cancelled(job_id))
    except InterruptedError:
        _mark_cancelled(job_id, "已取消（入库中止）")
        return
    except JobCancelled:
        _mark_cancelled(job_id, "已取消（入库中止）")
        return
    except Exception as e:
        _update(
            job_id,
            status="error",
            phase="error",
            progress=0,
            error=str(e),
            message=f"入库失败: {e}",
            finished_at=_now(),
        )
        print(f"[jobs] ingest fail {rid}: {e}")
        return

    _update(
        job_id,
        status="fast",
        phase="fast",
        progress=22,
        message="快速匹配中（IOC / 网络 / 持久化 / 进程 / 关键词）…",
    )

    try:
        t0 = time.perf_counter()
        a_fast = analyze_report(
            report, with_ai=False, stage="fast",
            cancel_check=lambda: _cancelled(job_id),
        )
        fast_ms = int((time.perf_counter() - t0) * 1000)
        if _cancelled(job_id):
            issues = (a_fast.get("summary_aggregated") or a_fast.get("summary") or {}).get("total") or 0
            _update(job_id, issues=issues, progress=40)
            _mark_cancelled(job_id, f"已取消（快速结果未落库，告警约 {issues}）")
            return
        _update(
            job_id,
            phase="save_fast",
            progress=42,
            message="保存快速匹配结果…",
        )
        # 快速阶段只写 result.json，避免整库双写卡顿；全量结束再完整落库
        t1 = time.perf_counter()
        save_analysis(report, a_fast, rid, persist="light")
        save_fast_ms = int((time.perf_counter() - t1) * 1000)
        issues = (a_fast.get("summary_aggregated") or a_fast.get("summary") or {}).get("total") or 0
        if _cancelled(job_id):
            _update(job_id, issues=issues, progress=48)
            _mark_cancelled(job_id, f"已取消（快速结果已保留，告警 {issues}）")
            print(f"[jobs] cancelled after fast {rid}")
            return
        print(f"[jobs] fast done {rid} issues={issues} match_ms={fast_ms} save_ms={save_fast_ms}")
        try:
            from . import applog
            applog.info(
                "jobs",
                f"fast done {rid} issues={issues} match_ms={fast_ms} save_ms={save_fast_ms}",
                rid=rid, issues=issues, match_ms=fast_ms, save_ms=save_fast_ms,
            )
        except Exception:
            pass
        _update(
            job_id,
            issues=issues,
            status="full",
            phase="full",
            progress=52,
            message=f"快速完成（告警 {issues}），全量规则匹配中（文件 / 系统日志）…",
        )
        time.sleep(0.05)
    except JobCancelled:
        _mark_cancelled(job_id, "已取消（快速匹配中止）")
        return
    except Exception as e:
        _update(
            job_id,
            status="error",
            phase="error",
            progress=0,
            error=str(e),
            message=f"快速匹配失败: {e}",
            finished_at=_now(),
        )
        print(f"[jobs] fast fail {rid}: {e}")
        return

    if _cancelled(job_id):
        _mark_cancelled(job_id, "已取消（跳过全量匹配）")
        return

    try:
        from .pipeline import HEAVY_MATCHER_NAMES
        t0 = time.perf_counter()
        a_full = analyze_report(
            report,
            with_ai=False,
            only_matchers=sorted(HEAVY_MATCHER_NAMES),
            base_analysis=a_fast,
            cancel_check=lambda: _cancelled(job_id),
        )
        full_ms = int((time.perf_counter() - t0) * 1000)
        if _cancelled(job_id):
            issues = (a_full.get("summary_aggregated") or a_full.get("summary") or {}).get("total") or 0
            _update(job_id, issues=issues, progress=85)
            _mark_cancelled(job_id, f"已取消（全量结果未落库，告警约 {issues}）")
            return
        _update(
            job_id,
            phase="save_full",
            progress=88,
            message="保存全量分析结果…",
        )
        # 大报告写盘前再让出 GIL，避免 Web 假死
        time.sleep(0.05)
        # 文件已入 files 表，结果包不再夹带超大 file_scans
        if report.get("_files_ingested") or int(report.get("_files_count") or 0) >= 3000:
            report = dict(report)
            report["file_scans"] = []
        if report.get("_event_logs_ingested"):
            report = dict(report)
            report["event_logs"] = []
        # 快+重合并后视为完整分析
        try:
            pipe = dict((a_full.get("pipeline") or {}))
            pipe["stage"] = "full"
            pipe["only_matchers"] = None
            a_full["pipeline"] = pipe
            meta = dict((a_full.get("meta") or {}))
            meta["stage"] = "full"
            meta.pop("only_matchers", None)
            a_full["meta"] = meta
        except Exception:
            pass
        t1 = time.perf_counter()
        save_analysis(report, a_full, rid, persist="full")
        save_full_ms = int((time.perf_counter() - t1) * 1000)
        time.sleep(0.02)
        issues = (a_full.get("summary_aggregated") or a_full.get("summary") or {}).get("total") or 0
        if _cancelled(job_id):
            _update(job_id, issues=issues, progress=95)
            _mark_cancelled(job_id, f"已取消（全量结果已写入，告警 {issues}）")
            return
        _update(
            job_id,
            issues=issues,
            status="done",
            phase="done",
            progress=100,
            message=f"匹配完成，聚合告警 {issues}",
            finished_at=_now(),
        )
        total_ms = int((time.perf_counter() - t_job) * 1000)
        print(
            f"[jobs] full done {rid} issues={issues} "
            f"match_ms={full_ms} save_ms={save_full_ms} total_ms={total_ms}"
        )
        try:
            from . import applog
            applog.info(
                "jobs",
                f"full done {rid} issues={issues} match_ms={full_ms} save_ms={save_full_ms} total_ms={total_ms}",
                rid=rid, issues=issues, match_ms=full_ms, save_ms=save_full_ms, total_ms=total_ms,
            )
        except Exception:
            pass
        _maybe_finish_workflow(job_id, rid, report, a_full)
    except JobCancelled:
        _mark_cancelled(job_id, "已取消（全量匹配中止）")
        return
    except Exception as e:
        _update(
            job_id,
            status="error",
            phase="error",
            progress=0,
            error=str(e),
            message=f"全量匹配失败（快速结果仍可用）: {e}",
            finished_at=_now(),
        )
        print(f"[jobs] full fail {rid}: {e}")


def _maybe_finish_workflow(job_id: str, rid: str, report: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    with _lock:
        wf = (_jobs.get(job_id) or {}).get("workflow") or ""
        prev_msg = (_jobs.get(job_id) or {}).get("message") or ""
    if not wf:
        return
    try:
        from .workflows import finish_after_analyze
        finish_after_analyze(wf, rid, report, analysis)
        _update(job_id, message=(prev_msg + " · 工作流后续已完成").strip(" ·"))
    except Exception as e:
        print(f"[jobs] workflow finish {wf}: {e}")
        _update(job_id, message=(prev_msg + f" · 工作流后续失败: {e}").strip(" ·"))
