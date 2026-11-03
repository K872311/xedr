"""删除分析报告：本地真源 + MySQL/ES/Redis 影子副本一起清。

安全约定：
- 只接受经 safe_report_id 校验的逻辑 ID，不接受客户端路径
- 文件列表由服务端按主机名/索引查出，不信请求体里的 file 列表
- 物理删除限制在 REPORTS_DIR 内（resolve 后再比）
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config
from . import paths as P
from .db_store import INDEX_DB, _connect, _init_index, delete_index_entry

_pending_lock = threading.Lock()
_PENDING = config.REPORTS_DIR / ".pending_purge.json"


def _lookup_index_row(rid: str) -> Dict[str, Any]:
    if not INDEX_DB.exists():
        return {}
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        row = conn.execute(
            "SELECT file, hostname, owner_id, owner_username FROM reports WHERE file=?",
            (rid,),
        ).fetchone()
        if not row:
            return {}
        keys = row.keys()
        return {
            "file": row["file"],
            "hostname": (row["hostname"] or "") if "hostname" in keys else "",
            "owner_id": (row["owner_id"] or "") if "owner_id" in keys else "",
            "owner_username": (row["owner_username"] or "") if "owner_username" in keys else "",
        }
    finally:
        conn.close()


def _list_files_sqlite(hostname: str) -> List[str]:
    if not INDEX_DB.exists():
        return []
    conn = _connect(INDEX_DB)
    try:
        _init_index(conn)
        rows = conn.execute("SELECT file FROM reports WHERE hostname=?", (hostname,)).fetchall()
        return [r["file"] for r in rows if r["file"]]
    finally:
        conn.close()


def _list_files_mysql(hostname: str) -> List[str]:
    try:
        from .mysql_db import mysql_ready, connect_mysql
        if not mysql_ready():
            return []
        conn = connect_mysql()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT file FROM reports WHERE hostname=%s", (hostname,))
                return [r["file"] for r in (cur.fetchall() or []) if r.get("file")]
        finally:
            conn.close()
    except Exception:
        return []


def list_files_for_host(hostname: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in _list_files_sqlite(hostname) + _list_files_mysql(hostname):
        try:
            rid = P.safe_report_id(raw)
        except ValueError:
            continue
        if rid in seen:
            continue
        seen.add(rid)
        out.append(rid)
    return out


def _enqueue_pending(rids: List[str], hostname: str = "") -> None:
    items = []
    for rid in rids:
        try:
            items.append({"file": P.safe_report_id(rid), "hostname": hostname or "", "at": time.time()})
        except ValueError:
            continue
    if not items:
        return
    with _pending_lock:
        cur: List[Dict[str, Any]] = []
        if _PENDING.exists():
            try:
                cur = json.loads(_PENDING.read_text(encoding="utf-8")) or []
            except Exception:
                cur = []
        have = {str(x.get("file") or "") for x in cur if isinstance(x, dict)}
        for it in items:
            if it["file"] not in have:
                cur.append(it)
                have.add(it["file"])
        try:
            config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            _PENDING.write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[report_delete] pending write: {e}")


def drain_pending_purge() -> Dict[str, Any]:
    """MySQL 恢复后补删影子副本。"""
    with _pending_lock:
        if not _PENDING.exists():
            return {"ok": True, "drained": 0}
        try:
            cur = json.loads(_PENDING.read_text(encoding="utf-8")) or []
        except Exception:
            cur = []
    left: List[Dict[str, Any]] = []
    drained = 0
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import delete_report_files
        mysql_ok = mysql_ready()
    except Exception:
        mysql_ok = False
        delete_report_files = None  # type: ignore
    for it in cur:
        if not isinstance(it, dict):
            continue
        try:
            rid = P.safe_report_id(it.get("file") or "")
        except ValueError:
            continue
        hn = str(it.get("hostname") or "")
        ok = True
        if mysql_ok and delete_report_files:
            try:
                delete_report_files([rid])
            except Exception as e:
                print(f"[report_delete] drain mysql {rid}: {e}")
                ok = False
        try:
            from .result_sync import purge_remote
            purge_remote([rid], hostname=hn or None, background=True)
        except Exception as e:
            print(f"[report_delete] drain remote {rid}: {e}")
        if ok:
            drained += 1
        else:
            left.append({"file": rid, "hostname": hn, "at": it.get("at") or time.time()})
    with _pending_lock:
        try:
            if left:
                _PENDING.write_text(json.dumps(left, ensure_ascii=False, indent=2), encoding="utf-8")
            elif _PENDING.exists():
                _PENDING.unlink()
        except Exception:
            pass
    return {"ok": True, "drained": drained, "left": len(left)}


def _delete_local(rid: str) -> Dict[str, Any]:
    removed_dirs: List[str] = []
    removed_files: List[str] = []
    folder = P.report_dir(rid)
    if folder.exists() and folder.is_dir():
        if P.safe_rmtree(folder):
            removed_dirs.append(folder.name)
    for p in (P.legacy_flat_report(rid), P.legacy_flat_result(rid), P.legacy_db_path(rid)):
        if p.exists() and p.is_file():
            try:
                root = config.REPORTS_DIR.resolve()
                target = p.resolve()
                target.relative_to(root)
                p.unlink()
                removed_files.append(p.name)
            except Exception as e:
                print(f"[report_delete] unlink {p}: {e}")
        for suf in ("-wal", "-shm"):
            wp = Path(str(p) + suf)
            if wp.exists():
                try:
                    wp.unlink()
                except OSError:
                    pass
    return {"removed_dirs": removed_dirs, "removed_files": removed_files}


def _mysql_delete(rids: List[str], hostname: str = "", by_host: bool = False) -> Dict[str, Any]:
    out = {"ok": False, "cleared": 0, "error": ""}
    try:
        from .mysql_db import mysql_ready
        from .mysql_store import delete_report_files, delete_reports_by_hostname
        if not mysql_ready():
            out["error"] = "mysql_down"
            _enqueue_pending(rids, hostname)
            return out
        n = 0
        if by_host and hostname:
            n = max(n, delete_reports_by_hostname(hostname))
        if rids:
            n = max(n, delete_report_files(rids))
        out["ok"] = True
        out["cleared"] = n
        return out
    except Exception as e:
        out["error"] = str(e)
        _enqueue_pending(rids, hostname)
        print(f"[report_delete] mysql: {e}")
        return out


def delete_one_report(rid: str) -> Dict[str, Any]:
    """删除一份分析报告：任务 → 本地 → 索引 → MySQL → ES/Redis。"""
    rid = P.safe_report_id(rid)
    row = _lookup_index_row(rid)
    local_exists = bool(
        P.resolve_report_json(rid)
        or P.resolve_analysis_db(rid)
        or P.resolve_result_json(rid)
        or (P.report_dir(rid).exists() and P.report_dir(rid).is_dir())
    )
    if not row and not local_exists:
        raise FileNotFoundError("报告不存在")
    hostname = (row.get("hostname") or "").strip()

    jobs_n = 0
    try:
        from .jobs import purge_jobs_for_files
        jobs_n = purge_jobs_for_files([rid])
    except Exception as e:
        print(f"[report_delete] jobs {rid}: {e}")

    local = _delete_local(rid)
    try:
        delete_index_entry(rid, mysql=False)
    except Exception as e:
        print(f"[report_delete] index {rid}: {e}")

    mysql = _mysql_delete([rid], hostname, by_host=False)
    try:
        from .result_sync import purge_remote
        purge_remote([rid], hostname=hostname or None, background=True)
    except Exception as e:
        print(f"[report_delete] remote {rid}: {e}")

    try:
        from .db_store import invalidate_list_cache, _invalidate_disk_cache
        invalidate_list_cache()
        _invalidate_disk_cache(rid)
    except Exception:
        pass

    return {
        "ok": True,
        "file": rid,
        "hostname": hostname,
        "jobs_cleared": jobs_n,
        "mysql": mysql,
        **local,
    }


def delete_reports_for_host(hostname: str) -> Dict[str, Any]:
    """按主机删除其下全部报告。hostname 必须来自服务端台账，不能来自请求体文件列表。"""
    hostname = (hostname or "").strip()
    if not hostname or hostname in {".", ".."} or any(c in hostname for c in "/\\:\0<>|*?"):
        raise ValueError("非法主机名")
    files = list_files_for_host(hostname)

    jobs_n = 0
    try:
        from .jobs import purge_jobs_for_files
        jobs_n = purge_jobs_for_files(files)
    except Exception as e:
        print(f"[report_delete] host jobs: {e}")

    removed_dirs: List[str] = []
    removed_files: List[str] = []
    stems = set()
    for rid in files:
        try:
            stems.add(P.report_stem(rid))
        except Exception:
            pass
        local = _delete_local(rid)
        removed_dirs.extend(local.get("removed_dirs") or [])
        removed_files.extend(local.get("removed_files") or [])
        try:
            delete_index_entry(rid, mysql=False)
        except Exception as e:
            print(f"[report_delete] index {rid}: {e}")

    # 只删索引里这台主机对应的目录，不用 hostname_ 前缀模糊扫
    try:
        root = config.REPORTS_DIR
        if root.exists():
            for d in root.iterdir():
                if not d.is_dir() or d.name in P.RESERVED or d.name.startswith("."):
                    continue
                try:
                    rid = P.safe_report_id(d.name)
                except ValueError:
                    continue
                if d.name in stems or rid in files:
                    if P.safe_rmtree(d) and d.name not in removed_dirs:
                        removed_dirs.append(d.name)
    except OSError as e:
        print(f"[report_delete] scan dirs: {e}")

    mysql = _mysql_delete(files, hostname, by_host=True)
    try:
        from .result_sync import purge_remote
        purge_remote(files, hostname=hostname, background=True)
    except Exception as e:
        print(f"[report_delete] host remote: {e}")

    # 兜底：按主机名清空残留索引（避免删完台账后 sync 又把主机建回来）
    try:
        if INDEX_DB.exists():
            conn = _connect(INDEX_DB)
            try:
                _init_index(conn)
                conn.execute("DELETE FROM reports WHERE hostname=?", (hostname,))
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        print(f"[report_delete] wipe sqlite host index: {e}")
    try:
        from .mysql_store import delete_reports_by_hostname
        delete_reports_by_hostname(hostname)
    except Exception as e:
        print(f"[report_delete] wipe mysql host index: {e}")

    # 扫磁盘：report_<hostname>_ 前缀目录（索引漏记时仍能清掉）
    try:
        root = config.REPORTS_DIR
        prefix = f"report_{hostname}_"
        if root.exists():
            for d in root.iterdir():
                if not d.is_dir() or d.name in P.RESERVED or d.name.startswith("."):
                    continue
                if d.name == hostname or d.name.startswith(prefix) or d.name in stems:
                    if P.safe_rmtree(d) and d.name not in removed_dirs:
                        removed_dirs.append(d.name)
    except OSError as e:
        print(f"[report_delete] host disk sweep: {e}")

    try:
        from .db_store import invalidate_list_cache, prune_stale_index
        invalidate_list_cache()
        prune_stale_index()
    except Exception as e:
        print(f"[report_delete] invalidate: {e}")

    return {
        "hostname": hostname,
        "removed_dirs": removed_dirs,
        "removed_files": removed_files,
        "index_cleared": len(files),
        "jobs_cleared": jobs_n,
        "mysql_cleared": int((mysql or {}).get("cleared") or 0),
        "mysql": mysql,
        "files": files,
    }
