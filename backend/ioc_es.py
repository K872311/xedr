# -*- coding: utf-8 -*-
"""IOC 情报 Elasticsearch 索引（遗留可选；IOC 管理默认已改走 MySQL）。

设计目标（快查，仅当 elasticsearch.enabled=true 时生效）：
  - 全量 keyword 精确匹配，不用全文分词
  - 文档 _id 稳定：sha1(type|value) → 可 upsert / mget
  - domain 父域：一次 terms 查询多个后缀
  - ip：同时匹配 value 与 ip_only

主路径见 backend/ioc_mysql.py；查询路径：LRU → Redis → MySQL → SQLite
索引默认名：cnpc_ioc（db_config.elasticsearch.index_ioc）
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cache_config import es_config
from . import es_client
from . import config

IOC_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "30s",
    },
    "mappings": {
        "properties": {
            "type": {"type": "keyword"},
            "value": {"type": "keyword", "ignore_above": 2048},
            "ip_only": {"type": "keyword"},
            "source": {"type": "keyword", "ignore_above": 256},
            "malware": {
                "type": "text",
                "fields": {"raw": {"type": "keyword", "ignore_above": 512}},
            },
            "sqlite_id": {"type": "long"},
            "updated_at": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
        }
    },
}

_index_ready = False
_sync_lock = threading.Lock()
_sync_state: Dict[str, Any] = {
    "running": False,
    "last_ok": False,
    "last_error": "",
    "indexed": 0,       # 本次实际写入条数
    "added": 0,         # 新增（ES 中原本不存在）
    "skipped": 0,       # 已存在而跳过
    "scanned": 0,       # 已扫描 SQLite 行数
    "total": 0,
    "mode": "",         # incremental | recreate
    "started_at": "",
    "finished_at": "",
    "elapsed_ms": 0,
    "errors": 0,
    "es_count_before": None,
    "es_count_after": None,
}


def _sync_state_path() -> Path:
    return Path(getattr(config, "CONFIG_DIR", None) or (Path(__file__).resolve().parent.parent / "config")) / "ioc_es_sync_state.json"


def _load_persisted_sync_state() -> None:
    """进程启动时恢复上次同步结果，避免页面看不到新增/跳过。"""
    p = _sync_state_path()
    if not p.is_file():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
        for k in (
            "last_ok", "last_error", "indexed", "added", "skipped", "scanned",
            "total", "mode", "started_at", "finished_at", "elapsed_ms", "errors",
            "es_count_before", "es_count_after",
        ):
            if k in data:
                _sync_state[k] = data[k]
        _sync_state["running"] = False
    except Exception as e:
        print(f"[ioc_es] load sync state failed: {e}")


def _persist_sync_state() -> None:
    """把最近一次同步结果落到磁盘，刷新页面仍可见。"""
    try:
        p = _sync_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_ok": bool(_sync_state.get("last_ok")),
            "last_error": _sync_state.get("last_error") or "",
            "indexed": int(_sync_state.get("indexed") or 0),
            "added": int(_sync_state.get("added") or 0),
            "skipped": int(_sync_state.get("skipped") or 0),
            "scanned": int(_sync_state.get("scanned") or 0),
            "total": int(_sync_state.get("total") or 0),
            "mode": _sync_state.get("mode") or "",
            "started_at": _sync_state.get("started_at") or "",
            "finished_at": _sync_state.get("finished_at") or "",
            "elapsed_ms": int(_sync_state.get("elapsed_ms") or 0),
            "errors": int(_sync_state.get("errors") or 0),
            "es_count_before": _sync_state.get("es_count_before"),
            "es_count_after": _sync_state.get("es_count_after"),
        }
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[ioc_es] persist sync state failed: {e}")


_load_persisted_sync_state()


def index_name() -> str:
    cfg = es_config()
    return str(cfg.get("index_ioc") or "cnpc_ioc").strip() or "cnpc_ioc"


def doc_id(ioc_type: str, value: str) -> str:
    raw = f"{(ioc_type or '').strip().lower()}|{(value or '').strip().lower()}".encode("utf-8", "ignore")
    return hashlib.sha1(raw).hexdigest()


def ensure_index(*, recreate: bool = False) -> bool:
    """确保 IOC 索引存在。"""
    global _index_ready
    es = es_client.get_client()
    if not es:
        return False
    idx = index_name()
    try:
        exists = es.indices.exists(index=idx)
        if recreate and exists:
            es.indices.delete(index=idx, ignore=[404])
            exists = False
            _index_ready = False
        if not exists:
            try:
                es.indices.create(index=idx, body=IOC_MAPPING)
            except TypeError:
                es.indices.create(index=idx, settings=IOC_MAPPING["settings"], mappings=IOC_MAPPING["mappings"])
            print(f"[ioc_es] created index {idx}")
        _index_ready = True
        return True
    except Exception as e:
        print(f"[ioc_es] ensure_index failed: {e}")
        return False


def count_docs() -> int:
    es = es_client.get_client()
    if not es:
        return -1
    idx = index_name()
    try:
        if not es.indices.exists(index=idx):
            return 0
        resp = es.count(index=idx)
        return int((resp or {}).get("count") or 0)
    except Exception:
        return -1


def _safe_str(v: Any, limit: int = 0) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        s = v.decode("utf-8", errors="replace")
    else:
        try:
            s = str(v)
        except Exception:
            s = repr(v)
    # 去掉替换符噪音
    s = s.replace("\ufffd", "").strip()
    if limit and len(s) > limit:
        s = s[:limit]
    return s


def _row_to_action(row: Tuple, updated_at: str, *, op_type: str = "index") -> Optional[Dict[str, Any]]:
    # row: id, type, value, ip_only, source, malware
    rid, typ, value, ip_only, source, malware = row
    typ = _safe_str(typ).lower()
    value = _safe_str(value, 2048).lower()
    if not typ or not value:
        return None
    ip_only_s = _safe_str(ip_only, 64).lower()
    if typ == "ip" and not ip_only_s:
        ip_only_s = value.split(":")[0].strip("[]")
    return {
        "_op_type": op_type,
        "_index": index_name(),
        "_id": doc_id(typ, value),
        "_source": {
            "type": typ,
            "value": value[:2048],
            "ip_only": ip_only_s[:64],
            "source": _safe_str(source, 256),
            "malware": _safe_str(malware, 1024),
            "sqlite_id": int(rid or 0),
            "updated_at": updated_at,
        },
    }


def _mget_existing_ids(es: Any, idx: str, ids: List[str], *, chunk: int = 1000) -> set:
    """批量探测哪些 _id 已在 ES 中存在。"""
    found: set = set()
    if not ids:
        return found
    for i in range(0, len(ids), chunk):
        part = ids[i : i + chunk]
        try:
            try:
                resp = es.mget(index=idx, ids=part, _source=False)
            except TypeError:
                resp = es.mget(index=idx, body={"ids": part}, _source=False)
        except Exception as e:
            print(f"[ioc_es] mget failed: {e!r}")
            # 探测失败时保守起见不跳过，后续走 create 由 ES 判重
            continue
        for doc in (resp or {}).get("docs") or []:
            if doc.get("found"):
                did = doc.get("_id")
                if did:
                    found.add(did)
    return found


def sync_from_sqlite(
    db_path: Optional[Path] = None,
    *,
    recreate: bool = False,
    batch_size: int = 3000,
) -> Dict[str, Any]:
    """SQLite → ES。

    - recreate=False（默认）：增量同步，mget 匹配已有 _id，只写入新增
    - recreate=True：删索引后全量重建
    """
    from . import ioc_db

    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "error": "同步进行中", **dict(_sync_state)}

    started = time.time()
    mode = "recreate" if recreate else "incremental"
    es_before = count_docs()
    _sync_state.update({
        "running": True,
        "last_ok": False,
        "last_error": "",
        "indexed": 0,
        "added": 0,
        "skipped": 0,
        "scanned": 0,
        "total": 0,
        "mode": mode,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "finished_at": "",
        "elapsed_ms": 0,
        "errors": 0,
        "es_count_before": es_before if es_before >= 0 else None,
        "es_count_after": None,
    })
    try:
        if not es_client.is_available():
            raise RuntimeError("Elasticsearch 不可用")
        path = Path(db_path) if db_path else ioc_db.get_db_path()
        if not path or not path.is_file():
            raise RuntimeError("IOC SQLite 不存在")
        if not ensure_index(recreate=recreate):
            raise RuntimeError("无法创建/确认 IOC 索引")

        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=60)
        # IOC 源库可能含非 UTF-8 字节，按替换解码避免中断导入
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace") if isinstance(b, (bytes, bytearray)) else b
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM ioc_records WHERE type IS NOT NULL AND type!='' AND value IS NOT NULL AND value!=''"
            ).fetchone()[0]
            _sync_state["total"] = int(total)
            from elasticsearch.helpers import bulk

            es = es_client.get_client()
            idx = index_name()
            es_empty = False
            if not recreate:
                try:
                    n0 = count_docs()
                    es_empty = n0 == 0
                except Exception:
                    es_empty = False
            # 增量时缩短 refresh；完成后恢复
            if not recreate:
                try:
                    es.indices.put_settings(index=idx, body={"index": {"refresh_interval": "-1"}})
                except TypeError:
                    try:
                        es.indices.put_settings(index=idx, settings={"index": {"refresh_interval": "-1"}})
                    except Exception:
                        pass
                except Exception:
                    pass

            updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            cur = conn.execute(
                "SELECT id, type, value, ip_only, source, malware FROM ioc_records "
                "WHERE type IS NOT NULL AND type!='' AND value IS NOT NULL AND value!=''"
            )
            indexed = 0
            added = 0
            skipped = 0
            scanned = 0
            errors_n = 0
            while True:
                rows = cur.fetchmany(batch_size)
                if not rows:
                    break
                scanned += len(rows)
                actions: List[Dict[str, Any]] = []
                for row in rows:
                    act = _row_to_action(row, updated_at, op_type="create" if not recreate else "index")
                    if act:
                        actions.append(act)

                if not actions:
                    _sync_state.update({"scanned": scanned, "indexed": indexed, "added": added, "skipped": skipped})
                    continue

                if not recreate and not es_empty:
                    ids = [a["_id"] for a in actions]
                    exists = _mget_existing_ids(es, idx, ids)
                    if exists:
                        filtered = []
                        for a in actions:
                            if a["_id"] in exists:
                                skipped += 1
                            else:
                                filtered.append(a)
                        actions = filtered
                    if not actions:
                        _sync_state.update({
                            "scanned": scanned,
                            "indexed": indexed,
                            "added": added,
                            "skipped": skipped,
                        })
                        continue

                ok, errors = bulk(
                    es,
                    actions,
                    raise_on_error=False,
                    request_timeout=120,
                    chunk_size=batch_size,
                )
                wrote = int(ok or 0)
                indexed += wrote
                added += wrote
                if errors:
                    # create 冲突等记入跳过/错误
                    for err in errors:
                        info = err.get("create") or err.get("index") or {}
                        status = info.get("status")
                        if status in (409,):
                            skipped += 1
                        else:
                            errors_n += 1
                _sync_state.update({
                    "scanned": scanned,
                    "indexed": indexed,
                    "added": added,
                    "skipped": skipped,
                    "errors": errors_n,
                })
            # 导入完成后强制 refresh，立即可查
            try:
                es.indices.refresh(index=idx)
            except Exception:
                pass
            # 恢复正常 refresh
            try:
                es.indices.put_settings(index=idx, body={"index": {"refresh_interval": "1s"}})
            except TypeError:
                try:
                    es.indices.put_settings(index=idx, settings={"index": {"refresh_interval": "1s"}})
                except Exception:
                    pass
            except Exception:
                pass

            elapsed = int((time.time() - started) * 1000)
            es_after = count_docs()
            _sync_state.update({
                "running": False,
                "last_ok": True,
                "last_error": "",
                "indexed": indexed,
                "added": added,
                "skipped": skipped,
                "scanned": scanned,
                "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "elapsed_ms": elapsed,
                "errors": errors_n,
                "es_count_after": es_after if es_after >= 0 else None,
            })
            _persist_sync_state()
            print(
                f"[ioc_es] {mode} added={added} skipped={skipped} "
                f"scanned={scanned}/{total} in {elapsed}ms errors={errors_n} "
                f"es {es_before}->{es_after}"
            )
            return {
                "ok": True,
                "index": idx,
                "indexed": indexed,
                "added": added,
                "skipped": skipped,
                "scanned": scanned,
                "total": total,
                "errors": errors_n,
                "elapsed_ms": elapsed,
                "recreate": recreate,
                "mode": mode,
                "es_count_before": es_before if es_before >= 0 else None,
                "es_count_after": es_after if es_after >= 0 else None,
            }
        finally:
            conn.close()
    except Exception as e:
        _sync_state.update({
            "running": False,
            "last_ok": False,
            "last_error": str(e),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed_ms": int((time.time() - started) * 1000),
            "es_count_after": count_docs() if es_client.is_available() else None,
        })
        _persist_sync_state()
        print(f"[ioc_es] sync failed: {type(e).__name__}: {e!r}")
        return {"ok": False, "error": f"{type(e).__name__}: {e}", **dict(_sync_state)}
    finally:
        _sync_lock.release()


def sync_status() -> Dict[str, Any]:
    out = dict(_sync_state)
    out["index"] = index_name()
    out["es_count"] = count_docs()
    out["es_available"] = es_client.is_available()
    # 方便前端判断「有没有可展示的上次结果」
    out["has_result"] = bool(
        out.get("finished_at")
        or out.get("running")
        or int(out.get("scanned") or 0) > 0
        or int(out.get("added") or 0) > 0
        or int(out.get("skipped") or 0) > 0
        or out.get("last_error")
    )
    return out


def start_sync_async(*, recreate: bool = False, only_if_empty: bool = False) -> Dict[str, Any]:
    """后台线程同步。"""
    if only_if_empty:
        n = count_docs()
        if n > 0:
            return {"ok": True, "skipped": True, "reason": "index_not_empty", "es_count": n}
        if n < 0:
            return {"ok": False, "error": "es_unavailable"}
    if _sync_state.get("running"):
        return {"ok": False, "error": "同步进行中", **sync_status()}

    def _run():
        sync_from_sqlite(recreate=recreate)

    t = threading.Thread(target=_run, name="ioc-es-sync", daemon=True)
    t.start()
    return {"ok": True, "started": True, "recreate": recreate}


def _hit_from_source(src: Dict[str, Any], match_type: str, matched: str) -> Dict[str, Any]:
    malware = (src.get("malware") or "").strip()
    source = (src.get("source") or "").strip()
    name = malware.split(",")[0].strip() if malware else (matched or "IOC")
    db_type = (src.get("type") or "").strip()
    return {
        "hash": matched if match_type in ("md5", "sha1", "sha256") else "",
        "domain": matched if match_type == "domain" else "",
        "ip": matched if match_type == "ip" else "",
        "url": matched if match_type == "url" else "",
        "name": (name or matched)[:120],
        "severity": "high",
        "tags": [t.strip() for t in malware.replace(";", ",").split(",") if t.strip()][:12],
        "source": source or "ioc_es",
        "malware": malware,
        "match_type": match_type,
        "matched": matched,
        "db_id": src.get("sqlite_id"),
        "db_type": db_type,
        "from_db": True,
        "from_es": True,
    }


def _search(filter_clauses: List[Dict[str, Any]], size: int = 20) -> List[Dict[str, Any]]:
    es = es_client.get_client()
    if not es:
        return []
    if not ensure_index():
        return []
    idx = index_name()
    body = {
        "size": size,
        "query": {"bool": {"filter": filter_clauses}},
        "_source": True,
    }
    try:
        try:
            resp = es.search(index=idx, body=body, request_timeout=3)
        except TypeError:
            resp = es.search(index=idx, query=body["query"], size=size, request_timeout=3)
        hits = (resp.get("hits") or {}).get("hits") or []
        return [h.get("_source") or {} for h in hits if h.get("_source")]
    except Exception as e:
        print(f"[ioc_es] search failed: {e}")
        return []


def lookup_exact(ioc_type: str, values: List[str], *, match_type: Optional[str] = None, size: int = 20) -> List[Dict[str, Any]]:
    """精确 terms 查询。values 已规范化小写。"""
    typ = (ioc_type or "").strip().lower()
    vals = [str(v).strip().lower() for v in (values or []) if str(v or "").strip()]
    if not typ or not vals:
        return []
    # 去重保序
    seen = set()
    uniq = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    srcs = _search(
        [{"term": {"type": typ}}, {"terms": {"value": uniq[:64]}}],
        size=size,
    )
    mt = match_type or typ
    out = []
    for s in srcs:
        matched = (s.get("value") or "").lower()
        out.append(_hit_from_source(s, mt, matched))
    return out


def lookup_ip(ip: str, size: int = 20) -> List[Dict[str, Any]]:
    v = (ip or "").strip().lower().strip("[]")
    if not v:
        return []
    # value 可能是 ip:port，同时查 value 与 ip_only
    srcs = _search(
        [
            {"term": {"type": "ip"}},
            {
                "bool": {
                    "should": [
                        {"term": {"value": v}},
                        {"term": {"ip_only": v}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        ],
        size=size,
    )
    return [_hit_from_source(s, "ip", (s.get("ip_only") or s.get("value") or v)) for s in srcs]


def lookup_domain(host: str, size: int = 20) -> List[Dict[str, Any]]:
    h = (host or "").strip().lower().strip(".")
    if not h or h.replace(".", "").isdigit():
        return []
    candidates = [h]
    parts = h.split(".")
    if len(parts) > 2:
        for i in range(1, min(len(parts) - 1, 4)):
            suffix = ".".join(parts[i:])
            if len(suffix) >= 4:
                candidates.append(suffix)
    return lookup_exact("domain", candidates, match_type="domain", size=size)


def lookup_url(urls: List[str], size: int = 20) -> List[Dict[str, Any]]:
    vals: List[str] = []
    for u in urls or []:
        u = (u or "").strip().lower()
        if not u:
            continue
        vals.append(u)
        if not u.endswith("/"):
            vals.append(u + "/")
        else:
            vals.append(u.rstrip("/"))
    return lookup_exact("url", vals, match_type="url", size=size)


def lookup_hash(hex_str: str, match_type: str = "md5", size: int = 20) -> List[Dict[str, Any]]:
    v = (hex_str or "").strip().lower()
    if not v:
        return []
    return lookup_exact("file_hash", [v], match_type=match_type or "md5", size=size)


def lookup_hashes(hex_values: List[str], *, chunk_size: int = 64) -> Dict[str, List[Dict[str, Any]]]:
    """批量精确查 file_hash。返回 value→hits；每批最多 chunk_size，不扫全库。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    seen = set()
    uniq: List[str] = []
    for raw in hex_values or []:
        v = str(raw or "").strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        uniq.append(v)
    if not uniq:
        return out
    cs = max(8, min(int(chunk_size or 64), 64))
    for i in range(0, len(uniq), cs):
        chunk = uniq[i : i + cs]
        # size 需盖住一批内多源重复命中
        hits = lookup_exact("file_hash", chunk, match_type="file_hash", size=min(500, max(64, len(chunk) * 8)))
        bucket: Dict[str, List[Dict[str, Any]]] = {v: [] for v in chunk}
        for h in hits:
            matched = str(h.get("matched") or h.get("hash") or h.get("value") or "").strip().lower()
            if matched in bucket:
                # 按长度标成 md5/sha1/sha256，便于前端分类
                n = len(matched)
                mt = "md5" if n == 32 else ("sha1" if n == 40 else ("sha256" if n == 64 else "file_hash"))
                row = dict(h)
                row["match_type"] = mt
                bucket[matched].append(row)
        for v, rows in bucket.items():
            out[v] = rows
    return out


def stats() -> Dict[str, Any]:
    return {
        "index": index_name(),
        "available": es_client.is_available(),
        "count": count_docs(),
        "sync": sync_status(),
    }
