"""Elasticsearch 客户端单例，带自动回退。

- ES 不可用或未配置时所有操作静默失败，不影响主流程。
- 默认验证 HTTPS 证书；自签证书应配置受信 CA。
- 索引目标：cnpc_findings（可在 db_config.json 中配置）。
"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from .cache_config import es_config

_lock = threading.Lock()
_client: Any = None
_available: Optional[bool] = None
_index_created: bool = False
_last_error: str = ""

FINDINGS_MAPPING = {
    "mappings": {
        "properties": {
            "report_id":    {"type": "keyword"},
            "hostname":     {"type": "keyword"},
            "analyzed_at":  {"type": "date", "format": "strict_date_time||strict_date_optional_time||epoch_millis"},
            "severity":     {"type": "keyword"},
            "category":     {"type": "keyword"},
            "matcher":      {"type": "keyword"},
            "rule_id":      {"type": "keyword"},
            "title":        {"type": "text", "analyzer": "standard", "fields": {"raw": {"type": "keyword"}}},
            "evidence":     {"type": "text", "analyzer": "standard"},
            "source":       {"type": "keyword"},
            "owner_id":     {"type": "keyword"},
        }
    }
}


def _quick_port_open(hosts: list, timeout: float = 0.35) -> bool:
    """配置开着但进程未起时，先 TCP 探活，避免 Elasticsearch 客户端卡满超时。"""
    import socket
    from urllib.parse import urlparse

    for raw in hosts or []:
        try:
            u = urlparse(str(raw))
            host = u.hostname or "127.0.0.1"
            port = int(u.port or (443 if u.scheme == "https" else 80))
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            continue
    return False


def _make_client():
    global _last_error
    cfg = es_config()
    if not cfg.get("enabled"):
        _last_error = "未启用"
        return None
    pw = cfg.get("password") or ""
    if not pw:
        _last_error = "未配置密码"
        return None
    try:
        from elasticsearch import Elasticsearch
        hosts = cfg.get("hosts") or ["https://127.0.0.1:9200"]
        if not _quick_port_open(hosts):
            _last_error = "端口未监听（进程未启动）"
            print("[es] connect skipped: port not open")
            return None
        user = cfg.get("user") or "elastic"
        raw_verify = cfg.get("verify_certs", True)
        if isinstance(raw_verify, str):
            verify = raw_verify.strip().lower() not in ("0", "false", "no", "off")
        else:
            verify = bool(raw_verify)
        kwargs = {
            "basic_auth": (user, pw),
            "verify_certs": verify,
            "ssl_show_warn": False,
            "request_timeout": 2.5,
        }
        # 本地自签证书：关闭校验时一并关闭主机名校验，避免 elastic-transport 仍失败
        if not verify:
            kwargs["ssl_assert_hostname"] = False
            kwargs["ssl_assert_fingerprint"] = None
        es = Elasticsearch(hosts, **kwargs)
        info = es.info()
        _last_error = ""
        print(f"[es] connected, version={info['version']['number']} verify_certs={verify}")
        return es
    except Exception as e:
        _last_error = f"{type(e).__name__}: {e}"
        print(f"[es] connect failed (ES indexing disabled): {e}")
        low = str(e).lower()
        if "certificate" in low or "ssl" in low or "tls" in low:
            _last_error += " · 本地自签可在 db_config.json 设 elasticsearch.verify_certs=false"
        return None


def get_client():
    global _client, _available
    with _lock:
        if _available is not None:
            return _client
        _client = _make_client()
        _available = _client is not None
        return _client


def is_available() -> bool:
    return get_client() is not None


def reset() -> None:
    global _client, _available, _index_created, _last_error
    with _lock:
        _client = None
        _available = None
        _index_created = False
        _last_error = ""


def probe_status(reprobe: bool = False) -> dict:
    """管理后台用：ES 连接态与失败原因。"""
    import time
    cfg = es_config()
    hosts = cfg.get("hosts") or []
    out = {
        "connected": False,
        "enabled": bool(cfg.get("enabled")),
        "hosts": hosts,
        "index": cfg.get("index") or cfg.get("findings_index") or "",
        "latency_ms": None,
        "version": "",
        "error": "",
        "hint": "",
    }
    if not cfg.get("enabled"):
        out["error"] = "未启用"
        out["hint"] = "告警不会写入 ES，主站检索走本地/MySQL。可在配置页打开。"
        return out
    if not (cfg.get("password") or ""):
        out["error"] = "未配置密码"
        out["hint"] = "Elasticsearch 需要账号密码，请到配置页填写。"
        return out
    if reprobe:
        reset()
    try:
        t0 = time.perf_counter()
        es = get_client()
        if es:
            info = es.info()
            out["connected"] = True
            out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            try:
                out["version"] = str((info or {}).get("version", {}).get("number") or "")
            except Exception:
                pass
        else:
            out["error"] = _last_error or "连接失败，索引已禁用"
            out["hint"] = "检查 ES 是否启动、HTTPS 地址、账号密码。本地自签证书请设 verify_certs=false。"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        low = str(e).lower()
        if "certificate" in low or "ssl" in low or "tls" in low:
            out["hint"] = "自签证书：在 db_config.json 的 elasticsearch.verify_certs 设为 false 后重启。"
        else:
            out["hint"] = "info() 调用失败，请核对证书与网络。"
    return out


def _ensure_index() -> bool:
    global _index_created
    if _index_created:
        return True
    es = get_client()
    if not es:
        return False
    try:
        cfg = es_config()
        idx = cfg["index_findings"]
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx, body=FINDINGS_MAPPING)
            print(f"[es] created index {idx}")
        _index_created = True
        return True
    except Exception as e:
        print(f"[es] ensure index failed: {e}")
        return False


def index_findings(
    report_id: str,
    hostname: str,
    analyzed_at: str,
    findings: List[Dict[str, Any]],
) -> int:
    """批量写入 findings 到 ES。出错静默，返回成功写入条数。"""
    if not findings:
        return 0
    es = get_client()
    if not es:
        return 0
    if not _ensure_index():
        return 0
    cfg = es_config()
    idx = cfg["index_findings"]
    try:
        from elasticsearch.helpers import bulk
        docs = []
        ts = analyzed_at or datetime.utcnow().isoformat() + "Z"
        owner_id = ""
        try:
            from .db_store import get_report_owner
            owner_id = str((get_report_owner(report_id) or {}).get("owner_id") or "")
        except Exception:
            owner_id = ""
        for f in findings:
            if not isinstance(f, dict):
                continue
            ev = f.get("evidence")
            if isinstance(ev, list):
                ev_s = " ".join(str(x) for x in ev[:8])
            else:
                ev_s = str(ev or "")
            reason = str(f.get("reason") or "")
            if reason and reason not in ev_s:
                ev_s = (ev_s + " " + reason).strip()
            doc_id = f"{report_id}_{f.get('matcher','')}__{f.get('rule_id','') or f.get('title','')[:40]}"
            docs.append({
                "_index": idx,
                "_id": doc_id[:200],
                "_source": {
                    "report_id": report_id,
                    "hostname": hostname,
                    "analyzed_at": ts,
                    "severity": f.get("severity") or "medium",
                    "category": f.get("category") or f.get("type") or "",
                    "matcher": f.get("matcher") or "",
                    "rule_id": f.get("rule_id") or "",
                    "title": f.get("title") or f.get("name") or "",
                    "evidence": ev_s[:2000],
                    "source": f.get("source") or "",
                    "owner_id": owner_id,
                },
            })
        if not docs:
            return 0
        ok, errors = bulk(es, docs, raise_on_error=False, request_timeout=15)
        if errors:
            print(f"[es] bulk partial errors: {len(errors)}")
        return ok
    except Exception as e:
        print(f"[es] index_findings failed: {e}")
        return 0


def search_findings(
    q: str,
    hostname: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = 50,
    user: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """跨主机全文检索 findings。ES 不可用时返回空列表。"""
    es = get_client()
    if not es:
        return []
    cfg = es_config()
    idx = cfg["index_findings"]
    try:
        q = (q or "").strip()
        must: List[Dict] = []
        if q:
            must.append({
                "multi_match": {
                    "query": q,
                    "fields": ["title^4", "evidence^2", "category", "rule_id", "hostname"],
                    "type": "best_fields",
                    "operator": "or",
                    "lenient": True,
                }
            })
        filter_: List[Dict] = []
        if hostname:
            filter_.append({"term": {"hostname": hostname}})
        if severity:
            filter_.append({"term": {"severity": severity}})
        try:
            from .ownership import is_admin
            if user and not is_admin(user):
                oid = str(user.get("id") or "").strip()
                if oid:
                    filter_.append({"term": {"owner_id": oid}})
                else:
                    return []
        except Exception:
            pass
        body: Dict[str, Any] = {
            "size": min(size, 200),
            "query": {"bool": {"must": must or [{"match_all": {}}], "filter": filter_}},
            "sort": [{"_score": "desc"}, {"analyzed_at": "desc"}],
        }
        try:
            resp = es.search(index=idx, body=body, request_timeout=10)
        except TypeError:
            resp = es.search(index=idx, query=body["query"], size=body["size"], sort=body["sort"])
        hits = (resp.get("hits") or {}).get("hits") or []
        return [{"_score": h.get("_score"), **(h.get("_source") or {})} for h in hits]
    except Exception as e:
        print(f"[es] search_findings failed: {e}")
        return []


def _delete_by_query(query: Dict[str, Any]) -> int:
    es = get_client()
    if not es:
        return 0
    cfg = es_config()
    idx = cfg["index_findings"]
    try:
        resp = es.delete_by_query(
            index=idx,
            body={"query": query},
            request_timeout=20,
            conflicts="proceed",
            refresh=False,
        )
        return int((resp or {}).get("deleted", 0) or 0)
    except TypeError:
        try:
            resp = es.delete_by_query(index=idx, query=query, conflicts="proceed")
            return int((resp or {}).get("deleted", 0) or 0)
        except Exception as e:
            print(f"[es] delete_by_query failed: {e}")
            return 0
    except Exception as e:
        print(f"[es] delete_by_query failed: {e}")
        return 0


def delete_findings_for_report(report_id: str) -> int:
    """删除某报告的所有 findings（重分析前清理）。"""
    rid = str(report_id or "").strip()
    if not rid:
        return 0
    return _delete_by_query({"term": {"report_id": rid}})


def delete_findings_for_reports(report_ids: List[str]) -> int:
    ids = [str(x).strip() for x in (report_ids or []) if str(x or "").strip()]
    if not ids:
        return 0
    n = 0
    for i in range(0, len(ids), 200):
        n += _delete_by_query({"terms": {"report_id": ids[i:i + 200]}})
    return n


def delete_findings_for_hostname(hostname: str) -> int:
    hn = str(hostname or "").strip()
    if not hn:
        return 0
    return _delete_by_query({"term": {"hostname": hn}})
