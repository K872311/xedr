# -*- coding: utf-8 -*-
"""Elastic Detection 与 ES 并行：端点事件写入 ES + EQL 周期检测（无需 Kibana 也能跑 TOML EQL 子集）。"""
from __future__ import annotations

import json
import re
import threading
import time
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config
from .cache_config import es_config

_lock = threading.RLock()
_index_ok = False
_rule_cursor = 0
_last_run: Dict[str, Any] = {}

EDR_EVENT_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {
                "properties": {
                    "type": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "dataset": {"type": "keyword"},
                }
            },
            "host": {
                "properties": {
                    "name": {"type": "keyword"},
                    "os": {"properties": {"type": {"type": "keyword"}}},
                }
            },
            "agent": {"properties": {"id": {"type": "keyword"}}},
            "process": {
                "properties": {
                    "name": {"type": "keyword"},
                    "command_line": {"type": "wildcard"},
                    "executable": {"type": "keyword"},
                    "pid": {"type": "long"},
                    "args": {"type": "wildcard"},
                }
            },
            "file": {"properties": {"path": {"type": "keyword"}, "name": {"type": "keyword"}}},
            "registry": {"properties": {"path": {"type": "keyword"}, "value": {"type": "keyword"}}},
            "dns": {"properties": {"question": {"properties": {"name": {"type": "keyword"}}}}},
            "message": {"type": "text"},
            "edr": {
                "properties": {
                    "summary": {"type": "text"},
                    "etype": {"type": "keyword"},
                    "module": {"type": "keyword"},
                }
            },
        }
    }
}

DETECTION_RULES_MAPPING = {
    "mappings": {
        "properties": {
            "rule_id": {"type": "keyword"},
            "elastic_rule_id": {"type": "keyword"},
            "name": {"type": "text"},
            "severity": {"type": "keyword"},
            "type": {"type": "keyword"},
            "language": {"type": "keyword"},
            "query": {"type": "text", "index": False},
            "rel_path": {"type": "keyword"},
            "enabled": {"type": "boolean"},
            "updated_at": {"type": "date"},
        }
    }
}


def _cfg() -> Dict[str, Any]:
    c = es_config()
    c.setdefault("index_edr_events", "cnpc_edr_events")
    c.setdefault("index_edr_detection_rules", "cnpc_edr_detection_rules")
    c.setdefault("edr_detection_enabled", False)
    c.setdefault("edr_detection_interval_sec", 300)
    c.setdefault("edr_detection_window_min", 15)
    c.setdefault("edr_detection_rules_per_run", 24)
    return c


def detection_enabled() -> bool:
    c = _cfg()
    return bool(c.get("enabled")) and bool(c.get("edr_detection_enabled"))


def _ensure_index(name: str, mapping: Dict[str, Any]) -> bool:
    from . import es_client

    es = es_client.get_client()
    if not es:
        return False
    try:
        if not es.indices.exists(index=name):
            es.indices.create(index=name, body=mapping)
            print(f"[edr-es] created index {name}")
        return True
    except Exception as e:
        print(f"[edr-es] ensure index {name}: {e}")
        return False


def ensure_edr_indices() -> bool:
    global _index_ok
    if _index_ok:
        return True
    c = _cfg()
    ok = _ensure_index(str(c["index_edr_events"]), EDR_EVENT_MAPPING)
    ok = _ensure_index(str(c["index_edr_detection_rules"]), DETECTION_RULES_MAPPING) and ok
    _index_ok = ok
    return ok


def _basename(path: str) -> str:
    p = str(path or "").replace("\\", "/")
    return p.rsplit("/", 1)[-1] if p else ""


def timeline_to_ecs(
    *,
    agent_id: str,
    hostname: str,
    etype: str,
    summary: str,
    detail: Dict[str, Any],
    ts: str,
) -> Dict[str, Any]:
    d = detail if isinstance(detail, dict) else {}
    et = str(etype or "event").lower()
    host_os = "windows"
    if "linux" in et or str(d.get("platform") or "").lower().startswith("linux"):
        host_os = "linux"
    proc_name = _basename(d.get("image") or d.get("process") or d.get("name") or "")
    cmd = str(d.get("command_line") or d.get("command") or summary or "")
    if not proc_name and cmd:
        proc_name = _basename(cmd.split()[0] if cmd.split() else "")
    fpath = str(d.get("path") or "")
    evt_type = "start" if "create" in et or et == "process_create" else "info"
    if "network" in et or "dns" in et:
        evt_type = "connection" if "connect" in et else "query"
    doc: Dict[str, Any] = {
        "@timestamp": ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": {
            "type": evt_type,
            "category": et.split("_")[0] if "_" in et else et,
            "action": et,
            "dataset": "edr.timeline",
        },
        "host": {"name": hostname or agent_id, "os": {"type": host_os}},
        "agent": {"id": agent_id},
        "message": summary,
        "edr": {"summary": summary, "etype": et, "module": "timeline"},
    }
    if proc_name or cmd:
        doc["process"] = {
            "name": proc_name or None,
            "command_line": cmd[:4096] if cmd else None,
            "executable": str(d.get("image") or d.get("path") or "")[:512] or None,
            "pid": int(d["pid"]) if str(d.get("pid") or "").isdigit() else None,
        }
    if fpath:
        doc["file"] = {"path": fpath[:1024], "name": _basename(fpath)}
    if "registry" in et:
        doc["registry"] = {"path": str(d.get("path") or "")[:512], "value": str(d.get("value") or "")[:512]}
    if "dns" in et:
        doc["dns"] = {"question": {"name": str(d.get("query") or d.get("name") or "")[:253]}}
    return doc


def index_timeline_event(
    agent_id: str,
    hostname: str,
    etype: str,
    summary: str,
    detail: Any,
    ts: str,
) -> bool:
    if not detection_enabled():
        return False
    from . import es_client

    if not es_client.is_available():
        return False
    if not ensure_edr_indices():
        return False
    c = _cfg()
    idx = str(c["index_edr_events"])
    det = detail if isinstance(detail, dict) else {}
    doc = timeline_to_ecs(agent_id=agent_id, hostname=hostname, etype=etype, summary=summary, detail=det, ts=ts)
    try:
        es = es_client.get_client()
        es.index(index=idx, document=doc)
        return True
    except Exception as e:
        print(f"[edr-es] index timeline: {e}")
        return False


def index_event_async(**kwargs: Any) -> None:
    threading.Thread(target=index_timeline_event, kwargs=kwargs, daemon=True).start()


def _load_eql_rules(limit: int = 500) -> List[Dict[str, Any]]:
    from . import elastic_detection_import as edi

    out: List[Dict[str, Any]] = []
    base = Path(config.RULES_DIR)
    for path in edi.iter_toml_files():
        if len(out) >= limit:
            break
        try:
            with open(path, "rb") as f:
                doc = tomllib.load(f)
        except Exception:
            continue
        rule = doc.get("rule") if isinstance(doc.get("rule"), dict) else None
        if not rule:
            continue
        if str(rule.get("type") or "").lower() != "eql":
            continue
        if str(rule.get("language") or "").lower() not in ("eql", ""):
            continue
        query = str(rule.get("query") or "").strip()
        if not query or "process where" not in query.lower() and "file where" not in query.lower():
            continue
        try:
            rel = str(path.relative_to(base)).replace("\\", "/")
        except ValueError:
            rel = path.name
        out.append({
            "id": edi._elastic_id(rule, rel),
            "elastic_rule_id": str(rule.get("rule_id") or ""),
            "name": str(rule.get("name") or "")[:200],
            "severity": str(rule.get("severity") or "medium"),
            "query": query,
            "rel_path": rel,
        })
    return out


def publish_detection_rules_to_es(*, max_rules: int = 2000) -> Dict[str, Any]:
    """将 TOML EQL 规则元数据写入 ES（Kibana Discover 可见；正式 Detection 仍建议 Kibana 导入）。"""
    from . import es_client

    if not es_client.is_available():
        return {"ok": False, "error": "ES 不可用"}
    if not ensure_edr_indices():
        return {"ok": False, "error": "索引创建失败"}
    rules = _load_eql_rules(limit=max_rules)
    c = _cfg()
    idx = str(c["index_edr_detection_rules"])
    es = es_client.get_client()
    n = 0
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        from elasticsearch.helpers import bulk

        actions = []
        for r in rules:
            actions.append({
                "_index": idx,
                "_id": r["id"],
                "_source": {**r, "type": "eql", "language": "eql", "enabled": True, "updated_at": now},
            })
        if actions:
            bulk(es, actions, raise_on_error=False)
            n = len(actions)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "published": n, "index": idx}


def run_detection_cycle(*, force: bool = False) -> Dict[str, Any]:
    """对 index_edr_events 跑一批 EQL（轮转，避免压垮 ES）。"""
    global _rule_cursor, _last_run
    if not detection_enabled() and not force:
        return {"ok": False, "skipped": "edr_detection_disabled"}
    from . import es_client

    if not es_client.is_available():
        return {"ok": False, "error": "ES 不可用"}
    if not ensure_edr_indices():
        return {"ok": False, "error": "索引未就绪"}
    c = _cfg()
    events_idx = str(c["index_edr_events"])
    batch = int(c.get("edr_detection_rules_per_run") or 24)
    window = int(c.get("edr_detection_window_min") or 15)
    rules = _load_eql_rules(limit=800)
    if not rules:
        return {"ok": False, "error": "无 EQL 规则"}
    with _lock:
        start = _rule_cursor % len(rules)
        _rule_cursor = (start + batch) % len(rules)
    chunk = rules[start : start + batch]
    es = es_client.get_client()
    hits_total = 0
    errors: List[str] = []
    fired: List[Dict[str, Any]] = []
    for r in chunk:
        q = r.get("query") or ""
        try:
            flt = {"range": {"@timestamp": {"gte": f"now-{window}m"}}}
            resp = None
            if hasattr(es, "eql"):
                eql = es.eql
                if hasattr(eql, "query"):
                    resp = eql.query(index=events_idx, query=q, filter=flt, size=10)
                elif hasattr(eql, "search"):
                    resp = eql.search(index=events_idx, body={"query": q, "filter": flt}, size=10)
            if resp is None:
                raise RuntimeError("ES 客户端无 eql 接口")
        except Exception as e:
            msg = str(e)
            if "eql" in msg.lower() or "parse" in msg.lower():
                errors.append(f"{r.get('id')}: parse/run")
            else:
                errors.append(f"{r.get('id')}: {msg[:120]}")
            continue
        seq = (resp or {}).get("hits") or {}
        events = seq.get("events") or []
        if not events:
            continue
        hits_total += len(events)
        fired.append({"rule_id": r.get("id"), "name": r.get("name"), "hits": len(events)})
        try:
            from . import agent_protocol

            for ev in events[:3]:
                host = ""
                ag = ""
                fields = ev.get("_source") or ev
                if isinstance(fields, dict):
                    host = str((fields.get("host") or {}).get("name") or "")
                    ag = str((fields.get("agent") or {}).get("id") or "")
                rname = str(r.get("name") or r.get("id") or "EQL 规则")
                agent_protocol.report_event({
                    "agent_id": ag or "es-detection",
                    "hostname": host,
                    "module": "elastic_es",
                    "severity": str(r.get("severity") or "high"),
                    "title": f"[ES/EQL] {rname}"[:200],
                    "building_block": True,
                    "detail": {
                        "rule_title": rname,
                        "rule_source": "elastic_es",
                        "elastic_rule_id": r.get("elastic_rule_id"),
                        "rule_id": r.get("id"),
                        "engine": "elasticsearch_eql",
                        "rel_path": r.get("rel_path"),
                    },
                })
        except Exception:
            pass
    _last_run = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rules_tried": len(chunk),
        "hits": hits_total,
        "fired_rules": len(fired),
        "errors": len(errors),
    }
    return {"ok": True, "last_run": _last_run, "fired": fired[:20], "errors_sample": errors[:8]}


def _hj_stack_hint() -> Dict[str, str]:
    p = Path(config.ROOT) / "config" / "hj_stack.json"
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        es = raw.get("elasticsearch") if isinstance(raw.get("elasticsearch"), dict) else {}
        return {
            "install_root": str(raw.get("install_root") or ""),
            "es_home": str(es.get("home") or ""),
            "es_url": str(es.get("url") or ""),
        }
    except Exception:
        return {}


def status() -> Dict[str, Any]:
    from . import es_client

    c = _cfg()
    probe = es_client.probe_status(reprobe=False)
    return {
        "ok": True,
        "es_connected": es_client.is_available(),
        "es_probe": probe,
        "detection_enabled": detection_enabled(),
        "index_edr_events": c.get("index_edr_events"),
        "index_edr_detection_rules": c.get("index_edr_detection_rules"),
        "interval_sec": c.get("edr_detection_interval_sec"),
        "last_run": _last_run,
        "hj_stack": _hj_stack_hint(),
        "note": "ES 安装目录见 config/hj_stack.json；启动 scripts/start_hj_elasticsearch.ps1 后重启 8100 或跑 setup_elasticsearch_edr.py。",
    }


def start_background_loop() -> None:
    if not detection_enabled():
        return

    def _loop() -> None:
        c = _cfg()
        interval = max(60, int(c.get("edr_detection_interval_sec") or 300))
        time.sleep(15)
        while True:
            try:
                run_detection_cycle()
            except Exception as e:
                print(f"[edr-es] cycle: {e}")
            time.sleep(interval)

    threading.Thread(target=_loop, name="edr-es-detection", daemon=True).start()
