# -*- coding: utf-8 -*-
"""IP 归属库：境内(guonei) / 云厂商(yun*)。

外联策略：仅当目标为「云」或「非境内」时告警；境内非云静默。

数据流（推荐）：
  ip/*.txt  --启动/重载-->  MySQL ip_ranges（权威）+ SQLite 缓存 + 可选 ES
  分析时：进程内存区间表二分查询（不对每个 IP 打 SQL）

原因：单份报告外联 IP 可达数百，CIDR 约上万条；逐条 SQL 范围查询会拖慢并发分析，
而内存二分是微秒级。库负责持久化与多实例一致，内存负责热路径。
"""
from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r"(?:/(?:3[0-2]|[12]?\d))?\b"
)

_lock = threading.RLock()
_loaded = False
_domestic: List[Tuple[int, int]] = []  # sorted (start, end) inclusive
_cloud: List[Tuple[int, int, str]] = []  # sorted (start, end, provider)
_stats: Dict[str, Any] = {}


def ip_dir() -> Path:
    env = (os.getenv("FORENSIC_IP_DIR") or "").strip()
    if env:
        return Path(env)
    return Path(getattr(config, "ROOT", Path("."))) / "ip"


def _ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address((ip or "").split("%")[0].strip().strip("[]")))
    except Exception:
        return None


def _parse_cidr_line(line: str) -> Optional[Tuple[int, int]]:
    s = (line or "").strip()
    if not s or s.startswith("#") or s.startswith(";"):
        return None
    m = _CIDR_RE.search(s.replace("：", ":"))
    if not m:
        return None
    raw = m.group(0)
    try:
        if "/" not in raw:
            raw = raw + "/32"
        net = ipaddress.ip_network(raw, strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            return None
        return int(net.network_address), int(net.broadcast_address)
    except Exception:
        return None


def _detect_provider(line: str, default: str = "") -> str:
    s = (line or "").strip()
    low = s.lower()
    mapping = (
        ("aws", "AWS"),
        ("azure", "Azure"),
        ("google", "Google"),
        ("oracle", "Oracle"),
        ("ibm", "IBM"),
        ("cloudflare", "Cloudflare"),
        ("digitalocean", "DigitalOcean"),
        ("linode", "Linode"),
        ("阿里云", "阿里云"),
        ("腾讯云", "腾讯云"),
        ("华为云", "华为云"),
        ("金山云", "金山云"),
        ("百度云", "百度云"),
        ("京东云", "京东云"),
    )
    for k, v in mapping:
        if k in low or k in s:
            return v
    # 纯标签行（无数字开头）
    if s and not s[0].isdigit() and not _CIDR_RE.search(s):
        return s.rstrip("：:").strip()[:40] or default
    return default


def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    ranges = sorted(ranges)
    out = [ranges[0]]
    for a, b in ranges[1:]:
        la, lb = out[-1]
        if a <= lb + 1:
            out[-1] = (la, max(lb, b))
        else:
            out.append((a, b))
    return out


def _in_ranges(ip_int: int, ranges: List[Tuple[int, int]]) -> bool:
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        a, b = ranges[mid]
        if ip_int < a:
            hi = mid - 1
        elif ip_int > b:
            lo = mid + 1
        else:
            return True
    return False


def _cloud_provider(ip_int: int) -> str:
    lo, hi = 0, len(_cloud) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        a, b, prov = _cloud[mid]
        if ip_int < a:
            hi = mid - 1
        elif ip_int > b:
            lo = mid + 1
        else:
            return prov or "cloud"
    return ""


def _read_files() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """从 ip/ 目录解析 CIDR。"""
    root = ip_dir()
    rows: List[Dict[str, Any]] = []
    meta = {"dir": str(root), "files": {}}
    if not root.is_dir():
        return rows, meta

    # guonei
    gfile = root / "guonei.txt"
    if gfile.is_file():
        n = 0
        for line in gfile.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = _parse_cidr_line(line)
            if not parsed:
                continue
            a, b = parsed
            rows.append({"cidr": line.strip(), "kind": "domestic", "provider": "境内", "start_ip": a, "end_ip": b})
            n += 1
        meta["files"]["guonei.txt"] = n

    # cloud files
    for fname in ("yun.txt", "yun2.txt", "yun3.txt"):
        p = root / fname
        if not p.is_file():
            continue
        n = 0
        cur_prov = fname.replace(".txt", "")
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = line.strip()
            if not raw:
                continue
            prov = _detect_provider(raw, cur_prov)
            # 标签行更新当前厂商
            if not _CIDR_RE.search(raw.replace("：", ":")):
                if prov:
                    cur_prov = prov
                continue
            if prov and not raw[0].isdigit():
                # 同行：IBM:5.10.116.0/22
                cur_prov = prov
            parsed = _parse_cidr_line(raw)
            if not parsed:
                continue
            a, b = parsed
            rows.append({
                "cidr": _CIDR_RE.search(raw.replace("：", ":")).group(0),
                "kind": "cloud",
                "provider": cur_prov or "cloud",
                "start_ip": a,
                "end_ip": b,
            })
            n += 1
        meta["files"][fname] = n
    return rows, meta


def _sqlite_path() -> Path:
    d = Path(getattr(config, "CONFIG_DIR", None) or (config.ROOT / "config"))
    d.mkdir(parents=True, exist_ok=True)
    return d / "ip_ranges.db"


def _sync_sqlite(rows: List[Dict[str, Any]]) -> int:
    path = _sqlite_path()
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS ip_ranges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cidr TEXT NOT NULL,
                kind TEXT NOT NULL,
                provider TEXT DEFAULT '',
                start_ip INTEGER NOT NULL,
                end_ip INTEGER NOT NULL
            )"""
        )
        conn.execute("DELETE FROM ip_ranges")
        conn.executemany(
            "INSERT INTO ip_ranges(cidr, kind, provider, start_ip, end_ip) VALUES (?,?,?,?,?)",
            [(r["cidr"], r["kind"], r["provider"], r["start_ip"], r["end_ip"]) for r in rows],
        )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


def _sync_mysql(rows: List[Dict[str, Any]]) -> int:
    from . import mysql_db
    if not mysql_db.mysql_ready():
        return 0
    conn = mysql_db.connect_mysql()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_ranges (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    cidr VARCHAR(64) NOT NULL,
                    kind VARCHAR(16) NOT NULL,
                    provider VARCHAR(64) DEFAULT '',
                    start_ip BIGINT UNSIGNED NOT NULL,
                    end_ip BIGINT UNSIGNED NOT NULL,
                    KEY idx_kind_range (kind, start_ip, end_ip)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute("TRUNCATE TABLE ip_ranges")
            batch = [(r["cidr"], r["kind"], r["provider"], r["start_ip"], r["end_ip"]) for r in rows]
            # 分批写入，避免单次 packet 过大
            step = 2000
            for i in range(0, len(batch), step):
                cur.executemany(
                    "INSERT INTO ip_ranges(cidr, kind, provider, start_ip, end_ip) VALUES (%s,%s,%s,%s,%s)",
                    batch[i:i + step],
                )
        conn.commit()
        return len(rows)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _load_memory_from_rows(rows: List[Dict[str, Any]]) -> None:
    global _domestic, _cloud, _stats, _loaded
    domestic_raw: List[Tuple[int, int]] = []
    cloud_raw: List[Tuple[int, int, str]] = []
    for r in rows:
        a, b = int(r["start_ip"]), int(r["end_ip"])
        if r.get("kind") == "cloud":
            cloud_raw.append((a, b, str(r.get("provider") or "cloud")))
        else:
            domestic_raw.append((a, b))
    domestic_raw = _merge_ranges(domestic_raw)
    cloud_raw.sort(key=lambda x: x[0])
    # merge adjacent same-provider cloud ranges lightly
    cloud_merged: List[Tuple[int, int, str]] = []
    for a, b, p in cloud_raw:
        if cloud_merged and cloud_merged[-1][2] == p and a <= cloud_merged[-1][1] + 1:
            la, lb, lp = cloud_merged[-1]
            cloud_merged[-1] = (la, max(lb, b), lp)
        else:
            cloud_merged.append((a, b, p))
    _domestic = domestic_raw
    _cloud = cloud_merged
    _stats = {
        "domestic_cidrs": sum(1 for r in rows if r.get("kind") == "domestic"),
        "cloud_cidrs": sum(1 for r in rows if r.get("kind") == "cloud"),
        "domestic_ranges": len(_domestic),
        "cloud_ranges": len(_cloud),
        "loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _loaded = True


def _load_rows_from_sqlite() -> List[Dict[str, Any]]:
    path = _sqlite_path()
    if not path.is_file():
        return []
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
    try:
        return [
            {"cidr": r[0], "kind": r[1], "provider": r[2], "start_ip": r[3], "end_ip": r[4]}
            for r in conn.execute("SELECT cidr, kind, provider, start_ip, end_ip FROM ip_ranges")
        ]
    finally:
        conn.close()


def _load_rows_from_mysql() -> List[Dict[str, Any]]:
    """从 MySQL ip_ranges 拉全量区间（启动/热加载用，不当作逐 IP 查询）。"""
    try:
        from . import mysql_db
        if not mysql_db.mysql_ready():
            return []
        conn = mysql_db.connect_mysql()
    except Exception:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cidr, kind, provider, start_ip, end_ip FROM ip_ranges "
                "ORDER BY kind, start_ip"
            )
            rows = cur.fetchall() or []
        out: List[Dict[str, Any]] = []
        for r in rows:
            if isinstance(r, dict):
                out.append({
                    "cidr": r.get("cidr") or "",
                    "kind": r.get("kind") or "",
                    "provider": r.get("provider") or "",
                    "start_ip": int(r.get("start_ip") or 0),
                    "end_ip": int(r.get("end_ip") or 0),
                })
            else:
                out.append({
                    "cidr": r[0] or "",
                    "kind": r[1] or "",
                    "provider": r[2] or "",
                    "start_ip": int(r[3] or 0),
                    "end_ip": int(r[4] or 0),
                })
        return out
    except Exception as e:
        print(f"[ip_catalog] mysql load: {e}")
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def reload_from_files(*, persist: bool = True) -> Dict[str, Any]:
    """从 ip/*.txt 重载，可选写入 MySQL/SQLite/ES。"""
    rows, meta = _read_files()
    with _lock:
        _load_memory_from_rows(rows)
        out = dict(_stats)
        out.update(meta)
        out["source"] = "files"
        if persist and rows:
            try:
                out["sqlite"] = _sync_sqlite(rows)
            except Exception as e:
                out["sqlite_error"] = str(e)
            try:
                n = _sync_mysql(rows)
                out["mysql"] = n
            except Exception as e:
                out["mysql_error"] = str(e)
            try:
                out["es"] = _sync_es(rows, recreate=True)
            except Exception as e:
                out["es_error"] = str(e)
        return out


def ensure_loaded() -> None:
    """保证内存区间表就绪。

    加载顺序：MySQL → SQLite → ip/*.txt（并回写库）。
    分析时只读内存，不对每个 IP 打 SQL。
    """
    global _loaded
    with _lock:
        if _loaded and (_domestic or _cloud):
            return

    # 1) MySQL 权威库
    try:
        rows = _load_rows_from_mysql()
        if rows:
            with _lock:
                _load_memory_from_rows(rows)
                _stats["source"] = "mysql"
            return
    except Exception as e:
        print(f"[ip_catalog] ensure mysql: {e}")

    # 2) 本地 SQLite 缓存
    try:
        rows = _load_rows_from_sqlite()
        if rows:
            with _lock:
                _load_memory_from_rows(rows)
                _stats["source"] = "sqlite"
            return
    except Exception as e:
        print(f"[ip_catalog] ensure sqlite: {e}")

    # 3) 文本文件 → 落库
    reload_from_files(persist=True)


def _prefer_es_classify() -> bool:
    """默认分析走内存；仅显式开启时才对每个 IP 打 ES。"""
    v = (os.getenv("FORENSIC_IP_ES") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


def _int_to_ip(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def ip_ranges_index() -> str:
    from .cache_config import es_config
    cfg = es_config()
    return str(cfg.get("index_ip_ranges") or "cnpc_ip_ranges").strip() or "cnpc_ip_ranges"


IP_RANGES_MAPPING = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "30s",
    },
    "mappings": {
        "properties": {
            "kind": {"type": "keyword"},
            "provider": {"type": "keyword", "ignore_above": 64},
            "cidr": {"type": "keyword"},
            "network": {"type": "ip_range"},
        }
    },
}


def _ensure_es_index(*, recreate: bool = False) -> bool:
    from . import es_client
    es = es_client.get_client()
    if not es:
        return False
    idx = ip_ranges_index()
    try:
        exists = es.indices.exists(index=idx)
        if recreate and exists:
            es.indices.delete(index=idx, ignore=[404])
            exists = False
        if not exists:
            try:
                es.indices.create(index=idx, body=IP_RANGES_MAPPING)
            except TypeError:
                es.indices.create(
                    index=idx,
                    settings=IP_RANGES_MAPPING["settings"],
                    mappings=IP_RANGES_MAPPING["mappings"],
                )
            print(f"[ip_catalog] created ES index {idx}")
        return True
    except Exception as e:
        print(f"[ip_catalog] ensure ES index failed: {e}")
        return False


def _sync_es(rows: List[Dict[str, Any]], *, recreate: bool = True) -> Dict[str, Any]:
    """把 CIDR 写入 ES ip_range 字段，分析时用 term 做包含查询。"""
    import hashlib
    from . import es_client
    if not es_client.is_available():
        return {"ok": False, "error": "es_unavailable", "indexed": 0}
    if not _ensure_es_index(recreate=recreate):
        return {"ok": False, "error": "ensure_index_failed", "indexed": 0}
    from elasticsearch.helpers import bulk
    es = es_client.get_client()
    idx = ip_ranges_index()
    actions = []
    for r in rows:
        cidr = (r.get("cidr") or "").strip()
        if not cidr:
            # 用 start/end 拼 CIDR 不稳，退化为起止范围
            try:
                a, b = int(r["start_ip"]), int(r["end_ip"])
                network = {"gte": _int_to_ip(a), "lte": _int_to_ip(b)}
                cidr = f"{_int_to_ip(a)}-{_int_to_ip(b)}"
            except Exception:
                continue
        else:
            # 规范为带 / 的 CIDR
            if "/" not in cidr:
                cidr = cidr + "/32"
            network = cidr
        kind = (r.get("kind") or "domestic").strip()
        prov = (r.get("provider") or "")[:64]
        did = hashlib.sha1(f"{kind}|{cidr}".encode()).hexdigest()
        actions.append({
            "_op_type": "index",
            "_index": idx,
            "_id": did,
            "_source": {
                "kind": kind,
                "provider": prov,
                "cidr": cidr,
                "network": network,
            },
        })
    indexed = 0
    errors_n = 0
    step = 3000
    for i in range(0, len(actions), step):
        ok, errors = bulk(
            es, actions[i:i + step],
            raise_on_error=False, request_timeout=120, chunk_size=step,
        )
        indexed += int(ok or 0)
        if errors:
            errors_n += len(errors)
    try:
        es.indices.refresh(index=idx)
    except Exception:
        pass
    try:
        es.indices.put_settings(index=idx, body={"index": {"refresh_interval": "1s"}})
    except Exception:
        try:
            es.indices.put_settings(index=idx, settings={"index": {"refresh_interval": "1s"}})
        except Exception:
            pass
    print(f"[ip_catalog] ES synced {indexed}/{len(actions)} errors={errors_n}")
    return {"ok": True, "indexed": indexed, "total": len(actions), "errors": errors_n, "index": idx}


def _classify_ip_es(raw: str) -> Optional[Dict[str, Any]]:
    """ES ip_range 包含查询；失败返回 None 以回退内存。"""
    from . import es_client
    if not es_client.is_available():
        return None
    es = es_client.get_client()
    if not es:
        return None
    idx = ip_ranges_index()
    try:
        if not es.indices.exists(index=idx):
            return None
        body = {
            "size": 8,
            "query": {"term": {"network": raw}},
            "_source": ["kind", "provider", "cidr"],
        }
        try:
            resp = es.search(index=idx, body=body, request_timeout=3)
        except TypeError:
            resp = es.search(index=idx, query=body["query"], size=8, request_timeout=3)
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            return {"ip": raw, "class": "overseas", "provider": "境外", "alert": True, "via": "es"}
        cloud = None
        domestic = None
        for h in hits:
            s = h.get("_source") or {}
            kind = (s.get("kind") or "").strip()
            if kind == "cloud" and cloud is None:
                cloud = s
            elif kind == "domestic" and domestic is None:
                domestic = s
        if cloud:
            return {
                "ip": raw,
                "class": "cloud",
                "provider": cloud.get("provider") or "cloud",
                "alert": True,
                "via": "es",
                "cidr": cloud.get("cidr") or "",
            }
        if domestic:
            return {
                "ip": raw,
                "class": "domestic",
                "provider": "境内",
                "alert": False,
                "via": "es",
                "cidr": domestic.get("cidr") or "",
            }
        return {"ip": raw, "class": "overseas", "provider": "境外", "alert": True, "via": "es"}
    except Exception as e:
        print(f"[ip_catalog] ES classify failed: {e}")
        return None


def classify_ip(ip: str) -> Dict[str, Any]:
    """返回 {class: private|domestic|cloud|overseas, provider, alert: bool}。

    分析路径默认走内存二分（数据来自 MySQL/SQLite/文件同步）。
    可选 FORENSIC_IP_ES=1 时优先打 ES；否则 ES 仅作内存未就绪时的兜底。
    """
    from .matchers.util import is_private_ip
    raw = (ip or "").split(":")[0].strip().strip("[]")
    if not raw or is_private_ip(raw):
        return {"ip": raw, "class": "private", "provider": "", "alert": False}
    ip_int = _ip_to_int(raw)
    if ip_int is None:
        return {"ip": raw, "class": "invalid", "provider": "", "alert": False}

    if _prefer_es_classify():
        es_hit = _classify_ip_es(raw)
        if es_hit is not None:
            return es_hit

    ensure_loaded()
    with _lock:
        ready = bool(_domestic or _cloud)
        if ready:
            prov = _cloud_provider(ip_int)
            if prov:
                return {"ip": raw, "class": "cloud", "provider": prov, "alert": True, "via": "memory"}
            if _in_ranges(ip_int, _domestic):
                return {"ip": raw, "class": "domestic", "provider": "境内", "alert": False, "via": "memory"}
            return {"ip": raw, "class": "overseas", "provider": "境外", "alert": True, "via": "memory"}

    # 内存空：再试 ES
    es_hit = _classify_ip_es(raw)
    if es_hit is not None:
        return es_hit
    return {"ip": raw, "class": "overseas", "provider": "境外", "alert": True, "via": "fallback"}


def locate_ip(ip: str) -> Dict[str, Any]:
    """只判境内 / 境外（境内段之外的公网地址均算境外，含港澳台），云厂商仅作附加信息。

    与 classify_ip 不同：云厂商 IP 不笼统归「云」，阿里云 / 腾讯云大陆段算境内。
    """
    raw = (ip or "").strip().strip("[]")
    if raw.count(":") == 1:
        raw = raw.split(":")[0]
    try:
        addr = ipaddress.IPv4Address(raw)
    except Exception:
        return {"ip": raw, "scope": "invalid", "cloud": ""}
    if not addr.is_global:
        return {"ip": raw, "scope": "nonpublic", "cloud": ""}
    ensure_loaded()
    n = int(addr)
    with _lock:
        cloud = _cloud_provider(n) if _cloud else ""
        if not _domestic:
            return {"ip": raw, "scope": "unknown", "cloud": cloud}
        scope = "domestic" if _in_ranges(n, _domestic) else "overseas"
    return {"ip": raw, "scope": scope, "cloud": cloud}


def stats() -> Dict[str, Any]:
    ensure_loaded()
    with _lock:
        out = dict(_stats)
    try:
        from . import es_client
        out["es_index"] = ip_ranges_index()
        out["es_available"] = es_client.is_available()
        if out["es_available"]:
            es = es_client.get_client()
            if es and es.indices.exists(index=out["es_index"]):
                out["es_count"] = int((es.count(index=out["es_index"]) or {}).get("count") or 0)
            else:
                out["es_count"] = 0
    except Exception as e:
        out["es_error"] = str(e)
    return out
