"""SQLite IOC 库（ioc/ioc_data*.db）查询，Redis 按需缓存。

表结构（与 ioc_data_sample.db 一致）:
  ioc_records(id, type, value, ip_only, source, malware)
  type: file_hash | ip | domain | url | ...

匹配策略：
  1. 按调用方给出的值做精确查询（绝不扫全表）
  2. 先查 Redis 缓存命中；未命中再查 MySQL（默认同步目标）
  3. 可选 ES；最后回退 SQLite；命中后写入 Redis
"""
from __future__ import annotations
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from . import config

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None
_db_path: Optional[Path] = None
_stats_cache: Optional[Dict[str, Any]] = None
# 用于检测磁盘上的库是否被替换（mtime_ns + size）
_file_sig: Optional[Tuple[str, int, int]] = None

# 常见良性主域：情报源常把它们误标进 IOC，匹配时直接忽略（具体恶意子域/长路径 URL 仍可命中）
_BENIGN_APEX = frozenset({
    "baidu.com", "bdstatic.com", "bing.com", "microsoft.com", "msn.com", "live.com",
    "office.com", "office365.com", "windows.com", "windowsupdate.com", "azure.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com",
    "qq.com", "gtimg.cn", "163.com", "126.com", "aliyun.com", "alipay.com", "taobao.com",
    "tmall.com", "jd.com", "huawei.com", "apple.com", "icloud.com", "akamaihd.net",
    "cloudflare.com", "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "wikipedia.org", "zhihu.com", "weixin.qq.com", "douyin.com", "bytedance.com",
    "amazon.com", "amazonaws.com", "cloudfront.net", "digicert.com", "verisign.com",
    # 安全厂商 / 情报站 / 常见企业门户（IOC 库常误收录）
    "virustotal.com", "vtapi.com", "ibm.com", "elastic.co", "elastic.com",
    "malwarebytes.com", "kaspersky.com", "symantec.com", "broadcom.com", "mcafee.com",
    "trendmicro.com", "sophos.com", "crowdstrike.com", "sentinelone.com", "paloaltonetworks.com",
    "cisco.com", "fortinet.com", "checkpoint.com", "abuse.ch", "urlhaus.abuse.ch",
    "hybrid-analysis.com", "any.run", "joesandbox.com", "alienvault.com", "otx.alienvault.com",
    "recordedfuture.com", "mandiant.com", "crowdstrike.com", "microsoftonline.com",
    "office.net", "msftconnecttest.com", "windowsupdate.com", "update.microsoft.com",
    "cdn.cloudflare.net", "fastly.net", "edgekey.net", "akamai.net", "akamaized.net",
    "oracle.com", "oraclecloud.com", "salesforce.com", "snowflake.com", "zoom.us",
    "slack.com", "atlassian.com", "jira.com", "notion.so", "dropbox.com", "box.com",
})
_MULTI_TLD = frozenset({
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "com.au", "com.hk",
})


_SQLITE_MALFORMED = ("malformed", "not a database", "file is not a database", "disk i/o error")


def sqlite_error_hint(err: BaseException) -> str:
    """把 SQLite 损坏类错误翻成管理页可操作提示（不读库内容）。"""
    msg = str(err or "").strip() or type(err).__name__
    low = msg.lower()
    if any(k in low for k in _SQLITE_MALFORMED):
        return (
            "源 SQLite 损坏或不完整（database disk image is malformed）。"
            "常见原因：拷贝未完成、进程占用、或 ioc 目录只剩 .db-wal/.db-shm。"
            "请把完整的 ioc_data.db 放到 IOC 目录后再同步，不要只拷 WAL/SHM。"
        )
    return msg


def ioc_dir_path() -> Path:
    return Path(getattr(config, "IOC_DIR", None) or (config.ROOT / "ioc"))


def preferred_ioc_db_path() -> Path:
    """用户指定源库：项目根 ioc_data.db；可用 FORENSIC_IOC_DB 覆盖。禁止 ioc_update。"""
    env = (os.getenv("FORENSIC_IOC_DB") or "").strip()
    if env:
        p = Path(env)
        if "ioc_update" in {x.lower() for x in p.parts}:
            return Path(config.ROOT) / "ioc_data.db"
        return p
    return Path(config.ROOT) / "ioc_data.db"


def source_layout() -> Dict[str, Any]:
    """只看路径/体积/旁路文件，不打开、不读 ioc_records。"""
    ioc_dir = ioc_dir_path()
    expected = preferred_ioc_db_path()
    wal = Path(str(expected) + "-wal")
    shm = Path(str(expected) + "-shm")
    main_ok = expected.is_file()
    wal_ok = wal.is_file()
    shm_ok = shm.is_file()
    size = int(expected.stat().st_size) if main_ok else 0
    hint = ""
    ready = False
    env = (os.getenv("FORENSIC_IOC_DB") or "").strip()
    if env and not main_ok:
        hint = f"环境变量 FORENSIC_IOC_DB 指向的文件不存在：{expected}"
    elif not main_ok and (wal_ok or shm_ok):
        hint = (
            f"缺少主库 {expected.name}，仅剩 WAL/SHM。"
            "请放入完整的 ioc_data.db 后再同步。"
        )
    elif not main_ok:
        hint = f"未找到源库：{expected}。请将 ioc_data.db 放到项目根目录。"
    elif size < 100:
        hint = f"源库文件过小（{size} 字节），不像完整 SQLite，请替换后再同步。"
    else:
        ready = True
    return {
        "ioc_dir": str(ioc_dir),
        "expected": str(expected.resolve() if main_ok else expected),
        "exists": main_ok,
        "size": size,
        "wal": wal_ok,
        "shm": shm_ok,
        "ready": ready,
        "hint": hint,
    }


def discover_ioc_db() -> Optional[Path]:
    """只用项目根 ioc_data.db（或 FORENSIC_IOC_DB）。不读 ioc_update，不默认回退 ioc/。"""
    env = (os.getenv("FORENSIC_IOC_DB") or "").strip()
    if env:
        p = Path(env)
        if "ioc_update" in {x.lower() for x in p.parts}:
            return None
        return p if p.is_file() else None
    root_db = Path(config.ROOT) / "ioc_data.db"
    if root_db.is_file():
        return root_db
    return None


def _file_signature(path: Path) -> Tuple[str, int, int]:
    st = path.stat()
    mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)))
    return (str(path.resolve()), mtime_ns, int(st.st_size))


def _close_conn_unlocked() -> None:
    global _conn
    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
        _conn = None


def _invalidate_unlocked(*, reason: str = "") -> None:
    """关闭连接并清空统计/路径缓存（调用方需持有 _lock）。"""
    global _db_path, _stats_cache, _file_sig, _ip_only_table
    _close_conn_unlocked()
    _db_path = None
    _stats_cache = None
    _file_sig = None
    _ip_only_table = None
    if reason:
        print(f"[ioc_db] invalidated ({reason})")


_ip_only_table: Optional[str] = None


def _ip_only_from(conn: sqlite3.Connection) -> str:
    """按 ip_only 查时显式指定索引。

    带上 type='ip' 后 SQLite 会改挑 (type,value) 索引，把 18 万行 ip 全扫一遍；
    显式 INDEXED BY 后同样的 20 次查询从 7 秒降到 0 毫秒。
    """
    global _ip_only_table
    if _ip_only_table is None:
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_ip_only'"
            ).fetchone()
            _ip_only_table = "ioc_records INDEXED BY idx_ip_only" if row else "ioc_records"
        except sqlite3.Error:
            _ip_only_table = "ioc_records"
    return _ip_only_table


def _refresh_path_unlocked() -> Optional[Path]:
    """重新发现路径；若文件签名变化则丢弃旧连接/统计。"""
    global _db_path, _file_sig, _stats_cache
    path = discover_ioc_db()
    if not path:
        if _db_path is not None or _conn is not None or _stats_cache is not None:
            _invalidate_unlocked(reason="db missing")
        return None
    try:
        sig = _file_signature(path)
    except OSError as e:
        _invalidate_unlocked(reason=f"stat failed: {e}")
        return None
    if _file_sig is None:
        _db_path = path
        _file_sig = sig
        return path
    if sig != _file_sig:
        _invalidate_unlocked(
            reason=f"file changed { _file_sig[2] }B@{_file_sig[1]} -> {sig[2]}B@{sig[1]}"
        )
        _db_path = path
        _file_sig = sig
        clear_local_cache()
        return path
    _db_path = path
    return path


def get_db_path() -> Optional[Path]:
    with _lock:
        return _refresh_path_unlocked()


def _connect() -> Optional[sqlite3.Connection]:
    global _conn
    with _lock:
        _refresh_path_unlocked()
        if _conn is not None:
            return _conn
        path = _db_path
        if not path:
            return None
        # 只读打开；替换库后依赖签名失效重开，避免一直读旧句柄
        conn = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            check_same_thread=False,
            timeout=30,
        )
        conn.row_factory = sqlite3.Row
        # 避免长期占用写锁侧的 WAL 认知异常：每次新连接读最新
        try:
            conn.execute("PRAGMA query_only=ON")
        except sqlite3.Error:
            pass
        _conn = conn
        return _conn


def reload() -> Optional[Path]:
    """强制重载：关连接、清缓存、按磁盘最新文件重新打开。"""
    global _stats_cache
    with _lock:
        _invalidate_unlocked(reason="manual reload")
    clear_local_cache()
    try:
        purge_benign_redis_cache()
    except Exception:
        pass
    path = get_db_path()
    # 预热连接 + 统计，确保返回值是新库
    _ = stats(force=True)
    return path


def file_info() -> Dict[str, Any]:
    """库文件元信息（不读全表）。"""
    path = get_db_path()
    out: Dict[str, Any] = {"path": str(path) if path else "", "exists": False}
    if not path:
        return out
    try:
        st = path.stat()
        out.update({
            "exists": True,
            "size": int(st.st_size),
            "size_mb": round(st.st_size / (1024 * 1024), 2),
            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
            "mtime_epoch": int(st.st_mtime),
        })
    except OSError as e:
        out["error"] = str(e)
    return out


# ---- 进程内 LRU（减轻同报告重复 lookup；禁止全表）----
_local_cache: Dict[str, tuple] = {}  # key -> (ts, results)
_local_cache_lock = threading.Lock()
_LOCAL_CACHE_TTL = 300
_LOCAL_CACHE_MAX = 8000


def clear_local_cache() -> None:
    with _local_cache_lock:
        _local_cache.clear()


def invalidate_cached_values(
    values: Optional[List[str]],
    *,
    kinds: Optional[Sequence[str]] = None,
) -> Dict[str, int]:
    """按值失效进程 LRU + Redis IOC 正缓存（情报库删除后避免假阳性）。"""
    local_n = 0
    redis_n = 0
    kind_list = [str(k).strip().lower() for k in (kinds or ("file_hash", "md5", "sha1", "sha256", "ip", "domain", "url")) if str(k).strip()]
    vals: List[str] = []
    seen = set()
    for raw in values or []:
        v = str(raw or "").strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        vals.append(v)
    if not vals:
        return {"local": 0, "redis": 0}
    with _local_cache_lock:
        for v in vals:
            keys = {f"{k}|{v}" for k in kind_list}
            hk = hash_kind(v)
            if hk:
                keys.add(f"{hk}|{v}")
                keys.add(f"file_hash|{v}")
            for key in keys:
                if key in _local_cache:
                    _local_cache.pop(key, None)
                    local_n += 1
    try:
        from .redis_client import is_available, rdel
        if is_available():
            for v in vals:
                for k in kind_list:
                    try:
                        if rdel(_redis_key(k, v)):
                            redis_n += 1
                    except Exception:
                        pass
                hk = hash_kind(v)
                if hk and hk not in kind_list:
                    try:
                        if rdel(_redis_key("file_hash", v)):
                            redis_n += 1
                    except Exception:
                        pass
    except Exception:
        pass
    return {"local": local_n, "redis": redis_n}


def _local_cache_get(key: str):
    with _local_cache_lock:
        item = _local_cache.get(key)
        if not item:
            return None
        ts, results = item
        if time.time() - ts > _LOCAL_CACHE_TTL:
            _local_cache.pop(key, None)
            return None
        return results


def _local_cache_put(key: str, results: List[Dict[str, Any]]) -> None:
    with _local_cache_lock:
        if len(_local_cache) >= _LOCAL_CACHE_MAX:
            # 简单淘汰：删最旧一半键
            items = sorted(_local_cache.items(), key=lambda x: x[1][0])
            for k, _ in items[: max(1, _LOCAL_CACHE_MAX // 2)]:
                _local_cache.pop(k, None)
        _local_cache[key] = (time.time(), results)


def sample_lookup(value: str, ioc_type: Optional[str] = None) -> Dict[str, Any]:
    """运维抽样查询（单值），禁止批量扫库。"""
    v = (value or "").strip()
    if not v:
        raise ValueError("请输入要查询的值")
    if len(v) > 512:
        raise ValueError("查询值过长")
    hits = lookup(v, ioc_type)
    return {"value": v, "type": ioc_type or "", "hits": hits, "count": len(hits)}


# ---- Redis 按需缓存（只缓存实际查过的值，绝不扫全表）----

def _redis_key(db_type: str, value: str) -> str:
    from .redis_client import prefix
    return f"{prefix()}ioc:{db_type}:{value.lower()}"


def _cache_hit_to_redis(hit: Dict[str, Any]) -> None:
    """把单条命中写入 Redis，供下次精确查询。"""
    try:
        from .redis_client import rset, is_available
        if not is_available():
            return
        db_type = (hit.get("db_type") or "").strip()
        matched = (hit.get("matched") or "").strip().lower()
        if not db_type or not matched:
            return
        # 哈希不写 Redis：情报库删除 MD5 后 7 天正缓存会造成假阳性；批量查已直接打 MySQL
        if db_type in ("file_hash", "md5", "sha1", "sha256") or bool(hash_kind(matched)):
            return
        # 绝不缓存良性整站，避免 VT/IBM 等误报残留
        if db_type in ("domain", "url") and (
            is_generic_benign_ioc(matched) or is_benign_host(extract_host(matched) or matched)
        ):
            return
        payload = json.dumps({
            "id": hit.get("db_id"),
            "type": db_type,
            "value": matched,
            "ip_only": matched if db_type == "ip" else "",
            "source": hit.get("source") or "",
            "malware": hit.get("malware") or "",
        }, ensure_ascii=False, separators=(",", ":"))
        # 域名/IP/URL 缓存 1 小时（缩短假阳性窗口）
        rset(_redis_key(db_type, matched), payload, ex=3600)
    except Exception:
        pass


def purge_benign_redis_cache() -> int:
    """清理 Redis 中良性域名 IOC 缓存（如 virustotal.com）。"""
    try:
        from .redis_client import get_client, prefix, rdel
        r = get_client()
        if not r:
            return 0
        pref = prefix()
        n = 0
        for apex in _BENIGN_APEX:
            for host in (apex, "www." + apex):
                for typ in ("domain", "url"):
                    key = f"{pref}ioc:{typ}:{host}"
                    n += rdel(key)
                    # 常见首页 URL
                    for u in (f"http://{host}", f"https://{host}", f"http://{host}/", f"https://{host}/"):
                        n += rdel(f"{pref}ioc:{typ}:{u}")
        return n
    except Exception:
        return 0


def clear_redis_ioc_cache() -> Dict[str, Any]:
    """清空 Redis 中全部 IOC 查询缓存，并清进程内 LRU。不改 MySQL / SQLite。"""
    local_before = 0
    with _local_cache_lock:
        local_before = len(_local_cache)
    clear_local_cache()
    from .redis_client import is_available, prefix, scan_delete
    pattern = f"{prefix()}ioc:*"
    if not is_available():
        return {
            "ok": False,
            "deleted": 0,
            "local_cleared": local_before,
            "pattern": pattern,
            "error": "Redis 不可用",
        }
    deleted = scan_delete(pattern)
    return {
        "ok": True,
        "deleted": int(deleted or 0),
        "local_cleared": local_before,
        "pattern": pattern,
    }



def _redis_lookup_one(db_type: str, value: str) -> Optional[Dict[str, Any]]:
    """从 Redis 精确取一条已缓存的 IOC；未命中返回 None。"""
    from .redis_client import rget
    raw = rget(_redis_key(db_type, value.lower()))
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _ioc_family_label(malware: str) -> str:
    """从 malware 字段取展示名；过滤占位符与误当作家族的 URL。"""
    raw = (malware or "").strip()
    if not raw:
        return ""
    first = raw.split(",")[0].split(";")[0].strip()
    low = first.lower()
    if low in {
        "", "unknown", "n/a", "na", "none", "null", "-", "--", "—",
        "unspecified", "not available", "unavailable", "generic",
        "malware", "trojan", "virus", "suspicious",
    }:
        return ""
    # 情报库常把报告 URL 填进 malware，不能当标题
    if low.startswith(("http://", "https://", "www.")):
        return ""
    if "://" in first:
        return ""
    return first[:80]


def _ioc_source_label(source: str) -> str:
    """来源展示：URL 只留域名，避免标题被长链接撑爆。"""
    src = (source or "").strip()
    if not src:
        return ""
    low = src.lower()
    if low in ("ioc_db", "ioc", "ioc_mysql", "mysql", "es", "sqlite"):
        return ""
    if low.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            host = (urlparse(src).hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            return host[:48]
        except Exception:
            return ""
    if len(src) > 40:
        return src[:36] + "…"
    return src


def _ioc_hit_title(malware: str, matched: str, match_type: str = "", source: str = "") -> str:
    """告警标题：优先家族名；否则「来源域名 · IOC 类型 命中 · 短哈希」。"""
    fam = _ioc_family_label(malware)
    if fam:
        return fam
    m = (matched or "").strip()
    mt = (match_type or "").strip().lower()
    kind = {
        "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256",
        "ip": "IP", "domain": "域名", "url": "URL", "file_hash": "哈希",
    }.get(mt, "")
    if not kind and len(m) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in m):
        kind = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(m), "哈希")
    short = m if len(m) <= 24 else (m[:12] + "…" + m[-6:])
    src_lab = _ioc_source_label(source)
    if kind and short:
        if src_lab:
            return f"{src_lab} · IOC {kind} 命中 · {short}"
        return f"IOC {kind} 命中 · {short}"
    if short:
        if src_lab:
            return f"{src_lab} · IOC 命中 · {short}"
        return f"IOC 命中 · {short}"
    if src_lab:
        return f"{src_lab} · IOC 命中"
    return "IOC 命中"


def _redis_row_to_hit(d: Dict[str, Any], match_type: str, matched: str) -> Dict[str, Any]:
    malware = (d.get("malware") or "").strip()
    source = (d.get("source") or "").strip()
    name = _ioc_hit_title(malware, matched, match_type, source)
    return {
        "hash": matched if match_type in ("md5", "sha1", "sha256") else "",
        "domain": matched if match_type == "domain" else "",
        "ip": matched if match_type == "ip" else "",
        "url": matched if match_type == "url" else "",
        "name": name[:120],
        "severity": "high",
        "tags": [t.strip() for t in malware.replace(";", ",").split(",") if t.strip()][:12],
        "source": source or "ioc_db",
        "malware": malware,
        "match_type": match_type,
        "matched": matched,
        "db_id": d.get("id"),
        "db_type": d.get("type"),
        "from_db": True,
        "from_redis": True,
    }


def hash_kind(hex_str: str) -> Optional[str]:
    h = (hex_str or "").strip().lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return None
    n = len(h)
    if n == 32:
        return "md5"
    if n == 40:
        return "sha1"
    if n == 64:
        return "sha256"
    return None


def sample_preview(limit: int = 10) -> Dict[str, Any]:
    """仅返回情报库前 N 条样例（默认 10），禁止用于整库浏览。"""
    lim = max(1, min(int(limit or 10), 10))
    out: Dict[str, Any] = {"ok": True, "limit": lim, "items": [], "path": str(_db_path or "")}
    conn = _connect()
    if not conn:
        out["ok"] = False
        out["error"] = "ioc db unavailable"
        return out
    try:
        rows = conn.execute(
            "SELECT id, type, value, source, malware FROM ioc_records ORDER BY id ASC LIMIT ?",
            (lim,),
        ).fetchall()
        items = []
        for r in rows:
            val = str(r["value"] or "")
            if len(val) > 80:
                val = val[:80] + "…"
            items.append({
                "id": r["id"],
                "type": r["type"] or "",
                "value": val,
                "source": (r["source"] or "")[:80],
                "malware": (r["malware"] or "")[:80],
            })
        out["items"] = items
        out["shown"] = len(items)
    except sqlite3.Error as e:
        out["ok"] = False
        out["error"] = sqlite_error_hint(e)
    return out


def apex_domain(host: str) -> str:
    """粗略取注册域（eTLD+1），用于白名单。"""
    h = (host or "").strip().lower().strip(".")
    if not h or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
        return h
    parts = h.split(".")
    if len(parts) < 2:
        return h
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def extract_host(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        try:
            return (urlparse(v).hostname or "").lower()
        except Exception:
            return ""
    # domain or host:port
    v = v.split("/")[0].split("?")[0]
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    return v.split(":")[0].strip(".")


def normalize_url(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    # 去掉末尾多余 /
    if v.count("/") > 2:
        v = v.rstrip("/")
    return v


def is_plausible_domain(value: str) -> bool:
    """排除文件名伪域名（rc.local / readme.md / foo.sh 等）。"""
    d = (value or "").strip().lower().rstrip(".")
    if not d or "." not in d:
        return False
    _file_basename = {
        "rc.local", "readme.md", "readme.txt", "license.md", "license.txt", "changelog.md",
        "hosts.allow", "hosts.deny", "resolv.conf", "nsswitch.conf", "sysctl.conf",
        "ld.so.conf", "pam.conf",
    }
    if d in _file_basename:
        return False
    _file_tld = {
        "7z", "bak", "bat", "bin", "cfg", "class", "conf", "config", "cpp", "css", "csv",
        "dat", "db", "deb", "desktop", "dll", "doc", "docx", "elf", "exe", "gif", "go",
        "gz", "htm", "html", "ico", "ini", "jar", "java", "jpeg", "jpg", "js", "json",
        "key", "ko", "list", "lock", "log", "lua", "md", "msi", "old", "out", "pdf",
        "pem", "php", "pid", "pl", "png", "ps1", "py", "rb", "rpm", "rs", "service",
        "sh", "so", "sql", "svg", "swp", "sys", "tar", "tmp", "toml", "txt", "unit",
        "xml", "xz", "yaml", "yml", "zip", "zsh",
    }
    parts = d.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld in _file_tld or tld.isdigit():
        return False
    if len(parts) == 2 and tld == "local":
        return False
    return True


def is_generic_benign_ioc(value: str) -> bool:
    """IOC 条目本身是否是「整站级」良性噪音（apex / www / 首页 URL）。"""
    v = (value or "").strip().lower()
    if not v:
        return False
    host = extract_host(v)
    apex = apex_domain(host)
    if apex not in _BENIGN_APEX:
        return False
    # 仅 apex / www.apex
    if host == apex or host == "www." + apex:
        if "://" not in v:
            return True
        # 首页 URL：无业务路径
        try:
            p = urlparse(v if "://" in v else "http://" + v)
            path = (p.path or "/").rstrip("/") or "/"
            return path == "/" and not p.query and not p.fragment
        except Exception:
            return True
    return False


def is_benign_host(host: str) -> bool:
    return apex_domain(host) in _BENIGN_APEX


def _row_to_hit(row: sqlite3.Row, match_type: str, matched: str) -> Dict[str, Any]:
    malware = (row["malware"] or "").strip()
    source = (row["source"] or "").strip()
    name = _ioc_hit_title(malware, matched, match_type, source)
    return {
        "hash": matched if match_type in ("md5", "sha1", "sha256") else "",
        "domain": matched if match_type == "domain" else "",
        "ip": matched if match_type == "ip" else "",
        "url": matched if match_type == "url" else "",
        "name": name[:120],
        "severity": "high",
        "tags": [t.strip() for t in malware.replace(";", ",").split(",") if t.strip()][:12],
        "source": source or "ioc_db",
        "malware": malware,
        "match_type": match_type,
        "matched": matched,
        "db_id": row["id"],
        "db_type": row["type"],
        "from_db": True,
    }


def lookup(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """按值查 IOC。

    哈希：只打权威库（MySQL→ES；MySQL 不可用时才 SQLite），不读进程 LRU / Redis。
    其它类型：本地 LRU → Redis → MySQL → ES → SQLite。
    """
    v = (value or "").strip().lower()
    if not v:
        return []
    t = (ioc_type or "").strip().lower()
    # 良性整站（VT/IBM 等）域名/URL 直接跳过，避免误报与缓存污染
    if t in ("", "domain", "url"):
        host = extract_host(v)
        if host and is_benign_host(host) and not host.replace(".", "").isdigit():
            return []
    from .redis_client import is_available as redis_ok
    hk = hash_kind(v)
    is_hash = t in ("file_hash", "md5", "sha1", "sha256") or bool(hk)
    cache_key = f"{t}|{v}"

    if not is_hash:
        cached = _local_cache_get(cache_key)
        if cached is not None:
            return list(cached)
        if redis_ok():
            results = _lookup_redis(value, ioc_type)
            if results:
                _local_cache_put(cache_key, results)
                return results

    # 人工独立库优先（ioc/ioc_manual.db），再走 MySQL
    try:
        from . import ioc_manual_db
        results = ioc_manual_db.lookup(value, ioc_type)
        if results:
            if not is_hash and redis_ok():
                for h in results:
                    _cache_hit_to_redis(h)
            if not is_hash:
                _local_cache_put(cache_key, results)
            return results
    except Exception:
        pass

    # MySQL 精确查（默认同步目标）；未命中再试可选 ES
    results = _lookup_mysql(value, ioc_type)
    if results:
        if not is_hash and redis_ok():
            for h in results:
                _cache_hit_to_redis(h)
        if not is_hash:
            _local_cache_put(cache_key, results)
        return results
    results = _lookup_es(value, ioc_type)
    if results:
        if not is_hash and redis_ok():
            for h in results:
                _cache_hit_to_redis(h)
        if not is_hash:
            _local_cache_put(cache_key, results)
        return results

    # MySQL 可用时哈希不再回落 SQLite，避免「MySQL 已删、SQLite 仍命中」
    mysql_up = False
    try:
        from . import ioc_mysql
        mysql_up = bool(ioc_mysql.is_available())
    except Exception:
        mysql_up = False
    if not (is_hash and mysql_up):
        results = _lookup_sqlite(value, ioc_type)
        if results and not is_hash and redis_ok():
            for h in results:
                _cache_hit_to_redis(h)
    else:
        results = []

    if not results and is_hash:
        try:
            invalidate_cached_values([v], kinds=("file_hash", "md5", "sha1", "sha256"))
        except Exception:
            pass
    if not is_hash:
        _local_cache_put(cache_key, results or [])
    return results or []


def _lookup_store(mod_name: str, value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """统一走 ioc_mysql / ioc_es 的精确查询接口。"""
    try:
        if mod_name == "mysql":
            from . import ioc_mysql as store
            if not store.is_available():
                return []
        else:
            from . import ioc_es as store
            from . import es_client
            if not es_client.is_available():
                return []
    except Exception:
        return []

    v = (value or "").strip().lower()
    if not v:
        return []
    results: List[Dict[str, Any]] = []
    seen: set = set()

    def _extend(hits: List[Dict[str, Any]]):
        for h in hits or []:
            rid = h.get("db_id")
            key = rid if rid is not None else (h.get("db_type"), h.get("matched"))
            if key in seen:
                continue
            ioc_val = (h.get("matched") or "").lower()
            mt = h.get("match_type") or ""
            if mt in ("domain", "url") and is_generic_benign_ioc(ioc_val):
                continue
            seen.add(key)
            results.append(h)

    try:
        if ioc_type in (None, "ip"):
            if ioc_type == "ip" or ("." in v and all(p.isdigit() for p in v.split(".") if p) and v.count(".") == 3):
                _extend(store.lookup_ip(v))

        if ioc_type in (None, "domain"):
            host = extract_host(v)
            if host and (ioc_type == "domain" or ("." in host and not host.replace(".", "").isdigit())):
                _extend(store.lookup_domain(host))

        if ioc_type in (None, "url") and (v.startswith("http://") or v.startswith("https://") or ioc_type == "url"):
            nv = normalize_url(v)
            candidates = {nv, v.rstrip("/"), v}
            if nv.startswith("https://"):
                candidates.add("http://" + nv[len("https://"):])
            elif nv.startswith("http://"):
                candidates.add("https://" + nv[len("http://"):])
            _extend(store.lookup_url(list(candidates)))
            host = extract_host(v)
            if host:
                _extend(store.lookup_domain(host))

        hk = hash_kind(v)
        if ioc_type in (None, "md5", "sha1", "sha256", "file_hash") and (hk or ioc_type in ("md5", "sha1", "sha256", "file_hash")):
            mtype = hk or (ioc_type if ioc_type in ("md5", "sha1", "sha256") else "md5")
            _extend(store.lookup_hash(v, match_type=mtype))
    except Exception as e:
        print(f"[ioc_db] {mod_name} lookup: {e}")
        return []
    return results


def _lookup_mysql(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return _lookup_store("mysql", value, ioc_type)


def _lookup_es(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Elasticsearch 精确查询（可选）；不可用返回空。"""
    return _lookup_store("es", value, ioc_type)


def _lookup_redis(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Redis 精确查询（含 domain 父域后缀）。"""
    v = (value or "").strip().lower()
    if not v:
        return []

    results: List[Dict[str, Any]] = []
    seen: set = set()

    def _add_redis(db_type: str, lookup_val: str, match_type: str, matched: str):
        d = _redis_lookup_one(db_type, lookup_val)
        if not d:
            return
        rid = d.get("id")
        if rid in seen:
            return
        ioc_val = (d.get("value") or "").lower()
        if match_type in ("domain", "url") and (
            is_generic_benign_ioc(ioc_val) or is_benign_host(extract_host(ioc_val) or ioc_val)
        ):
            return
        # 查询目标本身良性也丢弃
        if match_type in ("domain", "url") and is_benign_host(extract_host(matched) or matched):
            return
        seen.add(rid)
        results.append(_redis_row_to_hit(d, match_type, matched))

    def lookup_domain_redis(host: str):
        _add_redis("domain", host, "domain", host)
        parts = host.split(".")
        if len(parts) > 2:
            for i in range(1, min(len(parts) - 1, 4)):
                suffix = ".".join(parts[i:])
                if len(suffix) < 4:
                    continue
                _add_redis("domain", suffix, "domain", suffix)

    # IP
    if ioc_type in (None, "ip"):
        if ioc_type == "ip" or ("." in v and all(p.isdigit() for p in v.split(".") if p) and v.count(".") == 3):
            _add_redis("ip", v, "ip", v)

    # Domain
    if ioc_type in (None, "domain"):
        host = extract_host(v)
        if host and (ioc_type == "domain" or ("." in host and not host.replace(".", "").isdigit())):
            lookup_domain_redis(host)

    # URL
    if ioc_type in (None, "url") and (v.startswith("http://") or v.startswith("https://") or ioc_type == "url"):
        nv = normalize_url(v)
        candidates = {nv, v.rstrip("/"), v}
        if nv.startswith("https://"):
            candidates.add("http://" + nv[len("https://"):])
        elif nv.startswith("http://"):
            candidates.add("https://" + nv[len("http://"):])
        for u in candidates:
            if u:
                _add_redis("url", u, "url", u)
                _add_redis("url", u + "/", "url", u)
        host = extract_host(v)
        if host:
            lookup_domain_redis(host)

    # Hash
    hk = hash_kind(v)
    if ioc_type in (None, "md5", "sha1", "sha256", "file_hash") and (hk or ioc_type in ("md5", "sha1", "sha256", "file_hash")):
        _add_redis("file_hash", v, hk or ioc_type or "md5", v)

    return results


def _lookup_sqlite(value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """原始 SQLite 查询路径（Redis 未命中或不可用时使用）。"""
    v = (value or "").strip().lower()
    if not v:
        return []
    conn = _connect()
    if not conn:
        return []

    results: List[Dict[str, Any]] = []
    seen_ids = set()

    def add_rows(sql: str, params: tuple, mtype: str, matched: str):
        try:
            for row in conn.execute(sql, params):
                if row["id"] in seen_ids:
                    continue
                ioc_val = (row["value"] or "").strip().lower()
                if mtype in ("domain", "url") and is_generic_benign_ioc(ioc_val):
                    continue
                seen_ids.add(row["id"])
                results.append(_row_to_hit(row, mtype, matched))
        except sqlite3.Error:
            pass

    # 一律用 value=? 直查：lower(value)=? 会让 (type,value) 索引失效，
    # 退化成扫完该 type 的全部行（ip 有 18 万条，单次就要几百毫秒）。
    def lookup_domain_exact(host: str):
        if not host or is_benign_host(host) or is_generic_benign_ioc(host):
            return
        add_rows(
            "SELECT * FROM ioc_records WHERE type='domain' AND value=? LIMIT 20",
            (host,), "domain", host,
        )
        parts = host.split(".")
        if len(parts) > 2:
            for i in range(1, min(len(parts) - 1, 4)):
                suffix = ".".join(parts[i:])
                if len(suffix) < 4:
                    continue
                if is_benign_host(suffix) or is_generic_benign_ioc(suffix):
                    continue
                add_rows(
                    "SELECT * FROM ioc_records WHERE type='domain' AND value=? LIMIT 10",
                    (suffix,), "domain", suffix,
                )

    if ioc_type in (None, "ip"):
        if ioc_type == "ip" or ("." in v and all(p.isdigit() for p in v.split(".") if p) and v.count(".") == 3):
            add_rows(
                "SELECT * FROM ioc_records WHERE type='ip' AND value=? LIMIT 20",
                (v,), "ip", v,
            )
            add_rows(
                f"SELECT * FROM {_ip_only_from(conn)} WHERE ip_only=? AND type='ip' LIMIT 20",
                (v,), "ip", v,
            )

    if ioc_type in (None, "domain"):
        host = extract_host(v)
        if host and (ioc_type == "domain" or ("." in host and not host.replace(".", "").isdigit())):
            lookup_domain_exact(host)

    if ioc_type in (None, "url") and (v.startswith("http://") or v.startswith("https://") or ioc_type == "url"):
        nv = normalize_url(v)
        candidates = {nv, v.rstrip("/"), v}
        if nv.startswith("https://"):
            candidates.add("http://" + nv[len("https://"):])
        elif nv.startswith("http://"):
            candidates.add("https://" + nv[len("http://"):])
        for u in candidates:
            if not u:
                continue
            add_rows("SELECT * FROM ioc_records WHERE type='url' AND value=? LIMIT 20", (u,), "url", u)
            add_rows("SELECT * FROM ioc_records WHERE type='url' AND value=? LIMIT 20", (u + "/",), "url", u)
        host = extract_host(v)
        if host:
            lookup_domain_exact(host)

    hk = hash_kind(v)
    if ioc_type in (None, "md5", "sha1", "sha256", "file_hash") and (hk or ioc_type in ("md5", "sha1", "sha256", "file_hash")):
        mtype = hk or (ioc_type if ioc_type in ("md5", "sha1", "sha256") else "md5")
        # 哈希在库里大小写混存，两种写法都直查
        add_rows(
            "SELECT * FROM ioc_records WHERE type='file_hash' AND value IN (?,?) LIMIT 20",
            (v, v.upper()), mtype, v,
        )

    return results


def stats(*, force: bool = False) -> Dict[str, Any]:
    """IOC 库统计。磁盘文件被替换后会自动失效重算；force=True 强制重算。"""
    global _stats_cache
    # 先探测文件是否变更（会清掉陈旧 cache/连接）
    path = get_db_path()
    if force:
        with _lock:
            _stats_cache = None
    if _stats_cache is not None and not force:
        return _stats_cache
    meta = file_info()
    layout = source_layout()
    out: Dict[str, Any] = {
        "enabled": bool(path),
        "path": str(path) if path else "",
        "exists": bool(path and path.exists()),
        "total": 0,
        "by_type": {},
        "file_size": meta.get("size"),
        "file_size_mb": meta.get("size_mb"),
        "file_mtime": meta.get("mtime"),
        "refreshed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": layout,
    }
    if not layout.get("ready") and layout.get("hint"):
        out["error"] = layout["hint"]
        if not path:
            _stats_cache = out
            return out
    conn = _connect()
    if not conn:
        if not out.get("error"):
            out["error"] = layout.get("hint") or "ioc db unavailable"
        _stats_cache = out
        return out
    try:
        out["total"] = int(conn.execute("SELECT COUNT(*) FROM ioc_records").fetchone()[0])
        for row in conn.execute("SELECT type, COUNT(*) AS c FROM ioc_records GROUP BY type"):
            out["by_type"][row["type"] or ""] = int(row["c"])
    except sqlite3.Error as e:
        out["error"] = sqlite_error_hint(e)
    # Redis 状态（按需缓存，无全量预热）
    from .redis_client import is_available as redis_ok
    out["redis_enabled"] = redis_ok()
    out["redis_mode"] = "cache_on_hit"
    out["query_backend"] = "sqlite"
    try:
        from . import ioc_mysql
        my_st = ioc_mysql.stats()
        out["mysql"] = my_st
        out["mysql_table"] = my_st.get("table")
        out["mysql_count"] = my_st.get("count")
        out["mysql_available"] = bool(my_st.get("available"))
        if my_st.get("available") and int(my_st.get("count") or 0) > 0:
            out["query_backend"] = "mysql"
    except Exception as e:
        out["mysql_error"] = str(e)
    try:
        from . import ioc_es
        es_st = ioc_es.stats()
        out["es"] = es_st
        out["es_index"] = es_st.get("index")
        out["es_count"] = es_st.get("count")
        out["es_available"] = bool(es_st.get("available"))
        if out.get("query_backend") == "sqlite" and es_st.get("available") and int(es_st.get("count") or 0) > 0:
            out["query_backend"] = "es"
    except Exception as e:
        out["es_error"] = str(e)
    _stats_cache = out
    return out


def lookup_hashes_batch(
    hex_values: List[str],
    *,
    chunk_size: int = 64,
    bypass_cache: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """批量查 file_hash：始终打权威库（MySQL→ES；MySQL 不可用才 SQLite）。

    哈希不读进程 LRU / Redis，避免情报库删除后假阳性。
    bypass_cache 保留兼容（哈希路径已默认 bypass）。
    返回: {hash_hex: [hit, ...]}；未命中的 key 对应空列表。
    """
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in hex_values or []:
        v = (raw or "").strip().lower()
        if not v or v in seen:
            continue
        if not hash_kind(v):
            continue
        seen.add(v)
        need.append(v)

    if not need:
        return out

    # 人工独立库优先
    try:
        from . import ioc_manual_db
        man_hits = ioc_manual_db.lookup_hashes(need) or {}
    except Exception:
        man_hits = {}

    # MySQL 批量（主路径）
    store_hits: Dict[str, List[Dict[str, Any]]] = dict(man_hits)
    mysql_up = False
    try:
        from . import ioc_mysql
        mysql_up = bool(ioc_mysql.is_available())
        if mysql_up:
            my_hits = ioc_mysql.lookup_hashes(need, chunk_size=chunk_size) or {}
            for k, rows in (my_hits or {}).items():
                if rows and not store_hits.get(k):
                    store_hits[k] = rows
    except Exception:
        mysql_up = False

    # 未命中再试可选 ES
    still_need = [v for v in need if not (store_hits.get(v) or [])]
    if still_need:
        try:
            from . import ioc_es, es_client
            if es_client.is_available():
                es_hits = ioc_es.lookup_hashes(still_need, chunk_size=chunk_size) or {}
                for k, rows in (es_hits or {}).items():
                    if rows and not store_hits.get(k):
                        store_hits[k] = rows
        except Exception:
            pass

    still: List[str] = []
    for v in need:
        rows = list(store_hits.get(v) or [])
        if rows:
            fixed = []
            hk = hash_kind(v) or "md5"
            for h in rows:
                row = dict(h)
                row["match_type"] = hk
                row["matched"] = row.get("matched") or v
                if not row.get("hash"):
                    row["hash"] = v
                if not row.get("db_type"):
                    row["db_type"] = "file_hash"
                fixed.append(row)
            out[v] = fixed
        else:
            still.append(v)

    if still:
        try:
            invalidate_cached_values(still, kinds=("file_hash", "md5", "sha1", "sha256"))
        except Exception:
            pass

    # MySQL 可用时不回落 SQLite（否则 MySQL 已删的 MD5 会被 SQLite 旧库再次命中）
    if still and not mysql_up:
        sq = _lookup_sqlite_hashes(still)
        for v in still:
            out[v] = list(sq.get(v) or [])
    else:
        for v in still:
            out.setdefault(v, [])
    return out


def lookup_ips_batch(
    ips: List[str],
    *,
    chunk_size: int = 64,
    bypass_cache: bool = False,
) -> Dict[str, List[Dict[str, Any]]]:
    """批量查 IP：人工库 → 本地缓存 → MySQL IN →（可选）ES → SQLite 回退。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in ips or []:
        v = (raw or "").strip().lower().strip("[]")
        if not v or v in seen:
            continue
        seen.add(v)
        if not bypass_cache:
            cached = _local_cache_get(f"ip|{v}")
            if cached is not None:
                out[v] = list(cached)
                continue
        need.append(v)
    if not need:
        return out

    # 人工独立库优先（不依赖 MySQL 镜像）
    try:
        from . import ioc_manual_db
        man_hits = ioc_manual_db.lookup_ips(need) or {}
    except Exception:
        man_hits = {}

    store_hits: Dict[str, List[Dict[str, Any]]] = {v: list(man_hits.get(v) or []) for v in need}
    still_after_manual = [v for v in need if not store_hits.get(v)]
    mysql_ok = False
    try:
        from . import ioc_mysql
        mysql_ok = bool(ioc_mysql.is_available())
        if mysql_ok and still_after_manual:
            cs = max(8, min(int(chunk_size or 64), 128))
            for i in range(0, len(still_after_manual), cs):
                chunk = still_after_manual[i : i + cs]
                ph = ",".join(["%s"] * len(chunk))
                rows = ioc_mysql._query_rows(  # noqa: SLF001 — 批量 IN，与 lookup_exact 同源
                    f"SELECT id, type, value, ip_only, source, malware FROM {ioc_mysql.TABLE} "
                    f"WHERE type='ip' AND (value IN ({ph}) OR ip_only IN ({ph}))",
                    (*chunk, *chunk),
                    limit=max(64, len(chunk) * 4),
                )
                for r in rows or []:
                    hit = ioc_mysql._hit_from_row(  # noqa: SLF001
                        r, "ip", (r.get("ip_only") or r.get("value") or "").lower()
                    )
                    matched = (hit.get("matched") or "").lower()
                    for cand in chunk:
                        if cand == matched or cand == (r.get("value") or "").lower() or cand == (r.get("ip_only") or "").lower():
                            store_hits.setdefault(cand, []).append(hit)
    except Exception as e:
        mysql_ok = False
        print(f"[ioc_db] lookup_ips_batch mysql: {e}")

    still = [v for v in need if not store_hits.get(v)]
    if still:
        try:
            from . import ioc_es, es_client
            if es_client.is_available():
                for i in range(0, len(still), 64):
                    chunk = still[i : i + 64]
                    hits = ioc_es.lookup_exact("ip", chunk, match_type="ip", size=max(20, len(chunk) * 2)) or []
                    by_val: Dict[str, List] = {}
                    for h in hits:
                        m = (h.get("matched") or "").lower()
                        by_val.setdefault(m, []).append(h)
                    for v in chunk:
                        if by_val.get(v):
                            store_hits[v] = list(by_val[v])
        except Exception:
            pass

    if not mysql_ok:
        for v, rows in _lookup_sqlite_net_batch("ip", [v for v in need if not store_hits.get(v)]).items():
            if rows:
                store_hits[v] = rows

    for v in need:
        rows = list(store_hits.get(v) or [])
        out[v] = rows
        _local_cache_put(f"ip|{v}", rows)
    return out


def lookup_domains_batch(hosts: List[str], *, chunk_size: int = 64) -> Dict[str, List[Dict[str, Any]]]:
    """批量查域名：展开父域候选后一次 IN，再映射回原始 host。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in hosts or []:
        h = extract_host(raw) or (raw or "").strip().lower().strip(".")
        if not h or h in seen or h.replace(".", "").isdigit():
            continue
        if is_benign_host(h) or not is_plausible_domain(h):
            out[h] = []
            continue
        seen.add(h)
        cached = _local_cache_get(f"domain|{h}")
        if cached is not None:
            out[h] = list(cached)
            continue
        need.append(h)
    if not need:
        return out

    # host -> candidate suffixes
    cand_map: Dict[str, List[str]] = {}
    all_cands: List[str] = []
    cseen = set()
    for h in need:
        parts = h.split(".")
        cands = [h]
        if len(parts) > 2:
            for i in range(1, min(len(parts) - 1, 4)):
                suffix = ".".join(parts[i:])
                if len(suffix) >= 4:
                    cands.append(suffix)
        cand_map[h] = cands
        for c in cands:
            if c not in cseen:
                cseen.add(c)
                all_cands.append(c)

    hit_by_val: Dict[str, List[Dict[str, Any]]] = {}
    try:
        from . import ioc_manual_db
        for c, rows in (ioc_manual_db.lookup_values("domain", all_cands) or {}).items():
            if rows:
                hit_by_val.setdefault(c, []).extend(rows)
    except Exception:
        pass

    mysql_ok = False
    try:
        from . import ioc_mysql
        mysql_ok = bool(ioc_mysql.is_available())
        if mysql_ok:
            cs = max(8, min(int(chunk_size or 64), 128))
            for i in range(0, len(all_cands), cs):
                chunk = all_cands[i : i + cs]
                for h in ioc_mysql.lookup_exact("domain", chunk, match_type="domain", size=max(20, len(chunk) * 3)) or []:
                    m = (h.get("matched") or "").lower()
                    hit_by_val.setdefault(m, []).append(h)
    except Exception as e:
        mysql_ok = False
        print(f"[ioc_db] lookup_domains_batch mysql: {e}")

    if not mysql_ok:
        for c, rows in _lookup_sqlite_net_batch("domain", all_cands).items():
            if rows:
                hit_by_val.setdefault(c, []).extend(rows)

    for h in need:
        rows: List[Dict[str, Any]] = []
        for c in cand_map.get(h) or [h]:
            rows.extend(hit_by_val.get(c) or [])
        uniq = []
        keys = set()
        for r in rows:
            k = r.get("db_id") or (r.get("matched"), r.get("source"))
            if k in keys:
                continue
            keys.add(k)
            uniq.append(r)
        out[h] = uniq
        _local_cache_put(f"domain|{h}", uniq)
    return out


def lookup_urls_batch(urls: List[str], *, chunk_size: int = 64) -> Dict[str, List[Dict[str, Any]]]:
    """批量查 URL（精确 + 归一化变体）。"""
    out: Dict[str, List[Dict[str, Any]]] = {}
    need: List[str] = []
    seen = set()
    for raw in urls or []:
        v = (raw or "").strip()
        if not v:
            continue
        nv = normalize_url(v).lower()
        key = nv or v.lower()
        if key in seen:
            continue
        host = extract_host(key)
        if host and is_benign_host(host):
            out[key] = []
            seen.add(key)
            continue
        seen.add(key)
        cached = _local_cache_get(f"url|{key}")
        if cached is not None:
            out[key] = list(cached)
            continue
        need.append(key)
    if not need:
        return out

    variants: List[str] = []
    vseen = set()
    for u in need:
        for x in (u, u.rstrip("/"), u + "/" if not u.endswith("/") else u):
            xl = x.lower()
            if xl not in vseen:
                vseen.add(xl)
                variants.append(xl)

    hit_by_val: Dict[str, List[Dict[str, Any]]] = {}
    try:
        from . import ioc_manual_db
        for c, rows in (ioc_manual_db.lookup_values("url", variants) or {}).items():
            if rows:
                hit_by_val.setdefault(c, []).extend(rows)
                hit_by_val.setdefault(c.rstrip("/"), []).extend(rows)
    except Exception:
        pass

    mysql_ok = False
    try:
        from . import ioc_mysql
        mysql_ok = bool(ioc_mysql.is_available())
        if mysql_ok:
            cs = max(8, min(int(chunk_size or 64), 128))
            for i in range(0, len(variants), cs):
                chunk = variants[i : i + cs]
                for h in ioc_mysql.lookup_exact("url", chunk, match_type="url", size=max(20, len(chunk) * 2)) or []:
                    m = (h.get("matched") or "").lower()
                    hit_by_val.setdefault(m, []).append(h)
                    hit_by_val.setdefault(m.rstrip("/"), []).append(h)
    except Exception as e:
        mysql_ok = False
        print(f"[ioc_db] lookup_urls_batch mysql: {e}")

    if not mysql_ok:
        for v, rows in _lookup_sqlite_net_batch("url", variants).items():
            if rows:
                hit_by_val.setdefault(v, []).extend(rows)
                hit_by_val.setdefault(v.rstrip("/"), []).extend(rows)

    for u in need:
        rows = list(hit_by_val.get(u) or hit_by_val.get(u.rstrip("/")) or [])
        # 去重
        uniq = []
        keys = set()
        for r in rows:
            k = r.get("db_id") or (r.get("matched"), r.get("source"))
            if k in keys:
                continue
            keys.add(k)
            uniq.append(r)
        out[u] = uniq
        _local_cache_put(f"url|{u}", uniq)
    return out


def _lookup_sqlite_hashes(values: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """SQLite IN 批量精确查 file_hash。"""
    out: Dict[str, List[Dict[str, Any]]] = {v: [] for v in values}
    conn = _connect()
    if not conn or not values:
        return out
    for i in range(0, len(values), 64):
        chunk = values[i : i + 64]
        # 库里哈希大小写混存，两种写法都查；用 lower(value) 会让 (type,value) 索引失效，
        # 退化成扫完整个 file_hash 类型（十几万行）。
        cands = [v for v in chunk] + [v.upper() for v in chunk]
        ph = ",".join("?" * len(cands))
        sql = (
            f"SELECT * FROM ioc_records WHERE type='file_hash' AND value IN ({ph}) "
            f"LIMIT ?"
        )
        lim = min(500, max(64, len(chunk) * 8))
        try:
            for row in conn.execute(sql, (*cands, lim)):
                val = (row["value"] or "").strip().lower()
                if val not in out:
                    continue
                hk = hash_kind(val) or "md5"
                out[val].append(_row_to_hit(row, hk, val))
        except sqlite3.Error:
            # 回退逐条（极少）
            for v in chunk:
                for h in _lookup_sqlite(v, "file_hash"):
                    out[v].append(h)
    return out


def _lookup_sqlite_net_batch(kind: str, values: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """SQLite IN 批量精确查 ip/domain/url，仅在 MySQL 不可用时兜底。

    必须走 `value IN (...)` 而不是 `lower(value)=?`：后者让 (type,value) 索引失效，
    单次查询要扫完该 type 的全部行（ip 有 18 万条），逐条回退时会累成几十秒。
    """
    out: Dict[str, List[Dict[str, Any]]] = {v: [] for v in values}
    conn = _connect()
    if not conn or not values:
        return out
    seen_ids: Dict[str, set] = {}
    for i in range(0, len(values), 200):
        chunk = values[i : i + 200]
        ph = ",".join("?" * len(chunk))
        try:
            rows = list(conn.execute(
                f"SELECT * FROM ioc_records WHERE type=? AND value IN ({ph})",
                (kind, *chunk),
            ))
            if kind == "ip":
                rows.extend(conn.execute(
                    f"SELECT * FROM {_ip_only_from(conn)} WHERE ip_only IN ({ph}) AND type='ip'",
                    chunk,
                ))
        except sqlite3.Error:
            continue
        for row in rows:
            val = (row["value"] or "").strip().lower()
            key = val if val in out else ((row["ip_only"] or "").strip().lower() if kind == "ip" else "")
            if key not in out:
                continue
            if kind in ("domain", "url") and is_generic_benign_ioc(val):
                continue
            ids = seen_ids.setdefault(key, set())
            if row["id"] in ids:
                continue
            ids.add(row["id"])
            out[key].append(_row_to_hit(row, kind, key))
    return out
