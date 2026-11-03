"""Redis 客户端单例，带自动回退。

- Redis 不可用时所有操作静默失败，调用方继续走 SQLite/内存路径。
- 兼容 Redis 3.0.504（phpStudy），强制 RESP2 协议（protocol=2）。
"""
from __future__ import annotations

import json
import threading
from typing import Any, Optional

from .cache_config import redis_config

_lock = threading.Lock()
_client: Any = None          # redis.Redis 实例或 None
_available: Optional[bool] = None   # None=未探测
_last_error: str = ""


def _make_client():
    global _last_error
    cfg = redis_config()
    if not cfg.get("enabled"):
        _last_error = "未启用"
        return None
    try:
        import redis as _redis
        kw: dict = {
            "host": cfg["host"],
            "port": int(cfg["port"]),
            "db": int(cfg.get("db", 0)),
            "decode_responses": True,
            "socket_connect_timeout": 0.4,
            "socket_timeout": 0.4,
        }
        pw = cfg.get("password") or ""
        if pw:
            kw["password"] = pw
        # 强制 RESP2，避免旧版 Redis 报 "unknown command 'HELLO'"
        kw["protocol"] = int(cfg.get("protocol", 2))
        r = _redis.Redis(**kw)
        r.ping()
        _last_error = ""
        return r
    except Exception as e:
        _last_error = f"{type(e).__name__}: {e}"
        print(f"[redis] connect failed (fallback to local): {e}")
        return None


def get_client():
    """返回已连接的 Redis 客户端；不可用时返回 None。"""
    global _client, _available
    with _lock:
        if _available is not None:
            return _client
        _client = _make_client()
        _available = _client is not None
        if _available:
            cfg = redis_config()
            print(f"[redis] connected {cfg['host']}:{cfg['port']} (prefix={cfg['key_prefix']})")
        return _client


def is_available() -> bool:
    return get_client() is not None


def reset() -> None:
    """强制重新探测（reload 后调用）。"""
    global _client, _available, _last_error
    with _lock:
        try:
            if _client:
                _client.close()
        except Exception:
            pass
        _client = None
        _available = None
        _last_error = ""


def probe_status(reprobe: bool = False) -> dict:
    """管理后台用：连接态 + 延迟 + 失败原因。"""
    import time
    cfg = redis_config()
    out = {
        "connected": False,
        "enabled": bool(cfg.get("enabled")),
        "host": cfg.get("host"),
        "port": cfg.get("port"),
        "db": cfg.get("db", 0),
        "latency_ms": None,
        "error": "",
        "hint": "",
    }
    if not cfg.get("enabled"):
        out["error"] = "未启用"
        out["hint"] = "会话锁与热加载广播不可用，改配置后点「重新探测」。"
        return out
    if reprobe:
        reset()
    try:
        t0 = time.perf_counter()
        r = get_client()
        if r:
            r.ping()
            out["connected"] = True
            out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        else:
            out["error"] = _last_error or "连接失败，已回退本地"
            out["hint"] = "会话可能只在本机内存；多实例无法共享登录态。检查 Redis 地址/密码/是否启动。"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["hint"] = "Ping 失败，请检查 Redis 进程与防火墙。"
    return out


def prefix() -> str:
    return redis_config().get("key_prefix") or "cnpc:"


# ---- 便捷包装：出错返回 None / False，不抛异常 ----

def rget(key: str) -> Optional[str]:
    try:
        r = get_client()
        return r.get(key) if r else None
    except Exception:
        return None


def rset(key: str, value: str, ex: Optional[int] = None) -> bool:
    try:
        r = get_client()
        if not r:
            return False
        if ex:
            r.setex(key, ex, value)
        else:
            r.set(key, value)
        return True
    except Exception:
        return False


def rdel(*keys: str) -> int:
    try:
        r = get_client()
        if not r or not keys:
            return 0
        return r.delete(*keys) or 0
    except Exception:
        return 0


def scan_delete(match: str, count: int = 500) -> int:
    """SCAN + DELETE 按 glob 批量删键（兼容 Redis 3.x，避免 KEYS 阻塞）。"""
    try:
        r = get_client()
        if not r or not match:
            return 0
        deleted = 0
        cursor: Any = 0
        while True:
            cursor, keys = r.scan(cursor=cursor, match=match, count=max(1, int(count)))
            if keys:
                deleted += r.delete(*keys) or 0
            if cursor in (0, "0", b"0"):
                break
        return deleted
    except Exception:
        return 0


def rpipeline():
    """返回 pipeline 上下文管理器，或 None。"""
    try:
        r = get_client()
        return r.pipeline(transaction=False) if r else None
    except Exception:
        return None


def rjson_get(key: str) -> Optional[Any]:
    raw = rget(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw


def rjson_set(key: str, value: Any, ex: Optional[int] = None) -> bool:
    try:
        return rset(key, json.dumps(value, ensure_ascii=False), ex=ex)
    except Exception:
        return False
