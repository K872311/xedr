"""登录失败限流（内存；多进程各自计数，仍能挡住单点爆破）。"""
from __future__ import annotations
import time
import threading
from typing import Dict, Tuple

_lock = threading.Lock()
_hits: Dict[str, Tuple[int, float]] = {}  # key -> (fails, window_start)
_lockout: Dict[str, float] = {}  # key -> unlock_at
_actions: Dict[str, Tuple[int, float]] = {}

WINDOW = 600.0
MAX_FAILS = 8
LOCK_SECS = 900.0


def _key(ip: str, username: str) -> str:
    return f"{(ip or '?').strip()[:64]}|{(username or '').strip().lower()[:64]}"


def check_login_allowed(ip: str, username: str) -> None:
    now = time.time()
    with _lock:
        for k in (_key(ip, username), _key(ip, "*")):
            until = _lockout.get(k) or 0
            if until > now:
                raise ValueError("尝试次数过多，请稍后再试")
            if until and until <= now:
                _lockout.pop(k, None)
                _hits.pop(k, None)


def record_login_failure(ip: str, username: str) -> None:
    now = time.time()
    with _lock:
        for k, threshold in ((_key(ip, username), MAX_FAILS), (_key(ip, "*"), MAX_FAILS * 3)):
            n, start = _hits.get(k) or (0, now)
            if now - start > WINDOW:
                n, start = 0, now
            n += 1
            _hits[k] = (n, start)
            if n >= threshold:
                _lockout[k] = now + LOCK_SECS
                _hits.pop(k, None)


def record_login_success(ip: str, username: str) -> None:
    k = _key(ip, username)
    with _lock:
        _hits.pop(k, None)
        _lockout.pop(k, None)


def check_action_allowed(
    action: str,
    key: str,
    *,
    limit: int,
    window: float,
) -> None:
    """简单固定窗口限流；用于注册、同步分析和付费 AI 等敏感动作。"""
    now = time.time()
    k = f"action:{str(action)[:40]}:{str(key or '?')[:128]}"
    with _lock:
        n, start = _actions.get(k) or (0, now)
        if now - start >= window:
            n, start = 0, now
        if n >= max(1, int(limit)):
            wait = max(1, int(window - (now - start)))
            raise ValueError(f"请求过于频繁，请 {wait} 秒后再试")
        _actions[k] = (n + 1, start)
        if len(_actions) > 10_000:
            stale = [x for x, (_, s) in _actions.items() if now - s > max(window, 3600)]
            for x in stale[:5000]:
                _actions.pop(x, None)
