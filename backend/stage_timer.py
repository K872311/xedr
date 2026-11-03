"""阶段耗时打点：一次上传/任务内累计各阶段毫秒，结束时输出单条日志。

用法：
    t = StageTimer("upload_timing", "collect_report", rid=rid)
    with t.step("parse"):
        ...
    t.mark("save")            # 从上一次打点到现在
    t.emit(bytes=len(raw))    # 输出 stage=... total_ms=... parse_ms=... save_ms=...
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple


class NullTimer:
    """空实现：调用方不想打点时用，避免到处判空。"""

    def set(self, **fields: Any) -> "NullTimer":
        return self

    def mark(self, name: str) -> float:
        return 0.0

    def skip(self) -> None:
        return None

    @contextmanager
    def step(self, name: str):
        yield

    @property
    def total_ms(self) -> float:
        return 0.0

    def emit(self, **kwargs: Any) -> float:
        return 0.0


def null_timer() -> NullTimer:
    return NullTimer()


class StageTimer:
    """轻量计时器：只在内存里累加，emit 时才写日志。"""

    def __init__(self, channel: str, event: str, **fields: Any) -> None:
        self.channel = str(channel or "app")
        self.event = str(event or "stage")
        self.fields: Dict[str, Any] = {k: v for k, v in fields.items() if v is not None}
        self._t0 = time.perf_counter()
        self._last = self._t0
        self._stages: List[Tuple[str, float]] = []
        self._emitted = False

    def set(self, **fields: Any) -> "StageTimer":
        for k, v in fields.items():
            if v is not None:
                self.fields[k] = v
        return self

    def mark(self, name: str) -> float:
        """记录「上一次打点 → 现在」的耗时。"""
        now = time.perf_counter()
        ms = (now - self._last) * 1000.0
        self._last = now
        self._add(name, ms)
        return ms

    def skip(self) -> None:
        """丢弃上一次打点到现在的时间（不计入任何阶段）。"""
        self._last = time.perf_counter()

    @contextmanager
    def step(self, name: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            self._add(name, (time.perf_counter() - start) * 1000.0)
            self._last = time.perf_counter()

    def _add(self, name: str, ms: float) -> None:
        key = str(name or "stage").strip() or "stage"
        for i, (n, old) in enumerate(self._stages):
            if n == key:
                self._stages[i] = (n, old + ms)
                return
        self._stages.append((key, ms))

    @property
    def total_ms(self) -> float:
        return (time.perf_counter() - self._t0) * 1000.0

    def summary(self) -> str:
        parts = [f"stage={self.event}"]
        for k, v in self.fields.items():
            parts.append(f"{k}={v}")
        parts.append(f"total_ms={self.total_ms:.1f}")
        for name, ms in self._stages:
            parts.append(f"{name}_ms={ms:.1f}")
        return " ".join(parts)

    def emit(self, *, level: Optional[str] = None, slow_ms: float = 0.0, **fields: Any) -> float:
        """输出一条汇总日志；slow_ms>0 且超阈值时升级为 warn。"""
        self.set(**fields)
        total = self.total_ms
        if self._emitted:
            return total
        self._emitted = True
        lv = level or ("warn" if slow_ms > 0 and total >= slow_ms else "info")
        msg = self.summary()
        try:
            from . import applog
            applog.log(self.channel, msg, level=lv)
        except Exception:
            print(f"[{self.channel}] {msg}")
        return total
