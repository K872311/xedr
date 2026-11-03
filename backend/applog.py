"""应用日志：实时落盘（reports/applogs.jsonl）+ 小内存索引。"""
from __future__ import annotations

import builtins
import json
import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()
# 落盘串行锁：append 与 trim 必须互斥。trim 是「读全文 → 重写 → 替换」，
# 期间若有并发 append 写进旧文件，replace 一落地这些行就永久消失。
_FILE_LOCK = threading.Lock()
_FILE_KEEP = 20000
_LOG_BASENAME = "applogs.jsonl"
_BUF: deque = deque(maxlen=5000)
_TLS = threading.local()
_PRINT_INSTALLED = False
_ORIG_PRINT = builtins.print

_CHANNEL_RE = re.compile(r"^\[([a-zA-Z][\w.-]{0,31})\]\s*(.*)$")
_CAPTURE = {
    "jobs", "pipeline", "ioc", "db", "db_store", "mysql", "boot", "app",
    "eventlog", "audit", "jg", "Auto", "report_delete", "system_updates",
    "rules_reload", "bw_list_reload", "rule_index", "hot_reload", "ioc_db",
    "slow_request", "upload_timing", "job_timing",
    "api_error", "api_exception", "http",
}


def _reports_dir() -> Path:
    try:
        from . import config
        base = Path(config.REPORTS_DIR)
    except Exception:
        base = Path(__file__).resolve().parent.parent / "reports"
    base.mkdir(parents=True, exist_ok=True)
    return base.resolve()


def _log_path() -> Path:
    return _reports_dir() / _LOG_BASENAME


def _validated_log_path() -> Path:
    """仅允许清除 reports 目录下固定文件名，防止误删其它文件。"""
    path = _log_path().resolve()
    reports = _reports_dir()
    if path.name != _LOG_BASENAME:
        raise OSError("invalid applog file name")
    if path.parent != reports:
        raise OSError("applog path outside reports directory")
    return path


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _append_file(entry: Dict[str, Any]) -> bool:
    """追加一行并 fsync，确保落盘。"""
    try:
        line = json.dumps(entry, ensure_ascii=False)
        path = _validated_log_path()
        with _FILE_LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return True
    except Exception:
        return False


def _trim_file(max_lines: int | None = None) -> None:
    """偶尔裁剪落盘文件，避免无限增长。

    全程持 _FILE_LOCK：读全文与替换之间不能有并发 append，否则那些行随旧
    inode 一起被 replace 丢弃——审计日志静默少行比文件涨大严重得多。
    """
    keep = int(max_lines if max_lines is not None else _FILE_KEEP)
    path = _validated_log_path()
    try:
        with _FILE_LOCK:
            if not path.is_file() or path.stat().st_size < 2_500_000:
                return
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            # 留出余量再重写：否则行数一旦顶到上限，每 200 条日志就要整体重写一次全文
            if len(lines) <= keep + max(keep // 10, 200):
                return
            keep_lines = lines[-keep:]
            tmp = path.with_name(f"{_LOG_BASENAME}.tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.writelines(keep_lines)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.replace(path)
    except Exception:
        pass


_FILE_CACHE_LOCK = threading.Lock()
_FILE_CACHE: Dict[str, Any] = {
    "path": "",
    "consumed": 0,   # 已解析到的字节位置，总是落在换行边界上
    "rows": [],      # 解析出的日志条目
    "lines": 0,      # 非空物理行数
}


def _consume_appended(path: Path, size: int) -> None:
    """解析 consumed..size 之间新追加的完整行。调用方需持有 _FILE_CACHE_LOCK。"""
    start = int(_FILE_CACHE["consumed"])
    try:
        with open(path, "rb") as fh:
            fh.seek(start)
            chunk = fh.read(size - start)
    except OSError:
        return
    # 末尾可能是正在写、还没换行的半行，留到下次再读
    cut = chunk.rfind(b"\n")
    if cut < 0:
        return
    chunk = chunk[: cut + 1]
    rows: List[Dict[str, Any]] = _FILE_CACHE["rows"]
    lines = int(_FILE_CACHE["lines"])
    for raw in chunk.decode("utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        lines += 1
        try:
            obj = json.loads(raw)
        except Exception:
            continue
        if isinstance(obj, dict) and obj.get("message"):
            rows.append(obj)
    # 与落盘裁剪同口径，避免缓存无限增长
    if len(rows) > _FILE_KEEP:
        del rows[: len(rows) - _FILE_KEEP]
    _FILE_CACHE["lines"] = lines
    _FILE_CACHE["consumed"] = start + len(chunk)


def _load_file_rows() -> tuple[List[Dict[str, Any]], int]:
    """增量读取落盘日志，返回 (日志条目, 非空行数)。

    日志只会在尾部追加，所以按字节位置续读即可；裁剪和清空会让文件变小，
    据此判断缓存失效再整份重读。
    """
    path = _log_path()
    try:
        size = path.stat().st_size
    except OSError:
        size = -1
    with _FILE_CACHE_LOCK:
        key = str(path)
        if _FILE_CACHE["path"] != key or size < int(_FILE_CACHE["consumed"]):
            _FILE_CACHE.update(path=key, consumed=0, rows=[], lines=0)
        if size < 0:
            return [], 0
        if size > int(_FILE_CACHE["consumed"]):
            _consume_appended(path, size)
        return list(_FILE_CACHE["rows"]), int(_FILE_CACHE["lines"])


def _count_persisted_lines() -> int:
    return _load_file_rows()[1]


def log(channel: str, message: str, *, level: str = "info", echo: bool = True, **extra: Any) -> None:
    """写入缓冲与落盘；echo=True 时同步打控制台。"""
    if getattr(_TLS, "busy", False):
        return
    ch = str(channel or "app").strip() or "app"
    msg = str(message or "").strip()
    if not msg:
        return
    lv = str(level or "info").lower()
    entry: Dict[str, Any] = {
        "ts": _now_iso(),
        "ts_ms": int(time.time() * 1000),
        "level": lv,
        "channel": ch,
        "message": msg[:2000],
    }
    if extra:
        clean = {}
        for k, v in list(extra.items())[:12]:
            if v is None or str(k).startswith("_"):
                continue
            if isinstance(v, (str, int, float, bool)):
                clean[str(k)] = v
            else:
                clean[str(k)] = str(v)[:240]
        if clean:
            entry["extra"] = clean
    _TLS.busy = True
    try:
        persisted = _append_file(entry)
        with _LOCK:
            _BUF.append(entry)
            n = len(_BUF)
        if not persisted:
            _ORIG_PRINT(f"[applog] 落盘失败，已暂存内存: {msg[:120]}")
        if n % 200 == 0:
            _trim_file()
        if echo:
            prefix = f"[{ch}]"
            _ORIG_PRINT(f"{prefix} {msg}")
    finally:
        _TLS.busy = False


def info(channel: str, message: str, **extra: Any) -> None:
    log(channel, message, level="info", **extra)


def warn(channel: str, message: str, **extra: Any) -> None:
    log(channel, message, level="warn", **extra)


def error(channel: str, message: str, **extra: Any) -> None:
    log(channel, message, level="error", **extra)


def _capture_print(*args, **kwargs) -> None:
    _ORIG_PRINT(*args, **kwargs)
    if getattr(_TLS, "busy", False):
        return
    try:
        sep = kwargs.get("sep", " ")
        text = sep.join(str(a) for a in args).strip()
        if not text.startswith("["):
            return
        m = _CHANNEL_RE.match(text)
        if not m:
            return
        ch = m.group(1)
        if ch not in _CAPTURE and ch.lower() not in {x.lower() for x in _CAPTURE}:
            # 仍收录常见短通道名
            if len(ch) > 24:
                return
        body = (m.group(2) or text).strip() or text
        log(ch, body, echo=False)
    except Exception:
        pass


def install_print_capture() -> None:
    """把 print('[jobs] …') 等同步进应用日志。"""
    global _PRINT_INSTALLED
    if _PRINT_INSTALLED:
        return
    builtins.print = _capture_print
    _PRINT_INSTALLED = True


def boot(message: str = "应用日志已启用（全部实时落盘 reports/applogs.jsonl）") -> None:
    install_print_capture()
    log("boot", message, echo=True)


def _entry_ms(e: Dict[str, Any]) -> int:
    try:
        ms = int(e.get("ts_ms") or 0)
        if ms > 0:
            return ms
    except Exception:
        pass
    ts = e.get("ts")
    if isinstance(ts, (int, float)):
        n = float(ts)
        return int(n * 1000 if n < 1e12 else n)
    if isinstance(ts, str) and ts.strip():
        s = ts.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.astimezone()
            return int(dt.timestamp() * 1000)
        except Exception:
            pass
    return 0


def _parse_bound_ms(value: Any) -> Optional[int]:
    """接受毫秒 / 秒 / ISO8601 / datetime-local。"""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        n = float(value)
        if n <= 0:
            return None
        return int(n * 1000 if n < 1e12 else n)
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        n = float(s)
        return int(n * 1000 if n < 1e12 else n)
    s = s.replace("Z", "+00:00")
    # datetime-local: 2026-08-17T04:00
    try:
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def _read_file_tail(limit: int | None = None) -> List[Dict[str, Any]]:
    keep = max(int(limit if limit is not None else _FILE_KEEP), 1)
    rows = _load_file_rows()[0]
    return rows[-keep:] if len(rows) > keep else rows


def list_logs(
    *,
    limit: int = 200,
    offset: int = 0,
    channel: Optional[str] = None,
    level: Optional[str] = None,
    q: Optional[str] = None,
    since: Any = None,
    until: Any = None,
) -> Dict[str, Any]:
    lim = max(1, min(int(limit or 200), 500))
    off = max(0, int(offset or 0))
    ch = (channel or "").strip().lower()
    lv = (level or "").strip().lower()
    needle = (q or "").strip().lower()
    since_ms = _parse_bound_ms(since)
    until_ms = _parse_bound_ms(until)

    with _LOCK:
        mem = list(_BUF)
    file_rows, persisted_total = _load_file_rows()

    merged: Dict[str, Dict[str, Any]] = {}
    for e in file_rows + mem:
        ms = _entry_ms(e)
        key = f"{ms}|{e.get('channel')}|{e.get('level')}|{e.get('message')}"
        merged[key] = e
    rows = sorted(merged.values(), key=_entry_ms)

    matched: List[Dict[str, Any]] = []
    for e in reversed(rows):
        ms = _entry_ms(e)
        if since_ms is not None and ms and ms < since_ms:
            continue
        if until_ms is not None and ms and ms > until_ms:
            continue
        if ch and str(e.get("channel") or "").lower() != ch:
            continue
        if lv and str(e.get("level") or "").lower() != lv:
            continue
        if needle:
            blob = f"{e.get('message', '')} {e.get('channel', '')} {e.get('extra', '')}".lower()
            if needle not in blob:
                continue
        matched.append(e)

    total = len(matched)
    items = matched[off : off + lim]
    channels = sorted({str(x.get("channel") or "") for x in rows if x.get("channel")})
    oldest = _entry_ms(rows[0]) if rows else 0
    newest = _entry_ms(rows[-1]) if rows else 0
    return {
        "items": items,
        "total": total,
        "offset": off,
        "limit": lim,
        "buffered": len(mem),
        "persisted": persisted_total,
        "channels": channels,
        "path": str(_log_path()),
        "oldest_ms": oldest or None,
        "newest_ms": newest or None,
        "since": since_ms,
        "until": until_ms,
    }


def clear_logs() -> Dict[str, Any]:
    """清空应用日志：仅截断固定的 reports/applogs.jsonl，不接收外部路径。"""
    path = _validated_log_path()
    with _LOCK:
        mem_n = len(_BUF)
        _BUF.clear()
    file_n = _count_persisted_lines()
    try:
        with _FILE_LOCK:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("")
                fh.flush()
                os.fsync(fh.fileno())
    except Exception as exc:
        raise OSError(f"清除应用日志失败: {exc}") from exc
    tmp = path.with_name(f"{_LOG_BASENAME}.tmp")
    try:
        if tmp.is_file() and tmp.resolve().parent == path.parent:
            tmp.unlink(missing_ok=True)
    except Exception:
        pass
    log("boot", "应用日志已清空（管理员操作）", echo=True)
    return {
        "cleared_memory": mem_n,
        "cleared_file": file_n,
        "cleared_total": mem_n + file_n,
        "path": str(path),
    }


def export_logs_csv(
    *,
    channel: Optional[str] = None,
    level: Optional[str] = None,
    q: Optional[str] = None,
    since: Any = None,
    until: Any = None,
    max_rows: int = 50000,
) -> tuple:
    """导出应用日志 CSV（UTF-8 BOM）。"""
    import csv
    import io

    cap = max(1, min(50000, int(max_rows or 50000)))
    data = list_logs(
        limit=cap,
        offset=0,
        channel=channel,
        level=level,
        q=q,
        since=since,
        until=until,
    )
    items = data.get("items") or []
    total = int(data.get("total") or len(items))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["时间", "级别", "通道", "消息"])
    for it in items:
        writer.writerow([
            it.get("ts") or "",
            it.get("level") or "",
            it.get("channel") or "",
            it.get("message") or "",
        ])
    stamp = time.strftime("%Y%m%d_%H%M%S")
    truncated = total > len(items)
    name = f"applogs_{stamp}.csv" if not truncated else f"applogs_{stamp}_top{len(items)}.csv"
    return buf.getvalue().encode("utf-8-sig"), name, len(items)
