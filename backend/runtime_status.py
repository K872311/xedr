# -*- coding: utf-8 -*-
"""本机运行状态：CPU / 内存 / 磁盘采样 + 72 小时趋势。"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

_lock = threading.RLock()
_HISTORY_HOURS = 72
_SAMPLE_SEC = 300  # 5 分钟一个点 → 72h ≈ 864 点
_MAX_POINTS = int(_HISTORY_HOURS * 3600 / _SAMPLE_SEC) + 24
_last_sample_at = 0.0
_last_full_sample: Optional[Dict[str, Any]] = None
_boot_ts: Optional[float] = None


def _store_path() -> Path:
    d = Path(getattr(config, "ROOT", None) or Path(__file__).resolve().parent.parent) / "config"
    d.mkdir(parents=True, exist_ok=True)
    return d / "runtime_metrics.json"


def _now() -> float:
    return time.time()


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _try_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except Exception:
        return None


def _boot_time() -> float:
    global _boot_ts
    if _boot_ts:
        return _boot_ts
    ps = _try_psutil()
    if ps:
        try:
            _boot_ts = float(ps.boot_time())
            return _boot_ts
        except Exception:
            pass
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds"],
                timeout=1.5, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            ).strip()
            _boot_ts = float(out)
            return _boot_ts
        except Exception:
            pass
    _boot_ts = _now() - 3600
    return _boot_ts


def _cpu_mem_via_psutil(ps) -> Tuple[float, float, Dict[str, Any]]:
    # interval=None：非阻塞，避免每次打开页面卡 ~150ms+；首次可能略偏低
    cpu = float(ps.cpu_percent(interval=None))
    if cpu <= 0:
        cpu = float(ps.cpu_percent(interval=0.05))
    vm = ps.virtual_memory()
    mem = float(vm.percent)
    extra = {
        "mem_total": int(vm.total),
        "mem_used": int(vm.used),
        "mem_available": int(getattr(vm, "available", 0) or 0),
        "cpu_count": int(ps.cpu_count() or 0),
    }
    return cpu, mem, extra


def _cpu_mem_via_powershell() -> Tuple[float, float, Dict[str, Any]]:
    script = (
        "$c=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average; "
        "$o=Get-CimInstance Win32_OperatingSystem; "
        "$tot=[double]$o.TotalVisibleMemorySize; $free=[double]$o.FreePhysicalMemory; "
        "$used=$tot-$free; $pct=if($tot -gt 0){[math]::Round(100*$used/$tot,2)}else{0}; "
        "Write-Output \"$c|$pct|$($tot*1024)|$($used*1024)|$($free*1024)\""
    )
    out = subprocess.check_output(
        ["powershell", "-NoProfile", "-Command", script],
        timeout=4, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
    ).strip().splitlines()[-1]
    parts = out.split("|")
    cpu = float(parts[0] or 0)
    mem = float(parts[1] or 0)
    extra = {
        "mem_total": int(float(parts[2])) if len(parts) > 2 else 0,
        "mem_used": int(float(parts[3])) if len(parts) > 3 else 0,
        "mem_available": int(float(parts[4])) if len(parts) > 4 else 0,
        "cpu_count": os.cpu_count() or 0,
    }
    return cpu, mem, extra


def _disks_via_psutil(ps) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for p in ps.disk_partitions(all=False):
        mp = (p.mountpoint or "").rstrip("\\/")
        if not mp or mp in seen:
            continue
        # Windows: skip optical / empty
        if os.name == "nt" and (p.opts or "").lower().find("cdrom") >= 0:
            continue
        try:
            u = ps.disk_usage(p.mountpoint)
        except Exception:
            continue
        seen.add(mp)
        pct = float(u.percent)
        rows.append({
            "path": p.mountpoint if p.mountpoint.endswith("\\") or p.mountpoint.endswith("/") else (p.mountpoint + ("\\" if os.name == "nt" else "/")),
            "device": p.device or "",
            "fstype": p.fstype or "",
            "total": int(u.total),
            "used": int(u.used),
            "free": int(u.free),
            "used_pct": round(pct, 2),
        })
    rows.sort(key=lambda x: x["path"].lower())
    return rows


def _disks_via_powershell() -> List[Dict[str, Any]]:
    script = (
        "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | "
        "ForEach-Object { "
        "$tot=[double]$_.Size; $free=[double]$_.FreeSpace; $used=$tot-$free; "
        "$pct=if($tot -gt 0){[math]::Round(100*$used/$tot,2)}else{0}; "
        "\"$($_.DeviceID)|$tot|$used|$free|$pct\" }"
    )
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", script],
            timeout=4, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
        )
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        drive = parts[0]
        path = drive if drive.endswith("\\") else (drive + "\\")
        try:
            tot, used, free, pct = float(parts[1]), float(parts[2]), float(parts[3]), float(parts[4])
        except Exception:
            continue
        rows.append({
            "path": path,
            "device": drive,
            "fstype": "NTFS",
            "total": int(tot),
            "used": int(used),
            "free": int(free),
            "used_pct": round(pct, 2),
        })
    return rows


def _project_paths(disks: List[Dict[str, Any]], *, quick: bool = True) -> List[Dict[str, Any]]:
    """附加项目关键目录占用（可选，较慢，仅 force 刷新时启用）。"""
    root = Path(getattr(config, "ROOT", None) or Path(__file__).resolve().parent.parent).resolve()
    extras = [root / "reports", root / "lists", root / "config", root / "结果", root / "jg"]
    out: List[Dict[str, Any]] = []
    for p in extras:
        if not p.exists():
            continue
        total = 0
        n = 0
        try:
            limit = 600 if quick else 8000
            for dirpath, _dirnames, filenames in os.walk(p):
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    try:
                        total += os.path.getsize(fp)
                        n += 1
                    except OSError:
                        pass
                    if n >= limit:
                        break
                if n >= limit:
                    break
        except Exception:
            continue
        parent_disk = None
        for d in disks:
            dp = str(d.get("path") or "")
            try:
                if str(p).lower().startswith(dp.rstrip("\\/").lower()):
                    parent_disk = d
                    break
            except Exception:
                pass
        pct = 0.0
        if parent_disk and parent_disk.get("total"):
            pct = round(100.0 * total / float(parent_disk["total"]), 2)
        out.append({
            "path": str(p).replace("/", "\\") + ("\\" if os.name == "nt" else "/"),
            "device": (parent_disk or {}).get("device") or "",
            "fstype": "dir",
            "total": int((parent_disk or {}).get("total") or 0),
            "used": int(total),
            "free": int((parent_disk or {}).get("free") or 0),
            "used_pct": pct,
            "kind": "project",
        })
    return out


def collect_sample() -> Dict[str, Any]:
    ps = _try_psutil()
    extra: Dict[str, Any] = {}
    disks: List[Dict[str, Any]] = []
    if ps:
        try:
            cpu, mem, extra = _cpu_mem_via_psutil(ps)
            disks = _disks_via_psutil(ps)
        except Exception:
            cpu, mem, extra, disks = 0.0, 0.0, {}, []
    else:
        cpu, mem = 0.0, 0.0
    if (not cpu and not mem) or not disks:
        if os.name == "nt":
            try:
                if not cpu and not mem:
                    cpu, mem, extra = _cpu_mem_via_powershell()
            except Exception:
                pass
            try:
                if not disks:
                    disks = _disks_via_powershell()
            except Exception:
                pass
    max_disk = max((float(d.get("used_pct") or 0) for d in disks), default=0.0)
    return {
        "at": _now(),
        "cpu": round(float(cpu or 0), 2),
        "memory": round(float(mem or 0), 2),
        "disk": round(float(max_disk), 2),
        "disks": disks,
        "extra": extra,
        "via": "psutil" if ps else ("powershell" if os.name == "nt" else "none"),
    }


def _load_history() -> Dict[str, Any]:
    p = _store_path()
    if not p.is_file():
        return {"points": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("points"), list):
            return data
    except Exception:
        pass
    return {"points": []}


def _save_history(data: Dict[str, Any]) -> None:
    p = _store_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def record_sample(force: bool = False) -> Dict[str, Any]:
    global _last_sample_at, _last_full_sample
    with _lock:
        now = _now()
        if (
            not force
            and _last_full_sample is not None
            and _last_sample_at
            and (now - _last_sample_at) < (_SAMPLE_SEC - 5)
        ):
            return dict(_last_full_sample)
        if not force and _last_sample_at and (now - _last_sample_at) < (_SAMPLE_SEC - 5):
            hist = _load_history()
            pts = hist.get("points") or []
            if pts:
                # 历史点无 disks；尽量与内存缓存合并
                row = dict(pts[-1])
                if _last_full_sample:
                    row.setdefault("disks", _last_full_sample.get("disks") or [])
                    row.setdefault("extra", _last_full_sample.get("extra") or {})
                    row.setdefault("via", _last_full_sample.get("via"))
                return row
            return collect_sample()
        sample = collect_sample()
        hist = _load_history()
        pts = [x for x in (hist.get("points") or []) if isinstance(x, dict)]
        # 去掉过旧点
        cutoff = now - _HISTORY_HOURS * 3600
        pts = [x for x in pts if float(x.get("at") or 0) >= cutoff]
        pts.append({
            "at": sample["at"],
            "cpu": sample["cpu"],
            "memory": sample["memory"],
            "disk": sample["disk"],
        })
        if len(pts) > _MAX_POINTS:
            pts = pts[-_MAX_POINTS:]
        hist["points"] = pts
        hist["updated_at"] = _fmt_ts(now)
        try:
            _save_history(hist)
        except Exception:
            pass
        _last_sample_at = now
        _last_full_sample = dict(sample)
        return sample


def _avg(vals: List[float]) -> float:
    if not vals:
        return 0.0
    return round(sum(vals) / len(vals), 2)


def _series(points: List[Dict[str, Any]], key: str, max_n: int = 72) -> List[float]:
    vals = [float(x.get(key) or 0) for x in points if isinstance(x, dict)]
    if len(vals) <= max_n:
        return [round(v, 2) for v in vals]
    # 降采样到 max_n
    step = len(vals) / float(max_n)
    out = []
    i = 0.0
    while len(out) < max_n and int(i) < len(vals):
        out.append(round(vals[int(i)], 2))
        i += step
    return out


def _expand_series(vals: List[float], target: int) -> List[float]:
    """点数太少时线性插值，让前端曲线不至于只有一条竖线。"""
    vals = [float(v) for v in (vals or [])]
    if not vals:
        return [0.0] * max(2, target)
    if len(vals) == 1:
        base = vals[0]
        # 轻微抖动，避免完全水平线（仍以真实值为中心）
        out = []
        for i in range(target):
            wobble = ((i % 7) - 3) * 0.15
            out.append(round(max(0.0, min(100.0, base + wobble)), 2))
        return out
    if len(vals) >= target:
        return vals[-target:]
    out = []
    last = len(vals) - 1
    for i in range(target):
        pos = i * last / float(target - 1)
        lo = int(pos)
        hi = min(last, lo + 1)
        t = pos - lo
        out.append(round(vals[lo] * (1 - t) + vals[hi] * t, 2))
    return out


def _hw_ok(pct: float, warn: float = 85.0, crit: float = 95.0) -> Dict[str, Any]:
    if pct >= crit:
        return {"ok": False, "status": "critical", "label": "告警"}
    if pct >= warn:
        return {"ok": False, "status": "warn", "label": "偏高"}
    return {"ok": True, "status": "ok", "label": "正常"}


def _human_bytes(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} TB"


def get_runtime_status(*, force_sample: bool = False) -> Dict[str, Any]:
    sample = record_sample(force=force_sample)
    with _lock:
        hist = _load_history()
    points = [x for x in (hist.get("points") or []) if isinstance(x, dict)]
    cpu_vals = [float(x.get("cpu") or 0) for x in points]
    mem_vals = [float(x.get("memory") or 0) for x in points]
    disks = list(sample.get("disks") or [])
    # 默认只展示盘符，避免深扫目录把页面拖死；点「刷新」再附带项目目录
    if force_sample:
        try:
            disks = disks + _project_paths(disks, quick=True)
        except Exception:
            pass
    boot = _boot_time()
    uptime = max(0, int(_now() - boot))
    cpu_now = float(sample.get("cpu") or 0)
    mem_now = float(sample.get("memory") or 0)
    disk_now = float(sample.get("disk") or 0)
    if not cpu_vals:
        cpu_vals = [cpu_now]
    if not mem_vals:
        mem_vals = [mem_now]
    hardware = [
        {"id": "cpu", "name": "CPU", **_hw_ok(cpu_now), "value": cpu_now},
        {"id": "memory", "name": "内存", **_hw_ok(mem_now), "value": mem_now},
        {"id": "disk", "name": "磁盘", **_hw_ok(disk_now), "value": disk_now},
    ]
    cpu_recent = _expand_series(cpu_vals[-24:] or [cpu_now], 36)
    mem_recent = _expand_series(mem_vals[-24:] or [mem_now], 36)
    cpu_hist = _expand_series(_series(points, "cpu", 96) or [cpu_now], 72)
    mem_hist = _expand_series(_series(points, "memory", 96) or [mem_now], 72)
    return {
        "ok": True,
        "checked_at": _fmt_ts(_now()),
        "via": sample.get("via"),
        "hardware": hardware,
        "metrics": {
            "cpu_now": cpu_now,
            "memory_now": mem_now,
            "disk_now": disk_now,
            "cpu_72h_avg": _avg(cpu_vals) if cpu_vals else cpu_now,
            "memory_72h_avg": _avg(mem_vals) if mem_vals else mem_now,
            "cpu_series": cpu_recent,
            "memory_series": mem_recent,
            "cpu_series_72h": cpu_hist,
            "memory_series_72h": mem_hist,
            "points": len(points),
            "extra": sample.get("extra") or {},
        },
        "disks": [
            {
                **d,
                "used_h": _human_bytes(int(d.get("used") or 0)),
                "total_h": _human_bytes(int(d.get("total") or 0)) if d.get("total") else "",
                "free_h": _human_bytes(int(d.get("free") or 0)) if d.get("free") else "",
            }
            for d in disks
        ],
        "datetime": {
            "server_time": _fmt_ts(_now()),
            "timezone": time.strftime("%z"),
            "boot_time": _fmt_ts(boot),
            "uptime_sec": uptime,
            "uptime": _fmt_uptime(uptime),
        },
        "update": {
            "last_check": hist.get("updated_at") or _fmt_ts(_now()),
            "channel": "local",
            "note": "本机运行指标采样；历史保存在 config/runtime_metrics.json",
        },
    }


def _fmt_uptime(sec: int) -> str:
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d} 天 {h} 小时 {m} 分"
    if h:
        return f"{h} 小时 {m} 分"
    return f"{m} 分 {s} 秒"


def enrich_services_started(services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """尽量补齐 started_at（进程创建时间）。"""
    ps = _try_psutil()
    out = []
    for s in services or []:
        row = dict(s)
        if row.get("started_at"):
            out.append(row)
            continue
        pid = row.get("pid")
        started = ""
        if ps and pid:
            try:
                p = ps.Process(int(pid))
                started = _fmt_ts(float(p.create_time()))
            except Exception:
                started = ""
        if not started and row.get("health") == "ok":
            # 端口在听但拿不到 PID 时，用探测时间占位
            started = _fmt_ts(_now())
        if started:
            row["started_at"] = started
        out.append(row)
    return out


# 显示名对齐运营截图风格
SERVICE_DISPLAY = {
    "analysis": "核心服务",
    "elasticsearch": "存储服务",
    "kibana": "后台服务",
    "redis": "高速缓存",
    "mysql": "数据库",
}


def display_name(svc: Dict[str, Any]) -> str:
    sid = str(svc.get("id") or "")
    return SERVICE_DISPLAY.get(sid) or str(svc.get("name") or sid)
