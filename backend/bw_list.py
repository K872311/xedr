"""全局名单（黑 / 手动白 / 各 OS 基线规则）。

- whitelist.json（white）：运营后续手动加白；匹配时丢弃。
- win11_rules.json：Win11 干净系统基线误报；匹配时等同白名单丢弃。
- windows_server_rules.json：Windows Server 干净系统基线误报；匹配时等同白名单丢弃。
- blacklist.json（black）：确认恶意；命中抬高严重级别并打标。
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config
from .models import Finding

# 丢弃类名单（优先于黑名单）
SUPPRESS_LISTS = ("win11_rules", "windows_server_rules", "white")
LISTS = ("white", "black", "win11_rules", "windows_server_rules")
KINDS = ("evidence", "path", "rule_id", "title", "hash", "ip", "domain", "process", "custom")
MATCHES = ("contains", "exact", "prefix")
FILE_BY_LIST = {
    "black": "blacklist.json",
    "white": "whitelist.json",
    "win11_rules": "win11_rules.json",
    "windows_server_rules": "windows_server_rules.json",
}
LIST_BY_FILE = {v: k for k, v in FILE_BY_LIST.items()}
LIST_LABEL = {
    "black": "黑名单",
    "white": "白名单（手动）",
    "win11_rules": "Win11 基线规则",
    "windows_server_rules": "Windows Server 基线规则",
}
LIST_DESC = {
    "black": "确认恶意 / 抬高等级",
    "white": "后续手动加白（运营）",
    "win11_rules": "Win11 干净系统基线误报（正式默认）",
    "windows_server_rules": "Windows Server 干净系统基线误报（正式默认）",
}
# 管理台 / 发布展示顺序
LIST_ORDER = (
    ("black", "blacklist.json"),
    ("win11_rules", "win11_rules.json"),
    ("windows_server_rules", "windows_server_rules.json"),
    ("white", "whitelist.json"),
)
SUPPORTED_FILES_MSG = "仅支持 blacklist.json / whitelist.json / win11_rules.json / windows_server_rules.json"
SUPPORTED_LISTS_MSG = "list 须为 white / black / win11_rules / windows_server_rules"

_lock = threading.RLock()
_cache: Optional[Dict[str, Any]] = None
_cache_mtime: float = -1.0

_PATH_RE = re.compile(r"[a-zA-Z]:\\[^\s\"'<>|]{3,}")
_WIN_EXE_PATH_RE = re.compile(
    r"[a-zA-Z]:\\(?:[^\"'\r\n<>|]+\\)*[^\"'\r\n<>|\r\n]+\.(?:exe|dll|bat|cmd|vbs|ps1|sys)\b",
    re.I,
)
_TASK_EXE_AFTER_ARROW_RE = re.compile(
    r'=>\s*([a-zA-Z]:\\(?:[^\"\'\r\n<>|]+\\)*[^\"\'\r\n<>|\r\n]+\.(?:exe|dll|bat|cmd|vbs|ps1|sys))\b',
    re.I,
)
_GENERIC_RULE_IDS = frozenset({"task-fallback", "task-unsigned-fallback", ""})
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_DOM_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b")

# contains 匹配禁止使用的过泛关键字（易误伤整类告警）
_RISKY_CONTAINS = frozenset({
    "by", "task", "multiple", "the", "and", "exe", "dll", "cmd", "run", "user", "data",
})


def _validate_needle(kind: str, match: str, value: str) -> None:
    """写入前校验，避免过宽白名单误伤后续分析。"""
    kd = (kind or "evidence").strip().lower()
    mt = (match or "contains").strip().lower()
    val = (value or "").strip()
    if not val:
        raise ValueError("缺少名单值")
    if mt != "contains":
        return
    low = val.lower()
    if low in _RISKY_CONTAINS:
        raise ValueError(f"匹配值「{value}」过泛，请用完整路径/evidence 或 exact 匹配")
    if kd == "path":
        if len(val) < 20:
            raise ValueError("path 的 contains 匹配至少 20 字符，建议使用 exact 完整路径")
        if "\\windows\\start" in low.replace("/", "\\") and "startup" not in low:
            raise ValueError("启动目录白名单请用完整文件路径 exact 匹配，勿用 Start 前缀")
    elif kd in ("evidence", "custom", "process"):
        if len(val) < 12:
            raise ValueError("contains 匹配至少 12 字符")
    elif kd == "title" and len(val) < 4:
        raise ValueError("title 匹配过短")


def lists_dir() -> Path:
    d = config.ROOT / "lists"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_path(list_type: str = "") -> Path:
    """兼容旧调用：无参时返回目录说明用的主路径（黑名单文件）。"""
    lt = (list_type or "black").strip().lower()
    if lt not in LISTS:
        lt = "black"
    return lists_dir() / FILE_BY_LIST[lt]


def file_path(fname: str) -> Path:
    name = Path(fname).name
    if name not in LIST_BY_FILE:
        raise ValueError(SUPPORTED_FILES_MSG)
    return lists_dir() / name


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _empty(list_type: str = "") -> Dict[str, Any]:
    lt = (list_type or "").strip().lower()
    out: Dict[str, Any] = {"updated_at": "", "items": []}
    if lt in LISTS:
        out["list"] = lt
    return out


def _read_one_file(path: Path, list_type: str) -> Dict[str, Any]:
    if not path.is_file():
        return _empty(list_type)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _empty(list_type)
        items = data.get("items")
        if not isinstance(items, list):
            data["items"] = []
        data["list"] = list_type
        # 规范化每条 list 字段
        norm = []
        for x in data["items"]:
            if not isinstance(x, dict):
                continue
            row = dict(x)
            row["list"] = list_type
            norm.append(row)
        data["items"] = norm
        return data
    except Exception:
        return _empty(list_type)


def _write_one_file(path: Path, list_type: str, items: List[Dict[str, Any]], updated_at: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "list": list_type,
        "updated_at": updated_at or _now(),
        "items": [
            {**dict(x), "list": list_type}
            for x in (items or [])
            if isinstance(x, dict)
        ],
    }
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def _migrate_legacy() -> None:
    """旧版 lists/bw_list.json → blacklist.json + whitelist.json。"""
    legacy = lists_dir() / "bw_list.json"
    black_p = lists_dir() / "blacklist.json"
    white_p = lists_dir() / "whitelist.json"
    if not legacy.is_file():
        return
    if black_p.is_file() or white_p.is_file():
        return
    try:
        with open(legacy, encoding="utf-8") as f:
            data = json.load(f)
        items = (data or {}).get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            items = []
        black = [x for x in items if isinstance(x, dict) and str(x.get("list") or "") == "black"]
        white = [x for x in items if isinstance(x, dict) and str(x.get("list") or "") == "white"]
        ts = str((data or {}).get("updated_at") or _now()) if isinstance(data, dict) else _now()
        _write_one_file(black_p, "black", black, ts)
        _write_one_file(white_p, "white", white, ts)
        try:
            legacy.rename(lists_dir() / "bw_list.json.bak")
        except Exception:
            pass
        print("[bw_list] migrated bw_list.json → blacklist.json + whitelist.json")
    except Exception as e:
        print(f"[bw_list] migrate legacy failed: {e}")


def _ensure_files() -> None:
    _migrate_legacy()
    for lt, name in FILE_BY_LIST.items():
        p = lists_dir() / name
        if not p.is_file():
            _write_one_file(p, lt, [], _now())


def _combined_mtime() -> float:
    m = 0.0
    for name in FILE_BY_LIST.values():
        p = lists_dir() / name
        if p.is_file():
            m = max(m, p.stat().st_mtime)
    return m


def _read_raw() -> Dict[str, Any]:
    _ensure_files()
    files: Dict[str, Any] = {}
    items: List[Dict[str, Any]] = []
    updated = ""
    for lt, name in FILE_BY_LIST.items():
        block = _read_one_file(lists_dir() / name, lt)
        files[name] = block
        items.extend([x for x in (block.get("items") or []) if isinstance(x, dict)])
        updated = max(updated, str(block.get("updated_at") or ""))
    return {"updated_at": updated, "items": items, "files": files}


def _write_list_items(list_type: str, items: List[Dict[str, Any]]) -> None:
    lt = (list_type or "").strip().lower()
    if lt not in LISTS:
        raise ValueError(SUPPORTED_LISTS_MSG)
    _write_one_file(lists_dir() / FILE_BY_LIST[lt], lt, items, _now())


def _write_raw(data: Dict[str, Any]) -> None:
    """按 list 字段拆开写回各名单文件。"""
    items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
    ts = _now()
    buckets = {lt: [] for lt in LISTS}
    for x in items:
        lt = str(x.get("list") or "").strip().lower()
        if lt not in buckets:
            # 兼容未知 list：默认进手动白名单
            lt = "white"
        buckets[lt].append(x)
    for lt, rows in buckets.items():
        _write_one_file(lists_dir() / FILE_BY_LIST[lt], lt, rows, ts)


def load(force: bool = False) -> Dict[str, Any]:
    global _cache, _cache_mtime
    _ensure_files()
    mtime = _combined_mtime()
    with _lock:
        if force or _cache is None or mtime != _cache_mtime:
            _cache = _read_raw()
            _cache_mtime = mtime
        return dict(_cache)


def reload() -> Dict[str, Any]:
    return load(force=True)


def published_dir() -> Path:
    d = lists_dir() / "published"
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_publish_manifest() -> Dict[str, Any]:
    p = published_dir() / "manifest.json"
    if not p.is_file():
        return {"version": 0, "history": [], "is_release_default": False}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"version": 0, "history": [], "is_release_default": False}
        return data
    except Exception:
        return {"version": 0, "history": [], "is_release_default": False}


def publish_release(
    *,
    by: str = "admin",
    note: str = "",
    include_baseline: bool = True,
) -> Dict[str, Any]:
    """把当前名单固化为正式发布默认版（带版本号快照）。

    - 写入 lists/published/{blacklist,whitelist,win11_rules,windows_server_rules}.json
    - 可选同步 baselines/win11_baseline.json
    - 更新 lists/published/manifest.json
    - 给线上 JSON 打 release_version 标记
    """
    _ensure_files()
    load(force=True)
    ts = _now()
    pub = published_dir()
    copied: List[str] = []
    counts: Dict[str, int] = {}

    for lt, name in LIST_ORDER:
        src = lists_dir() / name
        data = _read_one_file(src, lt)
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        counts[lt] = len(items)
        payload = {
            "list": lt,
            "updated_at": ts,
            "release": True,
            "release_note": (note or "正式发布默认版")[:300],
            "release_by": (by or "")[:64],
            "items": items,
        }
        if lt in LIST_LABEL and lt not in ("black", "white"):
            payload["name"] = LIST_LABEL[lt]
            payload["desc"] = LIST_DESC.get(lt, "")
        # 线上文件也打标，标明即为正式版
        live = {
            "list": lt,
            "updated_at": data.get("updated_at") or ts,
            "release": True,
            "release_published_at": ts,
            "release_note": payload["release_note"],
            "release_by": payload["release_by"],
            "items": items,
        }
        if "name" in payload:
            live["name"] = payload["name"]
            live["desc"] = payload.get("desc", "")
        _write_one_file(src, lt, items, str(live.get("updated_at") or ts))
        # 上面 _write_one_file 不带 release 字段，补写完整 payload
        src.write_text(json.dumps(live, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        dst = pub / name
        dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        copied.append(name)

    baseline_info: Dict[str, Any] = {}
    if include_baseline:
        try:
            from . import baseline as baseline_mod

            bp = baseline_mod.baseline_path()
            if bp.is_file():
                raw = json.loads(bp.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw["release"] = True
                    raw["release_published_at"] = ts
                    raw["release_note"] = (note or "正式发布默认版")[:300]
                    bp.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    bdst = pub / "win11_baseline.json"
                    bdst.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                    copied.append("win11_baseline.json")
                    baseline_info = {
                        "services": len(raw.get("services") or []),
                        "tasks": len(raw.get("tasks") or []),
                        "startup": len(raw.get("startup") or []),
                    }
                    try:
                        baseline_mod.reload()
                    except Exception:
                        pass
        except Exception as e:
            baseline_info = {"error": str(e)}

    man = read_publish_manifest()
    ver = int(man.get("version") or 0) + 1
    entry = {
        "version": ver,
        "at": ts,
        "by": (by or "")[:64],
        "note": (note or "正式发布默认版 · OS 基线规则 + 手动白名单 + 黑名单")[:300],
        "files": copied,
        "counts": {lt: counts.get(lt, 0) for lt, _ in LIST_ORDER},
        "baseline": baseline_info,
        "is_release_default": True,
    }
    hist = list(man.get("history") or [])
    hist.insert(0, entry)
    man_out = {
        "version": ver,
        "updated_at": ts,
        "is_release_default": True,
        "release_label": "正式发布默认版",
        "current": entry,
        "history": hist[:50],
    }
    (pub / "manifest.json").write_text(
        json.dumps(man_out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # 打上版本号到 live（再读改写 release_version）
    for lt, name in LIST_ORDER:
        src = lists_dir() / name
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["release_version"] = ver
                data["release"] = True
                src.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass

    load(force=True)
    publish_notify(by=by, action="publish_release", list_type="")
    return {
        "ok": True,
        "version": ver,
        "published_dir": str(pub),
        "files": copied,
        "counts": counts,
        "baseline": baseline_info,
        "manifest": man_out,
        "stats": stats(),
    }


def list_files() -> Dict[str, Any]:
    """管理台：黑白名单文件清单。"""
    _ensure_files()
    data = load(force=True)
    files_blob = (data.get("files") or {}) if isinstance(data, dict) else {}
    man = read_publish_manifest()
    out = []
    for lt, name in LIST_ORDER:
        p = lists_dir() / name
        block = files_blob.get(name) if isinstance(files_blob, dict) else None
        items = (block or {}).get("items") if isinstance(block, dict) else []
        if not isinstance(items, list):
            # 直接读文件，兼容 release 字段
            try:
                raw = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
                items = raw.get("items") or []
                block = raw
            except Exception:
                items = []
        if not isinstance(items, list):
            items = []
        en = sum(1 for x in items if isinstance(x, dict) and x.get("enabled", True))
        out.append({
            "file": name,
            "list": lt,
            "label": LIST_LABEL.get(lt, lt),
            "desc": LIST_DESC.get(lt, ""),
            "path": str(p),
            "exists": p.is_file(),
            "size": p.stat().st_size if p.is_file() else 0,
            "mtime": datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds") if p.is_file() else "",
            "updated_at": str((block or {}).get("updated_at") or "") if isinstance(block, dict) else "",
            "count": len(items),
            "enabled_count": en,
            "release": bool((block or {}).get("release")) if isinstance(block, dict) else False,
            "release_version": (block or {}).get("release_version") if isinstance(block, dict) else None,
        })
    return {
        "dir": str(lists_dir()),
        "files": out,
        "stats": stats(),
        "publish": {
            "version": man.get("version") or 0,
            "updated_at": man.get("updated_at"),
            "is_release_default": bool(man.get("is_release_default")),
            "release_label": man.get("release_label") or "",
            "current": man.get("current") or {},
        },
    }


def read_file(fname: str) -> Dict[str, Any]:
    name = Path(fname).name
    lt = LIST_BY_FILE.get(name)
    if not lt:
        raise ValueError(SUPPORTED_FILES_MSG)
    _ensure_files()
    p = lists_dir() / name
    data = _read_one_file(p, lt)
    # 保留文件级元数据（release / name / desc）供编辑
    try:
        raw = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
        if isinstance(raw, dict):
            for k in ("release", "release_version", "release_note", "release_by", "name", "desc", "sources", "hosts"):
                if k in raw:
                    data[k] = raw[k]
    except Exception:
        pass
    return {
        "file": name,
        "list": lt,
        "label": LIST_LABEL.get(lt, lt),
        "path": str(p),
        "updated_at": data.get("updated_at") or "",
        "items": data.get("items") or [],
        "content": json.dumps(data, ensure_ascii=False, indent=2),
        "count": len(data.get("items") or []),
    }


def clear_file(fname: str, *, by: str = "") -> Dict[str, Any]:
    """清空名单文件条目（保留文件本身），写入即发布。"""
    return save_file(fname, {"items": []}, by=by)


def set_file_items_enabled(fname: str, enabled: bool, *, by: str = "") -> Dict[str, Any]:
    """将该名单文件内全部条目设为启用/停用，文件本身保留。"""
    name = Path(fname).name
    lt = LIST_BY_FILE.get(name)
    if not lt:
        raise ValueError(SUPPORTED_FILES_MSG)
    _ensure_files()
    p = lists_dir() / name
    with _lock:
        data = _read_one_file(p, lt)
        items = [dict(x) for x in (data.get("items") or []) if isinstance(x, dict)]
        ts = _now()
        for row in items:
            row["enabled"] = bool(enabled)
            row["at"] = ts
            row["list"] = lt
        _write_one_file(p, lt, items, ts)
        global _cache, _cache_mtime
        _cache = None
        _cache_mtime = -1.0
    publish_notify(by=by, action="enable_file" if enabled else "disable_file", item_id=name, list_type=lt)
    return read_file(name)


def batch_files(action: str, files: List[str], *, by: str = "") -> Dict[str, Any]:
    """管理台：对勾选的名单文件批量启用 / 停用 / 清空 / 发布。"""
    act = str(action or "").strip().lower()
    names: List[str] = []
    seen = set()
    for f in files or []:
        name = Path(str(f or "")).name
        if not name or name in seen:
            continue
        if name not in LIST_BY_FILE:
            raise ValueError(SUPPORTED_FILES_MSG + f"（收到 {name}）")
        seen.add(name)
        names.append(name)
    if not names:
        raise ValueError("未选择文件")
    if act == "unlock":
        return {
            "ok": True,
            "action": act,
            "done": 0,
            "skipped": len(names),
            "files": names,
            "note": "名单文件没有编辑锁，无需解锁",
        }
    if act == "publish":
        out = publish_release(by=by, note="批量发布正式版")
        return {"ok": True, "action": act, "done": len(names), "files": names, **out}
    if act not in ("enable", "disable", "delete"):
        raise ValueError("未知操作，仅支持 enable / disable / unlock / delete / publish")
    results: List[Dict[str, Any]] = []
    done = 0
    for name in names:
        try:
            if act == "enable":
                set_file_items_enabled(name, True, by=by)
            elif act == "disable":
                set_file_items_enabled(name, False, by=by)
            else:
                clear_file(name, by=by)
            results.append({"file": name, "ok": True})
            done += 1
        except Exception as e:
            results.append({"file": name, "ok": False, "error": str(e)})
    return {"ok": True, "action": act, "done": done, "results": results, "files": names}


def batch_items(action: str, ids: List[str], *, by: str = "") -> Dict[str, Any]:
    """管理台：对勾选的名单条目批量启用 / 停用 / 删除。"""
    act = str(action or "").strip().lower()
    id_list = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not id_list:
        raise ValueError("未选择条目")
    if act not in ("enable", "disable", "delete"):
        raise ValueError("未知操作，仅支持 enable / disable / delete")
    want = set(id_list)
    done = 0
    with _lock:
        data = _read_raw()
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        ts = _now()
        new_items: List[Dict[str, Any]] = []
        for old in items:
            iid = str(old.get("id") or "")
            if iid not in want:
                new_items.append(old)
                continue
            if act == "delete":
                done += 1
                continue
            row = dict(old)
            row["enabled"] = act == "enable"
            row["at"] = ts
            new_items.append(row)
            done += 1
        data["items"] = new_items
        _write_raw(data)
        global _cache, _cache_mtime
        _cache = None
        _cache_mtime = -1.0
    publish_notify(by=by, action=f"batch_{act}", item_id=",".join(id_list[:8]), list_type="")
    return {"ok": True, "action": act, "done": done}


def save_file(fname: str, content: Any, *, by: str = "") -> Dict[str, Any]:
    """保存整文件（JSON 对象或字符串），写入即发布。"""
    name = Path(fname).name
    lt = LIST_BY_FILE.get(name)
    if not lt:
        raise ValueError(SUPPORTED_FILES_MSG)
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON 解析失败: {e}") from e
    elif isinstance(content, dict):
        data = content
    else:
        raise ValueError("content 须为 JSON 对象或字符串")
    items_raw = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items_raw, list):
        raise ValueError("文件须包含 items 数组")
    items: List[Dict[str, Any]] = []
    for x in items_raw:
        if not isinstance(x, dict):
            continue
        row = dict(x)
        row["list"] = lt
        val = str(row.get("value") or "").strip()
        if not val:
            continue
        kd = str(row.get("kind") or "evidence").strip().lower()
        if kd not in KINDS:
            kd = "custom"
        mt = str(row.get("match") or "contains").strip().lower()
        if mt not in MATCHES:
            mt = "contains"
        row["kind"] = kd
        row["match"] = mt
        row["value"] = _norm_value(kd, val)[:800]
        if not row.get("id"):
            row["id"] = _make_id(lt, kd, row["value"], mt)
        items.append(row)
    with _lock:
        _write_one_file(lists_dir() / name, lt, items, _now())
        global _cache, _cache_mtime
        _cache = None
        _cache_mtime = -1.0
    publish_notify(by=by, action="save_file", item_id=name, list_type=lt)
    return read_file(name)


def stats(_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = _data if _data is not None else load()
    items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
    by_list = {lt: [x for x in items if x.get("list") == lt] for lt, _ in LIST_ORDER}
    man = read_publish_manifest()
    out: Dict[str, Any] = {
        "path": str(lists_dir()),
        "files": {lt: str(lists_dir() / name) for lt, name in LIST_ORDER},
        "updated_at": data.get("updated_at") or "",
        "total": len(items),
        "publish": {
            "version": man.get("version") or 0,
            "updated_at": man.get("updated_at"),
            "is_release_default": bool(man.get("is_release_default")),
            "release_label": man.get("release_label") or "",
        },
    }
    for lt, rows in by_list.items():
        out[lt] = len(rows)
        out[f"{lt}_enabled"] = sum(1 for x in rows if x.get("enabled", True))
    return out


def _make_id(list_type: str, kind: str, value: str, match: str) -> str:
    raw = f"{list_type}|{kind}|{match}|{(value or '').strip().lower()}"
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _norm_value(kind: str, value: str) -> str:
    v = (value or "").strip()
    if kind == "path":
        return v.replace("/", "\\")
    if kind in ("hash", "ip"):
        return v.lower()
    if kind == "domain":
        return v.lower().rstrip(".")
    return v


def enabled_items(list_type: Optional[str] = None) -> List[Dict[str, Any]]:
    data = load()
    out: List[Dict[str, Any]] = []
    for x in data.get("items") or []:
        if not isinstance(x, dict):
            continue
        if not x.get("enabled", True):
            continue
        lt = str(x.get("list") or "")
        if list_type and lt != list_type:
            continue
        if lt not in LISTS:
            continue
        out.append(x)
    return out


def list_items(
    list_type: str = "",
    q: str = "",
    enabled: Optional[bool] = None,
    limit: int = 500,
    offset: int = 0,
) -> Dict[str, Any]:
    data = load()
    items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
    lt = (list_type or "").strip().lower()
    if lt in LISTS:
        items = [x for x in items if x.get("list") == lt]
    qq = (q or "").strip().lower()
    if qq:
        items = [
            x
            for x in items
            if qq in str(x.get("value") or "").lower()
            or qq in str(x.get("note") or "").lower()
            or qq in str(x.get("rule_id") or "").lower()
            or qq in str(x.get("kind") or "").lower()
        ]
    if enabled is not None:
        items = [x for x in items if bool(x.get("enabled", True)) is bool(enabled)]
    items.sort(key=lambda x: str(x.get("at") or ""), reverse=True)
    total = len(items)
    slice_ = items[max(0, offset) : max(0, offset) + max(1, min(limit, 2000))]
    return {"items": slice_, "total": total, "stats": stats()}


def upsert_item(
    list_type: str,
    value: str,
    *,
    kind: str = "evidence",
    match: str = "contains",
    note: str = "",
    enabled: bool = True,
    by: str = "",
    source: str = "manual",
    rule_id: str = "",
    category: str = "",
    matcher: str = "",
    report_file: str = "",
    finding_id: str = "",
    title: str = "",
) -> Dict[str, Any]:
    lt = (list_type or "").strip().lower()
    if lt not in LISTS:
        raise ValueError(SUPPORTED_LISTS_MSG)
    kd = (kind or "evidence").strip().lower()
    if kd not in KINDS:
        kd = "custom"
    mt = (match or "contains").strip().lower()
    if mt not in MATCHES:
        mt = "contains"
    val = _norm_value(kd, value)
    if not val:
        raise ValueError("缺少名单值")
    _validate_needle(kd, mt, val)
    if len(val) > 800:
        val = val[:800]
    iid = _make_id(lt, kd, val, mt)
    with _lock:
        data = _read_raw()
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        row = {
            "id": iid,
            "list": lt,
            "kind": kd,
            "match": mt,
            "value": val,
            "enabled": bool(enabled),
            "note": (note or "")[:300],
            "by": (by or "")[:64],
            "source": (source or "manual")[:32],
            "rule_id": (rule_id or "")[:120],
            "category": (category or "")[:64],
            "matcher": (matcher or "")[:64],
            "report_file": (report_file or "")[:200],
            "finding_id": (finding_id or "")[:200],
            "title": (title or "")[:200],
            "at": _now(),
        }
        replaced = False
        for i, old in enumerate(items):
            if str(old.get("id") or "") == iid:
                # 保留首次创建时间感：更新字段但 id 不变
                row["at"] = _now()
                items[i] = row
                replaced = True
                break
        if not replaced:
            items.insert(0, row)
        data["items"] = items
        _write_raw(data)
        global _cache, _cache_mtime
        _cache = data
        _cache_mtime = _combined_mtime()
    publish_notify(by=by, action="upsert", item_id=iid, list_type=lt)
    return row


def update_item(item_id: str, **fields: Any) -> Dict[str, Any]:
    iid = str(item_id or "").strip()
    if not iid:
        raise ValueError("缺少 id")
    row_out: Optional[Dict[str, Any]] = None
    with _lock:
        data = _read_raw()
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        for i, old in enumerate(items):
            if str(old.get("id") or "") != iid:
                continue
            row = dict(old)
            if "enabled" in fields and fields["enabled"] is not None:
                row["enabled"] = bool(fields["enabled"])
            if "note" in fields and fields["note"] is not None:
                row["note"] = str(fields["note"] or "")[:300]
            if "match" in fields and fields["match"]:
                mt = str(fields["match"]).strip().lower()
                if mt in MATCHES:
                    row["match"] = mt
            if "value" in fields and fields["value"] is not None:
                kd = str(row.get("kind") or "evidence")
                val = _norm_value(kd, str(fields["value"]))
                if not val:
                    raise ValueError("名单值不能为空")
                row["value"] = val[:800]
            row["at"] = _now()
            items[i] = row
            data["items"] = items
            _write_raw(data)
            global _cache, _cache_mtime
            _cache = data
            _cache_mtime = _combined_mtime()
            row_out = row
            break
    if not row_out:
        raise ValueError("未找到该名单项")
    publish_notify(by=str(fields.get("by") or row_out.get("by") or ""), action="update", item_id=iid)
    return row_out


def delete_item(item_id: str) -> bool:
    iid = str(item_id or "").strip()
    if not iid:
        raise ValueError("缺少 id")
    with _lock:
        data = _read_raw()
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        new_items = [x for x in items if str(x.get("id") or "") != iid]
        if len(new_items) == len(items):
            return False
        data["items"] = new_items
        _write_raw(data)
        global _cache, _cache_mtime
        _cache = data
        _cache_mtime = _combined_mtime()
    publish_notify(action="delete", item_id=iid)
    return True


def _evidence_blobs(item: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    ev = item.get("evidence")
    if isinstance(ev, list):
        for x in ev:
            if x is not None:
                out.append(str(x))
    elif ev is not None:
        out.append(str(ev))
    for k in ("reason", "title", "name", "path", "ImagePath", "image_path", "command", "cmd"):
        v = item.get(k)
        if v is not None and str(v).strip():
            out.append(str(v))
    srcs = item.get("sources")
    if isinstance(srcs, list):
        out.extend(str(x) for x in srcs if x is not None)
    return out


def _text_match(hay: str, needle: str, match: str) -> bool:
    h = (hay or "").lower()
    n = (needle or "").lower()
    if not n:
        return False
    if match == "exact":
        return h == n
    if match == "prefix":
        return h.startswith(n)
    return n in h


    return n in h


def _first_evidence_line(finding: Dict[str, Any]) -> str:
    ev = (finding or {}).get("evidence")
    if isinstance(ev, list):
        for x in ev:
            s = str(x or "").strip()
            if s:
                return s
        return ""
    return str(ev or "").strip()


def _extract_persist_exe_paths(blob: str) -> List[str]:
    if not blob:
        return []
    out: List[str] = []
    seen = set()
    for m in _TASK_EXE_AFTER_ARROW_RE.finditer(blob):
        p = m.group(1).strip()
        key = p.lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    for m in _WIN_EXE_PATH_RE.finditer(blob):
        p = m.group(0).strip()
        key = p.lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    out.sort(key=len, reverse=True)
    return out


def _aggregate_finding_id(finding: Dict[str, Any]) -> str:
    """与 aggregate._asset_key 一致，供扫描管线匹配 UI 加白时的聚合 id。"""
    try:
        from .aggregate import _asset_key
        from .models import Finding

        extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
        ev = finding.get("evidence")
        if isinstance(ev, list):
            ev_str = "\n".join(str(x) for x in ev if x is not None)
        else:
            ev_str = str(ev or finding.get("reason") or "")
        src = str(finding.get("source") or "")
        if not src and isinstance(finding.get("sources"), list):
            src = str(finding.get("sources")[0] or "")
        f = Finding(
            category=str(finding.get("category") or finding.get("type") or ""),
            severity=str(finding.get("severity") or "medium"),
            title=str(finding.get("title") or finding.get("name") or ""),
            evidence=ev_str,
            source=src,
            rule_id=str(finding.get("rule_id") or ""),
            matcher=str(finding.get("matcher") or ""),
            extra=extra,
        )
        return _asset_key(f)
    except Exception:
        return ""


def _finding_id_candidates(finding: Dict[str, Any]) -> set:
    ids = set()
    raw_id = str(finding.get("id") or "").strip()
    if raw_id:
        ids.add(raw_id)
    try:
        from .finding_review import finding_id as _fid

        fid = str(_fid(finding) or "").strip()
        if fid:
            ids.add(fid)
    except Exception:
        pass
    agg = _aggregate_finding_id(finding)
    if agg:
        ids.add(agg)
    return ids


# 白名单 path/evidence 等按 matcher 族隔离，避免跨模块互相吞告警
_MATCHER_FAMILIES = {
    "eventlog": frozenset({"eventlog", "event_logs"}),
    "event_logs": frozenset({"eventlog", "event_logs"}),
    "files": frozenset({"files"}),
    "windows_process": frozenset({"windows_process"}),
    "persistence": frozenset({"persistence", "windows"}),
    "windows": frozenset({"persistence", "windows"}),
    "applogs": frozenset({"applogs", "app_logs"}),
    "app_logs": frozenset({"applogs", "app_logs"}),
    "browser": frozenset({"browser"}),
    "network": frozenset({"network"}),
}
_LOG_MATCHERS = frozenset({"eventlog", "event_logs", "applogs", "app_logs"})
_LOG_CATEGORIES = frozenset({"系统日志", "应用日志"})
_PATH_DEFAULT_MATCHERS = frozenset({
    "windows_process", "persistence", "windows", "files",
})
_PATH_DEFAULT_CATEGORIES = frozenset({
    "可疑进程", "持久化", "可疑文件", "可疑目录", "启动项", "计划任务", "服务",
})


def _matcher_family(name: str) -> frozenset:
    n = (name or "").strip().lower()
    if not n:
        return frozenset()
    return _MATCHER_FAMILIES.get(n, frozenset({n}))


def _whitelist_matcher_affinity_ok(
    ematcher: str, ecat: str, fmatcher: str, fcat: str, kind: str
) -> bool:
    """path/evidence 等白名单不得跨模块生效；rule_id/title/finding_id 仍可全局。"""
    em = (ematcher or "").strip().lower()
    fm = (fmatcher or "").strip().lower()
    ec = (ecat or "").strip()
    fc = (fcat or "").strip()

    if em:
        fam_e = _matcher_family(em)
        fam_f = _matcher_family(fm) if fm else frozenset()
        if fam_f and fam_e & fam_f:
            return True
        if ec and fc and ec == fc:
            return True
        # 条目标明了模块，但告警模块对不上 → 不匹配
        return False

    # 未标明 matcher 的路径/证据加白：默认只打进程/文件/持久化，绝不打日志类
    if fm in _LOG_MATCHERS or fc in _LOG_CATEGORIES:
        return False
    if kind == "path":
        if fm and fm not in _PATH_DEFAULT_MATCHERS:
            return False
        if not fm and fc and fc not in _PATH_DEFAULT_CATEGORIES:
            return False
    return True


def entry_matches_finding(entry: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    if not entry or not finding:
        return False
    if not entry.get("enabled", True):
        return False

    # 分析页加白时会记下 finding_id / rule_id / title：优先用这些做稳定匹配
    # （证据原文易因聚合/编码变化对不上，导致仍显示）
    efid = str(entry.get("finding_id") or "").strip()
    if efid and efid in _finding_id_candidates(finding):
        return True

    kind = str(entry.get("kind") or "evidence").lower()
    match = str(entry.get("match") or "contains").lower()
    value = str(entry.get("value") or "").strip()

    fmatcher = str(finding.get("matcher") or "").lower()
    fcat = str(finding.get("category") or finding.get("type") or "")
    ematcher = str(entry.get("matcher") or "").lower()
    ecat = str(entry.get("category") or "")

    # path/evidence/process/hash：按模块隔离，禁止跨 matcher 误伤
    # （如进程路径加白不得吞掉系统日志；文件告警加白不得影响进程告警）
    if kind in ("path", "evidence", "process", "hash", "ip", "domain", "custom"):
        if not _whitelist_matcher_affinity_ok(ematcher, ecat, fmatcher, fcat, kind):
            return False

    # rule_id 精确命中：仅 kind=rule_id 的条目按 rule_id 全局匹配
    erid = str(entry.get("rule_id") or "").strip()
    frid = str(finding.get("rule_id") or "").strip()
    if kind == "rule_id" and erid and frid and erid == frid:
        return True
    if kind == "rule_id" and value and frid and value == frid:
        return True

    # 标题精确/包含：仅 kind=title 的条目按标题匹配（path/evidence 的 title 仅为备注，不参与匹配）
    ft = str(finding.get("title") or finding.get("name") or "").strip()
    if kind == "title":
        etitle = str(entry.get("title") or "").strip()
        title_needles = []
        if value:
            title_needles.append(value)
        if etitle and etitle not in title_needles:
            title_needles.append(etitle)
        if ft and title_needles:
            ftl = ft.lower()
            if " — " in ft:
                ftl_alt = ft.split(" — ", 1)[-1].strip().lower()
            else:
                ftl_alt = ftl
            for tn in title_needles:
                tnl = tn.lower()
                if match == "contains":
                    if tnl in ftl or tnl in ftl_alt:
                        return True
                else:
                    if ftl == tnl or ftl_alt == tnl:
                        return True

    if not value:
        return False

    # 以下移除原 rule_id 元数据交叉匹配、非 title 类的 etitle 全局匹配

    candidates: List[str] = []
    if kind == "rule_id":
        candidates = [str(finding.get("rule_id") or "")]
    elif kind == "title":
        candidates = [ft]
        if " — " in ft:
            candidates.append(ft.split(" — ", 1)[-1].strip())
    elif kind == "path":
        candidates = _path_candidates_for_whitelist(finding)
    elif kind in ("hash", "ip", "domain", "process", "evidence", "custom"):
        candidates = _evidence_blobs(finding)
        if kind == "process":
            candidates.append(ft)
    else:
        candidates = _evidence_blobs(finding)

    for c in candidates:
        if _text_match(c, value, match):
            return True
        if kind == "path":
            if _text_match(c.replace("/", "\\"), value.replace("/", "\\"), match):
                return True
    return False


def _path_candidates_for_whitelist(finding: Dict[str, Any]) -> List[str]:
    """路径加白只用告警主路径，不用整段证据（避免日志里的旁路进程路径误伤）。"""
    out: List[str] = []
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    for k in (
        "path", "full_path", "image_path", "ImagePath", "resolved_path",
        "command_line", "command", "file",
    ):
        v = finding.get(k)
        if v is None:
            v = extra.get(k)
        if v is not None and str(v).strip():
            out.append(str(v).strip())
    # 证据里「name => path」主路径
    for blob in _evidence_blobs(finding):
        for m in _WIN_EXE_PATH_RE.finditer(blob or ""):
            # 仅取较短证据里的路径；超长 Defender 字段串不整段进候选
            if len(blob) <= 400:
                out.append(m.group(0))
        if " => " in blob:
            right = blob.split(" => ", 1)[-1].split("|", 1)[0].strip()
            if right:
                out.append(right)
    # 去重保序
    seen = set()
    uniq = []
    for p in out:
        pl = p.lower().replace("/", "\\")
        if pl in seen:
            continue
        seen.add(pl)
        uniq.append(p)
    return uniq


def classify_finding(finding: Dict[str, Any]) -> Optional[str]:
    """返回 suppress 名单名 / black / None。基线规则与手动白名单均优先于黑名单。"""
    if not finding:
        return None
    for lt in SUPPRESS_LISTS:
        for e in enabled_items(lt):
            if entry_matches_finding(e, finding):
                return lt
    for e in enabled_items("black"):
        if entry_matches_finding(e, finding):
            return "black"
    return None


def filter_findings(findings: List[Finding]) -> Tuple[List[Finding], Dict[str, int]]:
    """匹配后过滤：去掉各 OS 基线规则 / 手动白名单；黑名单命中抬高严重度。"""
    kept: List[Finding] = []
    dropped: Dict[str, int] = {f"dropped_{lt}": 0 for lt in SUPPRESS_LISTS}
    black_hit = 0
    suppress_items = {lt: enabled_items(lt) for lt in SUPPRESS_LISTS}
    black = enabled_items("black")
    if not any(suppress_items.values()) and not black:
        out_stats = {f"dropped_{lt}": 0 for lt in SUPPRESS_LISTS}
        out_stats["black_tagged"] = 0
        return findings, out_stats

    for f in findings or []:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)  # type: ignore
        dropped_here = False
        for lt in SUPPRESS_LISTS:
            if any(entry_matches_finding(e, d) for e in suppress_items[lt]):
                dropped[f"dropped_{lt}"] += 1
                dropped_here = True
                break
        if dropped_here:
            continue
        hit_black = any(entry_matches_finding(e, d) for e in black)
        if hit_black:
            black_hit += 1
            sev = (f.severity or "medium").lower()
            if sev not in ("high", "critical"):
                f.severity = "high"
            extra = dict(f.extra or {})
            extra["bw"] = "black"
            f.extra = extra
            if f.evidence and "[黑名单]" not in f.evidence:
                f.evidence = f"[黑名单] {f.evidence}"
            elif not f.evidence:
                f.evidence = "[黑名单]"
        kept.append(f)
    out = dict(dropped)
    out["black_tagged"] = black_hit
    # 兼容旧字段名
    out["dropped_white"] = dropped.get("dropped_white", 0)
    out["dropped_win11_rules"] = dropped.get("dropped_win11_rules", 0)
    return kept, out


def apply_to_finding_dicts(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """展示层：基线规则/白名单标 rejected；黑名单标 accepted + bw 标记。"""
    out: List[Dict[str, Any]] = []
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        kind = classify_finding(row)
        if kind in SUPPRESS_LISTS:
            row["bw_list"] = kind
            if (row.get("review_status") or "pending") == "pending":
                row["review_status"] = "rejected"
        elif kind == "black":
            row["bw_list"] = "black"
            if (row.get("review_status") or "pending") == "pending":
                row["review_status"] = "accepted"
            sev = str(row.get("severity") or "medium").lower()
            if sev not in ("high", "critical"):
                row["severity"] = "high"
        out.append(row)
    return out


def propose_from_finding(finding: Dict[str, Any], *, for_whitelist: bool = False) -> Dict[str, str]:
    """从告警推断默认 kind/value/match。分析页加白时优先 exact 证据/路径/标题，避免 contains 误伤。"""
    blobs = _evidence_blobs(finding or {})
    blob = " | ".join(blobs) if blobs else ""
    title = str((finding or {}).get("title") or (finding or {}).get("name") or "")
    rule_id = str((finding or {}).get("rule_id") or "")
    matcher = str((finding or {}).get("matcher") or "").lower()
    cat = str((finding or {}).get("category") or (finding or {}).get("type") or "")

    if for_whitelist:
        ev_line = _first_evidence_line(finding or {})
        if 8 <= len(ev_line) <= 480:
            return {"kind": "evidence", "value": ev_line, "match": "exact"}

        paths = _extract_persist_exe_paths(blob)
        if paths:
            best = paths[0]
            mt = "exact" if len(best) >= 16 else "contains"
            return {"kind": "path", "value": best, "match": mt}

        if cat == "持久化" and title.strip():
            return {"kind": "title", "value": title[:200], "match": "exact"}

    # 系统日志 / 有稳定 rule_id 的规则命中：优先按 rule_id 加白，避免证据原文对不上
    if rule_id and (matcher in ("eventlog", "event_logs", "keywords", "aux_rules") or cat in ("系统日志",)):
        return {"kind": "rule_id", "value": rule_id, "match": "exact"}

    if for_whitelist and rule_id and rule_id not in _GENERIC_RULE_IDS and not rule_id.startswith("sigma."):
        return {"kind": "rule_id", "value": rule_id, "match": "exact"}

    paths = _extract_persist_exe_paths(blob)
    if paths:
        best = paths[0]
        mt = "exact" if (for_whitelist or len(best) >= 16) else "contains"
        return {"kind": "path", "value": best, "match": mt}

    m = _PATH_RE.search(blob) or _PATH_RE.search(title)
    if m:
        path = m.group(0)
        mt = "exact" if for_whitelist or len(path) >= 16 else "contains"
        return {"kind": "path", "value": path, "match": mt}

    hm = _HASH_RE.search(blob)
    if hm:
        return {"kind": "hash", "value": hm.group(1).lower(), "match": "exact"}

    ipm = _IP_RE.search(blob) or _IP_RE.search(title)
    if ipm and cat in ("IOC", "网络外联", ""):
        return {"kind": "ip", "value": ipm.group(0), "match": "exact"}

    # IOC 标题常是域名/IP
    if cat == "IOC":
        dm = _DOM_RE.search(title) or _DOM_RE.search(blob)
        if dm:
            return {"kind": "domain", "value": dm.group(0).lower(), "match": "contains"}

    if rule_id:
        return {"kind": "rule_id", "value": rule_id, "match": "exact"}

    if title:
        return {"kind": "title", "value": title[:200], "match": "exact"}

    if blobs:
        # 取第一条证据，截断
        v = str(blobs[0]).strip()
        if len(v) > 240:
            v = v[:240]
        return {"kind": "evidence", "value": v, "match": "contains"}

    return {"kind": "evidence", "value": "", "match": "contains"}


def add_from_finding(
    list_type: str,
    finding: Dict[str, Any],
    *,
    by: str = "",
    note: str = "",
    report_file: str = "",
    finding_id: str = "",
    kind: str = "",
    value: str = "",
    match: str = "",
) -> Dict[str, Any]:
    from_analysis = bool(finding_id or (finding or {}).get("id"))
    prop = propose_from_finding(finding or {}, for_whitelist=(list_type == "white" and from_analysis))
    kd = (kind or prop.get("kind") or "evidence").strip()
    val = (value or prop.get("value") or "").strip()
    mt = (match or prop.get("match") or "contains").strip()
    if not val:
        raise ValueError("无法从告警提取名单值，请手动指定 value")
    agg_fid = _aggregate_finding_id(finding or {})
    store_fid = (finding_id or str((finding or {}).get("id") or "") or agg_fid or "").strip()
    row = upsert_item(
        list_type,
        val,
        kind=kd,
        match=mt,
        note=note,
        by=by,
        source="analysis",
        rule_id=str((finding or {}).get("rule_id") or ""),
        category=str((finding or {}).get("category") or (finding or {}).get("type") or ""),
        matcher=str((finding or {}).get("matcher") or ""),
        report_file=report_file,
        finding_id=store_fid,
        title=str((finding or {}).get("title") or (finding or {}).get("name") or ""),
    )
    return row


def publish_notify(
    *,
    by: str = "",
    action: str = "reload",
    item_id: str = "",
    list_type: str = "",
) -> Dict[str, Any]:
    """写入后自动发布：强制刷新本地缓存 + Redis 广播，主站多进程立刻生效。"""
    # 只加载一次：把加载好的数据传给 stats() 避免二次磁盘读。
    fresh = load(force=True)
    msg = {
        "at": _now(),
        "by": (by or "")[:64],
        "action": action,
        "item_id": item_id,
        "list": list_type,
        "stats": stats(_data=fresh),
    }
    published = False
    err = ""
    try:
        from .redis_client import get_client, is_available, prefix
        if is_available():
            r = get_client()
            r.publish(f"{prefix()}bw_list_reload", json.dumps(msg, ensure_ascii=False))
            published = True
    except Exception as e:
        err = str(e)
    return {"ok": True, "redis_pub": published, "error": err, "message": msg}


def overlay_reviews(
    findings: List[Dict[str, Any]],
    review_items: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """把全局黑白名单叠到本报告裁决：白→排除，黑→确认（已有明确裁决不降级）。"""
    try:
        from .finding_review import finding_id as _fid
    except Exception:
        def _fid(item: Dict[str, Any]) -> str:  # type: ignore
            return str((item or {}).get("id") or "")

    out: Dict[str, Dict[str, Any]] = {}
    for k, v in (review_items or {}).items():
        if isinstance(v, dict):
            out[str(k)] = dict(v)

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or _fid(f) or "").strip()
        if not fid:
            continue
        kind = classify_finding(f)
        if not kind:
            continue
        cur = out.get(fid) or {}
        cur_st = str(cur.get("status") or "pending").lower()
        if kind in SUPPRESS_LISTS:
            note_default = f"bw:{kind}"
            if cur_st != "rejected":
                out[fid] = {
                    **cur,
                    "status": "rejected",
                    "note": cur.get("note") or note_default,
                    "by": cur.get("by") or "bw_list",
                    "at": cur.get("at") or _now(),
                    "bw_list": kind,
                }
            else:
                out[fid] = {**cur, "bw_list": kind}
        elif kind == "black":
            if cur_st == "pending":
                out[fid] = {
                    **cur,
                    "status": "accepted",
                    "note": cur.get("note") or "bw:black",
                    "by": cur.get("by") or "bw_list",
                    "at": cur.get("at") or _now(),
                    "bw_list": "black",
                }
            else:
                out[fid] = {**cur, "bw_list": "black"}
    return out
