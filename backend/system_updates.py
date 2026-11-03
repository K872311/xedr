# -*- coding: utf-8 -*-
"""系统升级 / 库文件升级：历史、自动更新扫描、手动导入与落地。"""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import threading
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import config

_KINDS = ("system", "library")
_lock = threading.RLock()
_scanner_started = False
_SCAN_SEC = 60

# 系统包允许覆盖的相对路径前缀 / 文件
_SYS_PREFIXES = (
    "backend/",
    "frontend/dist/",
    "rules_admin/",
    "scripts/",
    "static/",
    "updates/applied/",
)
_SYS_FILES = {
    "server.py",
    "start.ps1",
    "start-vue.ps1",
    "requirements.txt",
    "README.md",
}


def _root() -> Path:
    return Path(getattr(config, "ROOT", None) or Path(__file__).resolve().parent.parent).resolve()


def _store_path() -> Path:
    d = _root() / "config"
    d.mkdir(parents=True, exist_ok=True)
    return d / "system_updates.json"


def _pkg_dir(kind: str) -> Path:
    d = _root() / "updates" / ("system" if kind == "system" else "library")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _inbox_dir(kind: str) -> Path:
    d = _root() / "updates" / "incoming" / ("system" if kind == "system" else "library")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _processed_dir(kind: str) -> Path:
    d = _root() / "updates" / "processed" / ("system" if kind == "system" else "library")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _backup_dir() -> Path:
    d = _root() / "updates" / "backup"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now_str() -> str:
    return time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())


def _default_store() -> Dict[str, Any]:
    ts = _now_str()
    return {
        "auto_update": {"system": False, "library": False},
        "last_check": {"system": "", "library": ""},
        "items": [
            {
                "id": "1.0.0-init",
                "kind": "system",
                "description": ["init update all"],
                "md5": "init",
                "installed_at": ts,
                "filename": "",
                "source": "seed",
            },
            {
                "id": "1.0.0-lib-init",
                "kind": "library",
                "description": ["init library baseline"],
                "md5": "init",
                "installed_at": ts,
                "filename": "",
                "source": "seed",
            },
        ],
    }


def _ensure_dirs() -> None:
    for k in _KINDS:
        _inbox_dir(k)
        _processed_dir(k)
        _pkg_dir(k)
    _backup_dir()
    readme = _root() / "updates" / "README.txt"
    if not readme.is_file():
        readme.write_text(
            "升级投放目录说明\n"
            "================\n"
            "1) 系统升级包放入: updates/incoming/system/\n"
            "2) 库文件升级包放入: updates/incoming/library/\n"
            "3) 开启「自动更新」后：库文件包会定时安装；系统包只留在投放目录，须登录后台手动导入或点「立即检查」\n"
            "4) 也可在页面点击「手动导入升级」或「立即检查」\n"
            "\n"
            "升级包格式\n"
            "--------\n"
            "- .zip 内可含 manifest.json（id / description / md5 / kind）\n"
            "- 系统包: files/ 下相对项目根的文件（限 backend/ frontend/dist/ rules_admin/ scripts/ 等）\n"
            "- 库文件包: rules/ lists/ ioc_data/ 或根目录 .json 规则文件\n",
            encoding="utf-8",
        )


def _normalize_store(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        data = _default_store()
    data.setdefault("auto_update", {"system": False, "library": False})
    data.setdefault("last_check", {"system": "", "library": ""})
    if not isinstance(data.get("auto_update"), dict):
        data["auto_update"] = {"system": False, "library": False}
    if not isinstance(data.get("last_check"), dict):
        data["last_check"] = {"system": "", "library": ""}
    if not isinstance(data.get("items"), list):
        data["items"] = []
    return data


def peek_local() -> Dict[str, Any]:
    """只读本地 system_updates.json，不触 MySQL。"""
    p = _store_path()
    if not p.is_file():
        return _default_store()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return _default_store()
    return _normalize_store(data)


def _write_local(data: Dict[str, Any]) -> None:
    p = _store_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def _load() -> Dict[str, Any]:
    _ensure_dirs()
    p = _store_path()
    if not p.is_file():
        data = _default_store()
        _write_local(data)
    else:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            data = _default_store()
        data = _normalize_store(data)
    has_lib = any(_norm_kind(x.get("kind")) == "library" for x in data["items"] if isinstance(x, dict))
    if not has_lib:
        data["items"].append({
            "id": "1.0.0-lib-init",
            "kind": "library",
            "description": ["init library baseline"],
            "md5": "init",
            "installed_at": _now_str(),
            "filename": "",
            "source": "seed",
        })
        _write_local(data)
    try:
        from . import platform_store
        remote = platform_store.load_updates()
        if remote is None:
            platform_store.seed_updates_from_local(data)
        elif remote.get("items"):
            merged = dict(data)
            merged["auto_update"] = remote.get("auto_update") or data.get("auto_update")
            merged["last_check"] = remote.get("last_check") or data.get("last_check")
            merged["items"] = remote["items"]
            _write_local(merged)
            return merged
        else:
            platform_store.seed_updates_from_local(data)
    except Exception as e:
        print("[system_updates] mysql load:", e)
    return data


def _save(data: Dict[str, Any]) -> None:
    data = _normalize_store(data)
    _write_local(data)
    try:
        from . import platform_store
        platform_store.save_updates(data)
    except Exception as e:
        print("[system_updates] mysql save:", e)


def _norm_kind(kind: Any) -> str:
    k = str(kind or "system").strip().lower()
    if k in ("lib", "library", "库", "库文件"):
        return "library"
    return "system"


def _desc_list(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw or "").strip()
    if not text:
        return []
    lines = [ln.strip() for ln in text.replace("\r", "").split("\n") if ln.strip()]
    return lines or [text]


def get_updates(*, kind: str = "system") -> Dict[str, Any]:
    kind = _norm_kind(kind)
    data = _load()
    auto = data.get("auto_update") or {}
    last = data.get("last_check") or {}
    items = [
        x for x in (data.get("items") or [])
        if isinstance(x, dict) and _norm_kind(x.get("kind") or "system") == kind
    ]
    items = sorted(items, key=lambda x: str(x.get("installed_at") or ""), reverse=True)
    inbox = _inbox_dir(kind)
    pending = [
        p.name for p in sorted(inbox.iterdir())
        if p.is_file() and p.suffix.lower() in (".zip", ".json", ".pkg", ".bin")
    ]
    return {
        "ok": True,
        "kind": kind,
        "auto_update": bool(auto.get(kind)),
        "last_check": last.get(kind) or "",
        "inbox_path": str(inbox),
        "pending": pending,
        "items": [
            {
                "id": str(x.get("id") or ""),
                "kind": kind,
                "description": _desc_list(x.get("description")),
                "md5": str(x.get("md5") or ""),
                "installed_at": str(x.get("installed_at") or ""),
                "filename": str(x.get("filename") or ""),
                "source": str(x.get("source") or ""),
                "applied": list(x.get("applied") or []),
            }
            for x in items
        ],
        "hint": (
            (
                "自动更新开启后会安装投放目录中的库文件包。"
                if kind == "library"
                else "系统包不会自动落地（避免未登录写入即覆盖程序）。请手动导入，或登录后点「立即检查」。"
            )
            + f"投放路径：updates/incoming/{'library' if kind == 'library' else 'system'}/"
        ),
    }


def set_auto_update(*, kind: str, enabled: bool) -> Dict[str, Any]:
    kind = _norm_kind(kind)
    with _lock:
        data = _load()
        auto = data.setdefault("auto_update", {"system": False, "library": False})
        auto[kind] = bool(enabled)
        _save(data)
    out: Dict[str, Any] = {"ok": True, "kind": kind, "auto_update": bool(enabled)}
    if enabled:
        try:
            # 系统包即使开启自动更新也不静默落地；库文件可立即安装
            scanned = check_and_apply(kind=kind, apply_packages=(kind != "system"))
            out["check"] = scanned
        except Exception as e:
            out["check_error"] = str(e)
    ensure_scanner()
    return out


def _md5_bytes(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()


def _parse_manifest(blob: bytes, filename: str) -> Dict[str, Any]:
    name = (filename or "").lower()
    meta: Dict[str, Any] = {}
    if name.endswith(".json"):
        try:
            obj = json.loads(blob.decode("utf-8", errors="replace"))
            # 纯规则文件也可能是 JSON 数组；仅对象当 manifest
            if isinstance(obj, dict) and ("id" in obj or "description" in obj or "files" in obj or "kind" in obj):
                meta = obj
        except Exception:
            meta = {}
    elif name.endswith(".zip") or name.endswith(".pkg"):
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for n in zf.namelist():
                    base = Path(n).name.lower()
                    if base in ("manifest.json", "update.json", "package.json"):
                        meta = json.loads(zf.read(n).decode("utf-8", errors="replace"))
                        break
        except Exception:
            meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta


def _safe_rel(path: str) -> Optional[str]:
    rel = str(path or "").replace("\\", "/").lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    return rel


def _allowed_system_rel(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    if rel in _SYS_FILES:
        return True
    return any(rel.startswith(p) for p in _SYS_PREFIXES)


def _backup_file(dest: Path) -> None:
    if not dest.is_file():
        return
    try:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        rel = dest.relative_to(_root())
        bak = _backup_dir() / stamp / rel
        bak.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dest, bak)
    except Exception:
        pass


def _write_bytes(dest: Path, blob: bytes) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _backup_file(dest)
    dest.write_bytes(blob)
    try:
        return str(dest.relative_to(_root())).replace("\\", "/")
    except Exception:
        return str(dest)


def _apply_library_package(blob: bytes, filename: str, meta: Dict[str, Any]) -> List[str]:
    applied: List[str] = []
    name = (filename or "").lower()
    # 归档原包
    archive = _pkg_dir("library") / f"{int(time.time())}_{Path(filename).name}"
    archive.write_bytes(blob)
    applied.append(str(archive.relative_to(_root())).replace("\\", "/"))

    if name.endswith(".zip") or name.endswith(".pkg"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for n in zf.namelist():
                if n.endswith("/"):
                    continue
                base = Path(n).name.lower()
                if base in ("manifest.json", "update.json", "package.json", "readme.txt", "readme.md"):
                    continue
                rel = _safe_rel(n)
                if not rel:
                    continue
                low = rel.lower()
                if low.startswith("rules/") or low.startswith("lists/") or low.startswith("ioc_data/") or low.startswith("ioc/"):
                    dest = _root().joinpath(*Path(rel).parts)
                elif low.endswith(".json"):
                    # 默认进 rules
                    dest = _root() / "rules" / Path(rel).name
                else:
                    continue
                applied.append(_write_bytes(dest, zf.read(n)))
        if len(applied) <= 1:
            raise ValueError("库文件包内未找到可安装的 rules/lists/ioc 文件")
        return applied

    # 单文件
    dest_name = str(meta.get("target") or Path(filename).name)
    dest_name = Path(dest_name).name
    low = dest_name.lower()
    if "ioc" in low and low.endswith((".db", ".sqlite", ".json")):
        dest = _root() / ("ioc" if low.endswith((".db", ".sqlite")) else "ioc_data") / dest_name
    elif any(k in low for k in ("list", "white", "black", "bw")):
        dest = _root() / "lists" / dest_name
    else:
        dest = _root() / "rules" / dest_name
    applied.append(_write_bytes(dest, blob))
    return applied


def _apply_system_package(blob: bytes, filename: str, meta: Dict[str, Any]) -> List[str]:
    applied: List[str] = []
    archive = _pkg_dir("system") / f"{int(time.time())}_{Path(filename).name}"
    archive.write_bytes(blob)
    applied.append(str(archive.relative_to(_root())).replace("\\", "/"))
    name = (filename or "").lower()

    # manifest.files: 相对路径列表从 zip 取
    if name.endswith(".zip") or name.endswith(".pkg"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for n in zf.namelist():
                if n.endswith("/"):
                    continue
                base = Path(n).name.lower()
                if base in ("manifest.json", "update.json", "package.json", "readme.txt", "readme.md"):
                    continue
                rel_raw = n.replace("\\", "/")
                # 支持 files/xxx 或 patches/xxx 或直接白名单路径
                if rel_raw.lower().startswith("files/"):
                    rel = _safe_rel(rel_raw[6:])
                elif rel_raw.lower().startswith("patches/"):
                    rel = _safe_rel("updates/applied/" + Path(rel_raw).name)
                else:
                    rel = _safe_rel(rel_raw)
                if not rel or not _allowed_system_rel(rel):
                    continue
                dest = _root().joinpath(*Path(rel).parts)
                applied.append(_write_bytes(dest, zf.read(n)))
        return applied

    # 单文件：仅允许白名单文件名落到 updates/applied 或根下已知文件
    dest_name = Path(str(meta.get("target") or filename)).name
    if dest_name in _SYS_FILES:
        dest = _root() / dest_name
    else:
        dest = _root() / "updates" / "applied" / dest_name
    applied.append(_write_bytes(dest, blob))
    return applied


def _record_item(item: Dict[str, Any]) -> None:
    with _lock:
        data = _load()
        items = [x for x in (data.get("items") or []) if isinstance(x, dict)]
        pid = str(item.get("id") or "")
        kind = _norm_kind(item.get("kind"))
        items = [
            x for x in items
            if not (str(x.get("id")) == pid and _norm_kind(x.get("kind") or "system") == kind)
        ]
        items.insert(0, item)
        data["items"] = items[:200]
        _save(data)


def import_package(
    *,
    kind: str,
    filename: str,
    blob: bytes,
    package_id: str = "",
    description: Any = None,
    source: str = "manual",
) -> Dict[str, Any]:
    kind = _norm_kind(kind)
    if kind == "system":
        from .security_flags import code_updates_allowed
        if not code_updates_allowed():
            return {"ok": False, "error": "系统代码升级已禁用；生产环境请设置 FORENSIC_ALLOW_CODE_UPDATE=1 后再导入"}
    if not blob:
        return {"ok": False, "error": "空文件"}
    if len(blob) > 80 * 1024 * 1024:
        return {"ok": False, "error": "升级包超过 80MB"}
    meta = _parse_manifest(blob, filename)
    if meta.get("kind"):
        # manifest 可强制 kind
        mk = _norm_kind(meta.get("kind"))
        if mk in _KINDS:
            kind = mk
    pid = (package_id or meta.get("id") or Path(filename).stem or "").strip()
    if not pid:
        pid = time.strftime("pkg-%Y%m%d-%H%M%S")
    desc = description if description is not None else meta.get("description")
    desc_list = _desc_list(desc)
    if not desc_list:
        desc_list = [f"{'自动' if source == 'auto' else '手动'}导入：{filename}"]
    md5 = str(meta.get("md5") or "").strip() or _md5_bytes(blob)

    # 同 md5 已安装则跳过（自动扫描时）
    if source == "auto" and md5 and md5 != "init":
        data = _load()
        for x in data.get("items") or []:
            if isinstance(x, dict) and str(x.get("md5")) == md5 and _norm_kind(x.get("kind")) == kind:
                return {"ok": True, "skipped": True, "reason": "same_md5", "item": x}

    try:
        if kind == "library":
            applied = _apply_library_package(blob, filename, meta)
        else:
            applied = _apply_system_package(blob, filename, meta)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    item = {
        "id": pid,
        "kind": kind,
        "description": desc_list,
        "md5": md5,
        "installed_at": _now_str(),
        "filename": filename,
        "applied": applied,
        "source": source,
    }
    _record_item(item)

    reload_info: Dict[str, Any] = {}
    if kind == "library":
        reload_info = _reload_libraries()
    return {"ok": True, "item": item, "applied": applied, "reload": reload_info}


def _reload_libraries() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        from backend.hot_reload import ensure_fresh_analysis
        out["rules"] = ensure_fresh_analysis(force=True)
    except Exception as e:
        out["rules_error"] = str(e)
    try:
        from backend import bw_list
        bw_list.load(force=True)
        out["bw_list"] = True
    except Exception as e:
        out["bw_list_error"] = str(e)
    try:
        from backend import ioc_db
        if hasattr(ioc_db, "clear_local_cache"):
            ioc_db.clear_local_cache()
        out["ioc_cache"] = True
    except Exception as e:
        out["ioc_error"] = str(e)
    return out


def check_and_apply(*, kind: Optional[str] = None, apply_packages: bool = True) -> Dict[str, Any]:
    """扫描投放目录。apply_packages=False 时只更新检查时间，不安装、不挪走文件。"""
    kinds = [_norm_kind(kind)] if kind else list(_KINDS)
    results: List[Dict[str, Any]] = []
    for k in kinds:
        inbox = _inbox_dir(k)
        processed = _processed_dir(k)
        files = sorted(
            [p for p in inbox.iterdir() if p.is_file() and p.suffix.lower() in (".zip", ".json", ".pkg", ".bin")],
            key=lambda p: p.stat().st_mtime,
        )
        if not apply_packages:
            with _lock:
                data = _load()
                lc = data.setdefault("last_check", {})
                lc[k] = _now_str()
                _save(data)
            results.append({"kind": k, "ok": True, "skipped": True, "reason": "scan_only", "pending": len(files)})
            continue
        for fp in files:
            try:
                blob = fp.read_bytes()
                out = import_package(kind=k, filename=fp.name, blob=blob, source="auto")
                # 移到 processed
                dest = processed / f"{int(time.time())}_{fp.name}"
                try:
                    fp.replace(dest)
                except Exception:
                    try:
                        shutil.move(str(fp), str(dest))
                    except Exception:
                        pass
                results.append({"file": fp.name, "kind": k, **{kk: out.get(kk) for kk in ("ok", "skipped", "error", "item")}})
            except Exception as e:
                results.append({"file": fp.name, "kind": k, "ok": False, "error": str(e)})
        with _lock:
            data = _load()
            lc = data.setdefault("last_check", {})
            lc[k] = _now_str()
            _save(data)
    return {
        "ok": True,
        "checked_at": _now_str(),
        "results": results,
        "applied": sum(1 for r in results if r.get("ok") and not r.get("skipped")),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "failed": sum(1 for r in results if r.get("ok") is False),
    }


def ensure_scanner() -> None:
    global _scanner_started
    if _scanner_started:
        return
    _scanner_started = True

    def _loop() -> None:
        while True:
            try:
                data = _load()
                auto = data.get("auto_update") or {}
                for k in _KINDS:
                    if auto.get(k):
                        # 系统包禁止无人值守落地（可覆盖 backend/）
                        check_and_apply(kind=k, apply_packages=(k != "system"))
            except Exception as e:
                print("[system_updates] scanner:", e)
            time.sleep(_SCAN_SEC)

    threading.Thread(target=_loop, daemon=True, name="system-updates-scan").start()
