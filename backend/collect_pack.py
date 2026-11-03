"""采集包 forensic-pack/v1：把大 JSON 拆成模块分片 + zip。"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "forensic-pack/v1"

HOST_KEYS = (
    "hostname", "os", "os_name", "os_family", "ip", "collect_time", "time",
    "collector", "source", "system_info", "timezone", "domain",
)
PROCESS_KEYS = ("processes",)
NETWORK_KEYS = (
    "established_connections", "open_ports", "dns_cache_entries", "hosts_file",
    "firewall_rules", "network", "net_sessions", "net_shares",
)
PERSIST_KEYS = (
    "services", "scheduled_tasks", "startup_items", "users", "drivers", "driver_entries",
    "wmi_subscriptions", "wmi_namespaces", "installed_programs", "prefetch_files",
    "run_mru", "bits_jobs", "recycle_bin", "usb_devices", "hotfixes", "wifi_profiles",
)
BROWSER_KEYS = ("browser_artifacts",)
# 已下线的内存 / $MFT 取证：旧报告残留键不打包、不回填
RETIRED_KEYS = ("memory_artifacts", "mft_artifacts")
JSONL_MAP = {
    "event_logs": "eventlog.jsonl",
    "file_scans": "files.jsonl",
}
SHARD_JSON = {
    "host": HOST_KEYS,
    "processes": PROCESS_KEYS,
    "network": NETWORK_KEYS,
    "persistence": PERSIST_KEYS,
    "browser": BROWSER_KEYS,
}
LIGHT_MODULES = ("host", "processes", "network", "persistence")
HEAVY_MODULES = ("eventlog", "files", "browser")
UI_MODULES = (
    ("processes", "进程", "processes", "processes"),
    ("network", "网络", "network", "established_connections"),
    ("persistence", "持久化", "services", "services"),
    ("eventlog", "事件日志", "event_logs", "event_logs"),
    ("files", "文件扫描", "file_scans", "file_scans"),
    ("browser", "浏览器", "browser", "browser_artifacts"),
)
_SKIP_PACK = frozenset(JSONL_MAP) | frozenset(RETIRED_KEYS) | frozenset(
    k for keys in SHARD_JSON.values() for k in keys
)


def _count_val(v: Any) -> int:
    if v is None or v == "" or v == {} or v == []:
        return 0
    if isinstance(v, list):
        return len(v)
    if isinstance(v, dict):
        return 1
    if isinstance(v, str):
        return 1 if v.strip() else 0
    return 1


def _pick(report: Dict[str, Any], keys: Tuple[str, ...]) -> Dict[str, Any]:
    out = {}
    for k in keys:
        if k in report:
            out[k] = report[k]
    return out


def _module_entry(name: str, filename: str, payload: Any, *, jsonl: bool = False) -> Dict[str, Any]:
    n = 0
    if jsonl and isinstance(payload, list):
        n = len(payload)
        status = "ok" if n else "empty"
    else:
        if isinstance(payload, dict):
            n = sum(_count_val(v) for v in payload.values())
        else:
            n = _count_val(payload)
        status = "ok" if n else "empty"
    return {"file": filename, "status": status, "count": n}


def build_pack_files(report: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, bytes]]:
    """返回 (manifest, {filename: bytes})。jsonl 按行，其余为 JSON。"""
    if not isinstance(report, dict):
        raise ValueError("报告必须是对象")
    files: Dict[str, bytes] = {}
    modules: Dict[str, Any] = {}

    for name, keys in SHARD_JSON.items():
        chunk = _pick(report, keys)
        raw = json.dumps(chunk, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        fname = f"{name}.json"
        files[fname] = raw
        modules[name] = _module_entry(name, fname, chunk)

    extras: Dict[str, Any] = {}
    for k, v in report.items():
        if k.startswith("_") or k in _SKIP_PACK:
            continue
        extras[k] = v
    if extras:
        files["extras.json"] = json.dumps(extras, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        modules["extras"] = _module_entry("extras", "extras.json", extras)

    for src_key, fname in JSONL_MAP.items():
        rows = report.get(src_key) if isinstance(report.get(src_key), list) else []
        buf = io.BytesIO()
        n = 0
        dirsnap_only = True
        for row in rows:
            if not isinstance(row, dict):
                continue
            buf.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            buf.write(b"\n")
            n += 1
            # 只要有一条不是 DirSnap，就不是纯快照模式
            if src_key == "file_scans" and str(row.get("root") or row.get("Root") or "").lower() != "dirsnap":
                dirsnap_only = False
        if n == 0:
            dirsnap_only = False
        files[fname] = buf.getvalue()
        mod = "eventlog" if src_key == "event_logs" else "files"
        mod_entry: Dict[str, Any] = {"file": fname, "status": "ok" if n else "empty", "count": n, "jsonl": True}
        if src_key == "file_scans" and n > 0 and dirsnap_only:
            mod_entry["scan_mode"] = "dirsnap"
        modules[mod] = mod_entry

    manifest = {
        "schema": SCHEMA,
        "hostname": str(report.get("hostname") or "unknown"),
        "os_family": str(report.get("os_family") or "").strip().lower(),
        "os": str(report.get("os") or report.get("os_name") or ""),
        "ip": str(report.get("ip") or "").split(",")[0].strip(),
        "collect_time": str(report.get("collect_time") or report.get("time") or ""),
        "collector": str(report.get("collector") or report.get("source") or ""),
        "modules": modules,
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    return manifest, files


def pack_report_to_zip(report: Dict[str, Any], dest: Path) -> Dict[str, Any]:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    manifest, files = build_pack_files(report)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    manifest["zip"] = str(dest)
    manifest["zip_bytes"] = dest.stat().st_size
    return manifest


def zip_is_forensic_pack(zf: zipfile.ZipFile) -> bool:
    names = [n.replace("\\", "/").lstrip("./") for n in zf.namelist()]
    if not any(n.endswith("manifest.json") for n in names):
        return False
    try:
        raw = _zip_read(zf, "manifest.json")
        man = json.loads(raw.decode("utf-8"))
        return isinstance(man, dict) and str(man.get("schema") or "").startswith("forensic-pack/")
    except Exception:
        return False


def path_is_forensic_pack(path: Path) -> bool:
    path = Path(path)
    if path.is_dir():
        man = path / "manifest.json"
        if not man.is_file():
            return False
        try:
            data = json.loads(man.read_text(encoding="utf-8"))
            return isinstance(data, dict) and str(data.get("schema") or "").startswith("forensic-pack/")
        except Exception:
            return False
    if path.suffix.lower() != ".zip":
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return zip_is_forensic_pack(zf)
    except Exception:
        return False


def _zip_read(zf: zipfile.ZipFile, want: str) -> bytes:
    want = want.replace("\\", "/").lstrip("./")
    for name in zf.namelist():
        n = name.replace("\\", "/").lstrip("./")
        if n == want or n.endswith("/" + want):
            return zf.read(name)
    raise FileNotFoundError(want)


def extract_pack_zip(zip_path: Path, dest_dir: Path) -> Dict[str, Any]:
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        if not zip_is_forensic_pack(zf):
            raise ValueError("不是 forensic-pack 采集包（缺少 manifest.json）")
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError("压缩包含非法路径")
            base = Path(name).name
            if not base or info.is_dir():
                continue
            target = dest_dir / base
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
    man_path = dest_dir / "manifest.json"
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json 无效")
    return manifest


def _load_json_file(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size <= 0:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def assemble_light_report(pack_dir: Path, manifest: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """只拼小分片，不读 eventlog/files jsonl。"""
    pack_dir = Path(pack_dir)
    if manifest is None:
        manifest = json.loads((pack_dir / "manifest.json").read_text(encoding="utf-8"))
    report: Dict[str, Any] = {}
    for name in ("host", "processes", "network", "persistence", "browser", "extras"):
        chunk = _load_json_file(pack_dir / f"{name}.json")
        if isinstance(chunk, dict):
            report.update(chunk)
    for k in RETIRED_KEYS:
        report.pop(k, None)
    mods = manifest.get("modules") if isinstance(manifest, dict) else {}
    ev = (mods or {}).get("eventlog") or {}
    fl = (mods or {}).get("files") or {}
    report["event_logs"] = []
    report["file_scans"] = []
    report["_event_logs_count"] = int(ev.get("count") or 0)
    report["_files_count"] = int(fl.get("count") or 0)
    report["_pack"] = True
    report["_pack_schema"] = SCHEMA
    if not report.get("hostname"):
        report["hostname"] = str((manifest or {}).get("hostname") or "unknown")
    if not report.get("os_family"):
        report["os_family"] = str((manifest or {}).get("os_family") or "")
    if not report.get("ip"):
        report["ip"] = str((manifest or {}).get("ip") or "")
    if not report.get("collect_time"):
        report["collect_time"] = str((manifest or {}).get("collect_time") or "")
    if not report.get("collector"):
        report["collector"] = str((manifest or {}).get("collector") or "")
    return report


# 轻量字段：report.json 若被瘦身/损坏为空，可从 pack 分片补回（不碰 jsonl）
_LIGHT_LIST_KEYS = (
    "processes", "services", "scheduled_tasks", "startup_items",
    "established_connections", "open_ports", "dns_cache_entries",
    "browser_artifacts", "prefetch_files", "users", "installed_programs",
)
_LIGHT_SCALAR_KEYS = (
    "hostname", "os", "os_family", "ip", "collect_time", "collector",
    "system_info", "hosts_file", "firewall_rules",
)


def hydrate_report_from_pack(rid: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """分析前：若 pack 存在且 report 缺轻量模块，从 pack/*.json 补全。

    保证进程 / 持久化 / 网络 / 浏览器等 matcher 有源数据；
    事件日志与文件清单仍靠 ensure_heavy_ready 入库，不在此装入内存。
    """
    if not isinstance(report, dict) or not rid:
        return report
    pack = pack_dir_for_rid(rid, create=False)
    man = pack / "manifest.json"
    if not man.is_file():
        return report
    try:
        light = assemble_light_report(pack)
    except Exception as e:
        print(f"[collect_pack] hydrate assemble: {e}")
        return report

    filled: List[str] = []
    for k in _LIGHT_LIST_KEYS:
        cur = report.get(k)
        empty = not isinstance(cur, list) or len(cur) == 0
        src = light.get(k)
        if empty and isinstance(src, list) and src:
            report[k] = src
            filled.append(k)
    for k in _LIGHT_SCALAR_KEYS:
        cur = report.get(k)
        empty = cur is None or cur == "" or cur == [] or cur == {}
        src = light.get(k)
        if empty and src not in (None, "", [], {}):
            report[k] = src
            filled.append(k)
    # extras：dir_snapshots / wmi_subscriptions 等
    for k in (
        "dir_snapshots", "wmi_subscriptions", "user_registry",
        "services_registry", "network_registry", "ps_history", "ps_artifacts",
        "execution_artifacts", "remote_access", "security_extras",
        "event_log_coverage", "system_timezone", "collection_quality",
        "environment", "file_scan_roots", "office_artifacts",
    ):
        cur = report.get(k)
        empty = cur is None or cur == "" or cur == [] or cur == {}
        src = light.get(k)
        if empty and src not in (None, "", [], {}):
            report[k] = src
            filled.append(k)

    report["_pack"] = True
    if int(report.get("_files_count") or 0) <= 0 and int(light.get("_files_count") or 0) > 0:
        report["_files_count"] = int(light["_files_count"])
    if int(report.get("_event_logs_count") or 0) <= 0 and int(light.get("_event_logs_count") or 0) > 0:
        report["_event_logs_count"] = int(light["_event_logs_count"])
    if filled:
        print(f"[collect_pack] hydrate {rid}: filled {', '.join(filled)}")
    return report


def match_data_coverage(report: Dict[str, Any]) -> Dict[str, Any]:
    """匹配前数据覆盖面：供 pipeline 记录，便于排查「模块无输出」。"""
    def nlist(key: str) -> int:
        v = report.get(key)
        return len(v) if isinstance(v, list) else 0

    return {
        "processes": nlist("processes"),
        "services": nlist("services"),
        "scheduled_tasks": nlist("scheduled_tasks"),
        "startup_items": nlist("startup_items"),
        "connections": nlist("established_connections"),
        "browser_artifacts": nlist("browser_artifacts"),
        "dir_snapshots": nlist("dir_snapshots"),
        "files_count": int(report.get("_files_count") or nlist("file_scans") or 0),
        "event_logs_count": int(report.get("_event_logs_count") or nlist("event_logs") or 0),
        "files_ingested": bool(report.get("_files_ingested")),
        "event_logs_ingested": bool(report.get("_event_logs_ingested")),
        "pack": bool(report.get("_pack")),
    }


def count_jsonl(path: Path) -> int:
    if not path.is_file():
        return 0
    n = 0
    with open(path, "rb") as fh:
        for line in fh:
            if line.strip():
                n += 1
    return n


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        return
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def pack_dir_for_rid(rid: str, *, create: bool = False) -> Path:
    from . import paths as P
    d = P.report_dir(rid, create=create) / "pack"
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def load_pack_manifest(rid: str) -> Optional[Dict[str, Any]]:
    p = pack_dir_for_rid(rid) / "manifest.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _collect_status(mod: Dict[str, Any], count: int) -> str:
    st = str((mod or {}).get("status") or "").lower()
    if st in ("missing", "failed", "empty", "ok"):
        if st == "ok" and count <= 0 and int((mod or {}).get("count") or 0) <= 0:
            return "empty"
        # files 模块全为 DirSnap 时标 dirsnap，区别于真正的全盘扫描
        if st == "ok" and str((mod or {}).get("scan_mode") or "").lower() == "dirsnap":
            return "dirsnap"
        return st
    if count > 0 or int((mod or {}).get("count") or 0) > 0:
        if str((mod or {}).get("scan_mode") or "").lower() == "dirsnap":
            return "dirsnap"
        return "ok"
    return "empty"


def _analyze_status(mod_id: str, collect: str, job: Optional[Dict[str, Any]]) -> str:
    if collect in ("empty", "missing", "failed"):
        return "skipped"
    if not job:
        return "done"
    phase = str(job.get("phase") or job.get("status") or "").lower()
    if phase in ("done",):
        return "done"
    if phase in ("error", "cancelled", "skipped"):
        return "error" if phase == "error" else "pending"
    if phase in ("queued", "load"):
        return "pending"
    light = mod_id in LIGHT_MODULES or mod_id in ("processes", "network", "persistence", "host")
    if phase in ("fast", "save_fast"):
        if light:
            return "analyzing" if phase == "fast" else "done"
        return "pending"
    if phase in ("full", "save_full", "partial"):
        if light:
            return "done"
        return "analyzing" if phase != "save_full" else "done"
    return "pending"


def module_status_list(
    manifest: Optional[Dict[str, Any]] = None,
    counts: Optional[Dict[str, Any]] = None,
    job: Optional[Dict[str, Any]] = None,
    quality: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """页面用：已分析 / 分析中 / 采集时未带。"""
    counts = counts or {}
    quality = quality or {}
    mods = (manifest or {}).get("modules") if isinstance(manifest, dict) else {}
    mods = mods if isinstance(mods, dict) else {}
    out = []
    for mid, label, qkey, ckey in UI_MODULES:
        n = int(counts.get(ckey) or counts.get(mid) or 0)
        if not n and isinstance(mods.get(mid), dict):
            n = int(mods[mid].get("count") or 0)
        collect = _collect_status(mods.get(mid) or {}, n)
        if collect == "empty" and str(quality.get(qkey) or "").lower() in ("ok", "degraded"):
            collect = str(quality.get(qkey)).lower()
        if collect == "empty" and str(quality.get(qkey) or "").lower() in ("failed", "missing"):
            collect = str(quality.get(qkey)).lower()
        analyze = _analyze_status(mid, collect, job)
        if collect in ("empty", "missing"):
            ui = "采集时未带"
            kind = "missing"
        elif collect == "dirsnap":
            ui = "仅目录快照"
            kind = "dirsnap"
        elif collect == "failed":
            ui = "采集失败"
            kind = "failed"
        elif analyze == "analyzing":
            ui = "分析中"
            kind = "analyzing"
        elif analyze == "pending":
            ui = "待分析"
            kind = "pending"
        elif analyze == "done":
            ui = "已分析"
            kind = "done"
        else:
            ui = "待分析"
            kind = "pending"
        out.append({
            "id": mid,
            "label": label,
            "collect": collect,
            "analyze": analyze,
            "status": kind,
            "text": ui,
            "count": n,
        })
    return out


def ingest_pack_jsonl(rid: str, cancel_check=None) -> Dict[str, int]:
    """把 pack/*.jsonl 流式灌进 SQLite，不把整表装进内存。"""
    from .db_store import ingest_event_logs_iter, ingest_file_scans_iter

    pack_dir = pack_dir_for_rid(rid, create=False)
    stats = {"event_logs": 0, "files": 0}
    evp = pack_dir / "eventlog.jsonl"
    flp = pack_dir / "files.jsonl"
    if evp.is_file() and evp.stat().st_size > 0:
        stats["event_logs"] = ingest_event_logs_iter(rid, iter_jsonl(evp), cancel_check=cancel_check)
    if flp.is_file() and flp.stat().st_size > 0:
        stats["files"] = ingest_file_scans_iter(rid, iter_jsonl(flp), cancel_check=cancel_check)
    return stats


def find_pack_root(path: Path) -> Optional[Path]:
    """zip 解压目录里定位 forensic-pack 根（允许包一层子目录）。"""
    path = Path(path)
    if path_is_forensic_pack(path):
        return path
    if not path.is_dir():
        return None
    try:
        kids = [p for p in path.iterdir() if p.is_dir() and not p.name.startswith(".")]
    except OSError:
        return None
    if len(kids) == 1 and path_is_forensic_pack(kids[0]):
        return kids[0]
    return None


def install_pack_dir(src: Path, rid: str) -> Path:
    import shutil
    dest = pack_dir_for_rid(rid, create=True)
    src = Path(src).resolve()
    dest_r = dest.resolve()
    if dest.exists() and dest_r != src:
        shutil.rmtree(dest, ignore_errors=True)
    if dest_r != src:
        shutil.copytree(src, dest)
    return dest
