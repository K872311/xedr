"""Windows 采集缺口字段检出：Amcache 内容 / 强制扩展·BHO / 缺口文件面 / SRUM / Navicat 等。"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding, build_anchor

_SUS_AMCACHE_DIRS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\recycle",
)
_TRUSTED_AMCACHE = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\windows\\installer\\",
)
_FORCE_HINTS = (
    "extensioninstallforcelist",
    "extensionsettings",
    "browser helper objects",
)
_GAP_FILE_ROOTS = {
    "FontsAnomaly": ("字体异常文件", "medium", "fonts_anomaly"),
    "System32Hidden": ("System32 隐藏 PE", "high", "system32_hidden"),
    "WindowsTemp": ("Windows\\Temp 可疑文件", "medium", "windows_temp"),
    "CryptnetUrlCache": ("CryptnetUrlCache 缓存", "info", "cryptnet_urlcache"),
}


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _norm(p: str) -> str:
    return (p or "").replace("/", "\\").lower()


def _amcache_path(app: Dict[str, Any]) -> str:
    return str(
        app.get("lower_case_long_path")
        or app.get("path")
        or app.get("name")
        or ""
    ).strip()


def _is_sus_amcache_path(path: str) -> bool:
    pl = _norm(path)
    if not pl or len(pl) < 4:
        return False
    if any(t in pl for t in _TRUSTED_AMCACHE):
        return False
    return any(s in pl for s in _SUS_AMCACHE_DIRS)


_GAP_PATH_HINTS = {
    "WindowsTemp": "\\windows\\temp\\",
    "CryptnetUrlCache": "cryptneturlcache",
    "FontsAnomaly": "\\windows\\fonts\\",
    "System32Hidden": "\\windows\\system32\\",
}


def _tag_root(f: Dict[str, Any]) -> str:
    root = str(f.get("root") or f.get("Root") or f.get("file_group") or f.get("group") or "").strip()
    if root in _GAP_FILE_ROOTS:
        return root
    pl = _norm(str(f.get("full_path") or f.get("path") or ""))
    if "cryptneturlcache" in pl:
        return "CryptnetUrlCache"
    if "\\windows\\temp\\" in pl or pl.endswith("\\windows\\temp"):
        return "WindowsTemp"
    if "\\windows\\fonts\\" in pl:
        # 仅非常规扩展名才算异常（与采集端一致）
        name = _norm(str(f.get("name") or pl.rsplit("\\", 1)[-1]))
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if name in ("desktop.ini", "fms_metadata.xml", "staticcache.dat"):
            return ""
        if ext not in ("fon", "ttf", "ttc", "otf", "compositefont") and name:
            return "FontsAnomaly"
        return ""
    if "\\windows\\system32\\" in pl and (f.get("hidden") or f.get("system")):
        ext = _norm(str(f.get("ext") or ""))
        if ext in (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr"):
            return "System32Hidden"
    return ""


def _files_by_root(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {k: [] for k in _GAP_FILE_ROOTS}
    rows = [f for f in _as_list(report.get("file_scans")) if isinstance(f, dict)]
    if not rows:
        from ..db_store import files_rid, query_files

        rid = files_rid(report)
        if rid:
            seen: Set[str] = set()
            for needle in _GAP_PATH_HINTS.values():
                try:
                    for row in query_files(rid, path_contains=needle, limit=120) or []:
                        fp = str(row.get("full_path") or "")
                        if not fp or fp in seen:
                            continue
                        seen.add(fp)
                        rows.append(row)
                except Exception:
                    continue
    for f in rows:
        root = _tag_root(f)
        if root in buckets:
            buckets[root].append(f)
    return buckets


def run_amcache_apps(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    ex = report.get("execution_artifacts") if isinstance(report.get("execution_artifacts"), dict) else {}
    apps = _as_list(ex.get("amcache_apps"))
    meta = {"amcache_apps": len(apps), "amcache_sus": 0}
    for app in apps:
        if not isinstance(app, dict):
            continue
        path = _amcache_path(app)
        if not _is_sus_amcache_path(path):
            continue
        sha1 = str(app.get("sha1") or app.get("file_id") or "").strip()
        name = str(app.get("name") or path).strip()
        key = f"Amcache可疑路径|{_norm(path)}|{sha1}"
        if key in seen:
            continue
        seen.add(key)
        meta["amcache_sus"] += 1
        evidence = f"{path}" + (f" SHA1={sha1}" if sha1 else "")
        findings.append(Finding(
            "执行痕迹", "medium", f"Amcache 可疑路径 → {name[:80]}",
            evidence, "execution_artifacts", "amcache_sus_path", "wininfosc_gap",
            extra={"path": path, "sha1": sha1, "publisher": app.get("publisher") or ""},
            anchor=build_anchor(path=path, sha256="", module="execution_artifacts", kind="amcache"),
        ))
        if meta["amcache_sus"] >= 40:
            break
    return findings, meta


def run_browser_policies(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    se = report.get("security_extras") if isinstance(report.get("security_extras"), dict) else {}
    items = _as_list(se.get("browser_policies"))
    meta = {"browser_policies": len(items)}
    for it in items:
        if not isinstance(it, dict):
            continue
        blob = " ".join(str(it.get(k) or "") for k in ("key", "value", "data")).lower()
        if not any(h in blob for h in _FORCE_HINTS):
            # 仍展示 Firefox 策略等
            if "policies" not in blob and "firefox" not in blob:
                continue
        is_force = "forcelist" in blob or "browser helper" in blob
        title = "浏览器强制扩展" if "forcelist" in blob else (
            "浏览器 BHO" if "browser helper" in blob else "浏览器策略项"
        )
        sev = "high" if is_force else "medium"
        detail = f"{it.get('key') or ''} {it.get('value') or ''}={it.get('data') or ''}".strip()
        key = f"浏览器策略|{detail[:200]}"
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            "安全配置", sev, title, detail, "security_extras",
            "browser_policy", "wininfosc_gap",
            extra={"key": it.get("key"), "value": it.get("value"), "data": it.get("data")},
        ))
        if len(findings) >= 30:
            break
    return findings, meta


def run_gap_files(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    buckets = _files_by_root(report)
    meta = {f"files_{k}": len(v) for k, v in buckets.items()}
    for root, (title, sev, rid) in _GAP_FILE_ROOTS.items():
        rows = buckets.get(root) or []
        if not rows:
            continue
        # Cryptnet 仅信息级汇总，避免刷屏
        if root == "CryptnetUrlCache":
            key = f"缺口文件|{root}|count"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "取证面", "info", f"{title} ×{len(rows)}",
                    f"root={root} count={len(rows)}", "file_scans", rid, "wininfosc_gap",
                    extra={"root": root, "count": len(rows)},
                ))
            continue
        for f in rows[:25]:
            path = str(f.get("full_path") or f.get("path") or "")
            name = str(f.get("name") or path)
            if not path:
                continue
            # WindowsTemp：只对 PE/脚本抬高
            if root == "WindowsTemp":
                ext = _norm(str(f.get("ext") or name))
                if not any(ext.endswith(x) for x in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr")):
                    continue
            key = f"缺口文件|{root}|{_norm(path)}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                "文件异常", sev, f"{title} → {name[:80]}",
                path, "file_scans", rid, "wininfosc_gap",
                extra={"root": root, "path": path, "hidden": f.get("hidden"), "system": f.get("system")},
                anchor=build_anchor(path=path, module="file_scans", kind=root),
            ))
    return findings, meta


def run_srum(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    ex = report.get("execution_artifacts") if isinstance(report.get("execution_artifacts"), dict) else {}
    srum = _as_list(ex.get("srum"))
    meta: Dict[str, Any] = {"srum_hits": len(srum), "srum_pack": False, "srum_rows": 0}
    path = ""
    if srum and isinstance(srum[0], dict):
        path = str(srum[0].get("path") or "")
    # pack 旁路二进制
    try:
        from ..db_store import files_rid
        rid = files_rid(report) or str(report.get("_rid") or report.get("report_file") or "").strip()
    except Exception:
        rid = str(report.get("_rid") or "").strip()
    pack_path = ""
    if rid:
        try:
            from ..collect_pack import pack_dir_for_rid
            p = pack_dir_for_rid(rid, create=False) / "artifacts" / "SRUDB.dat"
            if p.is_file() and p.stat().st_size > 0:
                meta["srum_pack"] = True
                pack_path = str(p)
                path = path or pack_path
        except Exception:
            pass
    if not path and not meta["srum_pack"]:
        return findings, meta

    # 可选 dissect.esedb 轻量解析（未安装则仅登记存在）
    parsed = _try_parse_srum(pack_path or path)
    if parsed:
        meta["srum_rows"] = int(parsed.get("rows") or 0)
        meta["srum_tables"] = parsed.get("tables") or []
        report.setdefault("_srum_parse", parsed)

    key = f"SRUM|present|{_norm(path)}"
    if key not in seen:
        seen.add(key)
        note = f"SRUDB 已采集 path={path}"
        if meta.get("srum_pack"):
            note += " (pack artifacts/SRUDB.dat)"
        if meta.get("srum_rows"):
            note += f" 解析行数≈{meta['srum_rows']}"
        findings.append(Finding(
            "执行痕迹", "info", "SRUM 资源使用库已采集",
            note, "execution_artifacts", "srum_present", "wininfosc_gap",
            extra={"path": path, "pack": meta["srum_pack"], "rows": meta.get("srum_rows")},
            anchor=build_anchor(path=path, pack_file="artifacts/SRUDB.dat" if meta["srum_pack"] else "", module="execution_artifacts", kind="srum"),
        ))
    return findings, meta


def _try_parse_srum(path: str) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    try:
        from pathlib import Path
        p = Path(path)
        if not p.is_file() or p.stat().st_size < 64:
            return None
    except Exception:
        return None
    try:
        from dissect.esedb import EseDB  # type: ignore
    except Exception:
        return None
    try:
        db = EseDB(path)
        tables = []
        rows = 0
        for t in list(db.tables())[:40]:
            name = getattr(t, "name", None) or str(t)
            tables.append(str(name))
            try:
                n = sum(1 for _ in t.records())
            except Exception:
                n = 0
            rows += min(n, 5000)
            if rows > 20000:
                break
        return {"tables": tables[:30], "rows": rows, "engine": "dissect.esedb"}
    except Exception:
        return None


def run_navicat(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    ureg = report.get("user_registry") if isinstance(report.get("user_registry"), dict) else {}
    items = _as_list(ureg.get("Navicat"))
    meta = {"navicat": len(items)}
    if not items:
        return findings, meta
    # 汇总一条，避免连接串刷屏
    key = "Navicat|present"
    if key not in seen:
        seen.add(key)
        sample = []
        for it in items[:5]:
            if isinstance(it, dict):
                sample.append(f"{it.get('key') or ''}\\{it.get('value') or ''}={str(it.get('data') or '')[:80]}")
        findings.append(Finding(
            "取证面", "info", f"Navicat 注册表残留 ×{len(items)}",
            "; ".join(sample) or f"count={len(items)}",
            "user_registry", "navicat", "wininfosc_gap",
            extra={"count": len(items)},
        ))
    return findings, meta


def run_eventlog_coverage(report: Dict, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    cov = _as_list(report.get("event_log_coverage"))
    meta = {"event_log_coverage": len(cov), "empty_channels": 0}
    empty = []
    for ch in cov:
        if not isinstance(ch, dict):
            continue
        try:
            n = int(ch.get("record_count") or 0)
        except (TypeError, ValueError):
            n = 0
        name = str(ch.get("channel") or "")
        if n <= 0 and name:
            empty.append(name)
    meta["empty_channels"] = len(empty)
    # 关键通道为空时提示
    critical_empty = [c for c in empty if re.search(r"^(Security|System|Application|Microsoft-Windows-Sysmon|PowerShell)", c, re.I)]
    if critical_empty:
        key = "事件通道覆盖|empty_critical"
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                "采集质量", "low", f"关键事件通道无记录 ×{len(critical_empty)}",
                ", ".join(critical_empty[:12]),
                "event_log_coverage", "eventlog_coverage_empty", "wininfosc_gap",
                extra={"channels": critical_empty[:20]},
            ))
    return findings, meta


def run(report: Dict, store=None, seen: Optional[Set[str]] = None) -> Tuple[List[Finding], Dict]:
    seen = seen if isinstance(seen, set) else set()
    all_f: List[Finding] = []
    meta: Dict[str, Any] = {}
    for fn in (
        run_amcache_apps,
        run_browser_policies,
        run_gap_files,
        run_srum,
        run_navicat,
        run_eventlog_coverage,
    ):
        f, m = fn(report, seen)
        all_f.extend(f)
        meta.update(m or {})
    tz = report.get("system_timezone")
    if isinstance(tz, dict) and (tz.get("key_name") or tz.get("tzutil")):
        meta["timezone"] = tz.get("key_name") or tz.get("tzutil")
    return all_f, meta
