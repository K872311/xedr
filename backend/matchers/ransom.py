"""勒索软件：按加密后缀对照本地家族库（来源 solarert.com/ransomdb）。

告警偏「全盘/跨目录加密」特征：短泛后缀、系统缓存锁文件、仅落在 System32 的零星命中不报。
"""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding

_lock = threading.RLock()
_CACHE: Optional[Dict[str, Any]] = None
_CACHE_MTIME: float = 0.0

# 短/泛后缀：需更高数量阈值，降低误报
_DEFAULT_AMBIGUOUS = {
    ".001", ".000", ".888", ".locked", ".encrypted", ".crypt", ".cry",
    ".enc", ".xxx", ".aaa", ".abc", ".zip", ".tmp", ".bak", ".dat", ".bin",
    ".lock", ".rs",
}

# 这些路径上的「加密后缀」几乎都是系统/缓存噪声，不计入勒索样本
_NOISE_PATH_MARKERS = (
    "\\d3dscache\\",
    "\\inetcache\\",
    "\\temporary internet files\\",
    "\\windows\\winsxs\\",
    "\\windows\\installer\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\assembly\\",
    "\\$recycle.bin\\",
    "\\system volume information\\",
)

# 短泛后缀落在系统目录时更不可信（如 SysWOW64\\*.rs、缓存 *.lock）
_SYSTEM_DIR_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\system\\",
    "\\program files\\",
    "\\program files (x86)\\",
)


def _families_path() -> Path:
    return Path(__file__).resolve().parents[2] / "rules" / "ransom_families.json"


def load_ransom_db(force: bool = False) -> Dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    path = _families_path()
    with _lock:
        mtime = 0.0
        try:
            mtime = path.stat().st_mtime
        except OSError:
            pass
        if not force and _CACHE is not None and mtime == _CACHE_MTIME:
            return _CACHE
        doc: Dict[str, Any] = {"families": [], "ambiguous_extensions": [], "thresholds": {}}
        if path.is_file():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                doc = {"families": [], "ambiguous_extensions": [], "thresholds": {}}
        _CACHE = doc if isinstance(doc, dict) else {"families": []}
        _CACHE_MTIME = mtime
        return _CACHE


def _norm_ext(ext: Any) -> str:
    e = str(ext or "").strip().lower()
    if not e:
        return ""
    if not e.startswith("."):
        e = "." + e
    return e


def _norm_path(p: str) -> str:
    return str(p or "").replace("/", "\\").strip().lower()


def _parent_dir(path: str) -> str:
    p = _norm_path(path).rstrip("\\")
    if "\\" not in p:
        return p
    return p.rsplit("\\", 1)[0]


def _is_noise_sample(path: str, ext: str, amb: Set[str]) -> bool:
    """系统缓存 / 系统目录上的泛后缀，不计入勒索加密样本。"""
    p = _norm_path(path)
    if not p:
        return True
    for m in _NOISE_PATH_MARKERS:
        if m in p:
            return True
    # DirectX / 各类 *.lock 缓存锁
    if ext == ".lock" and ("\\cache\\" in p or "\\appdata\\local\\" in p):
        return True
    if ext in amb or len(ext.lstrip(".")) <= 4:
        for m in _SYSTEM_DIR_MARKERS:
            if m in p:
                return True
    return False


def _build_index(doc: Dict[str, Any]) -> Tuple[Dict[str, List[Dict]], Set[str], Dict[str, int]]:
    ext_map: Dict[str, List[Dict]] = defaultdict(list)
    for fam in doc.get("families") or []:
        if not isinstance(fam, dict):
            continue
        for raw in fam.get("extensions") or []:
            e = _norm_ext(raw)
            if e:
                ext_map[e].append(fam)
    amb = {_norm_ext(x) for x in (doc.get("ambiguous_extensions") or []) if str(x).strip()}
    amb |= {e for e in _DEFAULT_AMBIGUOUS}
    # 体长 ≤4 的后缀默认视为易撞车（.lock / .crypt 等）
    for e in list(ext_map.keys()):
        if len(e.lstrip(".")) <= 4:
            amb.add(e)
    thr = doc.get("thresholds") if isinstance(doc.get("thresholds"), dict) else {}
    thresholds = {
        "specific_min_count": int(thr.get("specific_min_count") or 8),
        "ambiguous_min_count": int(thr.get("ambiguous_min_count") or 50),
        "critical_min_count": int(thr.get("critical_min_count") or 120),
        "min_unique_dirs": int(thr.get("min_unique_dirs") or 8),
    }
    return ext_map, amb, thresholds


def _file_rows(report: Dict, exts: List[str], limit: int = 5000) -> List[Dict]:
    scans = report.get("file_scans") or []
    if scans:
        want = {_norm_ext(x) for x in exts}
        out = []
        for f in scans:
            if not isinstance(f, dict):
                continue
            e = _norm_ext(f.get("ext"))
            if not e:
                name = str(f.get("name") or f.get("full_path") or "")
                if "." in name:
                    e = _norm_ext(name.rsplit(".", 1)[-1])
            if e in want:
                out.append(f)
            if len(out) >= limit:
                break
        return out
    from ..db_store import files_rid, query_files
    rid = files_rid(report)
    if not rid:
        return []
    out: List[Dict] = []
    seen_path: Set[str] = set()
    chunk = 80
    for i in range(0, len(exts), chunk):
        part = exts[i : i + chunk]
        try:
            rows = query_files(rid, exts=part, limit=min(limit, 5000))
        except Exception:
            rows = []
        for f in rows:
            fp = str(f.get("full_path") or "").lower()
            if fp and fp in seen_path:
                continue
            if fp:
                seen_path.add(fp)
            out.append(f)
            if len(out) >= limit:
                return out
    return out


def _severity(count: int, ambiguous: bool, thr: Dict[str, int], dirs: int) -> Optional[str]:
    """未达数量或目录离散度阈值则不报（避免零星误报当成全盘加密）。"""
    need = thr["ambiguous_min_count"] if ambiguous else thr["specific_min_count"]
    if count < need:
        return None
    if dirs < thr["min_unique_dirs"]:
        return None
    if count >= thr["critical_min_count"] and dirs >= thr["min_unique_dirs"] * 2:
        return "critical"
    if ambiguous and count < thr["ambiguous_min_count"] * 2:
        return "medium"
    return "high"


def run(report: Dict, store: Any, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    _ = store
    doc = load_ransom_db()
    ext_map, amb, thr = _build_index(doc)
    if not ext_map:
        return [], {"ransom_analysis": {"families_hit": [], "file_hits": 0, "db_families": 0}}

    all_exts = sorted(ext_map.keys())
    rows = _file_rows(report, all_exts, limit=5000)

    # family_id -> {ext -> [paths]}
    hit_map: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    fam_meta: Dict[str, Dict] = {}

    for f in rows:
        e = _norm_ext(f.get("ext"))
        if not e:
            name = str(f.get("name") or f.get("full_path") or "")
            if "." in name:
                e = _norm_ext(name.rsplit(".", 1)[-1])
        if e not in ext_map:
            continue
        path = str(f.get("full_path") or f.get("name") or "")
        if _is_noise_sample(path, e, amb):
            continue
        for fam in ext_map[e]:
            fid = str(fam.get("id") or fam.get("slug") or fam.get("name") or "")
            if not fid:
                continue
            fam_meta[fid] = fam
            lst = hit_map[fid][e]
            if len(lst) < 40:
                lst.append(path)

    findings: List[Finding] = []
    matched: List[Dict[str, Any]] = []
    families_hit: List[Dict[str, Any]] = []
    total_files = 0

    for fid, by_ext in hit_map.items():
        fam = fam_meta.get(fid) or {}
        count = 0
        samples: List[str] = []
        ext_counts: Dict[str, int] = {}
        parents: Set[str] = set()
        for f in rows:
            e = _norm_ext(f.get("ext"))
            if not e:
                name = str(f.get("name") or "")
                if "." in name:
                    e = _norm_ext(name.rsplit(".", 1)[-1])
            if e not in by_ext:
                continue
            if not any(str(x.get("id") or x.get("slug") or x.get("name")) == fid for x in ext_map.get(e) or []):
                continue
            path = str(f.get("full_path") or f.get("name") or "")
            if _is_noise_sample(path, e, amb):
                continue
            count += 1
            ext_counts[e] = ext_counts.get(e, 0) + 1
            parents.add(_parent_dir(path))
            if len(samples) < 12:
                samples.append(path)

        if count <= 0:
            continue
        hit_exts = list(ext_counts.keys())
        all_amb = bool(hit_exts) and all(e in amb for e in hit_exts)
        has_specific = any(e not in amb for e in hit_exts)
        # 只有泛后缀时走高阈值；混有特异后缀时只用特异计数开门，且特异本身也要够散
        if has_specific:
            specific_count = sum(c for e, c in ext_counts.items() if e not in amb)
            gate_count = specific_count if specific_count > 0 else count
            ambiguous = False
            # 特异后缀样本的目录离散度
            specific_dirs = {
                _parent_dir(p)
                for e, paths in by_ext.items()
                if e not in amb
                for p in paths
                if not _is_noise_sample(p, e, amb)
            }
            dir_n = len(specific_dirs) if specific_dirs else len(parents)
        else:
            gate_count = count
            ambiguous = all_amb
            dir_n = len(parents)

        sev = _severity(gate_count, ambiguous, thr, dir_n)
        if not sev:
            families_hit.append({
                "id": fid,
                "name": fam.get("name") or fid,
                "slug": fam.get("slug") or "",
                "url": fam.get("url") or "https://solarert.com/ransomdb",
                "count": count,
                "dirs": dir_n,
                "extensions": ext_counts,
                "samples": samples[:8],
                "severity": "info",
                "alert": False,
                "ambiguous": ambiguous,
                "activity": fam.get("activity") or "",
                "risk": fam.get("risk") or "",
            })
            total_files += count
            continue

        name = str(fam.get("name") or fid)
        top_ext = sorted(ext_counts.items(), key=lambda x: -x[1])
        ext_summary = ", ".join(f"{e}×{c}" for e, c in top_ext[:6])
        title = f"勒索软件 · {name}"
        evidence = (
            f"命中加密后缀 {ext_summary}，样本数 {count}，跨 {dir_n} 个目录"
            f"（达全盘/跨目录加密特征）\n"
            + "\n".join(samples[:8])
        )
        key = f"勒索软件|{title}|{fid}|{count}"
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                "勒索软件", sev, title, evidence[:2000],
                "文件扫描", f"ransom.{fid}", "ransom",
                extra={
                    "ransom_family": name,
                    "ransom_family_id": fid,
                    "ransom_slug": fam.get("slug") or "",
                    "ransom_url": fam.get("url") or "https://solarert.com/ransomdb",
                    "extensions": ext_counts,
                    "file_count": count,
                    "unique_dirs": dir_n,
                    "samples": samples[:12],
                    "ambiguous": ambiguous,
                },
            ))
        matched.append({
            "family": name,
            "id": fid,
            "count": count,
            "dirs": dir_n,
            "extensions": ext_counts,
            "severity": sev,
            "url": fam.get("url") or "",
        })
        families_hit.append({
            "id": fid,
            "name": name,
            "slug": fam.get("slug") or "",
            "url": fam.get("url") or "https://solarert.com/ransomdb",
            "count": count,
            "dirs": dir_n,
            "extensions": ext_counts,
            "samples": samples[:12],
            "severity": sev,
            "alert": True,
            "ambiguous": ambiguous,
            "activity": fam.get("activity") or "",
            "risk": fam.get("risk") or "",
            "description": str(fam.get("description") or "")[:240],
        })
        total_files += count

    families_hit.sort(key=lambda x: (-int(x.get("count") or 0), str(x.get("name") or "")))
    summary = {
        "source": doc.get("source") or "https://solarert.com/ransomdb",
        "updated": doc.get("updated") or "",
        "db_families": int(doc.get("family_count") or len(doc.get("families") or [])),
        "db_extensions": len(ext_map),
        "file_hits": total_files,
        "alert_families": sum(1 for x in families_hit if x.get("alert")),
        "families_hit": families_hit,
        "thresholds": thr,
    }
    return findings, {
        "matched_ransom": matched,
        "ransom_analysis": summary,
    }
