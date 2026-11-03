"""已加载驱动 / 服务注册表驱动 / .sys 文件 — LOLDrivers 黑名单哈希匹配。"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..driver_blacklist import DriverBlacklistHit, load_driver_blacklist
from ..models import Finding
from ..rules_loader import RuleStore

_HASH_BUDGET = 400
_KERNEL_DRIVER_TYPES = frozenset({"1", "2", "0x1", "0x2", "16", "32"})


def _norm_path(p: str) -> str:
    s = (p or "").replace("/", "\\").strip().strip('"')
    if s.startswith("\\??\\"):
        s = s[4:]
    elif s.lower().startswith("\\systemroot\\"):
        windir = os.environ.get("WINDIR", r"C:\Windows")
        s = windir + s[12:]
    s = os.path.expandvars(s)
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _is_kernel_driver_type(raw: str) -> bool:
    t = (raw or "").strip().lower()
    if t in _KERNEL_DRIVER_TYPES:
        return True
    try:
        n = int(t, 0)
        return n in (1, 2)
    except ValueError:
        return False


def _service_name_from_reg_key(key: str) -> str:
    parts = [p for p in str(key or "").replace("/", "\\").split("\\") if p]
    for i, p in enumerate(parts):
        if p.lower() == "services" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _build_path_hash_index(report: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    idx: Dict[str, Dict[str, str]] = {}

    def add(path: str, row: Dict[str, Any]) -> None:
        lp = _norm_path(path).lower()
        if not lp:
            return
        cur = idx.setdefault(lp, {})
        for k in ("md5", "sha1", "sha256"):
            v = str(row.get(k) or "").strip().lower()
            if v and not cur.get(k):
                cur[k] = v

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        for field in ("resolved_path", "path"):
            p = str(s.get(field) or "")
            if p.lower().endswith(".sys"):
                add(p, s)
    for f in report.get("file_scans") or []:
        if not isinstance(f, dict):
            continue
        fp = str(f.get("full_path") or f.get("path") or "")
        if fp.lower().endswith(".sys"):
            add(fp, f)
    return idx


def pivot_registry_kernel_drivers(report: Dict[str, Any]) -> List[Dict[str, str]]:
    """从 services_registry 合并 Type + ImagePath（仅内核/FS 驱动服务）。"""
    buckets: Dict[str, Dict[str, str]] = {}
    sreg = report.get("services_registry") or {}
    if not isinstance(sreg, dict):
        return []
    for label, items in sreg.items():
        if "Services" not in str(label) and "BITS" not in str(label):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "")
            sname = _service_name_from_reg_key(key)
            if not sname or sname.lower() in ("parameters", "security"):
                continue
            vn = str(item.get("value") or "").lower()
            data = str(item.get("data") or "").strip()
            if not data:
                continue
            slot = buckets.setdefault(sname.lower(), {"name": sname, "key": key})
            if vn == "type":
                slot["type"] = data
            elif vn == "imagepath":
                slot["image_path"] = data
            elif vn == "start":
                slot["start"] = data
    out: List[Dict[str, str]] = []
    for slot in buckets.values():
        if not _is_kernel_driver_type(slot.get("type") or ""):
            continue
        img = _norm_path(slot.get("image_path") or "")
        if not img.lower().endswith(".sys"):
            continue
        out.append({
            "name": slot.get("name") or "",
            "type": slot.get("type") or "",
            "image_path": img,
            "start": slot.get("start") or "",
            "source": "services_registry",
        })
    return out


def _hash_file_md5(path: str, limit: int = 32 * 1024 * 1024) -> str:
    try:
        p = path
        if not p or not os.path.isfile(p):
            return ""
        if os.path.getsize(p) > limit:
            return ""
        h = hashlib.md5()
        with open(p, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _severity(category: str) -> str:
    c = (category or "").lower()
    if "malicious" in c:
        return "critical"
    return "high"


def _emit(
    findings: List[Finding],
    matched: List[Dict],
    seen: Set[str],
    *,
    driver_name: str,
    path: str,
    hit: DriverBlacklistHit,
    state: str = "",
    source: str,
    service_name: str = "",
) -> None:
    key = f"驱动黑名单|{hit.hash_value}|{path.lower()}"
    if key in seen:
        return
    seen.add(key)
    title = f"驱动黑名单 · {hit.name} · {hit.category}"
    label = service_name or driver_name or hit.name
    ev = f"{label} => {path}"
    if state:
        ev += f" [{state}]"
    ev += f" | {hit.hash_type}={hit.hash_value}"
    if source == "services_registry":
        ev += " | 来源:服务注册表"
    elif source == "services":
        ev += " | 来源:服务"
    matched.append({
        "type": "driver_blacklist",
        "name": label,
        "path": path,
        "category": hit.category,
        "hash_type": hit.hash_type,
        "hash_value": hit.hash_value,
        "rule": title,
        "rule_id": "driver.blacklist.loldrivers",
        "source": source,
        "service_name": service_name,
    })
    findings.append(Finding(
        "持久化", _severity(hit.category), title, ev,
        "驱动", "driver.blacklist.loldrivers", "driver",
        extra={
            "path": path,
            "driver_name": driver_name,
            "service_name": service_name,
            "hash_type": hit.hash_type,
            "hash_value": hit.hash_value,
            "category": hit.category,
            "source": source,
            "state": state,
        },
    ))


def _try_hashes(
    bl,
    hashes: Dict[str, str],
    driver_name: str,
    path: str,
    state: str,
    source: str,
    findings: List[Finding],
    matched: List[Dict],
    seen: Set[str],
    service_name: str = "",
) -> bool:
    for kind in ("sha256", "sha1", "md5"):
        hv = (hashes.get(kind) or "").strip().lower()
        if not hv:
            continue
        got = bl.match_hash(hv)
        if not got:
            continue
        item, ht = got
        hit = DriverBlacklistHit(
            name=str(item.get("name") or driver_name or os.path.basename(path)),
            category=str(item.get("category") or "vulnerable driver"),
            hash_type=ht,
            hash_value=hv,
        )
        _emit(
            findings, matched, seen,
            driver_name=driver_name, path=path, hit=hit, state=state, source=source,
            service_name=service_name,
        )
        return True
    return False


def _match_driver_path(
    report: Dict[str, Any],
    bl,
    *,
    name: str,
    path: str,
    state: str,
    source: str,
    hashes: Optional[Dict[str, str]],
    hash_index: Dict[str, Dict[str, str]],
    hash_budget: List[int],
    findings: List[Finding],
    matched: List[Dict],
    seen: Set[str],
    service_name: str = "",
) -> None:
    path = _norm_path(path)
    if not path.lower().endswith(".sys"):
        return
    merged = dict(hash_index.get(path.lower()) or {})
    if hashes:
        for k, v in hashes.items():
            if v and not merged.get(k):
                merged[k] = v
    if _try_hashes(
        bl, merged, name, path, state, source, findings, matched, seen,
        service_name=service_name,
    ):
        return
    if hash_budget[0] <= 0:
        return
    md5 = _hash_file_md5(path)
    hash_budget[0] -= 1
    _try_hashes(
        bl, {"md5": md5}, name, path, state, source, findings, matched, seen,
        service_name=service_name,
    )


def _driver_entries(report, bl, findings, matched, seen, hash_index, hash_budget) -> None:
    for de in report.get("driver_entries") or []:
        if not isinstance(de, dict):
            continue
        name = str(de.get("name") or de.get("display_name") or "")
        path = _norm_path(str(de.get("resolved_path") or de.get("path") or ""))
        if not path:
            continue
        state = str(de.get("state") or de.get("status") or "")
        hashes = {
            "md5": str(de.get("md5") or ""),
            "sha1": str(de.get("sha1") or ""),
            "sha256": str(de.get("sha256") or ""),
        }
        _match_driver_path(
            report, bl, name=name, path=path, state=state, source="driver_entries",
            hashes=hashes, hash_index=hash_index, hash_budget=hash_budget,
            findings=findings, matched=matched, seen=seen,
        )


def _services_kernel_drivers(report, bl, findings, matched, seen, hash_index, hash_budget) -> None:
    seen_svc: Set[str] = set()
    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        sname = str(s.get("name") or "")
        path = _norm_path(str(s.get("resolved_path") or s.get("path") or ""))
        if not path.lower().endswith(".sys"):
            continue
        sk = f"{sname.lower()}|{path.lower()}"
        if sk in seen_svc:
            continue
        seen_svc.add(sk)
        status = str(s.get("status") or s.get("start_type") or "")
        hashes = {
            "md5": str(s.get("md5") or ""),
            "sha1": str(s.get("sha1") or ""),
            "sha256": str(s.get("sha256") or ""),
        }
        _match_driver_path(
            report, bl, name=os.path.basename(path), path=path, state=status,
            source="services", hashes=hashes, hash_index=hash_index,
            hash_budget=hash_budget, findings=findings, matched=matched, seen=seen,
            service_name=sname,
        )


def _registry_kernel_drivers(report, bl, findings, matched, seen, hash_index, hash_budget) -> None:
    for row in pivot_registry_kernel_drivers(report):
        sname = row.get("name") or ""
        path = row.get("image_path") or ""
        start = row.get("start") or ""
        _match_driver_path(
            report, bl, name=os.path.basename(path), path=path, state=start,
            source="services_registry", hashes=None, hash_index=hash_index,
            hash_budget=hash_budget, findings=findings, matched=matched, seen=seen,
            service_name=sname,
        )


def _sys_files(report, bl, findings, matched, seen, hash_index) -> None:
    seen_paths: Set[str] = set()
    for f in report.get("file_scans") or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp.lower().endswith(".sys"):
            continue
        lp = fp.lower()
        if lp in seen_paths:
            continue
        seen_paths.add(lp)
        name = str(f.get("name") or os.path.basename(fp))
        hashes = {
            "md5": str(f.get("md5") or ""),
            "sha1": str(f.get("sha1") or ""),
            "sha256": str(f.get("sha256") or ""),
        }
        merged = dict(hash_index.get(lp) or {})
        for k, v in hashes.items():
            if v and not merged.get(k):
                merged[k] = v
        _try_hashes(bl, merged, name, fp, "", "files", findings, matched, seen)


def _is_tempish_path(path: str) -> bool:
    low = (path or "").lower().replace("/", "\\")
    if not low:
        return False
    markers = (
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
    )
    if any(m in low for m in markers):
        return True
    # C:\Temp\foo.sys
    if re.match(r"^[a-z]:\\temp\\", low) or re.match(r"^[a-z]:\\tmp\\", low):
        return True
    return False


def _emit_temp_sys(
    findings: List[Finding],
    matched: List[Dict],
    seen: Set[str],
    *,
    name: str,
    path: str,
    hashes: Dict[str, str],
    signed: Any = None,
    sig_status: str = "",
) -> None:
    key = f"Temp驱动|{path.lower()}"
    if key in seen:
        return
    seen.add(key)
    title = f"Temp 目录驱动文件 · {name or os.path.basename(path)}"
    bits = [f"{name or os.path.basename(path)} => {path}"]
    st = str(sig_status or "").strip()
    if st:
        bits.append(f"签名:{st}")
    for k in ("md5", "sha1", "sha256"):
        hv = str(hashes.get(k) or "").strip()
        if hv:
            bits.append(f"{k}={hv}")
            break
    sev = "high"
    findings.append(Finding(
        "驱动", sev, title, " | ".join(bits),
        "驱动", "driver.temp.sys", "driver",
        extra={
            "path": path,
            "driver_name": name,
            "source": "temp_sys",
            "sig_status": st,
            "md5": str(hashes.get("md5") or ""),
            "sha1": str(hashes.get("sha1") or ""),
            "sha256": str(hashes.get("sha256") or ""),
            "signed": bool(signed),
        },
    ))
    matched.append({
        "type": "temp_sys",
        "name": name,
        "path": path,
        "rule_id": "driver.temp.sys",
    })


def _temp_sys_files(report, bl, findings, matched, seen, hash_index, hash_budget) -> None:
    """落地在 Temp 的 .sys：黑名单优先，否则报 Temp 目录驱动文件。"""
    seen_paths: Set[str] = set()

    def handle(fp: str, name: str, hashes: Dict[str, str], signed=None, sig_status: str = ""):
        fp = _norm_path(fp)
        if not fp.lower().endswith(".sys") or not _is_tempish_path(fp):
            return
        lp = fp.lower()
        if lp in seen_paths:
            return
        seen_paths.add(lp)
        merged = dict(hash_index.get(lp) or {})
        for k, v in (hashes or {}).items():
            if v and not merged.get(k):
                merged[k] = v
        before = len(matched)
        _try_hashes(
            bl, merged, name, fp, "", "temp_sys", findings, matched, seen,
        )
        if len(matched) > before:
            return
        if not any(merged.get(k) for k in ("md5", "sha1", "sha256")) and hash_budget[0] > 0:
            md5 = _hash_file_md5(fp)
            hash_budget[0] -= 1
            if md5:
                merged["md5"] = md5
                if _try_hashes(
                    bl, merged, name, fp, "", "temp_sys", findings, matched, seen,
                ):
                    return
        _emit_temp_sys(
            findings, matched, seen, name=name, path=fp, hashes=merged,
            signed=signed, sig_status=sig_status,
        )

    for f in report.get("file_scans") or []:
        if not isinstance(f, dict):
            continue
        fp = str(f.get("full_path") or f.get("path") or "")
        handle(
            fp,
            str(f.get("name") or os.path.basename(fp)),
            {
                "md5": str(f.get("md5") or ""),
                "sha1": str(f.get("sha1") or ""),
                "sha256": str(f.get("sha256") or ""),
            },
            signed=f.get("signed"),
            sig_status=str(f.get("sig_status") or ""),
        )
    for de in report.get("driver_entries") or []:
        if not isinstance(de, dict):
            continue
        fp = str(de.get("resolved_path") or de.get("path") or "")
        handle(
            fp,
            str(de.get("name") or de.get("display_name") or os.path.basename(fp)),
            {
                "md5": str(de.get("md5") or ""),
                "sha1": str(de.get("sha1") or ""),
                "sha256": str(de.get("sha256") or ""),
            },
            signed=de.get("signed"),
            sig_status=str(de.get("sig_status") or ""),
        )


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    del store
    findings: List[Finding] = []
    matched: List[Dict] = []
    bl = load_driver_blacklist()
    local_seen: Set[str] = set(seen or set())
    hash_index = _build_path_hash_index(report)
    hash_budget = [_HASH_BUDGET]
    _driver_entries(report, bl, findings, matched, local_seen, hash_index, hash_budget)
    _registry_kernel_drivers(report, bl, findings, matched, local_seen, hash_index, hash_budget)
    _services_kernel_drivers(report, bl, findings, matched, local_seen, hash_index, hash_budget)
    _sys_files(report, bl, findings, matched, local_seen, hash_index)
    _temp_sys_files(report, bl, findings, matched, local_seen, hash_index, hash_budget)
    seen.update(local_seen)
    return findings, {
        "driver_blacklist": matched,
        "driver_blacklist_loaded": bl.size if bl else 0,
        "driver_blacklist_hits": len([m for m in matched if m.get("type") == "driver_blacklist"]),
        "temp_sys_hits": len([m for m in matched if m.get("type") == "temp_sys"]),
    }
