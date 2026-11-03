"""Windows 进程行为检测（显式 processRules + Sigma behavior 兼容）"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore
from .persistence import (
    _SEV_RANK,
    _as_list,
    _contains_all,
    _contains_any,
    _dir_file_count_entity,
    _exe_paths_from_item,
    _host_signed_for_sideload,
    _hydrate_entity_dir_files,
    _immediate_under,
    _is_explicitly_unsigned,
    _is_unsigned,
    _norm_path,
    _pick,
    _rx,
    _unsigned_siblings_entity,
)


def _proc_name(p: Dict[str, Any]) -> str:
    return str(
        p.get("name") or p.get("process_name") or p.get("image_name")
        or p.get("ImageFileName") or p.get("exe") or ""
    ).strip()


def _proc_path(p: Dict[str, Any]) -> str:
    return _norm_path(str(
        p.get("path") or p.get("exe") or p.get("image_path")
        or p.get("ImagePath") or p.get("full_path") or ""
    ).strip())


def _proc_cmd(p: Dict[str, Any]) -> str:
    return str(
        p.get("command_line") or p.get("command") or p.get("cmdline")
        or p.get("CommandLine") or ""
    ).strip()


def _proc_parent_name(p: Dict[str, Any]) -> str:
    return str(
        p.get("parent_name") or p.get("ParentName") or p.get("parent") or ""
    ).strip()


def _proc_parent_path(p: Dict[str, Any]) -> str:
    return _norm_path(str(
        p.get("parent_path") or p.get("ParentPath") or ""
    ).strip())


def _proc_blob(p: Dict[str, Any]) -> str:
    parts = [
        _proc_name(p),
        _proc_path(p),
        _proc_cmd(p),
        str(p.get("user") or p.get("User") or "").strip(),
        _proc_parent_name(p),
        _proc_parent_path(p),
        str(p.get("parent_command_line") or "").strip(),
    ]
    return " | ".join(x for x in parts if x)


_DIRTY_MODULE_PATHS = (
    "\\users\\", "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
    "\\public\\", "\\downloads\\", "\\desktop\\", "\\perflogs\\",
)

# 整树视为系统（模块白加黑剔除）
_SYSTEM_MODULE_TREES = (
    "\\windows\\winsxs\\",
    "\\windows\\systemapps\\",
    "\\windows\\assembly\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\appcompat\\",
    "\\windows\\systemresources\\",
    "\\windows\\systemui\\",
    "\\windows\\immersivecontrolpanel\\",
    "\\windows\\fonts\\",
    "\\windows\\globalization\\",
    "\\windows\\registration\\",
    # Program Files 常为 catalog 签名，采集端易标成 unsigned（如 TabTip/ink）
    "\\program files\\",
    "\\program files (x86)\\",
)

# System32 / SysWOW64 下合法子目录（其余子目录视为异常落地，可参与白加黑）
_SYSTEM32_KNOWN_SUBDIRS = frozenset({
    "drivers", "driverstore", "wbem", "windowspowershell", "com", "config",
    "tasks", "spool", "catroot", "catroot2", "codeintegrity", "logfiles",
    "oobe", "migration", "speech", "ime", "mui", "en-us", "zh-cn", "zh-tw",
    "downlevel", "grouppolicy", "applocker", "appxdeployment", "appraiser",
    "advancedinstallers", "bits", "boot", "calculator", "certsrv", "cmiv2",
    "compat", "container", "csrss", "diag", "diagnostics", "directx",
    "driversetup", "dtsh", "dxdiag", "edgeupdate", "eventviewer", "f12",
    "fxstmp", "gesture", "hal", "input", "intel", "keyiso", "licensing",
    "locales", "macromed", "microsoft", "migwiz", "ndf", "networklist",
    "nls", "oobe", "opencl", "openssh", "package", "perfcounters",
    "perceptionsimulation", "perceptionsimulationtools", "printers",
    "ras", "restore", "sru", "sxs", "sysprep", "systemapps", "tcpip",
    "timeseries", "twain_32", "uim", "usmt", "vbscript", "wer",
    "winevt", "winrm", "wmi", "wow64", "wpc", "wsc",
})

# 兼容旧名
_SYSTEM_MODULE_PATHS = _SYSTEM_MODULE_TREES + (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
)


def _path_is_system(p: str) -> bool:
    """系统目录模块：默认不当作白加黑「黑 DLL」。

    System32/SysWOW64 根下直接文件 + 已知子树算系统；
    System32 下随机/未知子目录不算（如 System32\\2r9dmh\\ 白加黑落地）。
    """
    low = _norm_path(p).lower().replace("/", "\\")
    if not low:
        return False
    for n in _SYSTEM_MODULE_TREES:
        if n in low:
            return True
    m = re.search(r"(?:^|[a-z]:)\\windows\\(system32|syswow64)\\(.+)$", low)
    if m:
        rest = m.group(2)
        if "\\" not in rest:
            return True  # System32\foo.exe 根下直接文件
        first = rest.split("\\", 1)[0].lower()
        return first in _SYSTEM32_KNOWN_SUBDIRS
    # 其它 \\Windows\\... 仍算系统
    if re.search(r"(?:^|[a-z]:)\\windows\\", low):
        return True
    return False


def _same_dir(a: str, b: str) -> bool:
    """两路径父目录相同（不含子目录）。"""
    da = a.rsplit("\\", 1)[0].lower() if a and "\\" in a else ""
    db = b.rsplit("\\", 1)[0].lower() if b and "\\" in b else ""
    if not da or not db:
        return False
    return da == db


def _iter_modules(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """合并 modules / dlls：同路径优先保留带签名元数据的条目（dlls 常为无签名纯路径，会误报白加黑）。"""
    raw_list: List[Dict[str, Any]] = []
    for key in ("modules", "Modules", "dlls", "DLLs"):
        raw = proc.get(key)
        if not isinstance(raw, list):
            continue
        for m in raw:
            if isinstance(m, dict):
                raw_list.append(m)
            elif isinstance(m, str) and m.strip():
                raw_list.append({"name": m.strip(), "path": m.strip()})

    def _sig_score(m: Dict[str, Any]) -> int:
        score = 0
        if m.get("signed") is True:
            score += 40
        elif m.get("signed") is False:
            score += 10
        st = str(m.get("sig_status") or m.get("SigStatus") or "").strip()
        if st:
            score += 20
            if st.lower() in ("valid", "signed") or "valid" in st.lower():
                score += 20
        if m.get("signer") or m.get("Signer"):
            score += 5
        if m.get("company") or m.get("Company"):
            score += 2
        return score

    by_key: Dict[str, Dict[str, Any]] = {}
    for m in raw_list:
        mp = _module_path(m).lower()
        nm = str(m.get("name") or m.get("Name") or "").strip().lower()
        key = mp or nm
        if not key:
            continue
        prev = by_key.get(key)
        if prev is None or _sig_score(m) > _sig_score(prev):
            by_key[key] = m
    return list(by_key.values())


def _module_path(m: Dict[str, Any]) -> str:
    return _norm_path(str(m.get("path") or m.get("Path") or m.get("full_path") or "").strip())


def _module_ext(m: Dict[str, Any]) -> str:
    mp = _module_path(m)
    nm = str(m.get("name") or m.get("Name") or "").strip()
    blob = (mp or nm).rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if "." not in blob:
        return ""
    return blob.rsplit(".", 1)[-1]


def _module_is_exe_or_dll(m: Dict[str, Any], rule: Optional[Dict[str, Any]] = None) -> bool:
    """白加黑默认认 exe/dll/sys；规则可用 moduleExtAny 覆盖。"""
    allowed = [str(x).lstrip(".").lower() for x in _as_list((rule or {}).get("moduleExtAny"))]
    if not allowed:
        allowed = ["exe", "dll", "sys"]
    return _module_ext(m) in set(allowed)


def _file_meta_is_signed(meta: Dict[str, Any]) -> bool:
    if not isinstance(meta, dict):
        return False
    # SQLite/JSON 可能是 1/True；避免 `signed is True` 漏掉整数 1
    if meta.get("signed") in (True, 1, "1", "true", "True"):
        return True
    st = str(
        meta.get("sig_status") or meta.get("SigStatus") or meta.get("signer_status") or ""
    ).strip().lower()
    return st in ("valid", "signed") or ("valid" in st and "invalid" not in st)


def _put_file_sig(idx: Dict[str, Dict[str, Any]], path: str, meta: Dict[str, Any]) -> None:
    key = _norm_path(path).lower()
    if not key or not isinstance(meta, dict):
        return
    prev = idx.get(key)
    if prev and _file_meta_is_signed(prev) and not _file_meta_is_signed(meta):
        return
    idx[key] = meta


def build_file_sig_index(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """file_scans / files 表 → 路径签名索引（纠正进程模块采集漏签）。"""
    idx: Dict[str, Dict[str, Any]] = {}
    for key in ("file_scans", "files"):
        rows = report.get(key)
        if not isinstance(rows, list):
            continue
        for f in rows:
            if not isinstance(f, dict):
                continue
            fp = str(f.get("full_path") or f.get("path") or "").strip()
            if fp:
                _put_file_sig(idx, fp, f)

    # 仅补「看起来未签」的模块路径，避免全表扫描
    need: List[str] = []
    seen: Set[str] = set()
    for proc in report.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        for m in _iter_modules(proc):
            if not _is_unsigned(m):
                continue
            mp = _module_path(m)
            if not mp:
                continue
            low = mp.lower()
            if low in idx or low in seen:
                continue
            seen.add(low)
            need.append(mp)

    rid = str(report.get("_rid") or report.get("_files_rid") or report.get("report_id") or "").strip()
    if need and rid:
        try:
            from ..db_store import lookup_file_sigs_by_paths
            for fp, meta in (lookup_file_sigs_by_paths(rid, need) or {}).items():
                _put_file_sig(idx, fp, meta)
        except Exception:
            pass
    return idx


def enrich_process_modules_from_file_sigs(
    proc: Dict[str, Any],
    sig_index: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    """用文件清单 Valid 签名覆盖进程模块的漏检 unsigned（飞书/WPS 等同目录 DLL）。"""
    if not isinstance(proc, dict) or not sig_index:
        return proc
    for key in ("modules", "Modules", "dlls", "DLLs"):
        mods = proc.get(key)
        if not isinstance(mods, list):
            continue
        for m in mods:
            if not isinstance(m, dict):
                continue
            mp = _module_path(m)
            if not mp:
                continue
            meta = sig_index.get(mp.lower())
            if not meta or not _file_meta_is_signed(meta):
                continue
            # 仅「升级」为已签，不把 Valid 模块改成未签
            m["signed"] = True
            st = str(meta.get("sig_status") or meta.get("SigStatus") or "Valid").strip()
            if st:
                m["sig_status"] = st
                if "SigStatus" in m:
                    m["SigStatus"] = st
            signer = meta.get("signer") or meta.get("Signer")
            if signer:
                m["signer"] = signer
            company = meta.get("company") or meta.get("Company")
            if company and not (m.get("company") or m.get("Company")):
                m["company"] = company
            sig_type = meta.get("sig_type") or meta.get("SigType")
            if sig_type and not (m.get("sig_type") or m.get("SigType")):
                m["sig_type"] = sig_type
    return proc


def enrich_processes_module_sigs(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """就地回填报告内进程模块签名，返回索引供调用方复用。"""
    idx = build_file_sig_index(report)
    if not idx:
        return idx
    for proc in report.get("processes") or []:
        if isinstance(proc, dict):
            enrich_process_modules_from_file_sigs(proc, idx)
    return idx


# 已知大型厂商安装树（缺 DirSnap 总数时仍按「大目录」处理）
_VENDOR_LARGE_DIR_MARKERS = (
    "\\kingsoft\\wps office\\",
    "\\appdata\\local\\kingsoft\\",
    "\\kingsoft\\office\\",
    "\\jxbrowser\\",
    "\\chromium\\",
    "\\google\\chrome\\",
    "\\microsoft\\edge\\",
    "\\huorong\\",
    "\\battle.net",
    "\\nexon\\",
)


def _looks_like_vendor_large_dir(path: str) -> bool:
    low = _norm_path(path).lower()
    if not low:
        return False
    return any(m in low for m in _VENDOR_LARGE_DIR_MARKERS)


def _file_looks_signed(f: Dict[str, Any]) -> bool:
    if not isinstance(f, dict):
        return False
    if f.get("signed") is True:
        return True
    st = str(f.get("sig_status") or f.get("SigStatus") or "").strip().lower()
    if not st:
        return False
    st_compact = st.replace(" ", "").replace("-", "")
    if st_compact in ("valid", "signed") or ("valid" in st_compact and "invalid" not in st_compact):
        return True
    return False


def _count_same_dir_signed_peers(
    report: Optional[Dict[str, Any]],
    host: str,
) -> int:
    """同目录已签 PE（exe/dll/sys/ocx）数量，用于识别厂商安装树。"""
    if not host or not isinstance(report, dict):
        return 0
    host_n = _norm_path(host)
    parent = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent:
        return 0
    parent_l = parent.lower()
    host_l = host_n.lower()
    try:
        _hydrate_entity_dir_files(report)
    except Exception:
        pass
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    n = 0
    for f in cache.get(parent_l) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp or fp.lower() == host_l:
            continue
        if fp.rsplit("\\", 1)[0].lower() != parent_l:
            continue
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext not in ("exe", "dll", "sys", "ocx"):
            continue
        if _file_looks_signed(f):
            n += 1
    return n


def _vendor_signed_peer_suppress(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]],
    bad: List[Dict[str, Any]],
) -> bool:
    """同目录已签 PE 很多 + 未签载荷很少 → 厂商树（VMware/portable 安装等），应抑制。

    不依赖路径关键字，避免 D:\\changyong\\vm 这类无厂商目录名的便携安装漏判。
    """
    try:
        min_signed = int(rule.get("moduleMinSignedPeers") or 0)
    except (TypeError, ValueError):
        min_signed = 0
    if min_signed <= 0 or not bad or not isinstance(report, dict):
        return False
    host = _proc_path(proc)
    if not host:
        return False
    try:
        max_same = int(rule.get("moduleMaxUnsignedSameDir") or 1)
    except (TypeError, ValueError):
        max_same = 1
    if max_same <= 0:
        max_same = 1
    # 磁盘未签 DLL 数（优先）与已加载未签数取较大
    disk_n = 0
    for f in _unsigned_siblings_entity(report, host) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext in ("dll", "sys", "ocx"):
            disk_n += 1
    n_unsigned = max(len(bad), disk_n)
    if n_unsigned > max_same:
        return False
    signed_n = _count_same_dir_signed_peers(report, host)
    if signed_n < min_signed:
        return False
    proc["_sideload_signed_peers"] = signed_n
    proc["_sideload_vendor_peers"] = True
    return True


def _large_dir_sideload_ok(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]],
    bad: List[Dict[str, Any]],
) -> bool:
    """大型软件目录里零星未签 DLL：返回 False 表示应硬抑制（不定典型白加黑）。

    典型：WPS office6（232 项，仅 inkobj.dll 未签）、VMware 安装树（92 项，仅 libexpat.dll）。
    真实白加黑通常是「干净小目录 + 少量文件」。

    仅在规则显式配置 moduleMaxDirFiles 时生效；report=None 或未配置时一律 True。
    """
    try:
        max_files = int(rule.get("moduleMaxDirFiles") or 0)
    except (TypeError, ValueError):
        max_files = 0
    if max_files <= 0 or not bad or not isinstance(report, dict):
        return True
    per_dir: Dict[str, List[str]] = {}
    for m in bad:
        mp = _module_path(m) or _norm_path(str(m.get("full_path") or m.get("path") or ""))
        if not mp or "\\" not in mp:
            continue
        per_dir.setdefault(mp.rsplit("\\", 1)[0].lower(), []).append(mp)
    if not per_dir:
        return True
    top_dir = max(per_dir.keys(), key=lambda d: len(per_dir[d]))
    top = per_dir[top_dir]
    n_unsigned = len(top)
    # 大目录判定用磁盘未签 DLL 数更准（已加载可能只有 1 个）
    host = _proc_path(proc) or top[0]
    disk_n = 0
    for f in _unsigned_siblings_entity(report, host) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext in ("dll", "sys", "ocx"):
            disk_n += 1
    if disk_n > n_unsigned:
        n_unsigned = disk_n
    total = _dir_file_count_entity(report, top[0])
    try:
        min_unsigned = int(rule.get("moduleLargeDirMinUnsigned") or 0)
    except (TypeError, ValueError):
        min_unsigned = 0
    try:
        min_ratio = float(rule.get("moduleLargeDirMinUnsignedRatio") or 0)
    except (TypeError, ValueError):
        min_ratio = 0.0

    # 无目录规模：已知厂商大树 + 未签很少 → 仍按大目录抑制
    if total <= 0:
        if _looks_like_vendor_large_dir(host) and n_unsigned < max(min_unsigned or 3, 3):
            proc["_sideload_large_dir"] = True
            proc["_sideload_dir_files"] = 0
            return False
        return True

    if total <= max_files:
        return True
    proc["_sideload_dir_files"] = total
    if min_unsigned and n_unsigned < min_unsigned:
        proc["_sideload_large_dir"] = True
        return False
    if min_ratio > 0 and (n_unsigned / float(total)) < min_ratio:
        proc["_sideload_large_dir"] = True
        return False
    return True


def _unsigned_modules(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """白加黑：明确未签名模块；默认同目录，剔除系统路径。

    同目录严格口径：
    1) 优先已加载 modules 里同目录明确未签的 dll/sys/ocx
    2) 已加载超过 moduleMaxUnsignedSameDir（默认 1）→ 不像单 DLL 白加黑，直接否决
    3) 无已加载时：默认可回退 DirSnap；若 moduleRequireLoaded=true 则不回退（必须真加载才报）
    4) 已加载=1 时仍用磁盘兄弟数否决（目录堆满未签 DLL 的厂商树）

    采集常对模块填 signed=false + 空 sig_status（未校验）。不能把「未知」当「未签名」。
    """
    host = _proc_path(proc)
    host_dir = host.rsplit("\\", 1)[0] if host and "\\" in host else ""
    host_key = host.lower() if host else ""
    want_dirty = bool(rule.get("moduleDirtyPath") or rule.get("requireDirtyModulePath"))
    same_dir_only = rule.get("moduleSameDirOnly")
    if same_dir_only is None:
        same_dir_only = True
    cross_dir_only = bool(rule.get("moduleCrossDirOnly"))
    if cross_dir_only:
        same_dir_only = False
    exclude_sys = rule.get("moduleExcludeSystemPaths")
    if exclude_sys is None:
        exclude_sys = True
    strict = rule.get("moduleRequireExplicitUnsigned")
    if strict is None:
        strict = True
    require_loaded = bool(rule.get("moduleRequireLoaded") or rule.get("requireLoadedModule"))
    path_any = [_norm_path(x) for x in _as_list(rule.get("modulePathContainsAny"))]
    try:
        if rule.get("moduleMaxUnsignedSameDir") is None:
            max_same = 1
        else:
            max_same = max(0, int(rule.get("moduleMaxUnsignedSameDir")))
    except (TypeError, ValueError):
        max_same = 1

    loaded: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def _add(dst: List[Dict[str, Any]], m: Dict[str, Any]) -> None:
        mp = _module_path(m) or _norm_path(str(m.get("full_path") or m.get("path") or ""))
        key = (mp or str(m.get("name") or "")).lower()
        if not key or key in seen:
            return
        seen.add(key)
        dst.append(m)

    def _payload_ext_ok(m: Dict[str, Any]) -> bool:
        mp = _module_path(m) or _norm_path(str(m.get("full_path") or m.get("path") or m.get("name") or ""))
        ext = mp.rsplit(".", 1)[-1].lower() if "." in mp else ""
        if same_dir_only and not want_dirty:
            return ext in ("dll", "sys", "ocx")
        return _module_is_exe_or_dll(m, rule)

    for m in _iter_modules(proc):
        if strict:
            if not _is_explicitly_unsigned(m):
                continue
        elif not _is_unsigned(m):
            continue
        if not _payload_ext_ok(m):
            continue
        mp = _module_path(m)
        if not mp:
            continue
        if host_key and mp.lower() == host_key:
            continue
        if exclude_sys and _path_is_system(mp):
            continue
        if same_dir_only:
            if not host_dir or not _same_dir(host, mp):
                continue
        elif cross_dir_only:
            if not host_dir or _same_dir(host, mp):
                continue
        if path_any and not _contains_any(mp, path_any):
            continue
        if want_dirty:
            dirty = any(n in mp for n in _DIRTY_MODULE_PATHS) if mp else False
            foreign = bool(host_dir and mp and not _same_dir(host, mp))
            if not dirty and not foreign:
                continue
        _add(loaded, m)

    bad: List[Dict[str, Any]] = list(loaded)

    if same_dir_only and not want_dirty and max_same > 0 and len(loaded) > max_same:
        proc["_sideload_multi_dll"] = True
        proc["_sideload_siblings"] = list(loaded)
        return []

    if same_dir_only and not loaded and require_loaded:
        # 同目录规则要求真加载：无 modules 证据不定罪
        return []

    if same_dir_only and not loaded and isinstance(report, dict) and not want_dirty:
        hosts: List[str] = []
        if host:
            hosts.append(host)
        for p in _exe_paths_from_item(proc, _proc_cmd(proc)):
            if p and p.lower() not in {h.lower() for h in hosts}:
                hosts.append(p)
        try:
            _hydrate_entity_dir_files(report)
        except Exception:
            pass
        sibs: List[Dict[str, Any]] = []
        for h in hosts:
            for f in _unsigned_siblings_entity(report, h) or []:
                if not isinstance(f, dict):
                    continue
                fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
                if exclude_sys and fp and _path_is_system(fp):
                    continue
                ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
                if ext not in ("dll", "sys", "ocx"):
                    continue
                _add(sibs, f)
            if sibs:
                break
        if max_same > 0 and len(sibs) > max_same:
            proc["_sideload_multi_dll"] = True
            proc["_sideload_siblings"] = list(sibs)
            return []
        bad = sibs
        if bad:
            proc["_sideload_siblings"] = list(bad)
    elif same_dir_only and loaded:
        # 已加载仅 1 个未签 DLL 时，仍用磁盘同目录未签兄弟数校验：
        # 火绒/CEF 等常只加载 7z.dll，但目录里堆满未签 dll → 厂商树，不定白加黑。
        if isinstance(report, dict) and max_same > 0 and not want_dirty and host:
            try:
                _hydrate_entity_dir_files(report)
            except Exception:
                pass
            disk: List[Dict[str, Any]] = []
            disk_seen: Set[str] = set()
            for f in _unsigned_siblings_entity(report, host) or []:
                if not isinstance(f, dict):
                    continue
                fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
                if exclude_sys and fp and _path_is_system(fp):
                    continue
                ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
                if ext not in ("dll", "sys", "ocx"):
                    continue
                key = fp.lower()
                if not key or key in disk_seen:
                    continue
                disk_seen.add(key)
                disk.append(f)
            if len(disk) > max_same:
                proc["_sideload_multi_dll"] = True
                proc["_sideload_siblings"] = list(disk)
                return []
        proc["_sideload_siblings"] = list(loaded)
        proc["_sideload_loaded_only"] = True

    if bad and cross_dir_only and isinstance(report, dict):
        try:
            cross_max = int(rule.get("moduleMaxDirFiles") or 0)
        except (TypeError, ValueError):
            cross_max = 0
        if max_same > 0 and len(bad) > max_same:
            proc["_sideload_multi_dll"] = True
            proc["_sideload_siblings"] = list(bad)
            return []
        if cross_max > 0:
            try:
                _hydrate_entity_dir_files(report)
            except Exception:
                pass
            kept = []
            for m in bad:
                mp = _module_path(m) or _norm_path(str(m.get("full_path") or m.get("path") or ""))
                n = _dir_file_count_entity(report, mp) if mp else 0
                if n == 0 or n <= cross_max:
                    kept.append(m)
            if not kept:
                proc["_sideload_large_dir"] = True
                proc.pop("_sideload_siblings", None)
                return []
            bad = kept
        proc["_sideload_cross_dir"] = True
        proc["_sideload_siblings"] = list(bad)
    if bad and _vendor_signed_peer_suppress(proc, rule, report, bad):
        proc.pop("_sideload_siblings", None)
        return []
    if bad and not _large_dir_sideload_ok(proc, rule, report, bad):
        # 大目录零星未签：硬抑制（不再降级告警）
        proc.pop("_sideload_siblings", None)
        return []
    return bad


def _process_host_signed_ok(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
) -> bool:
    """requireHostSigned：与持久化白加黑一致。

    True=已签；False=明确未签（拦）；None/漏检时若还要求未签模块则放行（靠同目录未签定罪）。
    """
    if not (rule.get("requireHostSigned") or rule.get("requireSigned")):
        return True
    host = _proc_path(proc)
    hs = _host_signed_for_sideload(proc, report, host) if host else None
    if hs is True:
        return True
    if hs is False:
        return False
    # 漏检 / Run 路径与磁盘不一致：有未签同目录证据时仍可判（CloudAdapter→2131231.exe）
    if rule.get("requireUnsignedModule") or rule.get("hasUnsignedModule"):
        return True
    st = str(proc.get("sig_status") or proc.get("SigStatus") or "").strip().lower()
    return proc.get("signed") is True or st in ("valid", "signed") or ("valid" in st and "invalid" not in st)


def _process_title(rule: Dict[str, Any], proc: Dict[str, Any]) -> str:
    raw = str(rule.get("name") or "可疑进程").strip() or "可疑进程"
    payload = os.path.basename(_proc_path(proc)) or _proc_name(proc)
    if payload and payload.lower() not in raw.lower():
        return f"{raw} · {payload}"
    return raw


def _process_evidence(proc: Dict[str, Any]) -> str:
    name = _proc_name(proc)
    pid = proc.get("pid") if proc.get("pid") is not None else proc.get("PID")
    path = _proc_path(proc)
    cmd = _proc_cmd(proc)
    base = f"{name or 'process'}"
    if pid not in (None, "", 0, "0"):
        base += f" (PID {pid})"
    if path:
        base += f" => {path}"
    if cmd and _norm_path(cmd).lower() != path.lower():
        base += f" | {cmd}"
    return base[:2000]



def _is_dirty_sideload_rule(rule: Dict[str, Any]) -> bool:
    """脏路径侧载：证据标题用「黑DLL」（同目录未签仍用「未签名文件」）。"""
    if not isinstance(rule, dict):
        return False
    rid = str(rule.get("id") or "").lower()
    if "dirty" in rid:
        return True
    if rule.get("moduleDirtyPath") or rule.get("requireDirtyModulePath"):
        return True
    return False


def _sideload_evidence(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
) -> str:
    base = _process_evidence(proc)
    mods = _unsigned_modules(proc, rule, report)[:12]
    if not mods:
        return base
    bits = []
    for m in mods:
        nm = str(m.get("name") or "").strip() or os.path.basename(
            _module_path(m) or str(m.get("full_path") or "")
        ) or "module"
        mp = _module_path(m) or _norm_path(str(m.get("full_path") or m.get("path") or ""))
        st = str(m.get("sig_status") or m.get("SigStatus") or ("unsigned" if _is_unsigned(m) else ""))
        bits.append(f"{nm} [{st}]" + (f" @ {mp}" if mp else ""))
    # 脏路径 →「黑DLL」；同目录未签 →「未签名文件」
    label = "黑DLL" if _is_dirty_sideload_rule(rule) else "未签名文件"
    return (base + f"\n{label}:\n- " + "\n- ".join(bits))[:4000]


def _rule_looks_like_process(rule: Dict[str, Any]) -> bool:
    apply = [str(x).lower() for x in _as_list(rule.get("applyTo"))]
    if any(x in ("process", "processes", "running_process", "running_processes") for x in apply):
        return True
    blob = f"{rule.get('name') or ''} {rule.get('id') or ''}".lower()
    return "process" in blob or "进程" in blob


def _rule_targets_process(rule: Dict[str, Any], explicit: bool = False) -> bool:
    if not isinstance(rule, dict) or rule.get("enabled") is False:
        return False
    if explicit:
        return True
    apply = [str(x).lower() for x in _as_list(rule.get("applyTo"))]
    if apply and not any(x in ("process", "processes", "running_process", "running_processes") for x in apply):
        return False
    if str(rule.get("sigmaMode") or "").lower() == "behavior":
        return _rule_looks_like_process(rule)
    return False


def _process_rule_hit(
    proc: Dict[str, Any],
    rule: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
) -> bool:
    if rule.get("enabled") is False:
        return False

    name = _proc_name(proc)
    path = _proc_path(proc)
    cmd = _proc_cmd(proc)
    parent_name = _proc_parent_name(proc)
    parent_path = _proc_parent_path(proc)
    blob = _proc_blob(proc)
    matched = False

    if rule.get("requireUnsigned") and not _is_unsigned(proc):
        return False

    if rule.get("requireHostSigned") or rule.get("requireSigned"):
        if not _process_host_signed_ok(proc, rule, report):
            return False
        matched = True

    if rule.get("requireUnsignedModule") or rule.get("hasUnsignedModule"):
        bad = _unsigned_modules(proc, rule, report)
        if not bad:
            return False
        matched = True

    parent_eq = [x.lower() for x in _as_list(rule.get("parentNameEqualsAny"))]
    if parent_eq:
        got = {parent_name.lower(), os.path.basename(parent_path).lower()}
        got.discard("")
        if not (got & set(parent_eq)):
            return False
        matched = True

    parent_any = _as_list(rule.get("parentNameContainsAny"))
    if parent_any:
        hay = f"{parent_name} {parent_path}"
        if not _contains_any(hay, parent_any):
            return False
        matched = True

    parent_not = [x.lower() for x in _as_list(rule.get("parentNameNotEqualsAny"))]
    if parent_not:
        if not parent_name and not parent_path:
            return False
        got = parent_name.lower() or os.path.basename(parent_path).lower()
        if got in parent_not:
            return False
        matched = True

    name_eq = [x.lower() for x in _as_list(rule.get("nameEqualsAny"))]
    if name_eq:
        if name.lower() not in name_eq and os.path.basename(path).lower() not in name_eq:
            return False
        matched = True

    name_any = _as_list(rule.get("nameContainsAny"))
    if name_any:
        hay = f"{name} {os.path.basename(path)}"
        if not _contains_any(hay, name_any):
            return False
        matched = True

    if rule.get("nameRegex"):
        rx = _rx(str(rule.get("nameRegex")))
        if not rx or not rx.search(f"{name} {os.path.basename(path)}"):
            return False
        matched = True

    path_any = _as_list(rule.get("pathContainsAny")) or _as_list(rule.get("imageContainsAny"))
    if path_any:
        if not _contains_any(path, path_any):
            return False
        matched = True

    path_all = _as_list(rule.get("pathContainsAll")) or _as_list(rule.get("imageContainsAll"))
    if path_all:
        if not _contains_all(path, path_all):
            return False
        matched = True

    imm = _as_list(rule.get("pathImmediateUnder"))
    if imm:
        if not _immediate_under(path, imm):
            return False
        matched = True

    path_rx = rule.get("pathRegex") or rule.get("imageRegex")
    if path_rx:
        rx = _rx(str(path_rx))
        ok = bool(rx and path and rx.search(path))
        if not ok and blob:
            # cmdline 常带引号与参数，去掉末尾 $ 再搜
            pat = str(path_rx)
            if pat.rstrip().endswith("$"):
                pat = pat.rstrip()[:-1]
            rx2 = _rx(pat) if pat != str(path_rx) else rx
            ok = bool(rx2 and rx2.search(blob))
        if not ok:
            return False
        matched = True

    path_not = _as_list(rule.get("pathNotContainsAny"))
    if path_not:
        if not path:
            return False
        if _contains_any(path, path_not):
            return False
        matched = True

    if rule.get("commandRegex"):
        rx = _rx(str(rule.get("commandRegex")))
        if not rx or not rx.search(blob):
            return False
        matched = True

    cmd_any = _as_list(rule.get("commandContainsAny")) or _as_list(rule.get("commandContains"))
    if cmd_any:
        # Sigma 导入常把 AND/OR 拍扁成一张 contains 表；进程侧至少命中 2 项才算，避免 "process" 一词误伤全部进程
        if rule.get("commandMinHits") not in (None, ""):
            try:
                need = max(1, int(rule.get("commandMinHits")))
            except (TypeError, ValueError):
                need = 1
        elif len(cmd_any) >= 2 and str(rule.get("sigmaMode") or "").lower() == "behavior":
            need = 2
        else:
            need = 1
        hay = blob.lower()
        hits = sum(1 for n in cmd_any if n and n.lower() in hay)
        if hits < need:
            return False
        matched = True

    cmd_all = _as_list(rule.get("commandContainsAll"))
    if cmd_all:
        if not _contains_all(blob, cmd_all):
            return False
        matched = True

    cmd_not = _as_list(rule.get("commandNotContains"))
    if cmd_not and _contains_any(blob, cmd_not):
        return False

    return matched


def _iter_process_rules(win: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    for rule in win.get("processRules") or []:
        if not _rule_targets_process(rule, explicit=True):
            continue
        rid = str(rule.get("id") or "")
        if rid and rid in seen_ids:
            continue
        if rid:
            seen_ids.add(rid)
        out.append(rule)
    for key in ("taskRules", "serviceRules", "startupRules"):
        for rule in win.get(key) or []:
            if not _rule_targets_process(rule, explicit=False):
                continue
            rid = str(rule.get("id") or "")
            if rid and rid in seen_ids:
                continue
            if rid:
                seen_ids.add(rid)
            out.append(rule)
    return out


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched: List[Dict[str, Any]] = []
    win = getattr(store, "windows", None)
    if not isinstance(win, dict):
        return findings, {}

    rules = _iter_process_rules(win)
    if not rules:
        return findings, {}

    processes = report.get("processes") or []
    if not isinstance(processes, list):
        return findings, {}

    # 进程模块采集常把已签 DLL 标成 signed=false/空状态；用文件清单 Valid 回填后再判白加黑
    try:
        enrich_processes_module_sigs(report)
    except Exception:
        pass
    # 同目录 DirSnap：供白加黑在「未加载模块」场景仍可命中
    try:
        _hydrate_entity_dir_files(report)
    except Exception:
        pass

    for proc in processes:
        if not isinstance(proc, dict):
            continue
        name = _proc_name(proc)
        path = _proc_path(proc)
        cmd = _proc_cmd(proc)
        if not (name or path or cmd):
            continue
        rule = _pick(rules, lambda r, p=proc: _process_rule_hit(p, r, report))
        if not rule:
            continue
        title = _process_title(rule, proc)
        sev = str(rule.get("severity") or "high")
        # 大目录零星未签：降为 medium（可疑）
        cap = str(proc.get("_sideload_severity_cap") or "").strip().lower()
        if cap in ("medium", "low", "info") and proc.get("_sideload_large_dir"):
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            if order.get(sev.lower(), 1) < order.get(cap, 2):
                sev = cap
        pid = proc.get("pid") if proc.get("pid") is not None else proc.get("PID") or ""
        key = f"可疑进程|{title}|{pid}|{name}|{path}|{cmd}"
        if key in seen:
            continue
        seen.add(key)
        ev = (
            _sideload_evidence(proc, rule, report)
            if (rule.get("requireUnsignedModule") or rule.get("hasUnsignedModule"))
            else _process_evidence(proc)
        )
        if proc.get("_sideload_large_dir") and (rule.get("requireUnsignedModule") or rule.get("hasUnsignedModule")):
            n_dir = proc.get("_sideload_dir_files")
            tip = "大型软件目录内零星未签 PE，已降级为可疑"
            if n_dir:
                tip += f"（目录约 {n_dir} 个文件）"
            ev = (ev + f"\n备注: {tip}")[:4000]
        matched.append({
            "type": "process",
            "pid": pid,
            "name": name,
            "path": path,
            "command_line": cmd,
            "rule": title,
            "rule_id": rule.get("id"),
        })
        findings.append(Finding(
            "可疑进程",
            sev,
            title,
            ev,
            "进程",
            str(rule.get("id") or "windows.process"),
            "windows_process",
            extra={
                "pid": pid,
                "ppid": proc.get("ppid") if proc.get("ppid") is not None else proc.get("PPID"),
                "name": name,
                "path": path,
                "command_line": cmd,
                "user": proc.get("user") or proc.get("User") or "",
                "signed": proc.get("signed"),
                "sig_status": proc.get("sig_status") or proc.get("SigStatus"),
                "parent_name": _proc_parent_name(proc),
                "parent_path": _proc_parent_path(proc),
                "sideload": bool(rule.get("requireUnsignedModule") or rule.get("hasUnsignedModule")),
                "large_dir_sideload": bool(proc.get("_sideload_large_dir")),
            },
        ))

    return findings, {"matched_processes": matched}
