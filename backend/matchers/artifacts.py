"""Prefetch / 浏览器路径 / 注册表产物 / 回收站 / hosts+DNS — 吃灰字段启用"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore


BROWSER_PATH_HINTS = [
    ("History", "浏览器History"),
    ("Login Data", "浏览器Login Data"),
    ("Cookies", "浏览器Cookies"),
    ("Web Data", "浏览器Web Data"),
    ("places.sqlite", "Firefox书签/历史"),
]

_RX_CACHE: Dict[str, Optional[re.Pattern]] = {}


def _rx(pat: str) -> Optional[re.Pattern]:
    if not pat:
        return None
    if pat not in _RX_CACHE:
        try:
            _RX_CACHE[pat] = re.compile(pat, re.I)
        except re.error:
            _RX_CACHE[pat] = None
    return _RX_CACHE[pat]


def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)] if str(v).strip() else []


def _contains_any(text: str, needles: List[str]) -> bool:
    if not needles:
        return False
    tl = text.lower()
    return any(n.lower() in tl for n in needles if n)


def _contains_all(text: str, needles: List[str]) -> bool:
    if not needles:
        return False
    tl = text.lower()
    return all(n.lower() in tl for n in needles if n)


# 这些来源只是"程序运行过/被打开过"的历史痕迹，不代表当前注册表里存在该配置。
# 拿它们去判 COM 劫持、服务路径、代理 DLL 只会把 Office/Chrome 之类的正常程序算成持久化。
_HISTORY_LABELS = (
    "shimcache", "bam", "muicache", "appcompatcache", "appcompat",
    "amcache", "recentdocs", "userassist",
)

_CLSID_GUID_RE = re.compile(
    r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
)
_MS_CLSID_HINTS = (
    "00021401-0000-0000-c000-000000000046",  # shortcut
    "20d04fe0-3aea-1069-a2d8-08002b30309d",  # my computer
    "208d2c60-3aea-1069-a2d7-08002b30309d",  # network
    "645ff040-5081-101b-9f08-00aa002f954e",  # recycle
    "450d8fba-ad25-11d0-98a8-0800361b1103",  # docs
)
_MALICIOUS_CLSID = (
    "18907f3b-9afb-4f87-b764-f9a4e16a21b8",
    "73e709ea-5d93-4b2e-bbb0-99b7930da7e1",
)
_CLSID_RISK_RULE_IDS = (
    "reg.apt.CLSID_Persistence_LowFP",
    "reg.apt.CLSID_Shell_Manage_Hijack",
)
_COM_SERVER_KEYS = (
    "\\inprocserver32", "\\localserver32", "\\inprochandler32", "\\treatas",
)


def _is_clsid_com_persistence_key(key_lower: str, source_lower: str) -> bool:
    """CLSID 下 COM 持久化相关键：Server32/TreatAs，或 Shell 命名空间 verb（explorer shell:{guid}）。"""
    blob = f"{key_lower}|{source_lower}"
    if any(p in blob for p in _COM_SERVER_KEYS):
        return True
    if "clsid" not in blob:
        return False
    # 不限定目录名（OperaVPN/OpenraVPN 等均可变）；只看 CLSID + Shell + command 形态
    if "\\shell\\" in blob and "\\command" in blob:
        return True
    return False


# COM 载荷常见落地：ProgramData（见 _com_in_high_risk_dir）、Temp、AppData
_COM_WEAK_PROGRAMDATA = (
    "c:\\programdata\\microsoft\\visualstudio\\",
    "c:\\programdata\\microsoft\\windows defender\\",
    "c:\\programdata\\tencent\\",
    "c:\\programdata\\a-volute\\",
)
_COM_HIGH_RISK_DIRS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\downloads\\",
)
_COM_SUS_EXTS = (".dat", ".tmp", ".cache", ".bin")
_COM_TRUSTED_USER = (
    "\\appdata\\local\\microsoft\\onedrive\\",
    "\\appdata\\local\\microsoft\\edge\\",
    "\\appdata\\local\\microsoft\\teams\\",
    "\\appdata\\local\\microsoft\\office\\",
    "\\appdata\\roaming\\microsoft\\office\\",
    "\\appdata\\local\\microsoft\\windowsapps\\",
    "\\google\\chrome\\",
    "\\google\\drive\\",
    "\\mozilla\\firefox\\",
    "\\kingsoft\\wps office\\",
    "\\kingsoft\\office\\",
    "\\tencent\\",
)


def _extract_com_payload_path(data: str) -> str:
    """从 LocalServer32/InprocServer32 值抽出文件路径。"""
    s = str(data or "").strip().strip('"')
    if not s or s in ("-", "—"):
        return ""
    # 取第一个盘符绝对路径
    m = re.search(r"((?:[A-Za-z]:\\|\\\\)[^\"'<>|\r\n]+)", s)
    if m:
        s = m.group(1).strip().strip('"')
    # 去掉后续参数
    s = re.split(r"\s+--|\s+-", s, maxsplit=1)[0].strip().strip('"')
    s = s.replace("/", "\\")
    s = re.sub(r"\\+", r"\\", s)
    return s


def _norm_win_path_lower(p: str) -> str:
    s = str(p or "").lower().replace("/", "\\")
    return re.sub(r"\\+", r"\\", s)


# 从注册表 data / 启动命令中抽出 exe/dll 路径
_BIN_PATH_IN_TEXT = re.compile(
    r'(?i)(?:"([^"]+\.(?:exe|dll|sys|scr|com))"|((?:[a-z]:\\|\\\\)[^\s"]+\.(?:exe|dll|sys|scr|com)))'
)


def _extract_bin_path_from_text(text: str) -> str:
    m = _BIN_PATH_IN_TEXT.search(str(text or ""))
    if not m:
        return ""
    return (m.group(1) or m.group(2) or "").strip().strip('"')


def _reg_unsigned_gate_ok(
    rule: Dict,
    item: Dict,
    sig_index: Optional[Dict[str, Dict[str, Any]]],
    report: Optional[Dict] = None,
) -> bool:
    """requireUnsigned / UOS：仅在路径已证实未签（或已签+同目录未签 dll）时才允许告警。"""
    need_u = bool(rule.get("requireUnsigned"))
    need_uos = bool(rule.get("requireUnsignedOrUnsignedSibling"))
    if not need_u and not need_uos:
        return True
    path = _extract_bin_path_from_text(str(item.get("data") or ""))
    if not path:
        # AppInit 等可能是相对名 dll；采集端已写入 signed/sig_status
        if need_u and isinstance(item, dict) and item.get("signed") is False:
            st = str(item.get("sig_status") or item.get("SigStatus") or "").strip().lower()
            if st in ("notsigned", "unsigned", "invalid", "hashmismatch", "error", "nottrusted"):
                return True
        return False
    pl = _norm_win_path_lower(path)
    obj: Dict[str, Any] = {}
    # 采集侧已写入的 RegKey.signed / sig_status 优先
    if isinstance(item, dict):
        obj = {
            k: item[k]
            for k in ("signed", "sig_status", "SigStatus", "signer", "Signer")
            if k in item and item.get(k) is not None
        }
    if sig_index and pl in sig_index:
        indexed = dict(sig_index[pl])
        obj = {**indexed, **obj}
    if report:
        for si in report.get("startup_items") or []:
            if not isinstance(si, dict):
                continue
            sp = _norm_win_path_lower(str(si.get("path") or si.get("resolved_path") or ""))
            cmd_l = _norm_win_path_lower(str(si.get("command") or ""))
            if pl and (sp == pl or pl in cmd_l):
                # 启动项签名字段优先覆盖索引里的 unknown
                merged = {**obj, **si}
                obj = merged
                break
    try:
        from . import persistence as P
    except Exception:
        return False
    fake = {
        **(obj if isinstance(obj, dict) else {}),
        "path": path,
        "command": item.get("data"),
        "image_path": path,
    }
    if need_uos:
        return P._unsigned_or_unsigned_sibling_ok(
            fake, str(item.get("data") or ""), rule, report,
            explicit_only=bool(rule.get("uosExplicitOnly")),
        )
    return P._is_unsigned(fake)


def _is_ms_clsid(text: str) -> bool:
    low = (text or "").lower()
    return any(x in low for x in _MS_CLSID_HINTS)


def _com_payload_is_bin(path: str) -> bool:
    low = _norm_win_path_lower(path)
    return low.endswith(".exe") or low.endswith(".dll") or low.endswith(".sys")


def _com_in_high_risk_dir(path_lower: str) -> bool:
    if any(d in path_lower for d in _COM_HIGH_RISK_DIRS):
        return True
    if "\\programdata\\" in path_lower and not any(path_lower.startswith(w) for w in _COM_WEAK_PROGRAMDATA):
        return True
    return False


def _sig_state_from_obj(obj: Optional[Dict[str, Any]]) -> str:
    """返回 signed / unsigned / unknown。"""
    if not isinstance(obj, dict):
        return "unknown"
    if obj.get("signed") is True:
        return "signed"
    st = str(
        obj.get("sig_status") or obj.get("SigStatus") or obj.get("signature_status") or ""
    ).strip().lower()
    if st in ("valid", "signed") or ("valid" in st and "invalid" not in st and "not" not in st):
        return "signed"
    if obj.get("signed") is False:
        return "unsigned"
    if st in ("missing", "notsigned", "unsigned", "invalid", "error", "hashmismatch", "nottrusted"):
        return "unsigned"
    if st in ("", "-", "—", "unchecked", "unknown", "none", "n/a"):
        return "unknown"
    return "unknown"


def _build_path_sig_index(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """从 file_scans / 进程模块 / files 表建路径→签名索引，供 CLSID 载荷查签名。"""
    idx: Dict[str, Dict[str, Any]] = {}

    def put(path: str, obj: Dict[str, Any]) -> None:
        p = _norm_win_path_lower(path)
        if not p or not _com_payload_is_bin(p):
            return
        prev = idx.get(p)
        # 已有明确 signed/unsigned 时不覆盖成 unknown
        if prev and _sig_state_from_obj(prev) != "unknown" and _sig_state_from_obj(obj) == "unknown":
            return
        idx[p] = obj

    for f in report.get("file_scans") or []:
        if isinstance(f, dict):
            put(str(f.get("full_path") or f.get("path") or ""), f)
    for si in report.get("startup_items") or []:
        if isinstance(si, dict):
            put(str(si.get("path") or si.get("resolved_path") or ""), si)
            cmd = str(si.get("command") or "")
            m = _BIN_PATH_IN_TEXT.search(cmd)
            if m:
                put((m.group(1) or m.group(2) or ""), si)
    for proc in report.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        put(str(proc.get("path") or proc.get("exe") or ""), proc)
        for m in proc.get("modules") or proc.get("Modules") or []:
            if isinstance(m, dict):
                put(str(m.get("path") or m.get("Path") or ""), m)
            elif isinstance(m, str):
                put(m, {"path": m})

    # file_scans 已剥离时：按需从 files 表补签名（CLSID / Path 劫持依赖）
    rid = str(report.get("_rid") or report.get("_files_rid") or "").strip()
    if rid and report.get("_files_ingested") and not (report.get("file_scans") or []):
        need = [p for p, obj in idx.items() if _sig_state_from_obj(obj) == "unknown"]
        if need:
            try:
                from ..db_store import lookup_file_sigs_by_paths
                for fp, meta in (lookup_file_sigs_by_paths(rid, need[:800]) or {}).items():
                    if isinstance(meta, dict):
                        put(fp, meta)
            except Exception:
                pass
    return idx


def _build_file_path_set(report: Dict[str, Any]) -> Set[str]:
    paths: Set[str] = set()
    for f in report.get("file_scans") or []:
        if isinstance(f, dict):
            p = _norm_win_path_lower(str(f.get("full_path") or f.get("path") or ""))
            if p:
                paths.add(p)
    # 入库后 file_scans 为空：用高价值目录抽样补路径集合，供 Path 劫持判定
    if not paths:
        rid = str(report.get("_rid") or report.get("_files_rid") or "").strip()
        if rid and (report.get("_files_ingested") or int(report.get("_files_count") or 0) > 0):
            try:
                from ..db_store import query_files
                for hint in (
                    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\",
                    "\\users\\public\\", "\\appdata\\",
                ):
                    for row in query_files(rid, path_contains=hint, limit=400) or []:
                        p = _norm_win_path_lower(str(row.get("full_path") or row.get("path") or ""))
                        if p:
                            paths.add(p)
            except Exception:
                pass
    return paths


def _clsid_persistence_lowfp_eval(
    label: str,
    item: Dict,
    rule: Dict,
    sig_index: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """移植 0707 CLSID LowFP，并按签名分级：

    - 已签名 → 不输出（含高危目录；用户要求已签名一律不报）
    - 未签名 → high
    - 未知签名：路径脏才报 high，否则放行
    """
    key = str(item.get("key") or "")
    val = str(item.get("value") or "")
    data = str(item.get("data") or "")
    source = f"{label}|{key}|{val}".lower()
    key_lower = key.lower()
    source_lower = source.lower()
    if "clsid" not in source_lower and "clsid" not in key_lower:
        return None

    if not _is_clsid_com_persistence_key(key_lower, source_lower):
        return None

    path = _extract_com_payload_path(data)
    path_lower = _norm_win_path_lower(path)
    treatas = "\\treatas" in source or "\\treatas" in key.lower()

    for guid in _MALICIOUS_CLSID:
        if guid in source or guid in key.lower():
            return {
                "severity": "high",
                "path": path,
                "sig": "malicious_clsid",
                "in_high_risk": True,
                "note": "已知恶意 CLSID",
            }

    # System32 / SysWOW64 硬放行
    if "\\windows\\system32\\" in path_lower or "\\windows\\syswow64\\" in path_lower:
        return None
    if path_lower.startswith("c:\\windows\\system32\\") or path_lower.startswith("c:\\windows\\syswow64\\"):
        return None

    # 用户目录可信产品树
    if any(t in path_lower for t in _COM_TRUSTED_USER):
        return None
    if "\\windowsapps\\" in path_lower:
        return None

    # TreatAs 指向 GUID：按原评分；非文件载荷
    if treatas and not _com_payload_is_bin(path):
        risk = 0
        if _CLSID_GUID_RE.search(data or path):
            risk += 40 if _is_ms_clsid(data or path) else 80
        else:
            risk += 80
        if risk < int(rule.get("riskThreshold") or 50):
            return None
        return {
            "severity": "high",
            "path": path or data,
            "sig": "treatas",
            "in_high_risk": True,
            "note": "TreatAs 异常",
        }

    # 只对 exe/dll/sys 做签名分级输出
    if path and not _com_payload_is_bin(path):
        # 可疑扩展仍可按旧风险模型
        risk = 0
        for ext in _COM_SUS_EXTS:
            if path_lower.endswith(ext):
                risk += 30
                break
        if _com_in_high_risk_dir(path_lower):
            risk += 50
        if risk < int(rule.get("riskThreshold") or 50):
            return None
        return {
            "severity": "high",
            "path": path,
            "sig": "unusual_ext",
            "in_high_risk": _com_in_high_risk_dir(path_lower),
            "note": "非 exe/dll/sys 可疑扩展",
        }

    if not path:
        return None

    # 路径基础分：至少要像 COM 持久化候选（高危目录 / PF 非微软 / ShellEx）
    risk = 0
    in_hr = _com_in_high_risk_dir(path_lower)
    if in_hr:
        risk += 50
    if path_lower.startswith("c:\\program files\\") or path_lower.startswith("c:\\program files (x86)\\"):
        risk += 30
    if "shellex" in source_lower and ("hkey_current_user" in source_lower or "hkcu" in source_lower or "\\user\\" in source_lower):
        risk += 50
    if "\\shell\\" in key_lower and "\\command" in key_lower and "clsid" in key_lower:
        risk += 55
        in_hr = in_hr or _com_in_high_risk_dir(path_lower)

    # 查签名：item 自身 → 路径索引
    sig_obj = item
    st = _sig_state_from_obj(item)
    if st == "unknown" and sig_index:
        hit = sig_index.get(path_lower)
        if hit:
            sig_obj = hit
            st = _sig_state_from_obj(hit)

    # 已签名一律不输出（含 Temp/Public 等「高危目录」上的正签软件）
    if st == "signed":
        return None

    threshold = int(rule.get("riskThreshold") or 50)

    # 未签名 / 未知签名
    if risk < threshold and not in_hr:
        # 未知签名且路径不脏：不报，避免海量未知
        if st == "unknown":
            return None
        # 明确未签名：即使不在高危目录也报高危（COM 指向未签 exe/dll）
        return {
            "severity": "high",
            "path": path,
            "sig": "unsigned",
            "in_high_risk": False,
            "note": "未签名 exe/dll/sys",
            "sig_status": sig_obj.get("sig_status") or sig_obj.get("SigStatus") or "NotSigned",
        }

    return {
        "severity": "high",
        "path": path,
        "sig": st,
        "in_high_risk": in_hr,
        "note": "未签名或签名未知" + ("，且位于高危目录" if in_hr else ""),
        "sig_status": sig_obj.get("sig_status") or sig_obj.get("SigStatus") or st,
    }


def _clsid_persistence_lowfp_hit(label: str, item: Dict, rule: Dict) -> bool:
    return _clsid_persistence_lowfp_eval(label, item, rule) is not None


def _clsid_rule_key_ok(item: Dict, rule: Dict) -> bool:
    """clsid_risk_score 规则可选 keyContainsAny（如专打 Shell\\Manage\\command）。"""
    needles = _as_list(rule.get("keyContainsAny"))
    if not needles:
        return True
    key = str(item.get("key") or "")
    blob = f"{key}|{item.get('value') or ''}|{item.get('data') or ''}"
    return _contains_any(key, needles) or _contains_any(blob, needles)


_NORMAL_STARTUP_FOLDER_MARKERS = (
    r"\appdata\roaming\microsoft\windows\start menu\programs\startup",
    r"\programdata\microsoft\windows\start menu\programs\startup",
)


def _expand_shell_folder_path(raw: str) -> str:
    s = str(raw or "").strip().lower().replace("/", "\\")
    s = s.replace("%programdata%", r"c:\programdata")
    s = s.replace("%appdata%", r"c:\users\appdata\roaming")
    s = s.replace("%userprofile%", r"c:\users")
    return s


def _is_normal_startup_folder(data: str) -> bool:
    exp = _expand_shell_folder_path(data)
    return any(m in exp for m in _NORMAL_STARTUP_FOLDER_MARKERS)


def _startup_folder_hijack_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    """银狐：User Shell Folders\\Startup 被改到非标准目录。"""
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "startup_folder_hijack" and rid != "reg.sf.startup_folder_hijack":
        return None
    val = str(item.get("value") or "").strip()
    if val.lower() not in ("startup", "common startup"):
        return None
    data = str(item.get("data") or "").strip()
    if not data or _is_normal_startup_folder(data):
        return None
    kpath = str(item.get("key") or label or "")
    return {
        "path": data,
        "value_name": val,
        "location": kpath,
        "note": "启动目录被篡改到非标准位置，系统将从该路径加载启动项",
    }


def _startup_folder_hijack_hit(label: str, item: Dict, rule: Dict) -> bool:
    return _startup_folder_hijack_eval(label, item, rule) is not None


def _normalize_pending_path(p: str) -> str:
    s = str(p or "").strip()
    s = re.sub(r"^\?\?\\", "", s, flags=re.I)
    return s.lower().replace("/", "\\")


def _is_pending_startup_path(p: str) -> bool:
    n = _normalize_pending_path(p)
    return (
        r"\start menu\programs\startup" in n
        or n.endswith(r"\start menu\programs\startup")
        or r"\programs\startup" in n
    )


def _is_av_canary_pending(source: str, dest: str) -> bool:
    src = _normalize_pending_path(source)
    dst = _normalize_pending_path(dest)
    base = src.rsplit("\\", 1)[-1] if src else dst.rsplit("\\", 1)[-1]
    if base.startswith("!!!"):
        return True
    if not dst.strip() and r"\start menu" in src and not _is_pending_startup_path(src):
        low = base.lower()
        if not any(low.endswith(ext) for ext in (".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".vbs", ".js", ".ps1", ".lnk")):
            return True
    return False


def _pending_file_rename_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "pending_file_rename" and rid != "reg.sf.pending_file_rename":
        return None
    if str(item.get("value") or "").lower() != "pendingfilerenameoperations":
        return None
    raw = str(item.get("data") or "")
    if not raw.strip():
        return None
    suspicious_patterns = (
        r"\start menu\programs\startup",
        r".wofld",
        r"o:\\",
    )
    hits: List[str] = []
    for chunk in re.split(r"\s*\|\s*", raw):
        chunk = chunk.strip()
        if " -> " not in chunk:
            continue
        src, dst = chunk.split(" -> ", 1)
        if _is_av_canary_pending(src, dst):
            continue
        pair_l = _normalize_pending_path(src) + " -> " + _normalize_pending_path(dst)
        if any(p in pair_l for p in suspicious_patterns) or _is_pending_startup_path(src) or _is_pending_startup_path(dst):
            hits.append(chunk)
    if not hits:
        return None
    return {"pairs": hits[:8], "note": "银狐 PendingFileRenameOperations 无痕写入启动目录"}


def _dos_devices_hijack_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "dos_devices_hijack" and rid != "reg.sf.dos_devices":
        return None
    data = str(item.get("data") or "").strip()
    if not data:
        return None
    low = data.lower()
    markers = (
        r"\programdata\microsoft\windows\start menu\programs",
        r"\appdata\roaming\microsoft\windows\start menu\programs",
        r"\users\\",
        r"\programdata\\",
    )
    if not any(m in low for m in markers):
        return None
    return {
        "device": str(item.get("value") or ""),
        "target": data,
        "note": "虚拟设备映射到敏感目录，可能绕过启动目录监控",
    }


def _userinit_mpr_logon_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "userinit_mpr_logon" and rid != "reg.sf.userinit_mpr":
        return None
    if not _is_environment_key(label, item):
        return None
    val = str(item.get("value") or "")
    data = str(item.get("data") or "").strip()
    if not data:
        return None
    vlow = val.lower()
    if not (
        vlow in ("userinitmprlogonscript", "userinit", "userlnitmprlogonscript")
        or "userinit" in vlow
        or "userlnit" in vlow
    ):
        return None
    suspicious_exts = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")
    chunks = re.split(r"[;|]", data) if re.search(r"[;|]", data) else [data]
    for chunk in chunks:
        pl = chunk.strip().strip('"').lower()
        if any(ext in pl for ext in suspicious_exts):
            return {"script": data, "value_name": val, "note": "UserinitMprLogonScript 登录脚本持久化"}
    return None


_HEX16_RE = re.compile(r"^[0-9a-fA-F]{16}$")


def _silverfox_hex_key_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "silverfox_hex_key" and rid != "reg.sf.hkcu_hex_key":
        return None
    val = str(item.get("value") or "").strip()
    if not _HEX16_RE.match(val):
        return None
    if "plug" in str(item.get("key") or "").lower():
        return None
    data = str(item.get("data") or "").strip()
    return {"hex_key": val, "config": data[:200], "note": "银狐 RAT 16 位 hex 随机配置键"}


def _silverfox_space_key_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "silverfox_space_key" and rid != "reg.sf.hkcu_space_key":
        return None
    data = str(item.get("data") or "")
    key = str(item.get("key") or "")
    if "trailing space" not in data.lower() and not (key.endswith(" ") or key.rstrip() != key):
        return None
    return {"key": key, "note": "HKCU 根键名尾空格（银狐配置特征）"}


def _silverfox_plug_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "silverfox_plug" and rid != "reg.sf.plug_key":
        return None
    if "plug" not in str(item.get("key") or "").lower():
        return None
    return {"path": str(item.get("key") or ""), "note": "银狐 RAT PLUG 插件配置子键"}


def _ntuser_man_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "ntuser_man" and rid != "reg.sf.ntuser_man":
        return None
    if str(item.get("value") or "").lower() != "ntuser.man":
        return None
    return {
        "user_home": str(item.get("key") or ""),
        "note": str(item.get("data") or "NTUSER.MAN 强制配置"),
    }


# --- Environment Path 劫持（0707 collectSessionManagerPathHijackSegments） ---
_REG_RUN_CTX: Dict[str, Any] = {}

_PATH_HIJACK_WHITELIST_PREFIXES = (
    r"c:\python", r"c:\java\\", r"c:\jdk", r"c:\jre",
    r"c:\program files\nodejs\\", r"c:\ruby", r"c:\perl",
    r"c:\program files\go\\", r"c:\rust", r"c:\program files\git\\",
    r"c:\windows\\", r"c:\program files\\", r"c:\programdata\chocolatey\\",
    r"c:\program files\mitmproxy\\",
)
_PATH_HIJACK_VENDOR_PREFIXES = (
    r"c:\programdata\securecenter\modules\vrv\\",
    r"c:\programdata\kaspersky lab\\", r"c:\programdata\360\\",
    r"c:\programdata\kingsoft\\", r"c:\programdata\nvidia corporation\\",
    r"c:\programdata\intel\\",
)
_PATH_HIJACK_JUNK_MARKERS = (
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\",
    "\\users\\public\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\temp\\",
)
_PATH_HIJACK_USER_TOOL_SUFFIXES = (
    r"\appdata\local\programs\\",
    r"\appdata\local\microsoft\windowsapps",
    r"\go\bin", r"\appdata\roaming\npm", r"\appdata\roaming\cargo\bin",
    r"\appdata\local\pnpm", r"\appdata\local\yarn\bin",
    r"\.dotnet\tools", r"\.local\bin",
)
_PATH_HIJACK_TOOLCHAIN_BIN = (
    "python.exe", "pythonw.exe", "python3.exe", "node.exe", "go.exe",
    "java.exe", "javac.exe", "php.exe", "ruby.exe", "cargo.exe",
    "rustc.exe", "dotnet.exe", "git.exe",
)
_PATH_HIJACK_SYSTEM_BINS = (
    "cmd.exe", "net.exe", "net1.exe", "tasklist.exe", "reg.exe",
    "sc.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "powershell.exe", "pwsh.exe",
)


def _expand_path_segment(raw: str) -> str:
    s = str(raw or "").strip().strip('"').replace("/", "\\")
    low = s.lower()
    low = low.replace("%userprofile%", r"c:\users\__user__")
    low = low.replace("%programdata%", r"c:\programdata")
    low = low.replace("%appdata%", r"c:\users\__user__\appdata\roaming")
    return low


def _is_legit_absolute_user_tool_path(p: str) -> bool:
    p = _expand_path_segment(p)
    m = re.match(r"^[a-z]:\\users\\[^\\]+(.*)$", p, re.I)
    if not m:
        return False
    after_user = m.group(1).lower()
    for pref in _PATH_HIJACK_USER_TOOL_SUFFIXES:
        trim = pref.rstrip("\\")
        if after_user == pref or after_user.startswith(pref):
            return True
        if after_user == trim or after_user.startswith(trim + "\\"):
            return True
    return False


def _path_segment_has_system_binary_drop(segment: str, file_paths: Set[str]) -> bool:
    base = _norm_win_path_lower(_expand_path_segment(segment)).rstrip("\\")
    if not base:
        return False
    for name in _PATH_HIJACK_SYSTEM_BINS:
        if base + "\\" + name in file_paths:
            return True
    return False


def _is_toolchain_user_path_segment(p: str, file_paths: Set[str]) -> bool:
    p = _expand_path_segment(p)
    if _is_legit_absolute_user_tool_path(p):
        return True
    if re.search(r"\\appdata\\local\\programs\\python\\", p, re.I):
        return True
    if re.search(r"\\appdata\\local\\python\\", p, re.I):
        return True
    if re.search(r"\\appdata\\roaming\\python\\", p, re.I):
        return True
    base = p.rstrip("\\")
    for name in _PATH_HIJACK_TOOLCHAIN_BIN:
        if _norm_win_path_lower(base + "\\" + name) in file_paths:
            return True
    return False


def _is_junk_user_path_segment(p: str) -> bool:
    p = _expand_path_segment(p)
    return any(m in p for m in _PATH_HIJACK_JUNK_MARKERS)


def _collect_environment_path_hijack_segments(full_data: str, file_paths: Set[str]) -> List[str]:
    if not str(full_data or "").strip():
        return []
    hits: List[str] = []
    for raw in str(full_data).split(";"):
        orig = raw.strip()
        if not orig:
            continue
        if orig.lower().endswith(".exe"):
            hits.append(orig)
            continue
        p = _expand_path_segment(orig)
        skip = False
        for sd in _PATH_HIJACK_VENDOR_PREFIXES:
            if p.startswith(sd):
                skip = True
                break
        if skip:
            continue
        for white in _PATH_HIJACK_WHITELIST_PREFIXES:
            if p.startswith(white):
                skip = True
                break
        if skip:
            continue
        if _is_legit_absolute_user_tool_path(p):
            continue
        if _is_toolchain_user_path_segment(p, file_paths) and not _path_segment_has_system_binary_drop(orig, file_paths) and not _is_junk_user_path_segment(p):
            continue
        if _path_segment_has_system_binary_drop(orig, file_paths):
            hits.append(orig)
            continue
        if _is_junk_user_path_segment(p):
            hits.append(orig)
            continue
        if any(x in p for x in ("\\users\\", "\\public\\", "\\temp", "\\appdata\\", "\\desktop\\", "\\downloads\\")):
            hits.append(orig)
    return hits


def _is_environment_path_key(label: str, item: Dict) -> bool:
    if str(item.get("value") or "").strip().lower() != "path":
        return False
    kpath = str(item.get("key") or label or "").lower().replace("/", "\\")
    ll = label.lower()
    if ll == "environment":
        return True
    if "session manager\\environment" in kpath:
        return True
    if kpath == "environment" or kpath.endswith("\\environment"):
        return True
    return False


_WP_DIRTY_MARKERS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "\\programdata\\",
    "\\public\\",
    "\\perflogs\\",
    "\\downloads\\",
    "\\desktop\\",
)
_WP_PATH_ALLOW = (
    "\\windowsapps\\",
    "\\systemapps\\",
    "\\microsoft\\windows\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
)
_WP_PAYLOAD_RE = re.compile(
    r"(?i)([a-z]:\\[^\x00\r\n\"|]{3,260}?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|pbk))"
)
_WP_HEX_BYTE_RE = re.compile(r"(?i)\b([0-9a-f]{2})\b")
_WP_PATH_EXT_RE = re.compile(
    r"(?i)^[a-z]:\\.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|pbk)(?:\s|$)"
)
_WP_FAMILY_NAME_RE = re.compile(
    r"(?i)(?:SimpleActivityScheduleTimer|ShadowScheduler)[_\-{A-Fa-f0-9}]{0,80}"
)


def _wp_is_dirty_payload(path: str) -> bool:
    low = (path or "").replace("/", "\\").lower()
    if not low or "\\" not in low:
        return False
    if any(a in low for a in _WP_PATH_ALLOW):
        return False
    return any(m in low for m in _WP_DIRTY_MARKERS)


def _wp_extract_paths_from_text(text: str) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for m in _WP_PAYLOAD_RE.finditer(text or ""):
        p = (m.group(1) or "").strip().rstrip("\x00")
        if not p:
            continue
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _wp_scan_utf16le_paths(blob: bytes) -> List[str]:
    """任意字节对齐扫描 UTF-16LE 路径（结构体/.reg 续行可能打乱全局对齐）。"""
    out: List[str] = []
    seen: Set[str] = set()
    n = len(blob or b"")
    i = 0
    while i + 6 < n:
        c = blob[i]
        if (
            blob[i + 1] == 0
            and blob[i + 2 : i + 6] == b":\x00\\\x00"
            and ((ord("A") <= c <= ord("Z")) or (ord("a") <= c <= ord("z")))
        ):
            chars: List[str] = []
            j = i
            while j + 1 < n:
                lo, hi = blob[j], blob[j + 1]
                if lo == 0 and hi == 0:
                    break
                if hi != 0 or lo < 32 or lo == 0x22:  # 引号截断参数
                    break
                chars.append(chr(lo))
                j += 2
                if len(chars) > 260:
                    break
            s = "".join(chars).strip()
            low = s.lower()
            if (
                s
                and "\\" in s
                and re.search(r"\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|pbk)$", low)
                and low not in seen
            ):
                seen.add(low)
                out.append(s)
            i = j if j > i else i + 1
            continue
        i += 1
    return out


def _wp_scan_utf16le_family_name(blob: bytes) -> str:
    """在任意对齐下找 SimpleActivityScheduleTimer / ShadowScheduler。"""
    needles = (
        "SimpleActivityScheduleTimer".encode("utf-16-le"),
        "ShadowScheduler".encode("utf-16-le"),
    )
    raw = blob or b""
    for needle in needles:
        idx = raw.find(needle)
        if idx < 0:
            # 奇数对齐：隔字节插入 00 的变体不常见；再试大小写不敏感慢扫
            continue
        # 向后读到 NUL
        chars: List[str] = []
        j = idx
        while j + 1 < len(raw):
            lo, hi = raw[j], raw[j + 1]
            if lo == 0 and hi == 0:
                break
            if hi != 0 or lo < 32:
                break
            chars.append(chr(lo))
            j += 2
            if len(chars) > 96:
                break
        s = "".join(chars)
        m = _WP_FAMILY_NAME_RE.search(s)
        if m:
            return m.group(0)
    # 全局对齐解码兜底
    try:
        text = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        text = ""
    m = _WP_FAMILY_NAME_RE.search(text or "")
    return m.group(0) if m else ""


def _wp_decode_hex_blob(data: str) -> bytes:
    """解析 .reg 导出的 hex:aa,bb,cc 或空格分隔十六进制。"""
    raw = (data or "").strip()
    if not raw:
        return b""
    if raw.lower().startswith("hex:"):
        raw = raw[4:]
    # 去掉续行反斜杠与空白
    raw = raw.replace("\\", " ").replace(",", " ")
    parts = _WP_HEX_BYTE_RE.findall(raw)
    if len(parts) < 16:
        return b""
    try:
        return bytes(int(x, 16) for x in parts)
    except ValueError:
        return b""


def _wp_utf16le_to_text(blob: bytes) -> str:
    if not blob:
        return ""
    try:
        return blob.decode("utf-16-le", errors="ignore")
    except Exception:
        return ""


def _wp_payloads_from_item(item: Dict) -> List[str]:
    """采集端已解析的 Payload，或对 hex/二进制文本回退解析。"""
    data = str(item.get("data") or "").strip()
    if not data:
        return []
    paths: List[str] = []
    # 采集端：Data 形如 C:\...\a.exe 或 C:\...\a.exe | name=SimpleActivity...
    head = data.split("|", 1)[0].strip()
    if _WP_PATH_EXT_RE.match(head + " "):
        paths.append(head)
    paths.extend(_wp_extract_paths_from_text(data))
    blob = _wp_decode_hex_blob(data)
    if blob:
        paths.extend(_wp_extract_paths_from_text(_wp_utf16le_to_text(blob)))
        paths.extend(_wp_scan_utf16le_paths(blob))
    seen: Set[str] = set()
    out: List[str] = []
    for p in paths:
        p = (p or "").strip().rstrip("\x00")
        if " | name=" in p.lower():
            p = p.split("|", 1)[0].strip()
        if not p or "\\" not in p:
            continue
        key = p.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


_WP_LOLBIN_NAMES = (
    "rasphone.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
)


def _wp_taskscheduler_dirty_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "wp_taskscheduler_dirty" and rid != "reg.persist.wp_taskscheduler_dirty":
        return None
    ll = (label or "").lower()
    kpath = str(item.get("key") or "").lower().replace("/", "\\")
    if "wptaskscheduler" not in ll and "schedule\\wp\\taskscheduler\\schedules" not in kpath:
        return None
    data = str(item.get("data") or "")
    blob = _wp_decode_hex_blob(data)
    family = ""
    if "simpleactivityscheduletimer" in data.lower() or "shadowscheduler" in data.lower():
        m = _WP_FAMILY_NAME_RE.search(data)
        family = m.group(0) if m else "SimpleActivityScheduleTimer"
    elif blob:
        family = _wp_scan_utf16le_family_name(blob)
    payloads = _wp_payloads_from_item(item)
    dirty = [p for p in payloads if _wp_is_dirty_payload(p)]
    lolbins = []
    for p in payloads:
        base = str(p or "").replace("/", "\\").lower().rsplit("\\", 1)[-1]
        if base in _WP_LOLBIN_NAMES:
            lolbins.append(p)
    # 脏路径；或家族任务名（强 IOC，覆盖采集只抽出 System32 LOLBin / 未采到 .pbk）
    if not dirty and not family:
        return None

    if dirty:
        note = "WP TaskScheduler 隐蔽任务载荷落在用户可写/投放目录（schtasks 不可见）"
        path = dirty[0]
        pairs = dirty[:6]
    else:
        note = "WP TaskScheduler 隐蔽任务命中家族任务名（schtasks 不可见）"
        path = lolbins[0] if lolbins else family
        pairs = (lolbins[:4] + ([family] if family else []))[:6]
    if family:
        note += f"；任务名含 {family.split('{')[0].rstrip('_')}"
    if any(str(p or "").lower().endswith("rasphone.exe") for p in payloads):
        if any(str(p).lower().endswith(".pbk") for p in dirty):
            note += "；rasphone.exe + 脏 .pbk（LOLBin）"
        elif family:
            note += "；rasphone.exe LOLBin + 家族任务名（参数路径可能未采全）"
    return {
        "path": path,
        "pairs": pairs,
        "location": str(item.get("key") or label),
        "note": note,
    }


# TaskCache：白名单只作用于「任务树 Path 名」，Actions/可执行载荷永远按脏特征检。
# 这样 \\Microsoft\\Windows\\ 下挂 Public/Temp/-enc 仍会命中，不会因白路径整单放行。
_TASKCACHE_CMD_DIRTY_RE = re.compile(
    r"(?i)(-enc(?:odedcommand)?\b|frombase64string|downloadstring|iex\s*\(|"
    r"invoke-expression|invoke-webrequest|wget\s+https?://|curl\s+https?://|"
    r"cmd\.exe\s+/c|mshta\b|regsvr32\b|rundll32\b|wscript\b|cscript\b|"
    r"powershell(?:\.exe)?\s+-[a-z]*e)"
)


def _taskcache_is_tree_path(data: str) -> bool:
    """TaskCache Path 值多为 \\Folder\\TaskName，不是盘符路径。"""
    s = (data or "").strip().strip('"')
    if not s.startswith("\\"):
        return False
    if re.match(r"^[a-zA-Z]:\\", s) or s.startswith("\\\\"):
        return False
    return True


def _taskcache_dirty_payload_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    """计划任务 TaskCache：白名单=任务名路径；恶意看 Actions/可执行载荷。"""
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "taskcache_dirty_payload" and rid != "reg.apt.Scheduled_Task_Registry":
        return None
    ll = (label or "").lower()
    kpath = str(item.get("key") or "").lower().replace("/", "\\")
    if "taskcache" not in ll and "schedule\\taskcache" not in kpath:
        return None

    val = str(item.get("value") or "").strip()
    data = str(item.get("data") or "").strip()
    if not data:
        return None
    vlow = val.lower()

    # —— Path：任务树名 —— #
    if vlow == "path" or vlow.endswith("\\path"):
        if _taskcache_is_tree_path(data):
            # 任务树名（含 \\Microsoft\\Windows\\…）本身不报；
            # 白路径下挂马靠同 GUID 的 Actions 条目检出，避免整单放行。
            return None
        # Path 被写成盘符路径（异常）——按脏载荷检
        if _wp_is_dirty_payload(data) or _TASKCACHE_CMD_DIRTY_RE.search(data):
            return {
                "path": data[:260],
                "location": str(item.get("key") or label),
                "note": "TaskCache Path 指向用户可写/可疑位置（非任务树名）",
            }
        return None

    # —— Actions：始终检载荷，不受任务名白名单影响 —— #
    if vlow != "actions" and "actions" not in vlow:
        return None

    payloads = _wp_payloads_from_item(item)
    # 采集端可能已抽出 C:\...\a.exe | C:\...\b.exe；亦覆盖 .jpg 等伪装扩展
    seen_low = {p.lower() for p in payloads}
    for part in re.split(r"\s*\|\s*", data):
        part = part.strip().strip('"')
        if not part or "\\" not in part or part.lower() in seen_low:
            continue
        if (
            _WP_PATH_EXT_RE.match(part + " ")
            or re.search(r"(?i)\.(?:exe|dll|bat|cmd|ps1|vbs|js|jpg|jpeg|png|gif|dat|bin|tmp)$", part)
            or re.match(r"(?i)^[a-z]:\\", part)
        ):
            payloads.append(part)
            seen_low.add(part.lower())

    dirty = [p for p in payloads if _wp_is_dirty_payload(p)]
    # 整段 data 本身就是脏盘符路径时也计入（扩展名不在白名单抽取列表时）
    if re.match(r"(?i)^[a-z]:\\", data) and _wp_is_dirty_payload(data) and data.lower() not in {x.lower() for x in dirty}:
        dirty.append(data)
    cmd_hit = bool(_TASKCACHE_CMD_DIRTY_RE.search(data))

    # LOLBin + 脏目录参数（Actions 文本里同时出现）
    dlow = data.replace("/", "\\").lower()
    lolbin_dirty = any(x in dlow for x in _WP_LOLBIN_NAMES) and any(m in dlow for m in _WP_DIRTY_MARKERS)

    if not dirty and not cmd_hit and not lolbin_dirty:
        return None

    if dirty:
        note = "TaskCache Actions 载荷落在用户可写/投放目录（任务名白名单不豁免）"
        path = dirty[0]
        pairs = dirty[:6]
    elif cmd_hit:
        note = "TaskCache Actions 含编码命令/LOLBin 执行特征（任务名白名单不豁免）"
        path = data[:200]
        pairs = [data[:200]]
    else:
        note = "TaskCache Actions 含 LOLBin + 可疑目录（任务名白名单不豁免）"
        path = data[:200]
        pairs = [data[:200]]

    return {
        "path": path,
        "pairs": pairs,
        "location": str(item.get("key") or label),
        "note": note,
    }


def _environment_path_hijack_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "environment_path_hijack" and rid != "reg.apt.SessionManager_Path_Hijack":
        return None
    if not _is_environment_path_key(label, item):
        return None
    data = str(item.get("data") or "").strip()
    if not data:
        return None
    file_paths = _REG_RUN_CTX.get("file_paths") or set()
    segments = _collect_environment_path_hijack_segments(data, file_paths)
    if not segments:
        return None
    loc = str(item.get("key") or label or "Environment")
    if "session manager" in loc.lower():
        note = "Session Manager / HKCU Environment Path 注入可疑目录"
    else:
        note = "HKCU Environment Path 注入可疑目录"
    return {"pairs": segments[:8], "location": loc, "note": note}


def _is_environment_key(label: str, item: Dict) -> bool:
    kpath = str(item.get("key") or label or "").lower().replace("/", "\\")
    ll = label.lower()
    if ll == "environment":
        return True
    if "session manager\\environment" in kpath:
        return True
    if kpath == "environment" or kpath.endswith("\\environment"):
        return True
    return False


_BENIGN_ENV_VALUE_NAMES = frozenset({
    "path", "pathext", "temp", "tmp", "windir", "systemroot", "systemdrive",
    "programfiles", "programfiles(x86)", "programdata", "userprofile",
    "homdrive", "homedrive", "homepath", "os", "computername", "username",
    "userdomain", "logonserver", "sessionname", "number_of_processors",
    "processor_architecture", "processor_identifier", "comspec", "prompt",
    "onedrive", "onedrivecommercial", "onedriveconsumer",
    "gopath", "goroot", "java_home", "jre_home", "node_path", "npm_config_prefix",
    "pythonhome", "pythonpath", "include", "lib", "libpath", "psmodulepath",
    "driverdata", "public", "commonprogramfiles", "commonprogramfiles(x86)",
    "commonprogramw6432", "programw6432", "localappdata", "appdata",
})


def _split_env_data(data: str) -> List[str]:
    raw = str(data or "")
    parts = re.split(r"[\x00;|]", raw)
    out: List[str] = []
    for p in parts:
        p = p.strip().strip('"')
        if p:
            out.append(p)
    if not out and raw.strip():
        out.append(raw.strip().strip('"'))
    return out


def _is_abs_exe_path(p: str) -> bool:
    pl = p.lower().strip().strip('"')
    if not pl.endswith(".exe"):
        return False
    return bool(re.match(r"^[a-z]:\\", pl) or pl.startswith("\\\\"))


def _environment_exe_persistence_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    """非标准 Environment 变量直接指向 .exe（银狐 ccc/sssss + wefault.exe 类）。"""
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode != "environment_exe_persistence" and rid != "reg.sf.environment_exe":
        return None
    if not _is_environment_key(label, item):
        return None
    val_name = str(item.get("value") or "").strip()
    vlow = val_name.lower()
    if vlow in _BENIGN_ENV_VALUE_NAMES:
        return None
    if "userinit" in vlow or "userlnit" in vlow:
        return None
    exes = [x for x in _split_env_data(str(item.get("data") or "")) if _is_abs_exe_path(x)]
    if not exes:
        return None
    loc = str(item.get("key") or label or "Environment")
    return {
        "value_name": val_name,
        "script": exes[0],
        "pairs": [f"{val_name}={x}" for x in exes[:4]],
        "location": loc,
        "note": "Environment 非标准变量指向可执行文件（持久化/银狐常见）",
    }


_CUSTOM_REG_MODES: Dict[str, Any] = {
    "startup_folder_hijack": _startup_folder_hijack_eval,
    "pending_file_rename": _pending_file_rename_eval,
    "dos_devices_hijack": _dos_devices_hijack_eval,
    "userinit_mpr_logon": _userinit_mpr_logon_eval,
    "silverfox_hex_key": _silverfox_hex_key_eval,
    "silverfox_space_key": _silverfox_space_key_eval,
    "silverfox_plug": _silverfox_plug_eval,
    "ntuser_man": _ntuser_man_eval,
    "environment_path_hijack": _environment_path_hijack_eval,
    "environment_exe_persistence": _environment_exe_persistence_eval,
    "wp_taskscheduler_dirty": _wp_taskscheduler_dirty_eval,
    "taskcache_dirty_payload": _taskcache_dirty_payload_eval,
}


def _custom_reg_eval(label: str, item: Dict, rule: Dict) -> Optional[Dict[str, Any]]:
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    alias = {
        "reg.sf.startup_folder_hijack": "startup_folder_hijack",
        "reg.sf.pending_file_rename": "pending_file_rename",
        "reg.sf.dos_devices": "dos_devices_hijack",
        "reg.sf.userinit_mpr": "userinit_mpr_logon",
        "reg.sf.hkcu_hex_key": "silverfox_hex_key",
        "reg.sf.hkcu_space_key": "silverfox_space_key",
        "reg.sf.plug_key": "silverfox_plug",
        "reg.sf.ntuser_man": "ntuser_man",
        "reg.apt.SessionManager_Path_Hijack": "environment_path_hijack",
        "reg.sf.environment_exe": "environment_exe_persistence",
        "reg.persist.wp_taskscheduler_dirty": "wp_taskscheduler_dirty",
        "reg.apt.Scheduled_Task_Registry": "taskcache_dirty_payload",
    }
    name = mode if mode in _CUSTOM_REG_MODES else alias.get(rid)
    if not name:
        return None
    fn = _CUSTOM_REG_MODES.get(name)
    return fn(label, item, rule) if fn else None


def _reg_source_label_ok(label: str, item: Dict, rule: Dict) -> bool:
    labels = _as_list(rule.get("sourceLabels"))
    if not labels:
        return True
    ll = label.lower()
    key_l = str(item.get("key") or "").lower()
    for x in labels:
        xl = str(x).lower()
        if xl in ll or ll == xl or xl in key_l:
            return True
    return False


def _format_custom_reg_detail(custom_info: Dict[str, Any], kpath: str, val: str, data: str) -> str:
    note = str(custom_info.get("note") or "").strip()
    if custom_info.get("pairs"):
        body = " | ".join(custom_info["pairs"])
    elif custom_info.get("location") or custom_info.get("path"):
        body = f"{custom_info.get('location') or kpath} → {custom_info.get('path') or data}"
    elif custom_info.get("device"):
        body = f"{custom_info.get('device') or val} → {custom_info.get('target') or data}"
    elif custom_info.get("script"):
        body = f"{custom_info.get('value_name') or val}={custom_info.get('script')}"
    elif custom_info.get("hex_key"):
        body = f"HKCU\\SOFTWARE\\{custom_info.get('hex_key')}={custom_info.get('config') or data}"
    elif custom_info.get("user_home"):
        body = f"{custom_info.get('user_home')}\\NTUSER.MAN"
    elif custom_info.get("key"):
        body = str(custom_info.get("key"))
    else:
        body = f"{kpath} {val}={data}".strip()
    return f"{body} | {note}".strip(" |") if note else body


def _append_silverfox_combo(findings: List[Finding], seen: Set[str], matched_ids: Set[str]) -> None:
    if "reg.sf.combo_attack" in matched_ids:
        return
    startup = {"reg.sf.startup_folder_hijack"}
    reloc = {"reg.sf.pending_file_rename", "reg.sf.dos_devices"}
    if not (matched_ids & startup) or not (matched_ids & reloc):
        return
    title = "银狐组合攻击"
    detail = "同时存在启动目录篡改与 PendingFileRename/DosDevices _reloc 特征，高度可疑"
    key = f"持久化|{title}|combo|{detail[:80]}"
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(
        "持久化", "critical", title, detail,
        "registry", "SilverfoxCombo", "artifacts",
        extra={"persist_kind": "registry", "rule_id": "reg.sf.combo_attack"},
    ))


def _reg_item_hit(label: str, item: Dict, rule: Dict) -> bool:
    if rule.get("enabled") is False:
        return False

    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode in _CUSTOM_REG_MODES or rid.startswith("reg.sf."):
        return _custom_reg_eval(label, item, rule) is not None
    if mode == "clsid_risk_score" or rid in _CLSID_RISK_RULE_IDS:
        if not _clsid_rule_key_ok(item, rule):
            return False
        return _clsid_persistence_lowfp_hit(label, item, rule)

    # startup-only rules (no registry matchers)
    reg_fields = (
        "sourceLabels", "keyContains", "keyContainsAny", "anyContains", "anyContainsAny",
        "anyContainsAll", "valueNameEquals", "valueNameContains", "valueNameContainsAny",
        "valueNameIn", "dataRegex", "dataNotEmpty", "dataNotRegex",
    )
    startup_only = (
        rule.get("startupNameEquals") or rule.get("startupNameIn")
        or rule.get("commandRegex") or rule.get("commandContains") or rule.get("commandContainsAny")
    ) and not any(rule.get(k) for k in reg_fields)
    if startup_only:
        return False

    # 纯启动命令规则：不要拿去扫注册表键值（否则 APT32 的 wscript.exe 会误伤 ShimCache）
    if (rule.get("commandContainsAny") or rule.get("commandContains") or rule.get("commandRegex")) and not any(
        rule.get(k) for k in (
            "sourceLabels", "keyContains", "keyContainsAny", "valueNameEquals", "valueNameContains",
            "valueNameContainsAny", "valueNameIn", "dataNotEmpty", "dataRegex", "anyContains",
            "anyContainsAny", "anyContainsAll",
        )
    ):
        return False

    key = str(item.get("key") or "")
    val = str(item.get("value") or "")
    data = str(item.get("data") or "")
    blob = f"{label}|{key}|{val}|{data}"
    bl = blob.lower()
    hit = False

    ll_label = label.lower()
    key_l = str(item.get("key") or "").lower()
    excl = [str(x).lower() for x in _as_list(rule.get("excludeSourceLabels"))]
    # 标签或键路径命中排除源（MuiCache 常出现在 key 而非 source label）
    if excl and (
        any(x in ll_label for x in excl)
        or any(x in key_l for x in excl)
    ):
        return False

    # ShimCache/BAM/MuiCache/AppCompatCache：无显式 sourceLabels 的规则一律跳过。
    # 勿再用「含反斜杠的长 needle」放行——\program files 会把 Office 正常路径全打成高危。
    if any(x in ll_label or x in key_l for x in _HISTORY_LABELS) and not rule.get("sourceLabels"):
        return False

    labels = _as_list(rule.get("sourceLabels"))
    if labels:
        ll = label.lower()
        ok = False
        for x in labels:
            xl = str(x).lower()
            if xl in ll or ll == xl:
                ok = True
                break
            if xl == "services" and "services" in ll:
                ok = True
                break
        if not ok:
            return False
        hit = True

    # keyContains* 只匹配注册表键路径（含 label），不扫 value/data。
    # 否则 TaskCache 的 Path=\Microsoft\Windows\AppID\... 会误触发 COM AppID 规则。
    if rule.get("keyContains"):
        needle = str(rule["keyContains"]).lower()
        if needle not in key.lower() and needle not in ll_label:
            return False
        hit = True
    if rule.get("keyContainsAny"):
        key_blob = f"{label}|{key}"
        if not _contains_any(key_blob, _as_list(rule["keyContainsAny"])):
            return False
        hit = True
    if rule.get("valueNameEquals"):
        if val.lower() != str(rule["valueNameEquals"]).lower():
            return False
        hit = True
    if rule.get("valueNameContains"):
        if str(rule["valueNameContains"]).lower() not in val.lower():
            return False
        hit = True
    if rule.get("valueNameContainsAny"):
        if not _contains_any(val, _as_list(rule["valueNameContainsAny"])):
            return False
        hit = True
    if rule.get("valueNameIn"):
        names = [x.lower() for x in _as_list(rule["valueNameIn"])]
        if val.lower() not in names:
            return False
        hit = True
    if rule.get("dataNotEmpty"):
        if not data.strip():
            return False
        hit = True
    if rule.get("dataRegex"):
        rx = _rx(str(rule["dataRegex"]))
        if not rx or not rx.search(data):
            return False
        hit = True
    if rule.get("dataNotRegex"):
        rx = _rx(str(rule["dataNotRegex"]))
        if rx and rx.search(data):
            return False
        hit = True or hit
    if rule.get("anyContains"):
        if str(rule["anyContains"]).lower() not in bl:
            return False
        hit = True
    if rule.get("anyContainsAny"):
        if not _contains_any(blob, _as_list(rule["anyContainsAny"])):
            return False
        hit = True
    if rule.get("anyContainsAll"):
        if not _contains_all(blob, _as_list(rule["anyContainsAll"])):
            return False
        hit = True
    if rule.get("anyNotContainsAny"):
        if _contains_any(blob, _as_list(rule["anyNotContainsAny"])):
            return False
    return hit


def _startup_rule_hit(si: Dict, rule: Dict, report: Optional[Dict] = None) -> bool:
    if rule.get("enabled") is False:
        return False
    name = str(si.get("name") or "")
    cmd = str(si.get("command") or si.get("path") or "")
    blob = f"{name} {cmd} {si.get('path') or ''} {si.get('resolved_path') or ''}"
    hit = False

    # 与 persistence 启动项口径对齐：未签名，或已签名但同目录有未签 dll
    if rule.get("requireUnsignedOrUnsignedSibling") or rule.get("requireUnsigned"):
        try:
            from . import persistence as P
        except Exception:
            return False
        if rule.get("requireUnsignedOrUnsignedSibling"):
            if not P._unsigned_or_unsigned_sibling_ok(
                si, blob, rule, report,
                explicit_only=bool(rule.get("uosExplicitOnly")),
            ):
                return False
        elif rule.get("requireUnsigned") and not P._is_unsigned(si):
            return False

    # 注册表结构字段不应用于启动项扁平命令（除非明确是 Run/启动 规则）
    if rule.get("keyContains") or rule.get("keyContainsAny") or rule.get("sourceLabels") or rule.get("valueNameEquals") or rule.get("valueNameContains") or rule.get("valueNameContainsAny") or rule.get("valueNameIn") or rule.get("dataNotEmpty") or rule.get("dataRegex"):
        if not (rule.get("startupNameEquals") or rule.get("startupNameIn") or rule.get("commandRegex") or rule.get("commandContains") or rule.get("commandContainsAny")):
            return False

    if rule.get("startupNameEquals"):
        if name.lower() != str(rule["startupNameEquals"]).lower():
            return False
        hit = True
    if rule.get("startupNameIn"):
        names = [x.lower() for x in _as_list(rule["startupNameIn"])]
        if name.lower() not in names:
            return False
        hit = True
    if rule.get("commandRegex"):
        rx = _rx(str(rule["commandRegex"]))
        if not rx or not rx.search(cmd):
            return False
        hit = True
    any_n = _as_list(rule.get("commandContainsAny")) or _as_list(rule.get("commandContains"))
    any_n = [x for x in any_n if len(str(x).strip()) >= 3]
    if rule.get("commandContainsAny") or rule.get("commandContains"):
        if not any_n:
            return False
        need = 1
        raw = rule.get("commandMinHits")
        if raw not in (None, ""):
            try:
                need = max(1, int(raw))
            except (TypeError, ValueError):
                need = 1
        elif (
            len(any_n) >= 2
            and str(rule.get("sigmaMode") or "").lower() == "behavior"
            and rule.get("correlationRequired")
            and any(n and len(str(n)) <= 10 and "\\" not in str(n) for n in any_n)
        ):
            need = 2
        hay = cmd.lower()
        hits = sum(1 for n in any_n if n and n.lower() in hay)
        if hits < need:
            return False
        hit = True

    if rule.get("anyContainsAny"):
        rid = str(rule.get("id") or "").lower()
        scoped = bool(rule.get("startupNameEquals") or rule.get("startupNameIn") or rule.get("commandRegex") or any_n)
        run_like = any(x in rid for x in ("run_", "autorun", "lolbin", "powershell", "apt32", "cmd_start", "kimjong", "empire", "poshc2", "c_drive", "highrisk_path", "java_node"))
        if not (scoped or run_like):
            return False
        needles = [x for x in _as_list(rule["anyContainsAny"]) if len(str(x).strip()) >= 4]
        if not needles or not _contains_any(blob, needles):
            return False
        hit = True
    if rule.get("anyNotContainsAny"):
        if _contains_any(blob, _as_list(rule["anyNotContainsAny"])):
            return False
    return hit


def run_prefetch(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    return [], {"matched_prefetch": 0}


def run_registry(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings = []
    matched = []
    win = store.windows if isinstance(getattr(store, "windows", None), dict) else {}
    rules = [r for r in (win.get("registryRules") or []) if isinstance(r, dict) and r.get("enabled") is not False]
    sig_index = _build_path_sig_index(report)
    _REG_RUN_CTX["file_paths"] = _build_file_path_set(report)

    urls = (report.get("user_registry") or {}).get("IETypedURLs") or []
    for u in urls:
        data = u.get("data") if isinstance(u, dict) else str(u)
        if not data:
            continue
        key = f"浏览痕迹|TypedURL|{data}|注册表"
        if key in seen:
            continue
        seen.add(key)
        sev = "medium" if any(x in data.lower() for x in ("threat", "malware", "vuln", "abuse.ch", "github.com", "gitee.com")) else "low"
        findings.append(Finding("浏览痕迹", sev, "IETypedURL", data, "user_registry", "IETypedURLs", "artifacts"))

    bags: List[Tuple[str, List]] = []
    matched_ids: Set[str] = set()
    for bag_name in ("services_registry", "user_registry", "network_registry"):
        bag = report.get(bag_name) or {}
        if isinstance(bag, dict):
            for label, items in bag.items():
                if isinstance(items, list):
                    bags.append((str(label), items))

    for label, items in bags:
        for item in items:
            if not isinstance(item, dict):
                continue
            for rule in rules:
                if not _reg_source_label_ok(label, item, rule):
                    continue
                rid = str(rule.get("id") or "")
                if rid == "reg.sf.combo_attack":
                    continue
                mode = str(rule.get("matchMode") or "").strip().lower()
                is_clsid = mode == "clsid_risk_score" or rid in _CLSID_RISK_RULE_IDS
                custom_info = _custom_reg_eval(label, item, rule)
                clsid_info = None
                if is_clsid:
                    if not _clsid_rule_key_ok(item, rule):
                        continue
                    clsid_info = _clsid_persistence_lowfp_eval(label, item, rule, sig_index)
                    if not clsid_info:
                        continue
                elif custom_info is None and not _reg_item_hit(label, item, rule):
                    continue
                if not _reg_unsigned_gate_ok(rule, item, sig_index, report):
                    continue

                title = str(rule.get("name") or "注册表可疑项")
                sev = str(rule.get("severity") or "high")
                if clsid_info:
                    sev = str(clsid_info.get("severity") or sev)
                    if clsid_info.get("sig") in ("unsigned", "unknown"):
                        title = f"{title}（高危·未签名）"

                val = item.get("value") or ""
                data = item.get("data") or ""
                kpath = item.get("key") or ""
                detail = f"{kpath} {val}={data}".strip()
                if clsid_info:
                    bits = [
                        f"载荷:{clsid_info.get('path') or '-'}",
                        f"签名:{clsid_info.get('sig_status') or clsid_info.get('sig') or '-'}",
                        str(clsid_info.get("note") or ""),
                    ]
                    detail = f"{detail} | " + " · ".join(x for x in bits if x and x != "-")
                elif custom_info:
                    detail = _format_custom_reg_detail(custom_info, kpath, val, data)
                key = f"持久化|{title}|{label}|{detail[:160]}"
                if key in seen:
                    continue
                seen.add(key)
                matched_ids.add(rid)
                matched.append({
                    "type": "registry", "label": label, "rule": title, "rule_id": rid,
                    "detail": detail[:300],
                    "severity": sev,
                })
                extra = {"persist_kind": "registry", "rule_id": rid}
                if clsid_info:
                    extra.update({
                        "com_payload": clsid_info.get("path") or "",
                        "com_sig": clsid_info.get("sig") or "",
                        "com_sig_status": clsid_info.get("sig_status") or "",
                        "com_in_high_risk": bool(clsid_info.get("in_high_risk")),
                        "com_note": clsid_info.get("note") or "",
                    })
                findings.append(Finding(
                    "持久化", sev, title, detail[:500],
                    "registry", label, "artifacts",
                    extra=extra,
                ))

    _append_silverfox_combo(findings, seen, matched_ids)

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        for rule in rules:
            if not _startup_rule_hit(si, rule, report):
                continue
            title = str(rule.get("name") or "可疑启动项")
            sev = str(rule.get("severity") or "high")
            name = si.get("name") or ""
            cmd = si.get("command") or ""
            loc = si.get("location") or ""
            detail = f"{loc} {name}: {cmd}".strip()
            key = f"持久化|{title}|startup|{name}|{cmd}"
            if key in seen:
                continue
            seen.add(key)
            matched.append({"type": "startup_registry", "rule": title, "rule_id": rule.get("id"), "detail": detail[:300]})
            findings.append(Finding(
                "持久化", sev, title, detail[:400], "启动项", loc or "startup", "artifacts",
                extra={"persist_kind": "startup"},
            ))

    if not rules:
        sreg = report.get("services_registry") or {}
        for label in ("Winlogon", "IFEO"):
            for item in sreg.get(label) or []:
                if not isinstance(item, dict):
                    continue
                val, data = item.get("value") or "", item.get("data") or ""
                blob = f"{val}={data}"
                if label == "IFEO" and data and val.lower() == "debugger":
                    key = f"持久化|IFEO Debugger|{blob}|注册表"
                    if key not in seen:
                        seen.add(key)
                        findings.append(Finding("持久化", "critical", "IFEO映像劫持", blob, "注册表", "IFEO", "artifacts", extra={"persist_kind": "registry"}))
                if label == "Winlogon" and val.lower() in ("shell", "userinit") and data:
                    normal = val.lower() == "shell" and data.lower().strip() in ("explorer.exe", "explorer.exe,")
                    normal = normal or (val.lower() == "userinit" and "userinit.exe" in data.lower() and data.lower().count(",") <= 1)
                    if not normal:
                        key = f"持久化|Winlogon|{blob}|注册表"
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding("持久化", "high", f"Winlogon.{val}", data, "注册表", "Winlogon", "artifacts", extra={"persist_kind": "registry"}))

    _REG_RUN_CTX.clear()
    return findings, {"matched_registry_rules": matched, "registry_rules": len(rules)}


def run_browsers(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    from . import browsers as browsers_matcher
    return browsers_matcher.run(report, store, seen)


def run_recycle_hosts(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings = []
    rb = report.get("recycle_bin") or ""
    if isinstance(rb, str) and rb.strip():
        for line in rb.splitlines():
            low = line.lower()
            if "autorun" in low:
                key = f"回收站|autorun|{line.strip()[:80]}|回收站"
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding("回收站", "high", "可疑autorun", line.strip()[:200], "recycle_bin", "autorun", "artifacts"))

    hosts = report.get("hosts_file") or ""
    for line in str(hosts).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"\b(127\.0\.0\.1|::1)\b", line) and "localhost" in line.lower():
            continue
        if re.search(r"^\d+\.\d+\.\d+\.\d+\s+\S+", line) or ":" in line.split()[0] if line.split() else False:
            key = f"Hosts|{line}|hosts"
            if key not in seen:
                seen.add(key)
                findings.append(Finding("Hosts篡改", "medium", "hosts条目", line[:200], "hosts_file", "hosts", "artifacts"))

    return findings, {}


def _sid_rid(sid: Any) -> int:
    s = str(sid or "").strip()
    if not s:
        return -1
    try:
        return int(s.rsplit("-", 1)[-1])
    except ValueError:
        return -1


def _is_well_known_builtin_account(name: str, sid: Any) -> bool:
    """内置 Administrator/Guest 等：不因 ProfileList/仅目录 报影子账号。"""
    n = str(name or "").strip().lower()
    if not n:
        return False
    rid = _sid_rid(sid)
    if rid == 500 and n in ("administrator", "管理员"):
        return True
    if rid == 501 and n in ("guest", "来宾"):
        return True
    return n in (
        "administrator", "管理员", "guest", "来宾",
        "defaultaccount", "wdagutilityaccount", "defaultuser0",
    )


def run_shadow_accounts(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    """采集器多源交叉（net user / ProfileList / 用户目录 / RID）标记的影子账号候选。"""
    findings: List[Finding] = []
    for u in report.get("users") or []:
        if not isinstance(u, dict) or not u.get("shadow_suspect"):
            continue
        name = str(u.get("name") or "").strip()
        reason = str(u.get("shadow_reason") or "").strip()
        if not name:
            continue
        # 旧报告里内置 Administrator 被误标：仅 ProfileList/目录类依据直接丢弃
        if _is_well_known_builtin_account(name, u.get("sid")):
            residual_only = (
                "ProfileList" in reason
                or "仅有用户目录" in reason
                or "仅目录" in reason
            )
            rename_or_dup = any(x in reason for x in ("RID 500 已重命名", "$结尾", "共用同一 SID"))
            if residual_only and not rename_or_dup:
                continue
        key = f"影子账号|{name.lower()}"
        if key in seen:
            continue
        seen.add(key)
        # 改名 RID500 / $ 结尾 / SID 重复 → 高；仅目录或 ProfileList 残留 → 中（常见于删号残留）
        high = any(x in reason for x in ("RID 500", "$结尾", "共用同一 SID"))
        ev_parts = [f"用户名: {name}"]
        if u.get("sid"):
            ev_parts.append(f"SID: {u.get('sid')}")
        if u.get("profile_path"):
            ev_parts.append(f"配置目录: {u.get('profile_path')}")
        if u.get("groups"):
            ev_parts.append(f"组: {u.get('groups')}")
        ev_parts.append(f"依据: {reason or '多源账户列表不一致'}")
        findings.append(Finding(
            "账户",
            "high" if high else "medium",
            f"影子账号候选 → {name}",
            "\n".join(ev_parts)[:800],
            "users",
            "account.shadow_suspect",
            "artifacts",
        ))
    return findings, {}


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    all_f = []
    meta = {}
    for fn in (run_prefetch, run_registry, run_recycle_hosts, run_shadow_accounts):
        f, b = fn(report, store, seen)
        all_f.extend(f)
        meta.update(b or {})
    try:
        from . import wininfosc_gap
        gf, gm = wininfosc_gap.run(report, store, seen)
        all_f.extend(gf)
        meta.update(gm or {})
    except Exception as e:
        meta["wininfosc_gap_error"] = str(e)[:200]
    return all_f, meta
