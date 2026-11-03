"""Windows 持久化 — 计划任务 / 启动项 / WMI / 服务 ImagePath（rules-windows-system.json 全量）"""
from __future__ import annotations
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore

SUS_STARTUP = re.compile(
    r"(?:"
    r"appdata\\local\\temp|\\temp\\|\\tmp\\|downloads|users\\public|powershell\s+-e|"
    r"cmd\.exe\s+/c\s+|mshta|wscript|"
    r"conhost(?:\.exe)?\s+--headless|"
    r"appdata\\roaming\\(?!microsoft\\|packages\\).+\.(?:exe|dll|bat|cmd|scr|vbs|js|ps1)|"
    r"appdata\\roaming\\microsoft\\windows\.bat|"
    r"appdata\\roaming\\microsoft\\windows\\services\\|"
    r"appdata\\roaming\\microsoft\\[^\\\s\"]+\.(?:bat|cmd|ps1|vbs|js)"
    r")",
    re.I,
)
SUS_TASK = re.compile(
    r"(\\temp\\|\\tmp\\|appdata\\local\\temp|downloads|users\\public|programdata\\user|"
    r"powershell\s+-|wscript|cscript|mshta|regsvr32|certutil|bitsadmin|frombase64|"
    r"comain_|shellexec_rundll|shell32\.dll\s*,\s*shellexec|"
    r"rundll32.{0,160}(?:appdata\\|users\\public\\|programdata\\user\\|\\temp\\))",
    re.I,
)

_BENIGN_PERSIST = re.compile(
    r"(?i)("
    r"\\microsoft\\|"
    r"\\windowsapps\\|"
    r"\\onedrive\\|"
    r"onedrivestandaloneupdater|"
    r"\\google\\googleupdater\\|"
    r"\\wps office\\|"
    r"ksolaunch\.exe|"
    r"\\lenovo\\|"
    r"\\canon\\|"
    r"\\cloudflare\\|"
    r"\\watchdata\\|"
    r"wdusbkeytool|"
    r"\\doubao|"
    r"andisplay|"
    r"ideashare|"
    r"\\uwst\\|"
    r"onenote|"
    r"letsvpn|"
    r"mimo\.xiaomi\.com|"
    r"\\intel\\sur\\|"
    r"queencreek|"
    r"\\mysql\\|"
    r"\\nvidia"
    r")"
)
_BENIGN_OVERRIDE = re.compile(
    r"(?i)frombase64|encodedcommand|invoke-expression|mshta\s|certutil\s+-urlcache|iex\(",
)
_BENIGN_FAILCMD = re.compile(
    r"(?i)(\\nvidia|nvcontainerrecovery|\\intel\\sur\\|queencreek|\\mysql\\|\\driverstore\\)",
)
_PS_PROXY_VENDOR = re.compile(
    r"(?i)\\intel\\sur\\|queencreek|esrv_svc_queencreek",
)
_OFFICIAL_STARTUP_DIR = re.compile(
    r"(?i)\\microsoft\\windows\\start menu\\programs\\startup\\",
)
_STARTUP_NON_BIN = re.compile(r"(?i)\.(lnk|url|ini)$")


def _is_known_benign_persist(blob: str) -> bool:
    """厂商/系统常见持久化载荷；编码执行等仍放过检测。"""
    if not blob:
        return False
    if _BENIGN_OVERRIDE.search(blob):
        return False
    return bool(_BENIGN_PERSIST.search(blob))


def _skip_benign_startup(si: Dict[str, Any], name: str, cmd: str, blob: str) -> bool:
    """仅跳过 desktop.ini；Startup 目录 .lnk 需解析目标后再判，不再 blanket skip。"""
    hay = f"{name} {cmd} {blob} {si.get('path') or ''} {si.get('resolved_path') or ''}"
    if _BENIGN_OVERRIDE.search(hay) or SUS_TASK.search(hay):
        return False
    bases = []
    for s in (name, cmd, si.get("path") or "", si.get("shortcut_path") or ""):
        leaf = os.path.basename(_norm_path(str(s).split(" /", 1)[0].strip().strip('"'))).lower()
        if leaf:
            bases.append(leaf)
    if any(b == "desktop.ini" for b in bases):
        return True
    return False

_KNOWN_TASK_EXE = frozenset({
    "svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "conhost.exe", "dllhost.exe", "taskhostw.exe", "sihclient.exe", "devicecensus.exe",
    "musnotification.exe", "usoclient.exe", "ngentask.exe", "ngen.exe", "consent.exe",
    "browser_broker.exe", "runtimebroker.exe", "backgroundtaskhost.exe",
    "microsoftedgeupdate.exe", "msedge.exe", "chrome.exe", "firefox.exe",
    "multiple", "task",
})

_RX_CACHE: Dict[str, Optional[re.Pattern]] = {}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_PATH_IN_CMD = re.compile(
    r'(?i)(?:^|[\s"\'=])(([a-z]:\\|\\\\)[^"\'\r\n]*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|scr|msi|com))\b'
)


def _rx(pat: str) -> Optional[re.Pattern]:
    if not pat:
        return None
    if pat not in _RX_CACHE:
        try:
            _RX_CACHE[pat] = re.compile(pat, re.I)
        except re.error:
            _RX_CACHE[pat] = None
    return _RX_CACHE[pat]


def _svc_image(s: Dict) -> str:
    return str(
        s.get("path") or s.get("image_path") or s.get("ImagePath")
        or s.get("bin_path") or s.get("binary_path") or s.get("resolved_path") or ""
    )


def _service_bin_path(img: str) -> str:
    """服务 ImagePath 里真正的 exe/dll，不含 --defaults-file / 日志路径参数。"""
    s = (img or "").strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return _norm_path(s[1:end])
    m = _PATH_IN_CMD.search(" " + s.strip('"'))
    if m:
        return _norm_path(m.group(1))
    m = re.match(
        r'(?i)^((?:[a-z]:\\|\\\\)[^"\s]*\.(?:exe|dll|sys|bat|cmd))\b',
        s.strip('"'),
    )
    if m:
        return _norm_path(m.group(1))
    return _norm_path(s.split(" ", 1)[0].strip('"'))


_SVC_WINDIR = r"C:\Windows"


def _canonical_service_path(p: str) -> str:
    """服务 ImagePath 内核语义展开：\\??\\、\\SystemRoot\\、%SystemRoot%/%windir%、相对 System32\\ / SysWOW64\\。"""
    s = _norm_path(p)
    if not s:
        return ""
    low = s.lower()
    if low.startswith("\\??\\"):
        s = s[4:]
    elif low.startswith("\\systemroot\\"):
        s = _SVC_WINDIR + s[11:]
    else:
        for var in ("%systemroot%", "%windir%"):
            if low.startswith(var):
                s = _SVC_WINDIR + s[len(var):]
                break
        else:
            if re.match(r"(?i)^(?:system32|syswow64)\\", s):
                s = _SVC_WINDIR + "\\" + s
    return s


def _needles_are_paths(needles: List[str]) -> bool:
    return bool(needles) and all(("\\" in n or n.lower().startswith("c:")) for n in needles)


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


def _command_min_hits(rule: Dict, needles: List[str]) -> int:
    """Sigma 导入常把 AND 拍成 OR。短词单独出现噪声极大，至少命中 2 项。"""
    raw = rule.get("commandMinHits")
    if raw not in (None, ""):
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            return 1
    if str(rule.get("sigmaMode") or "").lower() != "behavior":
        return 1
    if not rule.get("correlationRequired") or len(needles) < 2:
        return 1
    short = sum(1 for n in needles if n and len(str(n)) <= 10 and "\\" not in str(n))
    if short:
        return 2
    return 1


def _norm_path(p: str) -> str:
    s = (p or "").strip().strip('"').strip("'")
    s = s.replace("/", "\\")
    # 进程模块常见 \\?\C:\... 长路径前缀，与 files 表普通盘符对不上
    if s.startswith("\\\\?\\UNC\\"):
        s = "\\" + s[7:]
    elif s.startswith("\\\\?\\"):
        s = s[4:]
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _is_sig_verify_error(st: str) -> bool:
    s = (st or "").strip().lower()
    if not s:
        return False
    return (
        s == "error"
        or s == "fileerror"
        or s.startswith("error_")
        or s.startswith("0x8009")
    )

def _is_com_handler(item: Dict[str, Any]) -> bool:
    """计划任务动作为 COM 处理程序（无独立 PE）。含采集端 Path=COM / Command=COM 处理程序。"""
    if not isinstance(item, dict):
        return False
    path = str(item.get("path") or item.get("resolved_path") or "").strip()
    cmd = str(
        item.get("command")
        or item.get("command_line")
        or item.get("actions")
        or ""
    ).strip()
    if isinstance(item.get("actions"), list):
        cmd = " ".join(str(x) for x in item.get("actions") or [])
    name = str(item.get("name") or item.get("task_name") or "").strip()
    pl = path.upper()
    if pl == "COM" or pl.startswith("COM ") or pl.startswith("COM\\"):
        return True
    cl = cmd.upper()
    if cl == "COM" or cl.startswith("COM ") or "COM 处理" in cmd or "COM HANDLER" in cl:
        return True
    if name.lower() == "desktop.ini" or path.lower().endswith("desktop.ini"):
        return True
    return False


def _is_microsoft_windows_com_task(name: str, item: Dict[str, Any]) -> bool:
    """\\Microsoft\\Windows\\* 下的系统 COM 任务（打印清理/EDP/BitLocker/Setup 等），非持久化载荷。"""
    nm = str(name or item.get("task_name") or item.get("name") or "")
    if "\\Microsoft\\Windows\\" not in nm and not nm.startswith("\\Microsoft\\Windows"):
        return False
    return _is_com_handler(item or {})


_MS_WIN_COM_TASK_EV_RX = re.compile(
    r"\\Microsoft\\Windows\\[^\\]+\\[^\\\n]*",
    re.I,
)


def is_stale_microsoft_windows_com_task_fp(finding: Any) -> bool:
    """历史误报：高频间隔规则打在系统 COM 任务上（PrintJobCleanup / SetupCleanup / EDP 等）。

    规则侧已排除；读旧 findings 时再滤一次，无需用户加白名单路径。
    """
    if not isinstance(finding, dict):
        return False
    rid = str(finding.get("rule_id") or finding.get("ruleId") or "").strip()
    if rid != "task.metadata_high_freq_interval":
        return False
    parts = [
        finding.get("title"),
        finding.get("reason"),
        finding.get("evidence"),
        finding.get("path"),
        (finding.get("extra") or {}).get("path") if isinstance(finding.get("extra"), dict) else "",
    ]
    if isinstance(finding.get("evidence"), list):
        parts.extend(finding.get("evidence") or [])
    blob = " ".join(str(p or "") for p in parts)
    if "\\Microsoft\\Windows\\" not in blob and "/Microsoft/Windows/" not in blob:
        return False
    up = blob.upper()
    if "COM" in up or "处理程序" in blob:
        return True
    # 标题/证据里已是系统任务短名且无独立 PE 路径时也滤掉
    if _MS_WIN_COM_TASK_EV_RX.search(blob) and not re.search(
        r"[A-Za-z]:\\[^\\\s]+\\[^\\\s]+\.(?:exe|dll|bat|cmd|ps1)",
        blob,
        re.I,
    ):
        return True
    return False


def filter_stale_microsoft_com_task_findings(findings: List[Any]) -> List[Any]:
    if not findings:
        return findings
    return [f for f in findings if not is_stale_microsoft_windows_com_task_fp(f)]


def _sig_status_text(item: Dict[str, Any]) -> str:
    if not isinstance(item, dict):
        return ""
    return str(
        item.get("sig_status") or item.get("SigStatus") or item.get("signature_status")
        or item.get("sigStatus") or ""
    ).strip().lower()


def _is_unsigned(item: Dict[str, Any]) -> bool:
    """Valid=已签；明确未签名=True。Missing/Unchecked=采集漏检，不当未签名。"""
    if not isinstance(item, dict):
        return True
    if item.get("signed") is True:
        return False
    st = _sig_status_text(item)
    if st in ("valid", "signed") or ("valid" in st and "invalid" not in st):
        return False
    if st in ("n/a", "na") or _is_com_handler(item) or _is_sig_verify_error(st):
        return False
    if st in ("missing", "unchecked", "unknown", "", "-", "—"):
        return False
    if st in ("notsigned", "unsigned", "none", "invalid"):
        return True
    if item.get("signed") is False:
        return True
    return False


def _is_explicitly_unsigned(item: Dict[str, Any]) -> bool:
    """仅有明确未签/无效证据时为 True。采集漏检（signed=false + 空状态）不当白加黑。"""
    if not isinstance(item, dict):
        return False
    if item.get("signed") is True:
        return False
    st = _sig_status_text(item)
    if st in ("valid", "signed") or ("valid" in st and "invalid" not in st):
        return False
    if st in ("n/a", "na") or _is_com_handler(item) or _is_sig_verify_error(st):
        return False
    if st in (
        "notsigned", "unsigned", "none", "invalid",
        "hashmismatch", "nottrusted", "untrusted", "bad", "expired",
    ):
        return True
    # missing / unchecked：注册表项常见漏检，不算已证实未签
    return False


def _is_invalid_signature(item: Dict[str, Any]) -> bool:
    """Authenticode 验证失败（NotTrusted/HashMismatch 等），不含单纯 NotSigned。"""
    if not isinstance(item, dict):
        return False
    raw = str(
        item.get("sig_status") or item.get("SigStatus") or item.get("signature_status") or ""
    ).strip()
    st = raw.lower().replace(" ", "").replace("_", "")
    if st in ("hashmismatch", "nottrusted", "invalid", "untrusted", "incompatible", "bad", "expired"):
        return True
    if "nottrusted" in st or "hashmismatch" in st:
        return True
    if raw in ("HashMismatch", "NotTrusted", "Incompatible"):
        return True
    return False


def _has_invalid_signature(
    item: Dict[str, Any],
    report: Optional[Dict[str, Any]] = None,
    blob: str = "",
) -> bool:
    if _is_invalid_signature(item or {}):
        return True
    if not isinstance(report, dict):
        return False
    for p in _exe_paths_from_item(item or {}, blob):
        disk = _host_file_from_report(report, p)
        if disk and _is_invalid_signature(disk):
            return True
    return False


def _file_is_signed(f: Dict[str, Any]) -> bool:
    if not isinstance(f, dict):
        return False
    if f.get("signed") is True:
        return True
    st = _sig_status_text(f)
    return st in ("valid", "signed") or ("valid" in st and "invalid" not in st)


def _host_file_from_report(report: Optional[Dict[str, Any]], host: str) -> Optional[Dict[str, Any]]:
    if not isinstance(report, dict) or not host:
        return None
    host_n = _norm_path(host).lower()
    if not host_n or "\\" not in host_n:
        return None
    parent_l = host_n.rsplit("\\", 1)[0]
    _hydrate_entity_dir_files(report)
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    for f in cache.get(parent_l) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or "")).lower()
        if fp == host_n:
            return f
    return None


def _host_signed_for_sideload(
    item: Dict[str, Any],
    report: Optional[Dict[str, Any]],
    host: str,
) -> Optional[bool]:
    """True=已签宿主, False=明确未签, None=漏检/Run 路径与磁盘不一致（有未签兄弟仍可判）。"""
    if _file_is_signed(item):
        return True
    disk = _host_file_from_report(report, host)
    if disk and _file_is_signed(disk):
        return True
    if disk and _file_explicitly_unsigned(disk):
        return False
    st = _sig_status_text(item)
    if st in ("notsigned", "unsigned", "invalid", "hashmismatch", "nottrusted"):
        return False
    if item.get("signed") is False and st not in ("missing", "unchecked", "unknown", "", "-", "—"):
        return False
    host_n = _norm_path(host).lower()
    parent_l = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if parent_l and isinstance(report, dict):
        _hydrate_entity_dir_files(report)
        cache = report.get("_entity_dir_files") or {}
        for f in cache.get(parent_l) or []:
            if not isinstance(f, dict):
                continue
            name = str(f.get("name") or "").lower()
            ext = (f.get("ext") or "").lower()
            if ext != ".exe" and not name.endswith(".exe"):
                continue
            if _file_is_signed(f):
                return True
    if st in ("missing", "unchecked", "unknown", "", "-", "—") or item.get("signed") is None:
        return None
    if _file_explicitly_unsigned(item):
        return False
    return None


def _exe_paths_from_item(item: Dict[str, Any], blob: str = "") -> List[str]:
    out: List[str] = []
    if isinstance(item, dict):
        for k in (
            "path", "resolved_path", "image_path", "ImagePath", "command", "Command",
            "task_to_run", "bin_path", "binary_path", "service_dll",
        ):
            v = item.get(k)
            if v is None:
                continue
            s = str(v).strip()
            if not s or s in ("-", "—"):
                continue
            out.append(s)
    if blob:
        out.append(str(blob))
    paths: List[str] = []
    for raw in out:
        n = _norm_path(raw)
        if not n:
            continue
        # 提取命令行中全部 exe/dll 等路径（.log 等不会进列表）
        for m in _PATH_IN_CMD.finditer(" " + n):
            paths.append(_norm_path(m.group(1)))
        if re.match(r"(?i)^([a-z]:\\|\\\\)", n) and re.search(
            r"(?i)\.(exe|dll|sys|bat|cmd|ps1|vbs|js|scr|msi|com)(?:\s|$|\"|')", n
        ):
            head = n.split(" /", 1)[0].split(" -", 1)[0].strip().strip('"')
            if re.search(r"(?i)\.(exe|dll|sys)$", head):
                paths.append(_norm_path(head))
    seen = set()
    uniq = []
    for p in paths:
        pl = p.lower()
        if pl in seen:
            continue
        seen.add(pl)
        uniq.append(p)
    return uniq


_HOST_BIN_NAMES = frozenset({
    "svchost.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe", "verclsid.exe",
    "cmstp.exe", "odbcconf.exe", "mavinject.exe", "regasm.exe", "regsvcs.exe",
    "installutil.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe",
})


def _host_paths_from_item(item: Dict[str, Any]) -> List[str]:
    """持久化宿主路径（ImagePath / resolved_path / 命令首个系统 LOLBin）。"""
    if not isinstance(item, dict):
        return []
    out: List[str] = []
    for k in ("resolved_path", "image_path", "ImagePath", "bin_path", "binary_path"):
        v = str(item.get(k) or "").strip()
        if not v or v in ("-", "—"):
            continue
        # resolved_path 已是完整路径；_service_bin_path 会在空格处截断 Program Files
        if k == "resolved_path":
            m = _PATH_IN_CMD.search(" " + v)
            bp = _norm_path(m.group(1)) if m else _norm_path(v)
        elif k in ("image_path", "ImagePath") or re.search(r'(?i)\.exe\s+[-/k]', v):
            bp = _service_bin_path(v)
        else:
            m = _PATH_IN_CMD.search(" " + v)
            bp = _norm_path(m.group(1)) if m else _norm_path(v)
        if bp:
            out.append(bp)
    for k in ("command", "Command", "task_to_run", "path"):
        v = str(item.get(k) or "").strip()
        if not v:
            continue
        m = _PATH_IN_CMD.search(" " + v)
        if m:
            p = _norm_path(m.group(1))
            if os.path.basename(p).lower() in _HOST_BIN_NAMES:
                out.append(p)
                break
        bare = _first_bare_exe(v)
        if bare and bare.lower() in _HOST_BIN_NAMES:
            out.append(bare)
            break
    seen = set()
    uniq = []
    for p in out:
        pl = _norm_path(p).lower()
        if not pl or pl in seen:
            continue
        seen.add(pl)
        uniq.append(_norm_path(p))
    return uniq


_STARTUP_BIN_EXT = re.compile(r"(?i)\.(exe|dll|sys|bat|cmd|ps1|vbs|js|scr|com|msi)$")


def _startup_image_path(si: Dict[str, Any], cmd: str) -> str:
    """启动项真实映像路径：优先 resolved_path/path，其次命令行里第一个可执行路径。"""
    if isinstance(si, dict):
        for k in ("resolved_path", "path", "image_path", "ImagePath"):
            v = str(si.get(k) or "").strip().strip('"')
            if not v or v in ("-", "—"):
                continue
            n = _norm_path(v)
            m = _PATH_IN_CMD.search(" " + n)
            p = _norm_path(m.group(1)) if m else n
            if p and _STARTUP_BIN_EXT.search(p):
                return p
    m = _PATH_IN_CMD.search(" " + _norm_path(str(cmd or "")))
    return _norm_path(m.group(1)) if m else ""


def _startup_fallback_ok(
    si: Dict[str, Any],
    cmd: str,
    name: str,
    report: Optional[Dict[str, Any]],
) -> bool:
    """兜底「可疑启动项」是否仍应告警。

    与高危路径 UOS 对齐：未签名程序，或已签名但同目录/已加载存在未签/未知 dll 才告；
    纯已签（如 Apifox）不再因 AppData\\Roaming 路径兜底误报。

    JxBrowser 类：已签宿主 + 命中点只落在非可执行参数（--crash-dump-dir=...\\Temp）→ 不告。
    """
    image = _startup_image_path(si, cmd)
    if not image:
        return True
    blob = f"{name} {cmd} {image}"
    # 映像/名称本身落在 AppData\\Roaming、Temp、Public 等：走 UOS，不单靠路径告
    if SUS_STARTUP.search(image) or SUS_STARTUP.search(str(name or "")):
        return _unsigned_or_unsigned_sibling_ok(
            si, blob, {"requireUnsignedOrUnsignedSibling": True}, report
        )
    image_l = image.lower()
    for p in _exe_paths_from_item(si, str(cmd or "")):
        if p.lower() == image_l:
            continue
        if SUS_STARTUP.search(p):
            return True  # 参数里另有落在可疑目录的可执行载荷
    # 只认宿主自身/磁盘记录的签名，不用「同目录有已签 exe」那种宽松回退
    if _file_is_signed(si) or _file_is_signed(_host_file_from_report(report, image) or {}):
        return False
    return True


def _is_dirty_sideload_rule(rule: Dict[str, Any]) -> bool:
    """脏路径侧载规则（id 含 dirty / 显式字段）。"""
    if not isinstance(rule, dict):
        return False
    rid = str(rule.get("id") or "").lower()
    if "dirty" in rid:
        return True
    if rule.get("dirtyPayload") or rule.get("requireDirtyPayloadPath"):
        return True
    return False


def _black_dll_evidence_block(rule: Dict[str, Any], item: Dict[str, Any], blob: str = "") -> str:
    """脏路径命中时追加「黑DLL:」块，供告警详情面板拆开展示。"""
    bits = []
    sibs = item.get("_sideload_siblings") if isinstance(item, dict) else None
    if isinstance(sibs, list) and sibs:
        for f in sibs[:12]:
            if not isinstance(f, dict):
                continue
            p = str(f.get("full_path") or f.get("path") or "")
            nm = str(f.get("name") or "") or (os.path.basename(p.replace("/", "\\")) if p else "")
            if nm or p:
                bits.append(f"{nm} @ {p}" if p else nm)
    if not bits and _is_dirty_sideload_rule(rule):
        paths = _payload_paths_from_item(item or {}, blob or "")
        pe = [p for p in paths if str(p).lower().endswith((".dll", ".sys", ".ocx", ".exe"))]
        if not pe:
            pe = list(paths)
        for p in pe[:12]:
            nm = os.path.basename(str(p).replace("/", "\\")) or p
            bits.append(f"{nm} @ {p}")
    if not bits:
        return ""
    label = "未签名文件" if "system32_subdir" in str((rule or {}).get("id") or "").lower() else "黑DLL"
    return f"\n{label}:\n- " + "\n- ".join(bits)


def _payload_paths_from_item(item: Dict[str, Any], blob: str = "") -> List[str]:
    """白加黑载荷路径：ServiceDll / 命令参数，排除宿主自身。"""
    hosts = {_norm_path(h).lower() for h in _host_paths_from_item(item or {})}
    out: List[str] = []
    if isinstance(item, dict):
        dll = str(item.get("service_dll") or item.get("ServiceDll") or "").strip()
        if dll and dll not in ("-", "—"):
            for m in _PATH_IN_CMD.finditer(" " + dll):
                out.append(_norm_path(m.group(1)))
            if re.match(r"(?i)^([a-z]:\\|\\\\)", _norm_path(dll)):
                out.append(_norm_path(dll.split(" /", 1)[0].split(",", 1)[0].strip().strip('"')))
    for p in _exe_paths_from_item(item or {}, blob):
        pl = _norm_path(p).lower()
        if not pl or pl in hosts:
            continue
        base = os.path.basename(pl)
        # 系统目录下的宿主名不算载荷
        if base in _HOST_BIN_NAMES and ("\\windows\\" in pl or "\\system32\\" in pl or "\\syswow64\\" in pl):
            continue
        out.append(_norm_path(p))
    seen = set()
    uniq = []
    for p in out:
        pl = p.lower()
        if pl in seen:
            continue
        seen.add(pl)
        uniq.append(p)
    return uniq


def _rule_path_gate_on_payload(rule: Dict) -> bool:
    """白加黑类规则的 pathContains/NotContains 只应打在载荷上，不能因 System32 宿主误杀。"""
    rid = str(rule.get("id") or "").lower()
    src = str(rule.get("source") or "").lower()
    if rule.get("payloadPathOnly") is True:
        return True
    if "sideload" in rid or "sideload" in src or "白加黑" in str(rule.get("name") or "") or "未签名" in str(rule.get("name") or ""):
        return True
    # 既约束宿主 ImagePath 又约束 path* 时，path* 视为载荷条件
    if _as_list(rule.get("imagePathContainsAny") or rule.get("imagePathContains")) and (
        rule.get("pathContainsAny") or rule.get("pathNotContainsAny") or rule.get("pathImmediateUnder")
    ):
        return True
    if _as_list(rule.get("commandContainsAny") or rule.get("commandContains")) and (
        rule.get("pathContainsAny") or rule.get("pathNotContainsAny")
    ):
        return True
    return False


def _immediate_under(path: str, roots: List[str]) -> bool:
    """是否为根目录下独立文件。

    - 绝对根：C:\\ProgramData\\a.exe → parent == C:\\ProgramData
    - 后缀根：…\\AppData\\Local\\a.exe → parent 以 \\appdata\\local 结尾
    """
    p = _norm_path(path)
    if not p:
        return False
    p = p.split(" /", 1)[0].split(" -", 1)[0].strip().strip('"')
    pl = p.replace("/", "\\")
    parent = os.path.dirname(pl).rstrip("\\").lower()
    base = os.path.basename(pl)
    if not base or base in (".", "..") or "." not in base:
        return False
    for root in roots:
        r = _norm_path(root).rstrip("\\").lower().replace("/", "\\")
        if not r:
            continue
        # 绝对路径根（盘符或 UNC）
        if len(r) >= 2 and r[1] == ":" or r.startswith("\\\\"):
            if parent == r:
                return True
            continue
        # 相对后缀：AppData\Local 或 \AppData\Local
        suf = r if r.startswith("\\") else "\\" + r
        if parent.endswith(suf) or parent == suf.lstrip("\\"):
            return True
    return False


def _path_unsigned_gate(
    item: Dict[str, Any],
    blob: str,
    rule: Dict,
    report: Optional[Dict[str, Any]] = None,
) -> Optional[bool]:
    """requireUnsigned / requireUnsignedOrUnsignedSibling / requireInvalidSignature / path*。

    requireUnsignedOrUnsignedSibling：未签名主机告警；已签名主机仅当同目录/已加载存在未签或未知签名 dll/sys/ocx 才告。
    签名缺失(Missing/Unchecked)不当未签名主机，但可作为可疑 DLL 载荷。
    """
    req_u = bool(rule.get("requireUnsigned"))
    req_uos = bool(rule.get("requireUnsignedOrUnsignedSibling"))
    req_inv = bool(rule.get("requireInvalidSignature"))
    sig = str(rule.get("sigStatus") or "").strip().lower()
    path_any = [_norm_path(x) for x in _as_list(rule.get("pathContainsAny"))]
    path_not = [_norm_path(x) for x in _as_list(rule.get("pathNotContainsAny"))]
    imm = [_norm_path(x) for x in _as_list(rule.get("pathImmediateUnder"))]
    if not (req_u or req_uos or req_inv or sig in ("unsigned", "invalid") or path_any or imm or path_not):
        return None

    if req_uos:
        if not _unsigned_or_unsigned_sibling_ok(
            item or {}, blob, rule, report,
            explicit_only=bool(rule.get("uosExplicitOnly")),
        ):
            return False
    elif req_u or sig == "unsigned":
        if not _is_unsigned(item or {}):
            return False

    if req_inv or sig == "invalid":
        if not _has_invalid_signature(item or {}, report, blob):
            return False

    # 白加黑：path* 只看 ServiceDll / 命令载荷，避免 System32 宿主触发 pathNotContains
    if _rule_path_gate_on_payload(rule):
        paths = _payload_paths_from_item(item or {}, blob)
        hay = " | ".join(paths).lower()
    else:
        paths = _exe_paths_from_item(item or {}, blob)
        # 重要：pathContainsAny 只看提取出的 exe/dll 路径，不把整段命令（含 -f 日志目录）拼进 hay。
        # 否则 NVIDIA 等「Program Files 真身 + ProgramData 日志」会被 C:\ProgramData\ 误杀。
        hay = " | ".join(paths).lower()

    if path_not and hay and _contains_any(hay, path_not):
        return False
    if path_not and not hay and _rule_path_gate_on_payload(rule):
        # 无载荷时不因宿主路径误杀；也没有脏路径可命中
        pass

    if not path_any and not imm:
        return True

    ok = False
    if path_any and hay and _contains_any(hay, path_any):
        ok = True
    if not ok and imm:
        for p in paths:
            if _immediate_under(p, imm):
                ok = True
                break
    return ok


def _host_bin_for_unsigned_gate(item: Dict[str, Any], blob: str) -> str:
    """服务/启动项/任务的主二进制路径。"""
    if isinstance(item, dict):
        dll = str(item.get("service_dll") or item.get("ServiceDll") or "").strip().strip('"')
        if dll and re.search(r"(?i)\.(dll|sys|ocx)(?:\s|$)", dll):
            m = _PATH_IN_CMD.search(" " + _norm_path(dll))
            if m:
                return _norm_path(m.group(1))
            return _norm_path(dll.split(" ", 1)[0])
        img = ""
        for k in ("image_path", "ImagePath", "path", "command", "command_line", "task_to_run"):
            v = str(item.get(k) or "").strip()
            if v and v not in ("-", "—"):
                img = v
                break
        if img:
            bp = _service_bin_path(img)
            if bp and re.search(r"(?i)\.(exe|dll|sys|ocx)(?:\s|$)", bp):
                return bp
            sp = _startup_image_path(item, img)
            if sp:
                return sp
    paths = _exe_paths_from_item(item or {}, blob)
    return paths[0] if paths else ""


def _unsigned_or_unsigned_sibling_ok(
    item: Dict[str, Any],
    blob: str,
    rule: Dict,
    report: Optional[Dict[str, Any]],
    *,
    explicit_only: Optional[bool] = None,
) -> bool:
    """未签名程序 → True；已签名且同目录/已加载存在未签（或未知）dll/sys/ocx → True。

    uosExplicitOnly / explicit_only=True：旁路载荷只认明确未签/验签失败，
    Missing/Unchecked 采集漏检不当脏。
    """
    if explicit_only is None:
        explicit_only = bool((rule or {}).get("uosExplicitOnly"))
    host = _host_bin_for_unsigned_gate(item, blob)
    disk = _host_file_from_report(report, host) if (report and host) else None
    if _is_explicitly_unsigned(item) or (disk and _file_explicitly_unsigned(disk)):
        return True
    signed = _file_is_signed(item) or (disk and _file_is_signed(disk))
    if not signed:
        return False
    if not host or not isinstance(report, dict):
        return False
    if explicit_only:
        if _loaded_explicit_unsigned_dlls(report, host):
            return True
    elif _loaded_unsigned_or_unknown_dlls(report, host):
        return True
    # System32/SysWOW64 宿主不做同目录未知扫描（目录巨大且模块常未验签）
    if _is_windows_system_module_path(host):
        return False
    sibs = _unsigned_siblings_entity(
        report, host, include_unknown=not explicit_only,
    )
    payloads = _sideload_payload_files(sibs)
    if explicit_only:
        payloads = [f for f in payloads if _file_explicitly_unsigned(f)]
    return bool(payloads)


def _loaded_explicit_unsigned_dlls(report: Optional[Dict[str, Any]], host: str) -> bool:
    """进程模块：仅明确未签/验签失败的 dll/sys/ocx。"""
    if not isinstance(report, dict) or not host:
        return False
    host_l = _norm_path(host).lower()
    if not host_l:
        return False
    for proc in report.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        pp = _norm_path(str(proc.get("path") or proc.get("exe") or "")).lower()
        if pp != host_l:
            continue
        for m in proc.get("modules") or proc.get("Modules") or []:
            if isinstance(m, str):
                mp = _norm_path(m)
                meta: Dict[str, Any] = {"path": mp}
            elif isinstance(m, dict):
                mp = _norm_path(str(m.get("path") or m.get("Path") or ""))
                meta = m
            else:
                continue
            if not mp or mp.lower() == host_l:
                continue
            ext = mp.rsplit(".", 1)[-1].lower() if "." in mp else ""
            if ext not in ("dll", "sys", "ocx"):
                continue
            if not (_file_is_signed(meta) or _file_explicitly_unsigned(meta)):
                disk = _file_by_path_from_report(report, mp)
                if isinstance(disk, dict):
                    meta = {**meta, **disk}
            if _file_explicitly_unsigned(meta):
                return True
    return False


def _loaded_unsigned_or_unknown_dlls(report: Optional[Dict[str, Any]], host: str) -> bool:
    """进程模块列表：宿主已加载未签/未知签名的 dll/sys/ocx。

    系统目录（System32/SysWOW64/WinSxS 等）模块若签名字段为空/未知，视为采集未验签，不计脏。
    系统目录仅在明确 NotSigned/Invalid 时才计。
    """
    if not isinstance(report, dict) or not host:
        return False
    host_l = _norm_path(host).lower()
    if not host_l:
        return False
    for proc in report.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        pp = _norm_path(str(proc.get("path") or proc.get("exe") or "")).lower()
        if pp != host_l:
            continue
        for m in proc.get("modules") or proc.get("Modules") or []:
            if isinstance(m, str):
                mp = _norm_path(m)
                meta: Dict[str, Any] = {"path": mp}
            elif isinstance(m, dict):
                mp = _norm_path(str(m.get("path") or m.get("Path") or ""))
                meta = m
            else:
                continue
            if not mp or mp.lower() == host_l:
                continue
            ext = mp.rsplit(".", 1)[-1].lower() if "." in mp else ""
            if ext not in ("dll", "sys", "ocx"):
                continue
            # 模块自身无签名时，尝试用目录缓存补全
            if not (_file_is_signed(meta) or _file_explicitly_unsigned(meta)):
                disk = _file_by_path_from_report(report, mp)
                if isinstance(disk, dict):
                    meta = {**meta, **disk}
            if _file_is_signed(meta):
                continue
            if _is_windows_system_module_path(mp):
                # 系统 DLL：只有明确未签/验签失败才告；空/Missing 忽略
                if _file_explicitly_unsigned(meta):
                    return True
                continue
            if _file_unsigned_or_unknown(meta):
                return True
    return False


def annotate_persist_sideload(
    item: Dict[str, Any],
    kind: str = "service",
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """列表页标记 sideload_suspect，供服务/计划任务/启动项「含未签模块」筛选。"""
    if not isinstance(item, dict):
        return item
    out = item
    rpt = report if isinstance(report, dict) else None
    if rpt is not None:
        _hydrate_entity_dir_files(rpt)
    try:
        from ..rules_loader import get_store
        store = get_store()
        win = store.windows if isinstance(getattr(store, "windows", None), dict) else {}
    except Exception:
        win = {}
    hit = False
    any_dir_probe = {
        "id": "persist.list.any_dir",
        "matchMode": "any_dir_sideload",
        "requireHostSigned": True,
        "maxDirFiles": 8,
        "maxUnsignedSiblings": 1,
    }
    if kind == "service":
        sname = str(out.get("name") or out.get("service_name") or "")
        img = _svc_image(out)
        dll = str(out.get("service_dll") or out.get("ServiceDll") or "")
        blob = f"{sname} {img} {dll}"
        for r in (win.get("serviceRules") or []):
            if not isinstance(r, dict) or r.get("enabled") is False:
                continue
            if (
                "sideload" not in str(r.get("id") or "").lower()
                and "白加黑" not in str(r.get("name") or "")
                and "未签名" not in str(r.get("name") or "")
            ):
                continue
            if _service_rule_hit(sname, img, r, out, rpt):
                hit = True
                break
        if not hit and "svchost.exe" in img.lower() and dll:
            dl = dll.lower().replace("/", "\\")
            dirty = ("\\appdata\\", "\\temp\\", "\\tmp\\", "\\users\\public\\", "\\public\\", "\\programdata\\", "\\downloads\\")
            sysp = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\")
            if any(x in dl for x in dirty) and not any(x in dl for x in sysp):
                hit = True
        if not hit and rpt is not None and _any_dir_sideload_hit(out, any_dir_probe, blob, rpt):
                hit = True
    elif kind in ("task", "scheduled_task", "startup"):
        cmd = str(
            out.get("command") or out.get("Command") or out.get("task_to_run")
            or out.get("path") or ""
        )
        name = str(out.get("name") or out.get("task_name") or "")
        blob = f"{name} {cmd} {out.get('path') or ''} {out.get('resolved_path') or ''}"
        key = "taskRules" if kind != "startup" else "startupRules"
        for r in (win.get(key) or []):
            if not isinstance(r, dict) or r.get("enabled") is False:
                continue
            if (
                "sideload" not in str(r.get("id") or "").lower()
                and "白加黑" not in str(r.get("name") or "")
                and "未签名" not in str(r.get("name") or "")
            ):
                continue
            if _task_rule_hit(blob, r, out, rpt):
                hit = True
                break
        if not hit and rpt is not None:
            sys32_probe = {
                "id": "task.sideload.system32_subdir",
                "matchMode": "system32_subdir_sideload",
                "requireHostSigned": True,
            }
            if _system32_subdir_sideload_hit(out, sys32_probe, blob, rpt):
                hit = True
        if not hit and rpt is not None and _any_dir_sideload_hit(out, any_dir_probe, blob, rpt):
            hit = True
    out["sideload_suspect"] = bool(hit)
    return out


_OFFICIAL_UPDATE_PATH_MARKERS = (
    "\\windows\\",
    "\\microsoft\\",
    "program files\\microsoft",
    "program files (x86)\\microsoft",
)

_DEFAULT_UPDATE_DISGUISE_NAMES = (
    "MicrosoftUpdate",
    "WindowsUpdate",
    "AdobeUpdate",
    "ChromeUpdate",
    "JavaUpdate",
    "SecurityUpdate",
    "IEUpdate",
)


def _semantic_update_disguise_hit(item: Dict[str, Any], rule: Dict, blob: str) -> bool:
    """任务名伪装成系统更新，但载荷不在 Windows/Microsoft 官方目录（不要求未签名）。"""
    tname = str(item.get("task_name") or item.get("name") or "").strip()
    if not tname:
        tname = (blob or "").split(" ", 1)[0].strip()
    names = _as_list(rule.get("nameContainsAny")) or list(_DEFAULT_UPDATE_DISGUISE_NAMES)
    tlow = tname.lower()
    if not any(str(n).lower() in tlow for n in names):
        return False
    # COM 处理程序没有可执行路径，无法判断“载荷不在官方目录”
    if _is_com_handler(item):
        return False
    cmd = str(item.get("command") or item.get("Command") or item.get("task_to_run") or item.get("path") or "")
    paths = _exe_paths_from_item(item, blob)
    hay = " | ".join([p for p in paths if p] + ([cmd] if cmd else [])).lower()
    if not hay.strip():
        return False
    if any(m in hay for m in _OFFICIAL_UPDATE_PATH_MARKERS):
        return False
    return True


# System32 合法子目录（与 windows_process 对齐；未知子目录 = 异常落地）
_SYSTEM32_KNOWN_SUBDIRS = frozenset({
    "drivers", "driverstore", "wbem", "windowspowershell", "com", "config",
    "tasks", "spool", "catroot", "catroot2", "codeintegrity", "logfiles",
    "oobe", "migration", "speech", "ime", "mui", "en-us", "zh-cn", "zh-tw",
    "downlevel", "grouppolicy", "applocker", "appxdeployment", "appraiser",
    "advancedinstallers", "bits", "boot", "compat", "container", "diag",
    "diagnostics", "directx", "driversetup", "edgeupdate", "f12", "fxstmp",
    "gesture", "hal", "input", "intel", "keyiso", "licensing", "locales",
    "macromed", "microsoft", "migwiz", "ndf", "networklist", "nls",
    "openssh", "package", "perfcounters", "printers", "ras", "restore",
    "dism",
    "sru", "sxs", "sysprep", "tcpip", "timeseries", "twain_32", "uim",
    "usmt", "vbscript", "wer", "winevt", "winrm", "wmi", "wow64", "wpc", "wsc",
})


def _system32_anomaly_subdir(path: str) -> Optional[str]:
    """若路径落在 System32/SysWOW64 下非白名单子目录，返回该子目录名。"""
    pl = _norm_path(path).lower().replace("/", "\\")
    m = re.search(r"(?:^|[a-z]:)\\windows\\(system32|syswow64)\\([^\\]+)\\.+$", pl)
    if not m:
        return None
    sub = m.group(2)
    if sub in _SYSTEM32_KNOWN_SUBDIRS:
        return None
    return sub


def _file_explicitly_unsigned(f: Dict[str, Any]) -> bool:
    """仅明确未签/验签失败；Missing/Unchecked 为采集漏检（经典白加黑仍不当载荷）。"""
    if not isinstance(f, dict):
        return False
    if f.get("signed") is True:
        return False
    st = str(f.get("sig_status") or f.get("SigStatus") or "").strip().lower()
    st = st.replace(" ", "").replace("-", "").replace("_", "")
    if st in ("valid", "signed") or ("valid" in st and "invalid" not in st):
        return False
    if st in ("missing", "unchecked", "unknown", "", "-", "—", "n/a", "na"):
        return False
    if st in ("notsigned", "unsigned", "none", "invalid", "hashmismatch", "nottrusted", "untrusted", "bad", "expired"):
        return True
    if "notsigned" in st or st == "unsigned":
        return True
    return False


def _file_sig_is_unknown(f: Dict[str, Any]) -> bool:
    """签名未知/漏检（非 Valid、也非明确未签）。"""
    if not isinstance(f, dict):
        return True
    if _file_is_signed(f):
        return False
    if _file_explicitly_unsigned(f):
        return False
    st = str(f.get("sig_status") or f.get("SigStatus") or "").strip().lower()
    st = st.replace(" ", "").replace("-", "").replace("_", "")
    if st in ("missing", "unchecked", "unknown", "", "-", "—", "n/a", "na", "none"):
        return True
    # signed=false 且无明确状态，按未知处理
    if f.get("signed") is False:
        return True
    return st == "" or st is None


def _file_unsigned_or_unknown(f: Dict[str, Any]) -> bool:
    """高危路径 UOS：未签或未知签名的 dll 均视为可疑载荷。"""
    return _file_explicitly_unsigned(f) or _file_sig_is_unknown(f)


def _entity_sideload_kind(rule: Optional[Dict[str, Any]]) -> Optional[str]:
    """any_dir 白加黑规则所属实体：startup / task / service。"""
    rid = str((rule or {}).get("id") or "").lower()
    if rid == "startup.sideload.any_dir":
        return "startup"
    if rid in ("task.sideload.any_dir",):
        return "task"
    if rid in ("svc.sideload.any_dir",) or rid.startswith("svc.sideload."):
        return "service"
    return None


def _entity_host_paths(item: Dict[str, Any], blob: str = "", kind: str = "") -> List[str]:
    """持久化实体宿主路径（启动项 path/command；任务/服务 resolved_path）。"""
    hosts = _host_paths_from_item(item or {})
    if not hosts:
        paths = _exe_paths_from_item(item or {}, blob)
        hosts = paths[:1] if paths else []
    if not hosts and kind == "startup":
        for k in ("path", "command", "Command"):
            v = str(item.get(k) or "").strip()
            if not v:
                continue
            m = _PATH_IN_CMD.search(" " + v)
            if m:
                hosts.append(_norm_path(m.group(1)))
                break
    return hosts


def _collect_entity_parent_dirs(report: Dict[str, Any]) -> Dict[str, str]:
    """从启动项/计划任务/服务收集需预载的同目录。"""
    dirs: Dict[str, str] = {}

    def add_host(host: str) -> None:
        parent = _norm_path(host).rsplit("\\", 1)[0] if "\\" in _norm_path(host) else ""
        if parent:
            dirs[parent.lower()] = parent

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        cmd = str(si.get("command") or si.get("path") or "")
        blob = f"{si.get('location') or ''} {si.get('name') or ''} {cmd} {si.get('path') or ''}"
        for host in _entity_host_paths(si, blob, "startup"):
            add_host(host)
        for p in _payload_paths_from_item(si, blob):
            add_host(p)

    for t in report.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        cmd = str(t.get("command") or t.get("path") or t.get("task_to_run") or "")
        name = str(t.get("task_name") or t.get("name") or "")
        blob = f"{name} {cmd} {t.get('resolved_path') or ''}"
        for host in _entity_host_paths(t, blob, "task"):
            add_host(host)
        for p in _payload_paths_from_item(t, blob):
            add_host(p)

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        img = _svc_image(s)
        blob = f"{s.get('name') or ''} {img} {s.get('service_dll') or ''}"
        for host in _entity_host_paths(s, blob, "service"):
            add_host(host)
        for p in _payload_paths_from_item(s, blob):
            add_host(p)

    for snap in report.get("dir_snapshots") or []:
        if not isinstance(snap, dict):
            continue
        src = str(snap.get("sources") or "").lower()
        if not any(x in src for x in ("startup", "task", "service", "process")):
            continue
        d = _norm_path(str(snap.get("dir") or ""))
        if d:
            dirs.setdefault(d.lower(), d)

    return dirs


def _entity_dir_snap_index(report: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """dir_snapshots 按目录归一化索引。

    snap 里的 total 是采集端「截断前」的目录项总数，是判断大型软件目录
    （WPS office6 232 项、JxBrowser chromium 等）唯一可靠的规模信号，
    所以它必须独立于 _entity_dir_files 的缓存短路而始终可用。
    """
    if not isinstance(report, dict):
        return {}
    cached = report.get("_entity_dir_snap")
    if isinstance(cached, dict) and cached:
        return cached
    snap_index: Dict[str, Dict[str, Any]] = {}
    for snap in report.get("dir_snapshots") or []:
        if not isinstance(snap, dict):
            continue
        d = _norm_path(str(snap.get("dir") or ""))
        if d:
            snap_index[d.lower()] = snap
    report["_entity_dir_snap"] = snap_index
    report["_startup_dir_snap"] = snap_index
    return snap_index


def _hydrate_entity_dir_files(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """启动项/计划任务/服务：从 dir_snapshots + file_scans / DB / pack files.jsonl 预载同目录文件。"""
    if not isinstance(report, dict):
        return {}
    # 目录规模索引先建，命中文件缓存短路时也不能丢 dir_snapshots.total
    snap_index = _entity_dir_snap_index(report)
    cached = report.get("_entity_dir_files")
    if isinstance(cached, dict) and cached:
        return cached
    cached_legacy = report.get("_startup_dir_files")
    if isinstance(cached_legacy, dict) and cached_legacy:
        report["_entity_dir_files"] = cached_legacy
        return cached_legacy

    dirs = _collect_entity_parent_dirs(report)
    cache: Dict[str, List[Dict[str, Any]]] = {k: [] for k in dirs}

    def _assign(parent_l: str, f: Dict[str, Any]) -> None:
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp or "\\" not in fp:
            return
        if fp.rsplit("\\", 1)[0].lower() != parent_l:
            return
        key = fp.lower()
        for existing in cache.get(parent_l) or []:
            if _norm_path(str(existing.get("full_path") or "")).lower() == key:
                return
        cache.setdefault(parent_l, []).append(f)

    for f in report.get("file_scans") or []:
        if isinstance(f, dict):
            for parent_l in dirs:
                _assign(parent_l, f)

    rid = ""
    try:
        from ..db_store import files_rid, query_files_under_dir
        rid = files_rid(report)
        if rid:
            for parent_l, parent in dirs.items():
                if cache.get(parent_l):
                    continue
                try:
                    resp = query_files_under_dir(rid, parent, limit=200)
                    for f in resp.get("items") or []:
                        if isinstance(f, dict):
                            _assign(parent_l, f)
                except Exception:
                    pass
    except Exception:
        pass

    need_pack = [parent for parent_l, parent in dirs.items() if not cache.get(parent_l)]
    if need_pack and rid:
        try:
            from ..collect_pack import iter_jsonl, pack_dir_for_rid
            flp = pack_dir_for_rid(rid) / "files.jsonl"
            if flp.is_file():
                want = {p.lower() for p in need_pack}
                for row in iter_jsonl(flp):
                    if not isinstance(row, dict):
                        continue
                    fp = _norm_path(str(row.get("full_path") or ""))
                    if not fp or "\\" not in fp:
                        continue
                    parent_l = fp.rsplit("\\", 1)[0].lower()
                    if parent_l in want:
                        _assign(parent_l, row)
        except Exception:
            pass

    report["_entity_dir_files"] = cache
    report["_entity_dir_snap"] = snap_index
    # 兼容旧键
    report["_startup_dir_files"] = cache
    report["_startup_dir_snap"] = snap_index
    return cache


def _hydrate_startup_dir_files(report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    return _hydrate_entity_dir_files(report)


def _unsigned_siblings_entity(
    report: Optional[Dict[str, Any]],
    host: str,
    include_unknown: bool = False,
) -> List[Dict[str, Any]]:
    """实体持久化：同目录未签名 dll/exe（pack / dir_snapshots，不依赖全量 file_scans）。

    include_unknown=True 时：未知/漏检签名的 dll/sys/ocx 也计入（高危路径 UOS 口径）。
    """
    if not host or not isinstance(report, dict):
        return []
    host_n = _norm_path(host)
    parent = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent:
        return []
    parent_l = parent.lower()
    host_l = host_n.lower()
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def consider(f: Dict[str, Any]) -> None:
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp or fp.lower() == host_l:
            return
        if fp.rsplit("\\", 1)[0].lower() != parent_l:
            return
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext not in ("dll", "sys", "ocx", "exe"):
            return
        if include_unknown:
            # UOS：仅 dll/sys/ocx 看未签+未知；未签 exe 兄弟仍只认明确未签
            if ext in ("dll", "sys", "ocx"):
                if not _file_unsigned_or_unknown(f):
                    return
            elif not _file_explicitly_unsigned(f):
                return
        elif not _file_explicitly_unsigned(f):
            return
        key = fp.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(f)

    _hydrate_entity_dir_files(report)
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    for f in cache.get(parent_l) or []:
        if isinstance(f, dict):
            consider(f)
    if out:
        return out[:12]
    return _unsigned_siblings(report, host)


def _sideload_payload_files(files: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """经典白加黑载荷：同目录未签 dll/sys/ocx（不含未签 exe 兄弟）。"""
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for f in files or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or f.get("name") or ""))
        if not fp:
            continue
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext not in ("dll", "sys", "ocx"):
            continue
        key = fp.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _max_unsigned_sideload_payloads(rule: Optional[Dict[str, Any]], default: int = 1) -> int:
    """同目录未签 DLL 上限；超过则不像典型「白 exe + 单黑 DLL」。"""
    if not isinstance(rule, dict):
        return default
    for key in ("maxUnsignedSiblings", "maxUnsignedDlls", "moduleMaxUnsignedSameDir"):
        if key not in rule or rule.get(key) is None:
            continue
        try:
            return max(0, int(rule.get(key)))
        except (TypeError, ValueError):
            continue
    return default


def _unsigned_siblings_startup(report: Optional[Dict[str, Any]], host: str) -> List[Dict[str, Any]]:
    return _unsigned_siblings_entity(report, host)


_CROSS_DIR_SYS = re.compile(
    r"(?i)\\windows\\(system32|syswow64|winsxs|servicing|assembly|microsoft\.net)\\",
)

# 进程模块里系统目录 DLL 常未填签名，不能当「未知脏 DLL」
_SYSTEM_MODULE_DIR_HINTS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\",
    "\\windows\\systemui\\",
)


def _is_windows_system_module_path(path: str) -> bool:
    pl = _norm_path(path).lower().replace("/", "\\")
    if not pl:
        return False
    if _CROSS_DIR_SYS.search(pl):
        return True
    return any(h in pl for h in _SYSTEM_MODULE_DIR_HINTS)


def _file_by_path_from_report(
    report: Optional[Dict[str, Any]], path: str
) -> Optional[Dict[str, Any]]:
    """按完整路径在已预载的目录缓存里取文件记录。"""
    if not isinstance(report, dict) or not path:
        return None
    p = _norm_path(path)
    if "\\" not in p:
        return None
    parent_l = p.rsplit("\\", 1)[0].lower()
    _hydrate_entity_dir_files(report)
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    pl = p.lower()
    for f in cache.get(parent_l) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or "")).lower()
        if fp == pl:
            return f
    return None


def _cross_dir_unsigned_payloads(
    item: Dict[str, Any],
    blob: str,
    report: Optional[Dict[str, Any]],
    hosts: List[str],
    max_dir_files: int = 0,
) -> List[Dict[str, Any]]:
    """跨目录白加黑：宿主 exe 加载「别的目录」里的未签名 DLL（常常孤零零一个）。

    同目录白加黑靠 _unsigned_siblings_entity 覆盖；这里补的是命令行/ServiceDll 明确
    指向其它目录的未签载荷——那种目录里往往只有这一个 DLL，没有兄弟文件可比对，
    所以判定完全落在载荷自身的签名状态上（必须是明确未签，漏检不算）。
    """
    if not isinstance(report, dict):
        return []
    host_ls = {_norm_path(h).lower() for h in hosts if h}
    host_dirs = {h.rsplit("\\", 1)[0] for h in host_ls if "\\" in h}
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for p in _payload_paths_from_item(item or {}, blob or ""):
        pn = _norm_path(p)
        pl = pn.lower()
        if not pl or pl in host_ls or pl in seen:
            continue
        if "\\" not in pl:
            continue
        if not pl.endswith((".dll", ".sys", ".ocx", ".exe")):
            continue
        if pl.rsplit("\\", 1)[0] in host_dirs:
            continue  # 同目录，交给 _unsigned_siblings_entity
        if _CROSS_DIR_SYS.search(pn):
            continue
        f = _file_by_path_from_report(report, pn)
        if not isinstance(f, dict) or not _file_explicitly_unsigned(f):
            continue  # 采集漏检/未校验不定罪
        if max_dir_files > 0:
            n = _dir_file_count_entity(report, pn)
            if n > max_dir_files:
                continue  # 大型厂商目录里的零星未签 DLL 不算跨目录白加黑
            item["_sideload_dir_files"] = n
        seen.add(pl)
        out.append(f)
    return out[:12]


def _dir_file_count_entity(report: Optional[Dict[str, Any]], host: str) -> int:
    """实体持久化：同目录文件数；优先 dir_snapshots.total。"""
    if not host or not isinstance(report, dict):
        return 0
    host_n = _norm_path(host)
    parent = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent:
        return 0
    parent_l = parent.lower()
    _hydrate_entity_dir_files(report)
    snap_map = _entity_dir_snap_index(report) or report.get("_startup_dir_snap") or {}
    snap = snap_map.get(parent_l)
    if isinstance(snap, dict):
        try:
            total = int(snap.get("total") or 0)
            if total > 0:
                return total
        except (TypeError, ValueError):
            pass
    seen: Set[str] = set()
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    for f in cache.get(parent_l) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if fp and "\\" in fp and fp.rsplit("\\", 1)[0].lower() == parent_l:
            seen.add(fp.lower())
    if seen:
        return len(seen)
    return _dir_file_count(report, host)


def _dir_file_count_startup(report: Optional[Dict[str, Any]], host: str) -> int:
    return _dir_file_count_entity(report, host)


def _unsigned_siblings(report: Optional[Dict[str, Any]], host: str) -> List[Dict[str, Any]]:
    """从 file_scans / files 表找宿主同目录的未签名 dll/sys/exe（排除宿主自身）。"""
    if not host or not isinstance(report, dict):
        return []
    host_n = _norm_path(host)
    parent = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent:
        return []
    parent_l = parent.lower()
    host_l = host_n.lower()
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def consider(f: Dict[str, Any]) -> None:
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp or fp.lower() == host_l:
            return
        if fp.rsplit("\\", 1)[0].lower() != parent_l:
            return
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext not in ("dll", "sys", "ocx", "exe"):
            return
        if not _file_explicitly_unsigned(f):
            return
        key = fp.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(f)

    for f in report.get("file_scans") or []:
        if isinstance(f, dict):
            consider(f)
    if out:
        return out[:12]

    try:
        from ..db_store import files_rid, query_files
        rid = files_rid(report)
        if rid:
            rows = query_files(
                rid,
                path_contains=parent,
                exts=[".dll", ".sys", ".ocx", ".exe"],
                limit=80,
            )
            for f in rows or []:
                if isinstance(f, dict):
                    consider(f)
    except Exception:
        pass
    return out[:12]


def _system32_subdir_sideload_hit(
    item: Dict[str, Any],
    rule: Dict,
    blob: str,
    report: Optional[Dict[str, Any]] = None,
) -> bool:
    """System32 异常子目录 + 已签名宿主 + 同目录未签名 DLL（典型白加黑：仅 1 个）。"""
    hosts = _host_paths_from_item(item or {})
    if not hosts:
        paths = _exe_paths_from_item(item or {}, blob)
        hosts = paths[:1] if paths else []
    require_signed = rule.get("requireHostSigned")
    if require_signed is None:
        require_signed = True
    max_payloads = _max_unsigned_sideload_payloads(rule, default=1)
    for host in hosts:
        sub = _system32_anomaly_subdir(host)
        if not sub:
            continue
        if require_signed:
            hs = _host_signed_for_sideload(item or {}, report, host)
            if hs is False:
                continue
        siblings = _unsigned_siblings_entity(report, host) if isinstance(report, dict) else _unsigned_siblings(report, host)
        payloads = _sideload_payload_files(siblings)
        if not payloads:
            continue
        if max_payloads > 0 and len(payloads) > max_payloads:
            item["_sideload_multi_dll"] = True
            item["_sideload_siblings"] = payloads
            continue
        item["_sideload_siblings"] = payloads
        item["_sideload_subdir"] = sub
        return True
    return False


def _dir_file_count(report: Optional[Dict[str, Any]], host: str) -> int:
    """宿主同目录（DirSnap 一级快照）的文件数；0 表示无数据。"""
    if not host or not isinstance(report, dict):
        return 0
    host_n = _norm_path(host)
    parent = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent:
        return 0
    parent_l = parent.lower()
    seen: Set[str] = set()

    def consider(f: Dict[str, Any]) -> None:
        fp = _norm_path(str(f.get("full_path") or f.get("path") or ""))
        if not fp or "\\" not in fp:
            return
        if fp.rsplit("\\", 1)[0].lower() != parent_l:
            return
        seen.add(fp.lower())

    for f in report.get("file_scans") or []:
        if isinstance(f, dict):
            consider(f)
    if not seen:
        try:
            from ..db_store import files_rid, query_files
            rid = files_rid(report)
            if rid:
                for f in query_files(rid, path_contains=parent, limit=200) or []:
                    if isinstance(f, dict):
                        consider(f)
        except Exception:
            pass
    return len(seen)


def _count_exe_in_parent(report: Optional[Dict[str, Any]], host: str, include_host: bool = False) -> int:
    """宿主同目录 .exe 数量。"""
    if not host or not isinstance(report, dict):
        return 0
    host_n = _norm_path(host).lower()
    parent_l = host_n.rsplit("\\", 1)[0] if "\\" in host_n else ""
    if not parent_l:
        return 0
    _hydrate_entity_dir_files(report)
    n = 0
    cache = report.get("_entity_dir_files") or report.get("_startup_dir_files") or {}
    for f in cache.get(parent_l) or []:
        if not isinstance(f, dict):
            continue
        fp = _norm_path(str(f.get("full_path") or f.get("path") or "")).lower()
        if not fp or fp.rsplit("\\", 1)[0] != parent_l:
            continue
        if not fp.endswith(".exe"):
            continue
        if not include_host and fp == host_n:
            continue
        n += 1
    if include_host and n == 0 and host_n.endswith(".exe"):
        return 1
    return n if include_host else n + (1 if host_n.endswith(".exe") else 0)


_ISOLATED_SKIP_PARENT = re.compile(
    r"(?i)(\\windows\\|\\windowsapps\\|\\microsoft\\|\\program files\\|\\program files \(x86\)\\"
    r"|\\nvidia\\|\\intel\\|\\google\\|\\kingsoft\\|\\wps office\\|\\dotnet\\|\\nodejs\\)",
)


def _isolated_single_exe_hit(
    item: Dict[str, Any],
    rule: Dict,
    blob: str,
    report: Optional[Dict[str, Any]] = None,
) -> bool:
    """Startup 引用外部目录且该目录仅 1 个 exe（紧凑投放目录）。"""
    if not isinstance(report, dict):
        return False
    hosts = _entity_host_paths(item or {}, blob, "startup")
    if not hosts:
        return False
    path_any = [_norm_path(x) for x in _as_list(rule.get("pathContainsAny"))]
    path_not = [_norm_path(x) for x in _as_list(rule.get("pathNotContainsAny"))]
    try:
        max_total = int(rule.get("maxDirFiles") or 6)
    except (TypeError, ValueError):
        max_total = 6
    require_startup_dir = bool(rule.get("requireStartupDir"))
    loc = str(item.get("location") or "").lower()
    if require_startup_dir and "startupdir" not in loc:
        return False
    for host in hosts:
        pl = _norm_path(host).lower()
        if not pl.endswith(".exe"):
            continue
        parent = pl.rsplit("\\", 1)[0]
        if _ISOLATED_SKIP_PARENT.search(parent):
            continue
        hay = pl
        if path_not and _contains_any(hay, path_not):
            continue
        if path_any and not _contains_any(hay, path_any):
            continue
        exe_total = _count_exe_in_parent(report, host, include_host=True)
        if exe_total != 1:
            continue
        total = _dir_file_count_entity(report, host)
        if total <= 0:
            continue
        if total > max_total:
            continue
        item["_isolated_dir"] = parent
        item["_isolated_exe_count"] = 1
        return True
    return False


def _any_dir_sideload_hit(
    item: Dict[str, Any],
    rule: Dict,
    blob: str,
    report: Optional[Dict[str, Any]] = None,
) -> bool:
    """任意目录白加黑：已签名宿主 + 同目录恰好少量未签 DLL + 目录文件数少。

    严格口径：同目录未签 dll/sys/ocx 超过 maxUnsignedSiblings（默认 1）时，
    更像厂商未签组件堆叠，不当典型「白 exe 加载单黑 DLL」。
    """
    entity_kind = _entity_sideload_kind(rule)
    use_entity = isinstance(report, dict)
    hosts = _entity_host_paths(item or {}, blob, entity_kind or "") if use_entity else _host_paths_from_item(item or {})
    if not hosts:
        paths = _exe_paths_from_item(item or {}, blob)
        hosts = paths[:1] if paths else []
    require_signed = rule.get("requireHostSigned")
    if require_signed is None:
        require_signed = True
    try:
        max_files = int(rule.get("maxDirFiles") or 0)
    except (TypeError, ValueError):
        max_files = 0
    max_payloads = _max_unsigned_sideload_payloads(rule, default=1)
    sib_fn = _unsigned_siblings_entity if use_entity else _unsigned_siblings
    count_fn = _dir_file_count_entity if use_entity else _dir_file_count
    allow_cross = rule.get("allowCrossDirPayload")
    if allow_cross is None:
        allow_cross = True
    path_not = [
        _norm_path(x) for x in (
            _as_list(rule.get("pathNotContainsAny"))
            or _as_list(rule.get("hostPathNotContainsAny"))
            or _as_list(rule.get("imagePathNotContains"))
        )
    ]
    if rule.get("requireEmptyHostMeta"):
        # 服务/任务宿主 PE 元数据为空：公司/产品/版本/描述均无（白加黑精简投放常见）
        meta_fields = (
            "company", "Company", "product", "Product", "product_name",
            "version", "Version", "file_version", "FileVersion",
            "description", "Description", "file_description", "FileDescription",
        )
        filled = False
        for k in meta_fields:
            v = (item or {}).get(k)
            if v is None:
                continue
            if str(v).strip():
                filled = True
                break
        if filled:
            return False

    for host in hosts:
        if path_not and _contains_any(_norm_path(host), path_not):
            continue
        if require_signed:
            hs = _host_signed_for_sideload(item or {}, report, host)
            if hs is False:
                continue
        siblings = sib_fn(report, host)
        payloads = _sideload_payload_files(siblings)
        if not payloads:
            # 跨目录白加黑：命令行/ServiceDll 指向别的目录里的未签 DLL（孤立单文件）
            if allow_cross and use_entity:
                cross = _cross_dir_unsigned_payloads(
                    item or {}, blob, report, [host], max_dir_files=max_files
                )
                cross_payloads = _sideload_payload_files(cross)
                if cross_payloads and (max_payloads <= 0 or len(cross_payloads) <= max_payloads):
                    item["_sideload_siblings"] = cross_payloads
                    item["_sideload_cross_dir"] = True
                    return True
                if cross_payloads and max_payloads > 0 and len(cross_payloads) > max_payloads:
                    item["_sideload_multi_dll"] = True
            continue
        if max_payloads > 0 and len(payloads) > max_payloads:
            item["_sideload_multi_dll"] = True
            item["_sideload_siblings"] = payloads
            continue
        if max_files > 0:
            n = count_fn(report, host)
            # 无快照数据（n==0）时不因文件数否决，未签名兄弟文件已是强证据
            if n > max_files:
                # 大目录（厂商安装树）同目录常有大量未签 DLL，不算典型白加黑落地
                item["_sideload_dir_files"] = n
                item["_sideload_over_limit"] = True
                continue
            item["_sideload_dir_files"] = n
        item["_sideload_siblings"] = payloads
        return True
    return False


# Drive:\Top\rand\PE  或  Drive:\Top\rand\rand\...\PE（允许多层短随机，如 bstlog\lUgtB\6T8YE\bV8C\x.exe）
_DRIVE_ROOT_SHORT_PE = re.compile(
    r'(?i)(?<![A-Za-z0-9_])([A-Za-z]:)\\'
    r'(?!(?:Windows|Program Files(?: \(x86\))?|ProgramData|Users|\$Recycle\.Bin)\\)'
    r'([^\\\/\s"\']+)\\'
    r'((?:[A-Za-z0-9]{2,8}\\)+)'
    r'([^\\\/\s"\']+\.(?:exe|dll|scr|bat|cmd))'
)


def _dropper_tree_path_hit(
    item: Dict,
    rule: Dict,
    blob: str,
    report: Optional[Dict] = None,
) -> bool:
    """按内容识别投放树路径：盘符根\\树根\\短随机\\PE，目录名不限 Drivers。
    优先与 file_scans 中的投放树根（drivers.dat / 多随机 PE 子目录）关联。
    """
    from .files import build_dropper_tree_roots, _dir_name_kind_ok, _norm_path

    hay = " ".join(
        str(x or "")
        for x in (
            blob,
            (item or {}).get("command"),
            (item or {}).get("path"),
            (item or {}).get("resolved_path"),
            (item or {}).get("image_path"),
        )
    )
    matches = list(_DRIVE_ROOT_SHORT_PE.finditer(hay))
    if not matches:
        return False

    roots = build_dropper_tree_roots((report or {}).get("file_scans") or [])
    trig = str((item or {}).get("triggers") or (item or {}).get("Triggers") or "")
    low_hay = hay.lower()
    soft = ("cmd" in low_hay and "start" in low_hay) or ("cd /d" in low_hay) or ("boot" in trig.lower())

    for m in matches:
        drive, top, mid, _pe = m.group(1), m.group(2), m.group(3), m.group(4)
        segs = [s for s in (mid or "").split("\\") if s]
        if not segs:
            continue
        # 第一层必须是短随机；多层时要求至少两层都像随机（深层投放链）
        if not _dir_name_kind_ok(segs[0], "random_short_alnum_2_8"):
            continue
        deep = len(segs) >= 2 and all(
            _dir_name_kind_ok(s, "random_short_alnum_2_8") for s in segs
        )
        root = _norm_path(f"{drive}\\{top}")
        # 有文件扫描关联：树根已由 drivers.dat / 布局确认
        if roots and root in roots:
            return True
        # 无扫描时：短随机子目录 + (cmd start / Boot) 仍报，避免漏检
        if soft:
            return True
        # 深层连续短随机路径本身即可确认（无需 cmd/Boot）
        if deep:
            return True
        # 路径本身含 Drivers 名（兼容）
        if "\\drivers\\" in root or root.endswith("\\drivers"):
            return True
    return False


def _task_rule_hit(
    blob: str,
    rule: Dict,
    item: Optional[Dict] = None,
    report: Optional[Dict] = None,
) -> bool:
    if rule.get("enabled") is False:
        return False
    mode = str(rule.get("matchMode") or "").strip().lower()
    rid = str(rule.get("id") or "")
    if mode == "semantic_update_disguise" or rid == "task.semantic_update_disguise":
        return _semantic_update_disguise_hit(item or {}, rule, blob)
    if mode == "system32_subdir_sideload" or rid == "task.sideload.system32_subdir":
        return _system32_subdir_sideload_hit(item or {}, rule, blob, report)
    if mode == "any_dir_sideload":
        return _any_dir_sideload_hit(item or {}, rule, blob, report)
    if mode == "isolated_single_exe":
        return _isolated_single_exe_hit(item or {}, rule, blob, report)
    if mode == "dropper_tree_path" or rid == "task.drivers-dropper":
        return _dropper_tree_path_hit(item or {}, rule, blob, report)
    if str(rule.get("id") or "") == "task.checkPowerShellProxy" and _PS_PROXY_VENDOR.search(blob or ""):
        return False
    gate = _path_unsigned_gate(item or {}, blob, rule, report)
    if gate is False:
        return False

    hit = False
    # 任务名关键词：只扫 name/task_name，避免命令行 -Command 误中 "command"
    name_any = _as_list(rule.get("nameContainsAny")) or _as_list(rule.get("taskNameContainsAny"))
    if name_any:
        tname = ""
        if isinstance(item, dict):
            tname = str(item.get("task_name") or item.get("name") or "").strip()
        if not tname:
            # blob 首段常为任务名
            tname = (blob or "").split(" ", 1)[0].strip()
        if not _contains_any(tname, name_any):
            return False
        hit = True

    if rule.get("commandRegex"):
        rid0 = str(rule.get("id") or "")
        # 规则声明或高频间隔专规：只看 Triggers；\\Microsoft\\Windows\\* + COM 系统任务一律不命中（无需白名单路径）
        skip_ms_com = bool(rule.get("skipMicrosoftWindowsCom")) or rid0 == "task.metadata_high_freq_interval"
        triggers_only = bool(rule.get("matchTriggersOnly")) or rid0 == "task.metadata_high_freq_interval"
        if skip_ms_com or triggers_only:
            tname = ""
            if isinstance(item, dict):
                tname = str(item.get("task_name") or item.get("name") or "")
            if skip_ms_com and (
                _is_com_handler(item or {}) or _is_microsoft_windows_com_task(tname, item or {})
            ):
                return False
            if skip_ms_com and "\\Microsoft\\Windows\\" in tname and not str(
                (item or {}).get("resolved_path") or ""
            ).strip():
                path0 = str((item or {}).get("path") or "").strip().upper()
                if path0 in ("", "COM", "N/A", "NA"):
                    return False
            hay = blob or ""
            if triggers_only and isinstance(item, dict):
                hay = str(item.get("triggers") or item.get("Triggers") or "").strip() or (blob or "")
            rx = _rx(str(rule["commandRegex"]))
            if not rx or not rx.search(hay):
                return False
            hit = True
        else:
            rx = _rx(str(rule["commandRegex"]))
            if not rx or not rx.search(blob):
                return False
            hit = True
    any_n = _as_list(rule.get("commandContainsAny")) or _as_list(rule.get("commandContains"))
    if any_n:
        need = _command_min_hits(rule, any_n)
        hay = (blob or "").lower()
        hits = sum(1 for n in any_n if n and n.lower() in hay)
        if hits < need:
            return False
        hit = True
    all_n = _as_list(rule.get("commandContainsAll"))
    if all_n:
        if not _contains_all(blob, all_n):
            return False
        hit = True
    trig_any = _as_list(rule.get("triggerContainsAny"))
    if trig_any:
        trig = ""
        if isinstance(item, dict):
            trig = str(item.get("triggers") or item.get("Triggers") or "")
        if not trig:
            # 兼容塞进 blob 的 Triggers=Boot
            trig = blob or ""
        if not _contains_any(trig, trig_any):
            return False
        hit = True
    not_n = _as_list(rule.get("commandNotContains"))
    if not_n and _contains_any(blob, not_n):
        return False

    traditional = bool(
        rule.get("commandRegex") or any_n or all_n or name_any or trig_any
        or rule.get("commandContains") or rule.get("commandContainsAny") or rule.get("commandContainsAll")
        or rule.get("nameContainsAny") or rule.get("taskNameContainsAny")
        or rule.get("triggerContainsAny")
    )
    if not traditional:
        return gate is True
    return hit


def _parent_service_from_reg_key(key: str) -> str:
    """从 ...\\Services\\tapisrv\\Parameters 解析服务名 tapisrv。"""
    parts = [p for p in str(key or "").replace("/", "\\").split("\\") if p]
    for i, p in enumerate(parts):
        if p.lower() == "services" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


# 服务名与 System32 ServiceDll 合法配对（Lotus 报告中的 DLL 在正常机上即为此）
_LEGIT_SYSTEM_SERVICEDLL: Dict[str, str] = {
    "tapisrv": "tapisrv.dll",
    "swprv": "swprv.dll",
    "appmgmt": "appmgmts.dll",
}


def _is_legit_system_servicedll(service_name: str, dll_or_path: str) -> bool:
    sn = (service_name or "").strip().lower()
    if not sn:
        return False
    raw = str(dll_or_path or "").strip().strip('"')
    base = os.path.basename(_norm_path(raw.split(" ", 1)[0])).lower()
    expect = _LEGIT_SYSTEM_SERVICEDLL.get(sn)
    if not expect or not base:
        return False
    if base != expect:
        return False
    low = raw.lower()
    return "\\system32\\" in low or "%systemroot%\\system32\\" in low or low.startswith("%systemroot%")


def _service_rule_hit(
    sname: str,
    img: str,
    rule: Dict,
    item: Optional[Dict] = None,
    report: Optional[Dict] = None,
) -> bool:
    if rule.get("enabled") is False:
        return False
    # 事件日志 HTML 转义：&amp;&amp; → &&，避免 7045 ImagePath 漏匹配
    img = (
        str(img or "")
        .replace("&amp;&amp;", "&&")
        .replace("&amp;", "&")
        .replace("\u0026amp;\u0026amp;", "&&")
    )
    dll = str((item or {}).get("service_dll") or (item or {}).get("ServiceDll") or "")
    # 注册表项 key 常为 ...\Services\<svc>\Parameters，sname 可能是 Parameters
    svc_for_pair = sname
    if isinstance(item, dict) and str(sname or "").lower() in ("parameters", "security"):
        parent = _parent_service_from_reg_key(str(item.get("key") or ""))
        if parent:
            svc_for_pair = parent
    dll_check = dll or img
    if str(rule.get("id") or "") == "apt.svc.dll.hijack_known":
        if _is_legit_system_servicedll(svc_for_pair, dll_check):
            return False
    # ImagePath + ServiceDll 一并参与匹配（APT oci.dll/wlbsctrl.dll 等常在 ServiceDll）
    img_blob = f"{img} {dll}".strip()
    blob = f"{sname} {img_blob}"
    if str(rule.get("matchMode") or "").strip().lower() == "any_dir_sideload":
        return _any_dir_sideload_hit(item or {}, rule, blob, report)
    gate = _path_unsigned_gate(item or {}, blob, rule, report)
    if gate is False:
        return False

    sl = (sname or "").lower()
    hit = False

    names = [x.lower() for x in _as_list(rule.get("serviceNameIn"))]
    if names:
        if sl not in names:
            return False
        hit = True

    any_n = _as_list(rule.get("imagePathContainsAny")) or _as_list(rule.get("imagePathContains"))
    if any_n:
        bin_path = _service_bin_path(img)
        rid_l = str(rule.get("id") or "").lower()
        # ServiceDll 路径规则：只扫 ServiceDll，避免 ImagePath 在用户目录的已签服务误报
        if rid_l.startswith("svc.dllpath") or "servicedll" in str(rule.get("name") or "").lower().replace(" ", ""):
            if not dll or not _contains_any(dll, any_n):
                return False
            hit = True
        elif _needles_are_paths(any_n):
            # 只扫宿主主二进制 / ServiceDll，不把命令行参数（-r ProgramData 日志目录等）算进路径命中
            hay = " ".join(x for x in (bin_path, dll) if x)
            if not _contains_any(hay, any_n):
                return False
            hit = True
        else:
            hay = img_blob or ""
            if not _contains_any(hay, any_n):
                return False
            hit = True

    all_n = _as_list(rule.get("imagePathContainsAll"))
    if all_n:
        if not _contains_all(img_blob or "", all_n):
            return False
        hit = True

    not_n = _as_list(rule.get("imagePathNotContains"))
    if not_n:
        # 路径白名单同样只看主二进制 / ServiceDll，避免参数路径误放行或误杀
        bin_path = _service_bin_path(img)
        not_hay = " ".join(x for x in (bin_path, dll) if x) or (img_blob or "")
        canon = " ".join(
            c for c in (_canonical_service_path(bin_path), _canonical_service_path(dll)) if c
        )
        if _contains_any(not_hay, not_n) or (canon and _contains_any(canon, not_n)):
            return False

    if rule.get("imagePathRegex"):
        rx = _rx(str(rule["imagePathRegex"]))
        if not rx or not rx.search(img_blob or ""):
            return False
        hit = True

    if rule.get("imagePathNotRegex"):
        rx = _rx(str(rule["imagePathNotRegex"]))
        if rx and rx.search(img_blob or ""):
            return False
        hit = True or hit

    traditional = bool(
        names or any_n or all_n
        or rule.get("imagePathRegex") or rule.get("imagePathNotRegex")
        or rule.get("imagePathContains") or rule.get("imagePathContainsAny")
        or rule.get("serviceNameIn")
    )
    if not traditional:
        return gate is True
    return hit


def _startup_rule_hit(si: Dict, blob: str, rule: Dict, report: Optional[Dict] = None) -> bool:
    return _task_rule_hit(blob, rule, item=si, report=report)


def _pick(rules: List[Dict], pred) -> Optional[Dict]:
    """同严重级取 score/confidence 更高者，避免宽规则抢先挡住精确规则。"""
    best = None
    best_key = (99, -1, -1)
    for rule in rules:
        if not pred(rule):
            continue
        rank = _SEV_RANK.get(str(rule.get("severity") or "high").lower(), 2)
        score = int(rule.get("score") or 0)
        conf = int(rule.get("confidence") or 0)
        key = (rank, -score, -conf)
        if key < best_key:
            best, best_key = rule, key
    return best


def _build_exe_path_index(report: Dict) -> Dict[str, str]:
    """exe 名 -> 完整路径（进程 + 已有全路径的计划任务/启动项）。"""
    idx: Dict[str, str] = {}
    for src in (
        report.get("processes") or [],
        report.get("scheduled_tasks") or [],
        report.get("startup_items") or [],
        report.get("services") or [],
        report.get("prefetch_files") or [],
        report.get("file_scans") or [],
    ):
        if not isinstance(src, list):
            continue
        for row in src:
            if not isinstance(row, dict):
                continue
            for field in ("path", "command", "command_line", "task_to_run", "resolved_path", "image_path", "ImagePath", "full_path", "exe"):
                v = str(row.get(field) or "").strip()
                if not v:
                    continue
                for m in _PATH_IN_CMD.finditer(" " + v):
                    full = _norm_path(m.group(1))
                    if re.match(r"(?i)^[a-z]:\\", full):
                        idx[os.path.basename(full).lower()] = full
                if re.match(r"(?i)^[a-z]:\\", _norm_path(v)):
                    head = _norm_path(v.split(" /", 1)[0].split(" -", 1)[0])
                    idx[os.path.basename(head).lower()] = head
    return idx


def _first_bare_exe(text: str) -> str:
    s = (text or "").strip().strip('"')
    if not s or "\\" in s or "/" in s:
        return ""
    m = re.match(r"(?i)^([^\s]+\.exe)\b", s)
    return m.group(1) if m else ""


def _randomish_exe_name(exe: str) -> bool:
    base = (exe or "").lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if len(base) < 6 or base in ("multiple", "task", "windows"):
        return False
    if not re.search(r"[0-9]", base) or not re.search(r"[a-z]", base):
        return False
    return True


def _payload_label(cmd: str, path: str, name: str) -> str:
    blob = f"{path or ''} {cmd or ''}"
    m = _PATH_IN_CMD.search(" " + blob)
    if m:
        return os.path.basename(_norm_path(m.group(1)))
    bare = _first_bare_exe(cmd) or _first_bare_exe(path)
    if bare:
        return bare
    leaf = str(name or "").rstrip("\\").rsplit("\\", 1)[-1].strip()
    if leaf and leaf.lower() not in ("windows", "microsoft", "system32"):
        return leaf[:48]
    return ""


def _persist_title(rule: Dict, kind: str, label: str = "") -> str:
    raw = str((rule or {}).get("name") or "").strip()
    raw_key = raw.lower().replace(" ", "_").replace("-", "_")
    generic = raw_key in ("", "high_risk_rules", "high_risk", "highrisk")
    defaults = {
        "scheduled_task": "可疑计划任务",
        "startup": "可疑启动项",
        "service": "可疑服务",
        "registry": "可疑注册表",
        "wmi": "WMI 永久事件订阅",
    }
    kind_hints = {
        "scheduled_task": ("计划任务", "task"),
        "startup": ("启动项", "startup"),
        "service": ("服务", "service"),
        "registry": ("注册表", "registry", "ifeo", "winlogon"),
        "wmi": ("wmi",),
    }
    hints = kind_hints.get(kind, ())
    matches_kind = (not hints) or any(h.lower() in raw.lower() for h in hints)
    if generic or not matches_kind:
        base = defaults.get(kind, "可疑持久化")
    else:
        base = raw or defaults.get(kind, "可疑持久化")
    if label and label.lower() not in base.lower():
        return f"{base} · {label}"
    return base


def _enrich_task_item(t: Dict[str, Any], exe_index: Dict[str, str]) -> Dict[str, Any]:
    item = dict(t)
    resolved = str(item.get("resolved_path") or "").strip()
    for field in ("command", "path", "task_to_run"):
        v = str(item.get(field) or "").strip()
        bare = _first_bare_exe(v)
        if bare and not resolved:
            hit = exe_index.get(bare.lower())
            if hit:
                resolved = hit
    if not resolved:
        blob = " ".join(str(item.get(k) or "") for k in ("command", "path", "task_to_run"))
        m = _PATH_IN_CMD.search(" " + blob)
        if m:
            resolved = _norm_path(m.group(1))
    if resolved:
        item["resolved_path"] = resolved
    return item


def _rule_by_id(rules: List[Any], rid: str) -> Optional[Dict[str, Any]]:
    for r in rules or []:
        if isinstance(r, dict) and str(r.get("id") or "") == rid:
            return r
    return None


def _skip_benign_microsoft_task(
    name: str,
    blob: str,
    item: Dict[str, Any],
    cmd: str,
    gate_rule: Optional[Dict[str, Any]] = None,
) -> bool:
    """仅跳过载荷也属正常的 \\Microsoft\\ 计划任务；AppData/rundll32 等仍检测。

    路径/未签名门控一律来自规则 JSON（通常是 high_risk_task），不在代码里写死路径。
    命名空间是 \\Microsoft\\ 但执行路径不在 Windows/Microsoft 官方目录时，
    视为语义伪装（如 MicrosoftUpdate → ProgramData\\…\\wefault.exe），不跳过。
    """
    nm = str(name or "")
    if "\\Microsoft\\" not in nm and not nm.startswith("\\Microsoft"):
        return False
    # 系统命名空间下的 COM 处理程序（BitLocker/EDP/打印/Setup 等）无独立 exe，属正常任务。
    # 须先于 SUS_TASK：任务名/触发器里偶然命中 sus 词也不应把 COM 系统任务当持久化。
    if _is_com_handler(item or {}) or _is_microsoft_windows_com_task(nm, item or {}):
        return True
    if SUS_TASK.search(blob):
        return False
    # 只看执行载荷路径，不要把任务名里的 \\Microsoft\\ 当成官方目录
    payload = " ".join(
        str(x or "")
        for x in (
            cmd,
            (item or {}).get("path"),
            (item or {}).get("resolved_path"),
            (item or {}).get("command"),
        )
    ).lower()
    if payload.strip() and not any(m in payload for m in _OFFICIAL_UPDATE_PATH_MARKERS):
        return False
    if isinstance(gate_rule, dict) and (
        gate_rule.get("pathContainsAny") or gate_rule.get("pathImmediateUnder") or gate_rule.get("requireUnsigned")
    ):
        gate = _path_unsigned_gate(item, blob, gate_rule, None)
        if gate is True:
            return False
    if _is_unsigned(item) and _task_unsigned_fallback(item, blob, cmd):
        return False
    return True


def _task_unsigned_fallback(item: Dict[str, Any], blob: str, cmd: str) -> bool:
    """未签名/缺签名且载荷可疑（裸 exe 名、非系统目录）。"""
    if not _is_unsigned(item):
        return False
    if _is_known_benign_persist(f"{blob} {cmd}"):
        return False
    if SUS_TASK.search(blob):
        return True
    resolved = str(item.get("resolved_path") or "").strip()
    if resolved:
        rl = resolved.lower()
        if "\\windows\\" not in rl and "\\program files" not in rl:
            return True
    bare = _first_bare_exe(cmd) or _first_bare_exe(str(item.get("path") or ""))
    if not bare:
        return False
    if bare.lower() in _KNOWN_TASK_EXE:
        return False
    if _randomish_exe_name(bare):
        return True
    return False


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched = []
    _ensure_persist_report_context(report)
    win = store.windows if isinstance(store.windows, dict) else {}
    task_rules = [r for r in (win.get("taskRules") or []) if isinstance(r, dict) and r.get("enabled") is not False]
    service_rules = [r for r in (win.get("serviceRules") or []) if isinstance(r, dict) and r.get("enabled") is not False]
    startup_rules = [r for r in (win.get("startupRules") or []) if isinstance(r, dict) and r.get("enabled") is not False]
    hr_task = _rule_by_id(task_rules, "high_risk_task")
    exe_index = _build_exe_path_index(report)
    try:
        from ..ingest import resolve_scheduled_task_paths, resolve_startup_item_paths, exe_basename_index
        extra = exe_basename_index(report)
        exe_index.update({k: v for k, v in extra.items() if k not in exe_index})
        resolve_scheduled_task_paths(report, extra)
        resolve_startup_item_paths(report, extra)
        exe_index = _build_exe_path_index(report)
    except Exception:
        pass

    if report.get("startup_items") or report.get("scheduled_tasks") or report.get("services"):
        _hydrate_entity_dir_files(report)

    for t in report.get("scheduled_tasks") or []:
        if not isinstance(t, dict):
            continue
        name = t.get("task_name") or t.get("name") or ""
        cmd = t.get("command") or t.get("actions") or t.get("path") or ""
        if isinstance(cmd, list):
            cmd = " ".join(str(x) for x in cmd)
        item = _enrich_task_item(t, exe_index)
        # 最先剔除：\\Microsoft\\Windows\\* + COM（打印清理/EDP/Setup/BitLocker 等系统任务）
        if _is_microsoft_windows_com_task(str(name), item):
            continue
        trig = str(t.get("triggers") or item.get("triggers") or "")
        wd = str(t.get("working_directory") or item.get("working_directory") or "")
        blob = (
            f"{name} {cmd} {item.get('path') or ''} {item.get('resolved_path') or ''} "
            f"{wd} {trig}"
        ).strip()
        if _skip_benign_microsoft_task(name, blob, item, str(cmd), gate_rule=hr_task):
            # 白加黑 sideload 不受 Microsoft 任务名豁免：伪装成 MicrosoftEdge* 的随机任务仍需检测
            if not _any_dir_sideload_hit(item, {"id": "task.sideload.any_dir", "requireHostSigned": True, "maxDirFiles": 8, "maxUnsignedSiblings": 1}, blob, report):
                # APT / 更新名语义伪装（伪 Microsoft 命名空间）不受良性豁免
                bypass_rules = [
                    r for r in task_rules
                    if str(r.get("id") or "").startswith("apt.")
                    or str(r.get("matchMode") or "") == "semantic_update_disguise"
                    or "disguise" in str(r.get("id") or "").lower()
                    or "semantic_update" in str(r.get("id") or "").lower()
                ]
                rule = (
                    _pick(bypass_rules, lambda r, b=blob, it=item: _task_rule_hit(b, r, it, report))
                    if bypass_rules else None
                )
                if not rule:
                    continue
            else:
                rule = {
                    "id": "task.sideload.any_dir",
                    "name": "计划任务白加黑：任意目录",
                    "severity": "critical",
                }
        else:
            rule = _pick(task_rules, lambda r, b=blob, it=item: _task_rule_hit(b, r, it, report)) if task_rules else None
            if not rule and _system32_subdir_sideload_hit(
                item,
                {"id": "task.sideload.system32_subdir", "requireHostSigned": True},
                blob,
                report,
            ):
                rule = {
                    "id": "task.sideload.system32_subdir",
                    "name": "计划任务白加黑：System32异常子目录",
                    "severity": "critical",
                }
        if not rule and _task_unsigned_fallback(item, blob, str(cmd)):
            rule = {"id": "task-unsigned-fallback", "name": "可疑计划任务-未签名", "severity": "high"}
        if not rule and SUS_TASK.search(blob) and not _is_known_benign_persist(blob):
            rule = {"id": "task-fallback", "name": "可疑计划任务", "severity": "high"}
        if not rule:
            continue
        payload = _payload_label(str(cmd), str(item.get("resolved_path") or item.get("path") or ""), str(name))
        hit_title = _persist_title(rule, "scheduled_task", payload)
        sev = str(rule.get("severity") or "high")
        key = f"持久化|{hit_title}|{name}|{cmd}"
        if key in seen:
            continue
        seen.add(key)
        full = str(item.get("resolved_path") or "").strip()
        ev = f"{name}" + (f" => {cmd}" if cmd else "")
        if full and _norm_path(full).lower() not in _norm_path(str(cmd)).lower():
            ev = f"{name} => {cmd}  [路径 {full}]" if cmd else f"{name} => {full}"
        matched.append({
            "type": "scheduled_task", "name": name, "command": cmd,
            "rule": hit_title, "rule_id": rule.get("id"),
        })
        ev = (ev or "") + _black_dll_evidence_block(rule, item, blob)
        findings.append(Finding(
            "持久化", sev, hit_title, ev,
            "计划任务", str(rule.get("id") or "windows.scheduledTasks"), "persistence",
            extra={
                "signed": item.get("signed"),
                "sig_status": item.get("sig_status") or item.get("SigStatus"),
                "path": full or item.get("path") or "",
                "persist_kind": "task",
                "sideload": "sideload" in str(rule.get("id") or "").lower(),
                "dirty_sideload": _is_dirty_sideload_rule(rule),
            },
        ))

    for si in report.get("startup_items") or []:
        if not isinstance(si, dict):
            continue
        cmd = si.get("command") or si.get("path") or ""
        name = si.get("name") or ""
        loc = si.get("location") or ""
        blob = f"{loc} {name} {cmd} {si.get('path') or ''} {si.get('resolved_path') or ''} {si.get('shortcut_path') or ''}"
        if _skip_benign_startup(si, str(name), str(cmd), blob):
            continue
        rule = None
        if startup_rules:
            rule = _pick(startup_rules, lambda r, b=blob, it=si, rpt=report: _startup_rule_hit(it, b, r, rpt))
        # High risk 类路径+未签名规则：无 applyTo 限制时也对启动项生效
        if not rule and task_rules:
            for r in task_rules:
                if not (r.get("requireUnsigned") or r.get("requireInvalidSignature")
                        or str(r.get("sigStatus") or "").lower() in ("unsigned", "invalid")):
                    continue
                if not (r.get("pathContainsAny") or r.get("pathImmediateUnder")):
                    continue
                apply = [str(x).lower() for x in _as_list(r.get("applyTo"))]
                if apply and "startup" not in apply and "startup_items" not in apply:
                    continue
                if _startup_rule_hit(si, blob, r, report):
                    rule = r
                    break
        if not rule and not _is_known_benign_persist(blob) and (
            SUS_STARTUP.search(str(cmd)) or SUS_STARTUP.search(str(name))
        ) and _startup_fallback_ok(si, str(cmd), str(name), report):
            rule = {"id": "startup-fallback", "name": "可疑启动项", "severity": "high"}
        if not rule:
            continue
        payload = _payload_label(str(cmd), str(si.get("path") or ""), str(name))
        hit_title = _persist_title(rule, "startup", payload)
        sev = str(rule.get("severity") or "high")
        key = f"持久化|{hit_title}|{loc}|{name}|{cmd}"
        if key in seen:
            continue
        seen.add(key)
        if rule.get("requireUnsignedOrUnsignedSibling"):
            host = _host_bin_for_unsigned_gate(si, blob)
            if host:
                payloads = _sideload_payload_files(_unsigned_siblings_entity(report, host))
                if payloads:
                    si = {**si, "_sideload_siblings": payloads}
        matched.append({
            "type": "startup", "name": name, "command": cmd, "location": loc,
            "rule": hit_title, "rule_id": rule.get("id"),
        })
        findings.append(Finding(
            "持久化", sev, hit_title, f"{name}: {cmd}" + _black_dll_evidence_block(rule, si, blob), "启动项",
            str(rule.get("id") or "windows.startup"), "persistence",
            extra={
                "signed": si.get("signed"),
                "sig_status": si.get("sig_status") or si.get("SigStatus"),
                "path": si.get("path") or "",
                "persist_kind": "startup",
                "sideload": "sideload" in str(rule.get("id") or "").lower(),
                "dirty_sideload": _is_dirty_sideload_rule(rule),
            },
        ))

    for s in report.get("services") or []:
        if not isinstance(s, dict):
            continue
        sname = str(s.get("name") or s.get("service_name") or "")
        img = _svc_image(s)
        if not img and not sname:
            continue
        rule = _pick(
            service_rules,
            lambda r, n=sname, i=img, it=s: _service_rule_hit(n, i, r, it, report),
        ) if service_rules else None
        if not rule:
            continue
        payload = _payload_label(img, img, sname)
        hit_title = _persist_title(rule, "service", payload)
        sev = str(rule.get("severity") or "high")
        key = f"持久化|{hit_title}|{sname}|{img}"
        if key in seen:
            continue
        seen.add(key)
        if rule.get("requireUnsignedOrUnsignedSibling"):
            host = _host_bin_for_unsigned_gate(s, img or sname)
            if host:
                payloads = _sideload_payload_files(_unsigned_siblings_entity(report, host))
                if payloads:
                    s = {**s, "_sideload_siblings": payloads}
        matched.append({
            "type": "service", "name": sname, "image_path": img,
            "rule": hit_title, "rule_id": rule.get("id"),
        })
        svc_ev = (
            f"{sname}" + (f" => {img}" if img else "")
            + (f" | ServiceDll: {s.get('service_dll') or s.get('ServiceDll')}" if (s.get("service_dll") or s.get("ServiceDll")) else "")
            + _black_dll_evidence_block(rule, s, img or sname)
        )
        findings.append(Finding(
            "持久化", sev, hit_title, svc_ev,
            "服务", str(rule.get("id") or "windows.services"), "persistence",
            extra={
                "signed": s.get("signed"),
                "sig_status": s.get("sig_status") or s.get("SigStatus"),
                "path": img,
                "service_dll": s.get("service_dll") or s.get("ServiceDll") or "",
                "persist_kind": "service",
                "sideload": "sideload" in str(rule.get("id") or "").lower(),
                "dirty_sideload": _is_dirty_sideload_rule(rule),
            },
        ))

    sreg = report.get("services_registry") or {}
    for label, items in sreg.items():
        if "Services" not in str(label) and "BITS" not in str(label):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            vn = str(item.get("value") or "").lower()
            if vn not in ("imagepath", "servicedll", "failurecommand"):
                continue
            key_path = str(item.get("key") or "")
            sname = key_path.rsplit("\\", 1)[-1] if key_path else ""
            img = str(item.get("data") or "")
            if not img:
                continue
            if vn == "failurecommand" and _BENIGN_FAILCMD.search(img):
                continue
            rule = _pick(
                service_rules,
                lambda r, n=sname, i=img: _service_rule_hit(n, i, r, item),
            ) if service_rules else None
            if not rule:
                continue
            payload = _payload_label(img, img, sname)
            hit_title = _persist_title(rule, "service", payload)
            if vn == "servicedll":
                hit_title = hit_title if "ServiceDll" in hit_title or "DLL" in hit_title else f"ServiceDll-{hit_title}"
            elif vn == "failurecommand":
                hit_title = f"FailureCommand-{hit_title}"
            sev = str(rule.get("severity") or "high")
            key = f"持久化|{hit_title}|{sname}|{img}"
            if key in seen:
                continue
            seen.add(key)
            matched.append({
                "type": "service_registry", "name": sname, "image_path": img,
                "rule": hit_title, "rule_id": rule.get("id"), "value": vn,
            })
            findings.append(Finding(
                "持久化", sev, hit_title,
                f"{sname} => {img}",
                "服务注册表", label, "persistence",
                extra={"persist_kind": "registry", "path": img},
            ))

    wmi = report.get("wmi_subscriptions")
    if isinstance(wmi, dict):
        status = wmi.get("status") or "empty"
        filters = wmi.get("filters") or wmi.get("event_filters") or []
        consumers = wmi.get("consumers") or wmi.get("command_line_event_consumers") or []
        bindings = wmi.get("bindings") or wmi.get("filter_to_consumer_bindings") or []
        if status not in ("empty", "unavailable", "error", "") and (filters or consumers or bindings):
            detail = f"filters={len(filters)} consumers={len(consumers)} bindings={len(bindings)}"
            key = f"持久化|WMI订阅|{detail}"
            if key not in seen:
                seen.add(key)
                matched.append({
                    "type": "wmi",
                    "filters": len(filters),
                    "consumers": len(consumers),
                    "bindings": len(bindings),
                })
                findings.append(Finding(
                    "持久化", "high", "WMI 永久事件订阅", detail, "WMI", "windows.wmi", "persistence",
                    extra={"persist_kind": "wmi"},
                ))

    return findings, {"matched_suspicious": matched}


def load_dir_snapshots_for_rid(rid: str) -> List[Dict[str, Any]]:
    """从 pack/extras.json 或 report.json 读取 dir_snapshots。

    优先 extras（小）；勿先整份解析 report.json（列表页会卡数秒）。
    """
    if not rid:
        return []
    try:
        from ..collect_pack import pack_dir_for_rid
        import json
        ep = pack_dir_for_rid(rid) / "extras.json"
        if ep.is_file():
            data = json.loads(ep.read_text(encoding="utf-8-sig"))
            snaps = data.get("dir_snapshots") if isinstance(data, dict) else None
            if isinstance(snaps, list) and snaps:
                return [x for x in snaps if isinstance(x, dict)]
    except Exception:
        pass
    try:
        from .. import paths as P
        import json
        rp = P.resolve_report_json(rid)
        if rp and rp.is_file():
            # 大报告整读很贵；仅当 extras 没有时才兜底
            data = json.loads(rp.read_text(encoding="utf-8-sig"))
            snaps = data.get("dir_snapshots") if isinstance(data, dict) else None
            if isinstance(snaps, list) and snaps:
                return [x for x in snaps if isinstance(x, dict)]
    except Exception:
        pass
    return []


def _ensure_persist_report_context(report: Dict[str, Any]) -> None:
    """pack 快速阶段：补 _rid、从 extras 载入 dir_snapshots（report.json 可能已瘦身）。"""
    if not isinstance(report, dict):
        return
    rid = str(report.get("_rid") or report.get("_files_rid") or "").strip()
    if rid:
        report.setdefault("_rid", rid)
        report.setdefault("_files_rid", rid)
    if not report.get("dir_snapshots") and rid:
        snaps = load_dir_snapshots_for_rid(rid)
        if snaps:
            report["dir_snapshots"] = snaps


def build_persist_sideload_report(rid: str, section: str, items: List[Any]) -> Dict[str, Any]:
    """列表页「含未签模块」标注用的最小 report 上下文。"""
    ctx: Dict[str, Any] = {
        "_rid": rid,
        "_files_rid": rid,
        "file_scans": [],
        "startup_items": [],
        "scheduled_tasks": [],
        "services": [],
        "dir_snapshots": load_dir_snapshots_for_rid(rid),
    }
    if section == "startup_items":
        ctx["startup_items"] = [x for x in items if isinstance(x, dict)]
    elif section == "scheduled_tasks":
        ctx["scheduled_tasks"] = [x for x in items if isinstance(x, dict)]
    elif section == "services":
        ctx["services"] = [x for x in items if isinstance(x, dict)]
    try:
        from ..collect_pack import load_pack_manifest, pack_dir_for_rid
        if (pack_dir_for_rid(rid) / "files.jsonl").is_file():
            ctx["_pack"] = True
        man = load_pack_manifest(rid)
        if isinstance(man, dict):
            fl = (man.get("modules") or {}).get("files") or {}
            ctx["_files_count"] = int(fl.get("count") or 0)
    except Exception:
        pass
    _ensure_persist_report_context(ctx)
    if ctx.get("startup_items") or ctx.get("scheduled_tasks") or ctx.get("services"):
        _hydrate_entity_dir_files(ctx)
    return ctx


def annotate_persist_sideload_list(section: str, items: List[Any], rid: str = "") -> List[Any]:
    """批量标注 sideload_suspect（启动项/计划任务/服务列表 API）。"""
    if not isinstance(items, list) or not items:
        return items or []
    sample = next((x for x in items if isinstance(x, dict)), None)
    if sample:
        p = str(sample.get("path") or sample.get("resolved_path") or sample.get("command") or "")
        if p.startswith("/") or str(sample.get("name") or "").endswith(".service"):
            return items
    kind = {
        "services": "service",
        "scheduled_tasks": "task",
        "startup_items": "startup",
    }.get(section, "")
    if not kind:
        return items
    rpt = build_persist_sideload_report(rid, section, items) if rid else None
    out = []
    for it in items:
        if isinstance(it, dict):
            try:
                out.append(annotate_persist_sideload(it, kind, rpt))
            except Exception:
                out.append(it)
        else:
            out.append(it)
    return out
