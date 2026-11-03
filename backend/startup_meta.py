"""启动项：从 command 解析路径，本地文件可读时补签名/公司信息（兼容旧报告）。"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from .lnk_parse import resolve_lnk_target

_ENV_MAP = {
    "%windir%": lambda: os.environ.get("WINDIR", r"C:\Windows"),
    "%systemroot%": lambda: os.environ.get("WINDIR", r"C:\Windows"),
    "%system32%": lambda: str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"),
    "%programfiles%": lambda: os.environ.get("ProgramFiles", r"C:\Program Files"),
    "%programfiles(x86)%": lambda: os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    "%programdata%": lambda: os.environ.get("ProgramData", r"C:\ProgramData"),
    "%appdata%": lambda: os.environ.get("APPDATA", ""),
    "%localappdata%": lambda: os.environ.get("LOCALAPPDATA", ""),
    "%userprofile%": lambda: os.environ.get("USERPROFILE", ""),
}

_GOOD_SIG = frozenset({
    "Valid", "NotSigned", "HashMismatch", "NotTrusted",
    "Incompatible", "UnknownError",
})


def _local_enrichment_enabled() -> bool:
    """报告路径属于被采集终端，默认禁止平台服务器访问这些路径。"""
    return (os.environ.get("FORENSIC_LOCAL_META_ENRICH") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _has_good_meta(row: Dict[str, Any]) -> bool:
    """已有可靠签名结果则不再重查（Error/空 会重试）。"""
    st = (row.get("sig_status") or "").strip()
    stl = st.lower()
    if not st or stl in ("error", "unknown", "missing", "unchecked") or stl.startswith("error"):
        return False
    if st in _GOOD_SIG:
        return True
    if row.get("signer") and st:
        return True
    return False


def extract_exe_path(command: str) -> str:
    c = (command or "").strip()
    if not c or c.startswith("{") or c.lower() == "com handler":
        return ""
    # Startup .lnk：优先解析快捷方式目标
    lnk = c.split(" -> ", 1)[0].strip().strip('"')
    if lnk.lower().endswith(".lnk") and os.path.isfile(lnk):
        target = resolve_lnk_target(lnk)
        if target:
            return os.path.normpath(target)
    path = ""
    if c.startswith('"'):
        end = c.find('"', 1)
        if end > 1:
            path = c[1:end]
    else:
        low = c.lower()
        for flag in ("-file ", "-f ", "/file "):
            i = low.find(flag)
            if i >= 0:
                rest = c[i + len(flag):].strip()
                if rest.startswith('"'):
                    end = rest.find('"', 1)
                    if end > 1:
                        path = rest[1:end]
                        break
                parts = rest.split()
                if parts:
                    path = parts[0]
                    break
        if not path:
            cut = -1
            for ext in (".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".js"):
                i = low.find(ext)
                if i >= 0:
                    cut = i + len(ext)
                    break
            if cut > 0:
                path = c[:cut]
            else:
                path = c.split()[0] if c.split() else ""
    path = path.strip()
    if not path:
        return ""
    if path.startswith("\\??\\"):
        path = path[4:]
    windir = os.environ.get("WINDIR", r"C:\Windows")
    low = path.lower()
    if low.startswith("system32\\") or low.startswith("system32/") or low.startswith("syswow64\\"):
        path = str(Path(windir) / path)
        low = path.lower()
    # \SystemRoot\...
    for key, val in (
        ("\\systemroot", windir),
        ("%systemroot%", windir),
        ("%windir%", windir),
        ("%system32%", str(Path(windir) / "System32")),
        ("%programfiles%", os.environ.get("ProgramFiles", r"C:\Program Files")),
        ("%programfiles(x86)%", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        ("%programdata%", os.environ.get("ProgramData", r"C:\ProgramData")),
        ("%appdata%", os.environ.get("APPDATA", "")),
        ("%localappdata%", os.environ.get("LOCALAPPDATA", "")),
        ("%userprofile%", os.environ.get("USERPROFILE", "")),
    ):
        while key in low and val:
            idx = low.index(key)
            path = path[:idx] + val + path[idx + len(key):]
            low = path.lower()
    path = os.path.expandvars(path)
    path = os.path.normpath(path)
    # 裸名：Winlogon Shell=explorer.exe → %windir%\explorer.exe 等
    if path and not (len(path) >= 3 and path[1] == ":"):
        base = os.path.basename(path)
        windir = os.environ.get("WINDIR", r"C:\Windows")
        known = {
            "explorer.exe": str(Path(windir) / "explorer.exe"),
            "userinit.exe": str(Path(windir) / "System32" / "userinit.exe"),
        }
        cand = known.get(base.lower())
        if cand and (not _local_enrichment_enabled() or os.path.isfile(cand)):
            return cand
        for c in (
            str(Path(windir) / base),
            str(Path(windir) / "System32" / base),
            str(Path(windir) / "SysWOW64" / base),
        ):
            if os.path.isfile(c):
                return c
            if not _local_enrichment_enabled() and known.get(base.lower()) == c:
                return c
    return path


def _service_dll(name: str) -> str:
    if not name or not _local_enrichment_enabled():
        return ""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\{name}\Parameters",
        )
        try:
            val, _ = winreg.QueryValueEx(key, "ServiceDll")
        finally:
            winreg.CloseKey(key)
        return extract_exe_path(str(val or ""))
    except OSError:
        return ""


def _apply_meta(row: Dict[str, Any], meta: Dict[str, Any]) -> None:
    if not meta:
        return
    row["company"] = meta.get("company") or row.get("company") or ""
    row["product"] = meta.get("product") or row.get("product") or ""
    row["description"] = meta.get("description") or row.get("description") or ""
    row["file_version"] = meta.get("file_version") or row.get("file_version") or ""
    row["signed"] = bool(meta.get("signed"))
    row["signer"] = meta.get("signer") or ""
    row["sig_status"] = meta.get("sig_status") or ""
    row["sig_type"] = meta.get("sig_type") or row.get("sig_type") or ""


def enrich_startup_items(items: List[Dict[str, Any]], max_n: int = 80) -> List[Dict[str, Any]]:
    """补齐启动项签名（Valid/NotSigned 等已有结果则跳过）。"""
    return _enrich_by_command(items, cmd_keys=("command",), path_key="path", max_n=max_n)


def enrich_scheduled_tasks(items: List[Dict[str, Any]], max_n: int = 100) -> List[Dict[str, Any]]:
    """补齐计划任务签名。"""
    return _enrich_by_command(items, cmd_keys=("command", "task_to_run"), path_key="path", max_n=max_n)


def enrich_services(items: List[Dict[str, Any]], max_n: int = 120) -> List[Dict[str, Any]]:
    """补齐服务 ImagePath / ServiceDll 签名。"""
    if not items:
        return items
    cache: Dict[str, Dict[str, Any]] = {}
    done = 0
    out = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        row = dict(it)
        if _has_good_meta(row):
            out.append(row)
            continue
        resolved = row.get("resolved_path") or extract_exe_path(row.get("path") or "")
        dll = row.get("service_dll") or _service_dll(row.get("name") or "")
        if resolved:
            row["resolved_path"] = resolved
        if dll:
            row["service_dll"] = dll
        for cand in (dll, resolved):
            if not cand or done >= max_n:
                continue
            lp = cand.lower()
            if lp not in cache:
                cache[lp] = _file_meta(cand)
                done += 1
            meta = cache.get(lp) or {}
            if meta:
                _apply_meta(row, meta)
                break
        out.append(row)
    return out


def _enrich_by_command(
    items: List[Dict[str, Any]],
    cmd_keys: tuple,
    path_key: str = "path",
    max_n: int = 80,
) -> List[Dict[str, Any]]:
    if not items:
        return items
    cache: Dict[str, Dict[str, Any]] = {}
    done = 0
    out = []
    for it in items:
        if not isinstance(it, dict):
            out.append(it)
            continue
        row = dict(it)
        if _has_good_meta(row):
            out.append(row)
            continue
        cmd = ""
        for k in cmd_keys:
            if row.get(k):
                cmd = str(row.get(k))
                break
        path = row.get(path_key) or extract_exe_path(cmd)
        if path:
            row[path_key] = path
        if path and done < max_n:
            lp = path.lower()
            if lp not in cache:
                cache[lp] = _file_meta(path)
                done += 1
            _apply_meta(row, cache.get(lp) or {})
        out.append(row)
    return out


def _powershell_exe() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    exe = Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(exe) if exe.is_file() else "powershell"


def _ps_env() -> Dict[str, str]:
    """隔离 PSModulePath，避免 PowerShell 7 模块污染导致 Authenticode cmdlet 加载失败。"""
    env = os.environ.copy()
    root = os.environ.get("SystemRoot", r"C:\Windows")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    env["PSModulePath"] = ";".join([
        str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
        str(Path(pf) / "WindowsPowerShell" / "Modules"),
    ])
    return env


def _file_meta(path: str) -> Dict[str, Any]:
    """用 Windows PowerShell 5.1 取签名（仅当文件存在）。"""
    import json
    import tempfile
    if not path or not _local_enrichment_enabled():
        return {}
    norm = str(path).strip().replace("/", "\\")
    if norm.startswith("\\\\") or norm.startswith("\\?\\") or norm.startswith("\\.\\"):
        return {}
    if not os.path.isfile(path):
        return {}
    try:
        path = str(Path(path).resolve())
    except OSError:
        pass
    script = f"""
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [Console]::OutputEncoding
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
$p = {json.dumps(path)}
$out = [ordered]@{{
  company=''; product=''; description=''; file_version='';
  signed=$false; signer=''; sig_status='Unknown'; sig_type=''
}}
if (-not (Test-Path -LiteralPath $p)) {{
  $out.sig_status = 'Missing'
  $out | ConvertTo-Json -Compress
  exit 0
}}
try {{
  $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
  $out.company = [string]$vi.CompanyName
  $out.product = [string]$vi.ProductName
  $out.description = [string]$vi.FileDescription
  $out.file_version = [string]$vi.FileVersion
}} catch {{}}
try {{
  # Authenticode(文件) 与 Catalog(目录/.cat) 均计入有效签名
  $sig = Get-AuthenticodeSignature -LiteralPath $p
  if ($null -ne $sig) {{
    $out.sig_status = [string]$sig.Status
    $out.sig_type = [string]$sig.SignatureType
    if ($sig.SignerCertificate) {{
      $out.signer = [string]$sig.SignerCertificate.Subject
    }}
    if ($out.sig_status -eq 'Valid') {{ $out.signed = $true }}
  }}
}} catch {{
  $out.sig_status = 'Error'
}}
if (-not $out.sig_status) {{ $out.sig_status = 'Unknown' }}
$out | ConvertTo-Json -Compress
"""
    fd, script_path = tempfile.mkstemp(suffix=".ps1")
    os.close(fd)
    try:
        with open(script_path, "w", encoding="utf-8-sig") as f:
            f.write(script)
        raw = subprocess.check_output(
            [_powershell_exe(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path],
            stderr=subprocess.DEVNULL, timeout=25, env=_ps_env(),
        ).decode("utf-8", errors="replace").strip()
        if not raw:
            return {}
        line = raw.splitlines()[-1].strip()
        return json.loads(line)
    except Exception:
        return {}
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

