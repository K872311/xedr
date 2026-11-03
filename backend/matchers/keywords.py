"""关键字 / 可疑命令 — rules-keywords 启发 + 内置应急命令特征（真正可跑）"""
from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple

from ..models import Finding
from ..rules_loader import RuleStore

# Autopsy 原版 regex 含 BOUNDARY_CHARS 等 Java 占位，不能直接用。
# 这里提供可执行的应急命令特征库，并叠加简化的 IP/URL/Email 抽取。
SUSPICIOUS_CMDS = [
    ("powershell -enc", "PowerShell 编码执行", "high"),
    ("powershell -encodedcommand", "PowerShell 编码执行", "high"),
    ("frombase64string", "Base64 解码执行", "high"),
    ("invoke-expression", "IEX 动态执行", "high"),
    ("iex(", "IEX 动态执行", "high"),
    ("downloadstring", "远程下载 cradle", "high"),
    ("downloadfile", "远程下载文件", "high"),
    ("invoke-webrequest", "Web 下载", "medium"),
    ("wget ", "工具下载", "medium"),
    ("curl ", "工具下载", "medium"),
    # 注意：不要用裸 lsass.exe — 正常系统进程/服务路径必命中。转储类用 procdump/sekurlsa/mimikatz 及 JSON 里更具体的 needle。
    ("procdump", "进程转储", "high"),
    ("sekurlsa", "LSASS 凭据", "critical"),
    ("mimikatz", "凭据转储工具", "critical"),
    ("comsvcs.dll", "LSASS 内存转储(comsvcs)", "critical"),
    ("MiniDump", "进程 MiniDump 转储", "high"),
    ("regsvr32", "代理执行(regsvr32)", "medium"),
    ("mshta ", "代理执行(mshta)", "high"),
    ("certutil -urlcache", "Certutil 下载", "high"),
    ("bitsadmin /transfer", "BITS 下载", "high"),
    ("schtasks /create", "创建计划任务", "medium"),
    ("net user ", "账户操作", "medium"),
    ("net localgroup administrators", "提权加组", "high"),
    ("whoami /priv", "权限侦察", "low"),
    ("vssadmin delete shadows", "删除卷影(勒索/反取证)", "critical"),
    ("wmic process call create", "WMIC 远程创建进程", "high"),
    ("nltest", "域侦察", "medium"),
    ("rubeus", "Kerberos 攻击工具", "critical"),
    ("bloodhound", "域渗透工具", "high"),
    ("impacket", "Impacket 工具链", "high"),
]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

_VENDOR_IEX_HOSTS = (
    "mimo.xiaomi.com",
    "cdn.xiaomi.com",
    "download.microsoft.com",
    "aka.ms/",
    "aka.ms?",
)
_IEX_TITLE_HINTS = ("iex", "cradle", "download and execute", "download and execution")
_MINIDUMP_NOISE = (
    "sentry", "crashpad", "breakpad", "crashreporter",
    "annotation=format=minidump", "sentry_client", "sentry.native",
)
# Sigma 拍扁后的短开关：JSON 被删时匹配器仍补回 AND
_BUILTIN_REQUIRES = {
    "--port": ("--adcs", "adcspwn"),
    "-target": ("krbrelay", "smbkeyword", "-victim", "remotekrbrelay"),
    "-decode": ("certutil",),
    "-decodehex": ("certutil",),
    "-config": ("certreq",),
    "\\appdata\\local\\temp": ("mofcomp",),
    "\\windows\\temp\\": ("mofcomp",),
    "\\system\\currentcontrolset\\services\\": ("networkprovider",),
    "/account": ("sharpsuccessor", "/impersonate"),
}


def _token_in(low: str, token: str) -> bool:
    """`.exe` 必须落在路径分隔符后；短命令行开关不能当前缀（--decoder 不该等于 -decode）。"""
    tl = (token or "").lower()
    if not tl:
        return False
    if tl.endswith(".exe"):
        idx = 0
        while True:
            i = low.find(tl, idx)
            if i < 0:
                return False
            if i == 0 or low[i - 1] in '\\/"\' \t=:':
                return True
            idx = i + 1
            if idx >= len(low):
                return False
    flag = (tl.startswith("-") or tl.startswith("/")) and len(tl) <= 24
    if not flag:
        return tl in low
    idx = 0
    while True:
        i = low.find(tl, idx)
        if i < 0:
            return False
        before_ok = i == 0 or low[i - 1] in ' \t"\'=:-'
        after = i + len(tl)
        after_ok = after >= len(low) or low[after] not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
        if before_ok and after_ok:
            return True
        idx = i + 1
        if idx >= len(low):
            return False


def _skip_vendor_iex(title: str, low: str) -> bool:
    tl = (title or "").lower()
    if not any(h in tl for h in _IEX_TITLE_HINTS):
        return False
    return any(h in low for h in _VENDOR_IEX_HOSTS)


def _skip_noisy_keyword(title: str, needle: str, low: str) -> bool:
    tl = (title or "").lower()
    nl = (needle or "").lower()
    if "minidump" in tl and any(x in low for x in _MINIDUMP_NOISE):
        return True
    if "renamed" in tl and nl.endswith(".exe"):
        if f"\\system32\\{nl}" in low or f"\\syswow64\\{nl}" in low:
            return True
    return False


def _cmds_from_store(store: RuleStore) -> List[Tuple[str, str, str, Tuple[str, ...]]]:
    """合并内置特征 + rules-keywords.json 的 suspiciousCmds。

    Sigma 规则被摊平成一条条独立 needle 后，原本的 AND 语义就丢了：`/config`
    单独命中会把 Canon 的 `Cnpspcnt.exe /Config:*.xml` 当成 dnscmd 后门。
    `requiresAny` 用来补回伴随条件——同一段文本里还得出现原始程序名才算命中。
    """
    out: List[Tuple[str, str, str, Tuple[str, ...]]] = [(n, t, s, ()) for n, t, s in SUSPICIOUS_CMDS]
    seen = {n.lower() for n, _, _, _ in out}
    raw = store.keywords.get("suspiciousCmds") if isinstance(getattr(store, "keywords", None), dict) else None
    if not isinstance(raw, list):
        return out
    for row in raw:
        if not isinstance(row, dict) or row.get("enabled") is False:
            continue
        needle = str(row.get("needle") or row.get("pattern") or "").strip()
        if len(needle) < 4:
            continue
        key = needle.lower()
        if key in seen:
            continue
        seen.add(key)
        title = str(row.get("title") or row.get("name") or needle)[:120]
        sev = str(row.get("severity") or row.get("level") or "high").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "high"
        req = row.get("requiresAny")
        req_t = tuple(str(x).lower() for x in req if str(x).strip()) if isinstance(req, list) else ()
        extra = _BUILTIN_REQUIRES.get(key)
        if extra:
            req_t = tuple(dict.fromkeys(list(req_t) + [x.lower() for x in extra]))
        out.append((needle, title, sev, req_t))
    return out


def _scan_text(
    text: str,
    source: str,
    seen: Set[str],
    findings: List[Finding],
    matched: List,
    cmds: List[Tuple[str, str, str, Tuple[str, ...]]],
) -> None:
    if not text or not text.strip():
        return
    low = text.lower()
    for needle, title, sev, requires in cmds:
        nl = needle.lower()
        if not _token_in(low, nl):
            continue
        if requires and not any(_token_in(low, r) for r in requires):
            continue
        if _skip_vendor_iex(title, low):
            continue
        if _skip_noisy_keyword(title, nl, low):
            continue
        idx = low.find(nl)
        snippet = text[max(0, idx - 20): idx + 80].replace("\n", " ")
        key = f"可疑命令|{title}|{snippet}|{source}"
        if key in seen:
            continue
        seen.add(key)
        matched.append({"name": title, "source": source, "snippet": snippet})
        findings.append(Finding("可疑命令", sev, title, f"{source}: {snippet}", source, needle, "keywords"))

    # 简化抽取（对应 keywords 意图，避免全量误报：仅对 PS 历史）
    if source.startswith("PS历史"):
        for m in URL_RE.findall(text)[:5]:
            key = f"关键字|URL|{m}|{source}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding("关键字", "low", "URL", f"{source}: {m}", source, "url", "keywords"))


def run(report: Dict, store: RuleStore, seen: Set[str]) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []
    matched: List[Dict] = []
    cmds = _cmds_from_store(store)

    for i, block in enumerate(report.get("ps_history") or []):
        src = f"PS历史#{i}"
        if isinstance(block, str) and ":" in block[:40]:
            src = "PS历史:" + block.split(":", 1)[0]
        _scan_text(block if isinstance(block, str) else str(block), src, seen, findings, matched, cmds)

    for si in report.get("startup_items") or []:
        _scan_text(si.get("command") or "", "启动命令", seen, findings, matched, cmds)

    for t in report.get("scheduled_tasks") or []:
        blob = f"{t.get('task_name') or ''} {t.get('command') or t.get('actions') or ''}"
        _scan_text(blob, "计划任务", seen, findings, matched, cmds)

    for s in report.get("services") or []:
        _scan_text(s.get("path") or "", "服务路径", seen, findings, matched, cmds)

    for p in report.get("processes") or []:
        if not isinstance(p, dict):
            continue
        name = p.get("name") or p.get("image") or p.get("Image") or ""
        cmd = p.get("cmdline") or p.get("command_line") or p.get("CommandLine") or p.get("cmd") or ""
        _scan_text(f"{name} {cmd}", "进程", seen, findings, matched, cmds)

    return findings, {"matched_keywords": matched, "cmd_rules": len(cmds)}
