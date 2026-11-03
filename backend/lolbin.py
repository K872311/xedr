# -*- coding: utf-8 -*-
"""LOLBin（系统自带程序滥用）检测。

按「进程名 + 命令行特征 (+ 父进程)」匹配，覆盖常见代理执行 / 下载 / 解码 / 凭据 / 破坏恢复类手法。
规则为本项目自行编写，思路参考公开 ATT&CK 技术说明，不包含第三方规则原文。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_OFFICE = r"(winword|excel|powerpnt|outlook|msaccess|onenote|mspub|visio)\.exe"
_SCRIPT_HOST = r"(wscript|cscript|mshta|powershell|pwsh|cmd)\.exe"
_URL = r"(https?://|\\\\[a-z0-9_.-]+\\|ftp://)"
_USERDIR = r"\\(users\\[^\\]+\\(appdata|downloads|desktop|documents)|users\\public|programdata|windows\\temp|temp|tmp)\\"

# 每条：id, title, severity, technique, tactic, image(正则), cmd(正则, 可空), parent(正则, 可空)
RULES: List[Dict[str, Any]] = [
    {"id": "lol-certutil-download", "title": "certutil 下载文件", "severity": "high",
     "technique": "T1105", "tactic": "command_and_control",
     "image": r"certutil\.exe", "cmd": r"(-|/)(urlcache|verifyctl)\b.*" + _URL},
    {"id": "lol-certutil-decode", "title": "certutil 解码/编码载荷", "severity": "high",
     "technique": "T1140", "tactic": "defense_evasion",
     "image": r"certutil\.exe", "cmd": r"(-|/)(decode|decodehex|encode)\b"},
    {"id": "lol-mshta-remote", "title": "mshta 执行远程或内联脚本", "severity": "high",
     "technique": "T1218.005", "tactic": "defense_evasion",
     "image": r"mshta\.exe", "cmd": r"(" + _URL + r"|javascript:|vbscript:|about:)"},
    {"id": "lol-mshta-userdir", "title": "mshta 运行用户目录 HTA", "severity": "high",
     "technique": "T1218.005", "tactic": "defense_evasion",
     "image": r"mshta\.exe", "cmd": _USERDIR + r".*\.hta"},
    {"id": "lol-regsvr32-squiblydoo", "title": "regsvr32 远程脚本组件(Squiblydoo)", "severity": "high",
     "technique": "T1218.010", "tactic": "defense_evasion",
     "image": r"regsvr32\.exe", "cmd": r"(/i:\s*" + _URL + r"|scrobj\.dll)"},
    {"id": "lol-regsvr32-userdir", "title": "regsvr32 注册用户目录 DLL", "severity": "medium",
     "technique": "T1218.010", "tactic": "defense_evasion",
     "image": r"regsvr32\.exe", "cmd": _USERDIR + r".*\.(dll|ocx|sct|txt|dat)"},
    {"id": "lol-rundll32-script", "title": "rundll32 执行脚本协议", "severity": "high",
     "technique": "T1218.011", "tactic": "defense_evasion",
     "image": r"rundll32\.exe", "cmd": r"(javascript:|vbscript:|mshtml,runhtmlapplication|" + _URL + r")"},
    {"id": "lol-rundll32-minidump", "title": "rundll32 调用 comsvcs MiniDump（疑似 LSASS 转储）", "severity": "critical",
     "technique": "T1003.001", "tactic": "credential_access",
     "image": r"rundll32\.exe", "cmd": r"comsvcs(\.dll)?[, ]+(#\s*24|minidump)"},
    {"id": "lol-rundll32-userdir", "title": "rundll32 加载用户目录 DLL", "severity": "medium",
     "technique": "T1218.011", "tactic": "defense_evasion",
     "image": r"rundll32\.exe", "cmd": _USERDIR + r"[^,]*\.(dll|dat|tmp|bin|cpl)?\s*,"},
    {"id": "lol-rundll32-noargs", "title": "rundll32 无参数运行（常见注入宿主）", "severity": "medium",
     "technique": "T1218.011", "tactic": "defense_evasion",
     "image": r"rundll32\.exe", "cmd": r"^\s*\"?[a-z]:\\[^\"]*rundll32\.exe\"?\s*$"},
    {"id": "lol-msbuild-userproj", "title": "MSBuild 编译执行用户目录工程", "severity": "high",
     "technique": "T1127.001", "tactic": "defense_evasion",
     "image": r"msbuild\.exe", "cmd": _USERDIR + r".*\.(xml|csproj|proj|targets|txt)"},
    {"id": "lol-msbuild-office-parent", "title": "办公/脚本进程拉起 MSBuild", "severity": "high",
     "technique": "T1127.001", "tactic": "defense_evasion",
     "image": r"msbuild\.exe", "parent": r"(" + _OFFICE + r"|" + _SCRIPT_HOST + r"|explorer\.exe)"},
    {"id": "lol-installutil", "title": "InstallUtil 卸载模式执行程序集", "severity": "high",
     "technique": "T1218.004", "tactic": "defense_evasion",
     "image": r"installutil\.exe", "cmd": r"(/logfile=|/logtoconsole=false|\s/u\s)"},
    {"id": "lol-regasm-regsvcs", "title": "RegAsm/RegSvcs 执行用户目录程序集", "severity": "high",
     "technique": "T1218.009", "tactic": "defense_evasion",
     "image": r"(regasm|regsvcs)\.exe", "cmd": _USERDIR},
    {"id": "lol-bitsadmin", "title": "bitsadmin 下载/持久化任务", "severity": "high",
     "technique": "T1197", "tactic": "defense_evasion",
     "image": r"bitsadmin\.exe", "cmd": r"/(transfer|addfile|setnotifycmdline|create)\b"},
    {"id": "lol-wmic-proc-create", "title": "WMIC 远程/本地创建进程", "severity": "high",
     "technique": "T1047", "tactic": "execution",
     "image": r"wmic\.exe", "cmd": r"process\s+call\s+create"},
    {"id": "lol-wmic-xsl", "title": "WMIC 加载远程 XSL 脚本", "severity": "high",
     "technique": "T1220", "tactic": "defense_evasion",
     "image": r"wmic\.exe", "cmd": r"/format:\s*\"?(" + _URL + r"|.*\.xsl)"},
    {"id": "lol-wmic-shadow", "title": "WMIC 删除卷影副本", "severity": "critical",
     "technique": "T1490", "tactic": "impact",
     "image": r"wmic\.exe", "cmd": r"shadowcopy\s+delete"},
    {"id": "lol-vssadmin-delete", "title": "vssadmin 删除/缩减卷影副本", "severity": "critical",
     "technique": "T1490", "tactic": "impact",
     "image": r"vssadmin\.exe", "cmd": r"(delete\s+shadows|resize\s+shadowstorage)"},
    {"id": "lol-bcdedit-recovery", "title": "bcdedit 关闭系统恢复", "severity": "critical",
     "technique": "T1490", "tactic": "impact",
     "image": r"bcdedit\.exe", "cmd": r"(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"},
    {"id": "lol-wbadmin-delete", "title": "wbadmin 删除备份目录", "severity": "critical",
     "technique": "T1490", "tactic": "impact",
     "image": r"wbadmin\.exe", "cmd": r"delete\s+(catalog|systemstatebackup|backup)"},
    {"id": "lol-wevtutil-clear", "title": "wevtutil 清空事件日志", "severity": "high",
     "technique": "T1070.001", "tactic": "defense_evasion",
     "image": r"wevtutil\.exe", "cmd": r"\s(cl|clear-log)\s"},
    {"id": "lol-cmstp", "title": "CMSTP 加载 INF 绕过 UAC/AppLocker", "severity": "high",
     "technique": "T1218.003", "tactic": "defense_evasion",
     "image": r"cmstp\.exe", "cmd": r"(/s|/ni|/au).*\.inf"},
    {"id": "lol-odbcconf", "title": "odbcconf 注册 DLL", "severity": "high",
     "technique": "T1218.008", "tactic": "defense_evasion",
     "image": r"odbcconf\.exe", "cmd": r"(regsvr|-f\s|/f\s|/a\s*\{)"},
    {"id": "lol-msiexec-remote", "title": "msiexec 静默安装远程包", "severity": "high",
     "technique": "T1218.007", "tactic": "defense_evasion",
     "image": r"msiexec\.exe", "cmd": r"/(i|package)\s*\"?" + _URL},
    {"id": "lol-msiexec-dllreg", "title": "msiexec /y /z 加载 DLL", "severity": "high",
     "technique": "T1218.007", "tactic": "defense_evasion",
     "image": r"msiexec\.exe", "cmd": r"\s/(y|z)\s*\"?[a-z]:\\"},
    {"id": "lol-forfiles", "title": "forfiles 间接执行命令", "severity": "medium",
     "technique": "T1202", "tactic": "defense_evasion",
     "image": r"forfiles\.exe", "cmd": r"/c\s"},
    {"id": "lol-pcalua", "title": "pcalua 间接执行程序", "severity": "medium",
     "technique": "T1202", "tactic": "defense_evasion",
     "image": r"pcalua\.exe", "cmd": r"-a\s"},
    {"id": "lol-msdt-follina", "title": "msdt 诊断协议执行（Follina 类）", "severity": "critical",
     "technique": "T1218", "tactic": "defense_evasion",
     "image": r"msdt\.exe", "cmd": r"(it_browseforfile|pcwdiagnostic|it_rebrowseforfile)"},
    {"id": "lol-mavinject", "title": "mavinject 注入 DLL", "severity": "critical",
     "technique": "T1218.013", "tactic": "defense_evasion",
     "image": r"mavinject(64)?\.exe", "cmd": r"/injectrunning"},
    {"id": "lol-msxsl", "title": "msxsl 执行 XSL 脚本", "severity": "high",
     "technique": "T1220", "tactic": "defense_evasion",
     "image": r"msxsl\.exe"},
    {"id": "lol-control-cpl", "title": "control 加载用户目录 CPL", "severity": "high",
     "technique": "T1218.002", "tactic": "defense_evasion",
     "image": r"control\.exe", "cmd": _USERDIR + r".*\.cpl"},
    {"id": "lol-reg-save-hive", "title": "reg 导出 SAM/SECURITY/SYSTEM 配置单元", "severity": "critical",
     "technique": "T1003.002", "tactic": "credential_access",
     "image": r"reg\.exe", "cmd": r"(save|export)\s+\"?hklm\\(sam|security|system)\b"},
    {"id": "lol-ntdsutil-ifm", "title": "ntdsutil 导出 NTDS（IFM）", "severity": "critical",
     "technique": "T1003.003", "tactic": "credential_access",
     "image": r"ntdsutil\.exe", "cmd": r"(ifm|create\s+full)"},
    {"id": "lol-esentutl-copy", "title": "esentutl 卷影复制敏感文件", "severity": "high",
     "technique": "T1003", "tactic": "credential_access",
     "image": r"esentutl\.exe", "cmd": r"/y\s.*(/vss|ntds\.dit|\\sam\b|\\system\b)"},
    {"id": "lol-schtasks-susp", "title": "schtasks 创建可疑任务", "severity": "high",
     "technique": "T1053.005", "tactic": "persistence",
     "image": r"schtasks\.exe",
     "cmd": r"/create\b.*(" + _URL + r"|powershell|pwsh|mshta|rundll32|regsvr32|cmd\s*/c|" + _USERDIR + r")"},
    {"id": "lol-ps-encoded", "title": "PowerShell 编码/隐藏执行", "severity": "high",
     "technique": "T1059.001", "tactic": "execution",
     "image": r"(powershell|pwsh)\.exe",
     "cmd": r"(\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string)"},
    {"id": "lol-ps-hidden-bat-scriptblock", "title": "隐藏 PowerShell 从 BAT 解出 ScriptBlock 执行", "severity": "high",
     "technique": "T1059.001", "tactic": "execution",
     "image": r"(powershell|pwsh)\.exe",
     "cmd": r"(windowstyle\s+hidden|executionpolicy\s+bypass).*(readalltext|\[scriptblock\]::create|lastindexof\s*\(\s*['\"]rem#)"},
    {"id": "lol-ps-download", "title": "PowerShell 下载执行", "severity": "high",
     "technique": "T1059.001", "tactic": "execution",
     "image": r"(powershell|pwsh)\.exe",
     "cmd": r"(downloadstring|downloadfile|invoke-webrequest|iwr\s|start-bitstransfer|net\.webclient).*(iex|invoke-expression|\|\s*iex|-outfile)"},
    {"id": "lol-script-userdir", "title": "WSH 执行用户目录脚本", "severity": "medium",
     "technique": "T1059.005", "tactic": "execution",
     "image": r"(wscript|cscript)\.exe", "cmd": _USERDIR + r".*\.(js|jse|vbs|vbe|wsf|wsh)"},
    {"id": "lol-wscript-hidden-temp", "title": "WScript 静默运行 Temp/Public 脚本", "severity": "high",
     "technique": "T1059.005", "tactic": "execution",
     "image": r"wscript\.exe",
     "cmd": r"(//b|//nologo).*(\\temp\\|\\tmp\\|\\users\\public\\|\\public\\).*\.(vbs|js|wsf|wsh)"},
    {"id": "lol-office-child", "title": "办公软件拉起脚本/LOLBin", "severity": "high",
     "technique": "T1566.001", "tactic": "initial_access",
     "image": r"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|wmic)\.exe",
     "parent": _OFFICE},
    {"id": "lol-curl-userdir", "title": "curl 下载到用户/临时目录", "severity": "medium",
     "technique": "T1105", "tactic": "command_and_control",
     "image": r"curl\.exe",
     "cmd": r"(-o|--output)\s+\"?[a-z]:\\[^\"]*\\(appdata|temp|tmp|downloads|public|programdata)\\"},
    {"id": "lol-hh-remote", "title": "hh.exe 打开远程 CHM", "severity": "high",
     "technique": "T1218.001", "tactic": "defense_evasion",
     "image": r"hh\.exe", "cmd": _URL},
    {"id": "lol-ieexec", "title": "ieexec 下载执行远程程序", "severity": "high",
     "technique": "T1105", "tactic": "command_and_control",
     "image": r"ieexec\.exe", "cmd": _URL},
    {"id": "lol-cmd-hidden-chain", "title": "cmd 串联下载与执行", "severity": "medium",
     "technique": "T1059.003", "tactic": "execution",
     "image": r"cmd\.exe",
     "cmd": r"/c\b.*(certutil|bitsadmin|curl|powershell).*(&|&&|\|).*(start\s|\.exe|rundll32|regsvr32)"},
]

_COMPILED: List[Dict[str, Any]] = []


def _compile() -> List[Dict[str, Any]]:
    if _COMPILED:
        return _COMPILED
    for r in RULES:
        c = dict(r)
        c["_img"] = re.compile(r"(^|\\)" + r["image"] + r"$", re.I)
        c["_cmd"] = re.compile(r["cmd"], re.I) if r.get("cmd") else None
        c["_par"] = re.compile(r"(^|\\)" + r["parent"] + r"$", re.I) if r.get("parent") else None
        _COMPILED.append(c)
    return _COMPILED


def _basename(p: str) -> str:
    p = str(p or "").strip().strip('"')
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def match(item: Dict[str, Any], *, disabled: Optional[set] = None) -> List[Dict[str, Any]]:
    """对单个进程条目匹配 LOLBin 规则，返回命中列表。"""
    if not isinstance(item, dict):
        return []
    name = _basename(item.get("name") or item.get("path") or item.get("image") or "")
    if not name.endswith(".exe"):
        return []
    path = str(item.get("path") or item.get("image") or "")
    cmd = str(item.get("command_line") or item.get("command") or "")
    parent = _basename(item.get("parent_name") or item.get("parent_path") or "")
    hits: List[Dict[str, Any]] = []
    for r in _compile():
        if disabled and r["id"] in disabled:
            continue
        if not (r["_img"].search(name) or (path and r["_img"].search(path.lower()))):
            continue
        if r["_par"] is not None and not (parent and r["_par"].search(parent)):
            continue
        matched = ""
        if r["_cmd"] is not None:
            if not cmd:
                continue
            m = r["_cmd"].search(cmd)
            if not m:
                continue
            matched = m.group(0)[:200]
        else:
            matched = f"{parent} → {name}" if parent else name
        hits.append({
            "rule_id": r["id"], "title": r["title"], "severity": r["severity"],
            "technique": r["technique"], "tactic": r["tactic"], "matched": matched,
        })
    return hits


def technique_for_text(text: str) -> Optional[Dict[str, str]]:
    """按告警标题反查 ATT&CK（供看板映射）。"""
    t = str(text or "")
    for r in RULES:
        if r["title"] in t:
            return {"technique": r["technique"], "tactic": r["tactic"]}
    return None


def catalog() -> List[Dict[str, Any]]:
    return [{k: r.get(k) for k in ("id", "title", "severity", "technique", "tactic", "image", "cmd", "parent")} for r in RULES]
