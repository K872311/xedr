# -*- coding: utf-8 -*-
"""Agent 专用实时规则（与主平台规则库分离，降低误报）。

文件：rules/agent-live-rules.json
管理台可增删改启用；快照上报时仅用本库匹配。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

RULES_FILE = "agent-live-rules.json"
_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {"mtime": 0.0, "doc": None}

_MODULES = (
    "process", "service", "task", "startup", "network", "sysinfo", "file", "user",
    "software", "hotfix", "listen", "timeline",
)
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# 仅用于时间线展示/过滤，不应进入端上 EVM（否则会「每条进程创建都 evm_hit」）
_SENSOR_EVM_SKIP_IDS = frozenset({
    "sensor-etw-proc",
    "sensor-etw-proc-exit",
    "sensor-dns",
    "sensor-dns-summary",
    "sensor-win-ps-script",
    "sensor-win-ps-module",
})
_FIELD_DEFAULT = {
    "process": ["name", "path", "command_line", "user"],
    "service": ["name", "display_name", "path", "account"],
    "task": ["task_name", "command", "path", "execute"],
    "startup": ["name", "command", "path", "location"],
    "network": ["local", "remote", "state", "proto"],
    "sysinfo": ["hostname", "caption"],
    "file": ["name", "path", "directory", "ext"],
    "user": ["name", "session", "state"],
}


def _path() -> Path:
    return Path(config.RULES_DIR) / RULES_FILE


def is_elastic_rule(r: Dict[str, Any]) -> bool:
    """Elastic 导入规则（含误标为 custom 的旧数据）。"""
    if not isinstance(r, dict):
        return False
    if str(r.get("source") or "").strip().lower() == "elastic":
        return True
    rid = str(r.get("id") or "").strip().lower()
    if rid.startswith("elastic-"):
        return True
    if str(r.get("elastic_rule_id") or "").strip():
        return True
    note = str(r.get("note") or "").strip()
    return note.startswith("Elastic:") or note.startswith("Elastic EVM")


def _enrich_rule_item(r: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(r)
    if is_elastic_rule(out) and str(out.get("source") or "").lower() != "elastic":
        out["source"] = "elastic"
    return out


def _merge_evm_rules_for_ui(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把 elastic_evm_import 中仅时间线执行的规则并入控制台列表（与快照规则区分）。"""
    try:
        from . import elastic_detection_import as _edi
    except Exception:
        return rules
    by_id = {str(r.get("id") or ""): r for r in rules if str(r.get("id") or "")}
    for er in _edi.load_evm_import_rules(enabled_only=False):
        if not isinstance(er, dict):
            continue
        eid = str(er.get("id") or "").strip()
        if not eid or eid in by_id:
            continue
        base = eid.replace(".evm", "").replace(".fim", "")
        snap = by_id.get(base)
        by_id[eid] = {
            "id": eid,
            "title": str(er.get("title") or (snap.get("title") if snap else "") or eid)[:120],
            "severity": str(er.get("severity") or (snap or {}).get("severity") or "medium"),
            "source": "elastic",
            "rule_channel": "evm",
            "etype": str(er.get("etype") or ""),
            "patterns": list(er.get("patterns") or [])[:24],
            "match": str(er.get("match") or "substring"),
            "enabled": er.get("enabled") is not False,
            "building_block": bool(er.get("building_block")),
            "elastic_rule_id": str(er.get("elastic_rule_id") or (snap or {}).get("elastic_rule_id") or ""),
            "note": "Elastic EVM（时间线子串近似，非完整 EQL/KQL）",
            "modules": [],
            "builtin": False,
        }
    return list(by_id.values())


def _default_rules() -> List[Dict[str, Any]]:
    """内置少量高置信规则，避免平台全量规则误报。"""
    return [
        {
            "id": "agent-ps-enc",
            "title": "PowerShell 编码执行",
            "severity": "high",
            "modules": ["process", "task", "startup"],
            "fields": ["command_line", "command", "path"],
            "patterns": ["-enc ", "-encodedcommand", "frombase64string"],
            "match": "substring",
            "enabled": True,
            "note": "命令行含编码执行特征",
        },
        {
            "id": "agent-temp-exe",
            "title": "临时目录可执行文件",
            "severity": "high",
            "modules": ["process", "service", "startup"],
            "fields": ["path", "command", "command_line"],
            "patterns": ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"],
            "match": "substring",
            "enabled": True,
            "note": "路径落在临时目录",
        },
        {
            "id": "agent-download-lolbin",
            "title": "计划任务可疑下载器",
            "severity": "high",
            "modules": ["task", "startup"],
            "fields": ["command", "path"],
            "patterns": ["certutil", "bitsadmin", "invoke-webrequest", "iwr ", "wget ", "curl "],
            "match": "substring",
            "enabled": True,
            "note": "",
        },
        {
            "id": "agent-svc-userdir",
            "title": "服务位于用户目录",
            "severity": "medium",
            "modules": ["service"],
            "fields": ["path"],
            "patterns": ["\\users\\", "\\appdata\\"],
            "match": "substring",
            "enabled": False,
            "note": "默认关闭：部分合法软件也会装在用户目录",
        },
        {
            "id": "agent-unsigned-exe",
            "title": "未签名可执行文件",
            "severity": "medium",
            "modules": ["process", "file", "startup", "service"],
            "fields": ["path", "name", "signed"],
            "patterns": ["*"],
            "file_exts": ["exe", "dll", "sys", "scr"],
            "signed_filter": "unsigned",
            "match": "substring",
            "enabled": True,
            "note": "签名状态非 Valid（含未签名/异常）",
        },
        {
            "id": "agent-root-drop",
            "title": "磁盘根目录投放可执行文件",
            "severity": "high",
            "modules": ["file", "process"],
            "fields": ["path"],
            "patterns": [r"^[A-Za-z]:\\[^\\]+\.(exe|dll|bat|cmd|ps1|scr)$"],
            "file_exts": ["exe", "dll", "bat", "cmd", "ps1", "scr"],
            "match": "regex",
            "enabled": True,
            "note": "仅匹配盘符根下一层，如 C:\\evil.exe（需 Agent 文件模块扫到）",
        },
        {
            "id": "agent-progdata-temp-unsigned",
            "title": "ProgramData/Temp 未签名可执行新增",
            "severity": "high",
            "modules": ["file", "process"],
            "fields": ["path", "command_line"],
            "path_prefixes": [r"C:\ProgramData", r"C:\Windows\Temp"],
            "file_exts": ["exe", "dll", "bat", "cmd", "ps1", "scr", "msi", "js", "vbs", "hta"],
            "signed_filter": "unsigned",
            "patterns": ["*"],
            "match": "substring",
            "enabled": True,
            "note": "实时主要靠 FIM+EVM；快照模块周期复核。Temp 含 Windows\\Temp，用户 Temp 见下方 regex 规则。",
        },
        {
            "id": "agent-user-temp-unsigned",
            "title": "用户 Temp 未签名可执行（regex）",
            "severity": "high",
            "modules": ["file", "process"],
            "fields": ["path"],
            "file_exts": ["exe", "dll", "bat", "cmd", "ps1", "scr", "msi"],
            "signed_filter": "unsigned",
            "patterns": [
                r"(?i)[A-Za-z]:\\Users\\[^\\]+\\AppData\\Local\\Temp\\[^\\]+\.(exe|dll|bat|cmd|ps1|scr|msi)$",
            ],
            "match": "regex",
            "enabled": False,
            "note": "默认关闭（量大）；需要时可开启。",
        },
    ]


def _sensor_builtin_rules() -> List[Dict[str, Any]]:
    """Agent 传感器内置检出（ETW / 事件通道 / 差分 / 内核），展示在规则管理中可开关。

    匹配字段供服务端入库过滤：etype / summary_contains。
    """
    common = {
        "source": "sensor",
        "builtin": True,
        "modules": ["timeline"],
        "fields": ["etype", "summary", "path"],
        "patterns": [],
        "match": "substring",
        "file_exts": [],
        "signed_filter": "",
        "path_prefixes": [],
    }

    def R(rid: str, title: str, severity: str, etype: str, summary_contains: str, note: str, *, enabled: bool = True) -> Dict[str, Any]:
        return {
            **common,
            "id": rid,
            "title": title,
            "severity": severity,
            "enabled": enabled,
            "note": note,
            "etype": etype,
            "summary_contains": summary_contains,
            "patterns": [summary_contains] if summary_contains else [etype],
        }

    return [
        R("sensor-etw-hot-file", "ETW 可疑目录文件创建", "high", "file_create", "ETW可疑目录文件创建",
          "ETW Kernel-File：Temp/Downloads/Public 等目录落地可执行/脚本"),
        R("sensor-etw-file", "ETW 文件创建", "medium", "file_create", "ETW文件创建",
          "ETW Kernel-File：热路径下的文件创建（非投放区）"),
        R("sensor-diff-hot-file", "可疑目录文件创建（差分）", "high", "file_create", "可疑目录文件创建",
          "快照差分：文件模块扫到热目录新增（标题不含 ETW 前缀）"),
        R("sensor-etw-hot-proc", "可疑路径进程（ETW）", "medium", "process_create_etw", "可疑路径进程",
          "ETW 进程创建且映像路径落在 Temp/AppData 等"),
        R("sensor-etw-proc", "ETW 进程创建", "info", "process_create_etw", "ETW进程创建",
          "普通进程创建遥测（量大，日志调查可压噪）", enabled=True),
        R("sensor-wmi-hot-proc", "可疑路径进程（WMI）", "medium", "process_create_live", "可疑路径进程",
          "WMI 订阅到的可疑路径进程创建"),
        R("sensor-diff-hot-proc", "可疑路径进程创建（差分）", "medium", "process_create", "可疑路径进程",
          "进程快照差分检出"),
        {
            **R("sensor-etw-dll", "未签名 DLL 加载", "medium", "image_load_etw", "未签名 DLL",
               "ETW ImageLoad：无签名/签名异常；系统目录只报这类；Valid（含目录签名）一律放过"),
            "signed_filter": "unsigned",
            "patterns": ["未签名 DLL", "系统目录未签名 DLL", "可疑目录未签名 DLL", "可疑目录 DLL"],
        },
        R("sensor-etw-driver", "未签名驱动加载", "critical", "driver_load_etw", "未签名驱动",
          "ETW ImageLoad：.sys 且签名非 Valid（含 System32\\drivers）"),
        R("sensor-etw-net", "ETW 外联", "medium", "network_connect_etw", "ETW外联",
          "时间线保留；威胁事件仅 IOC 命中时产生"),
        R("sensor-diff-net", "网络外联（差分）", "medium", "network_connect", "外联",
          "时间线保留；威胁事件仅 IOC 命中时产生"),
        R("sensor-dns", "DNS 查询", "info", "dns_query", "DNS",
          "时间线保留；威胁事件仅 IOC 命中时产生"),
        R("sensor-dns-summary", "DNS 汇总", "info", "dns_summary", "DNS 汇总",
          "时间线保留；不晋升威胁事件"),
        R("sensor-dns-nx-burst", "DNS 大量解析失败（疑似 DGA）", "high", "dns_nx_burst", "DNS 大量解析失败",
          "同一进程 5 分钟内 ≥25 个不同域名 NXDOMAIN"),
        R("sensor-etw-proc-exit", "ETW 进程退出", "info", "process_exit_etw", "ETW进程退出",
          "量大，默认不入时间线；进程实体的退出时间照常记录", enabled=False),
        R("sensor-reg-security", "注册表安全项变更", "high", "registry_set", "注册表安全项变更",
          "实时注册表：Defender 排除/策略、LSA、WDigest、UAC、防火墙、UAC 绕过键等"),
        R("sensor-reg-security-del", "注册表安全项删除", "medium", "registry_delete", "注册表安全项删除",
          "实时注册表：安全相关值被删除"),
        R("sensor-fim-add", "FIM 文件新增", "medium", "fim_add", "FIM新增",
          "可执行文件仅明确未签名才告警；hosts/任务等非 PE 照常"),
        R("sensor-fim-modify", "FIM 文件修改", "medium", "fim_modify", "FIM修改",
          "可执行文件仅明确未签名才告警；Valid 一律放过"),
        R("sensor-fim-delete", "FIM 文件删除", "medium", "fim_delete", "FIM删除",
          "文件完整性：受监控文件被删除"),
        R("sensor-fim-rename", "FIM 文件重命名", "medium", "fim_rename", "FIM重命名",
          "文件完整性：受监控文件被改名"),
        R("sensor-fim-overflow", "FIM 变更过多", "medium", "fim_overflow", "FIM 变更过多",
          "每分钟超过 120 条时合并计数"),
        R("sensor-persist-add", "持久化新增", "high", "persist_add", "持久化新增",
          "Run/Startup/可疑服务 ImagePath/hosts 等新增"),
        R("sensor-persist-mod", "持久化修改", "high", "persist_modify", "持久化修改",
          "持久化点内容变更"),
        R("sensor-persist-del", "持久化删除", "medium", "persist_delete", "持久化删除",
          "持久化点被删除"),
        R("sensor-win-logon", "登录成功", "info", "win_logon", "登录成功",
          "Security 4624（已过滤系统会话噪声）", enabled=True),
        R("sensor-win-logon-fail", "登录失败", "medium", "win_logon_fail", "登录失败",
          "Security 4625"),
        R("sensor-win-explicit-logon", "显式凭据登录", "medium", "win_explicit_logon", "显式凭据",
          "Security 4648"),
        R("sensor-win-account-create", "账号创建", "high", "win_account_create", "账号创建",
          "Security 4720"),
        R("sensor-win-account-enable", "账号启用", "medium", "win_account_enable", "账号启用",
          "Security 4722"),
        R("sensor-win-password-reset", "密码重置", "medium", "win_password_reset", "密码重置",
          "Security 4724"),
        R("sensor-win-group-add", "加入用户组", "high", "win_group_add", "加入",
          "Security 4728/4732/4756"),
        R("sensor-win-service", "服务安装", "high", "win_service_install", "服务安装",
          "System 7045 / Security 4697"),
        R("sensor-win-task-create", "计划任务创建", "high", "win_task_create", "计划任务创建",
          "Security 4698"),
        R("sensor-win-task-update", "计划任务更新", "medium", "win_task_update", "计划任务更新",
          "Security 4702"),
        R("sensor-win-task-ops", "计划任务操作", "medium", "win_task_ops", "任务计划",
          "TaskScheduler Operational；有缓存时带 Command"),
        R("sensor-win-bits", "BITS 传输", "medium", "win_bits", "BITS",
          "BITS-Client：Job/URL/本地路径"),
        R("sensor-win-smb", "SMB 客户端", "medium", "win_smb", "SMB",
          "SmbClient/Security：共享路径"),
        R("sensor-wmi-persist-add", "WMI 永久订阅新增", "high", "wmi_persist_add", "WMI 永久订阅新增",
          "root\\subscription FilterToConsumerBinding"),
        R("sensor-wmi-persist-mod", "WMI 永久订阅修改", "high", "wmi_persist_modify", "WMI 永久订阅修改",
          "WMI 永久订阅载荷变更"),
        R("sensor-wmi-persist-del", "WMI 永久订阅删除", "medium", "wmi_persist_delete", "WMI 永久订阅删除",
          "WMI 永久订阅移除"),
        R("sensor-win-audit-clear", "清空安全日志", "critical", "win_audit_clear", "安全日志被清空",
          "Security 1102"),
        R("sensor-win-special-priv", "特殊权限分配", "medium", "win_special_priv", "特殊权限",
          "Security 4672（仅保留 Debug/Impersonate/Tcb/LoadDriver 等）"),
        R("sensor-win-service-state", "服务状态变更", "info", "win_service_state", "服务状态",
          "System 7036", enabled=False),
        R("sensor-win-service-config", "服务启动类型变更", "medium", "win_service_config", "服务启动类型",
          "System 7040；BITS/Windows Update 等系统服务已在晋升侧压噪"),
        R("sensor-win-ps-module", "PowerShell 模块日志", "info", "win_ps_module", "PowerShell 模块",
          "需本机开启 Module Logging；通道 Microsoft-Windows-PowerShell/Operational 4103", enabled=False),
        R("sensor-win-ps-script", "PowerShell 脚本块", "info", "win_ps_scriptblock", "PowerShell 脚本块",
          "时间线保留；仅可疑特征(high)晋升威胁事件"),
        R("sensor-win-ps-script-hot", "可疑 PowerShell 脚本块", "high", "win_ps_scriptblock", "可疑 PowerShell",
          "ScriptBlock 含 -enc / IEX / DownloadString 等"),
        R("sensor-process-access", "进程打开（Sysmon）", "medium", "process_access", "进程打开",
          "Sysmon 10，过滤可疑访问权限；需安装 Sysmon"),
        R("sensor-remote-thread", "远程线程（Sysmon）", "high", "remote_thread", "远程线程",
          "Sysmon 8"),
        R("sensor-registry-write", "注册表写入（Sysmon）", "medium", "registry_write", "注册表写入",
          "Sysmon 13"),
        R("sensor-kernel-hot-proc", "可疑路径进程（内核）", "medium", "process_create_kernel", "可疑路径进程",
          "FaKmon 驱动进程回调"),
        {
            **R("sensor-kernel-dll", "可疑目录未签名模块（内核）", "medium", "image_load_kernel", "未签名模块",
                "FaKmon ImageLoad：投放区且未签名；有签名一律放过"),
            "signed_filter": "unsigned",
            "patterns": ["未签名模块", "可疑目录未签名模块", "可疑目录模块"],
        },
        R("sensor-kernel-driver", "内核驱动加载", "high", "driver_load_kernel", "内核驱动加载",
          "FaKmon 驱动加载"),
        R("sensor-kernel-inject", "远程线程注入（内核）", "high", "remote_thread_kernel", "远程线程注入",
          "FaKmon 远程线程"),
        R("sensor-kernel-protect", "自保护拦截", "high", "protect_block_kernel", "拦截对 Agent",
          "FaKmon 自保护"),
    ]


def _default_doc() -> Dict[str, Any]:
    return {
        "meta": {
            "name": "Agent 实时规则",
            "version": "1.1",
            "description": "快照规则 + 传感器内置检出（可开关），与主平台规则库独立",
        },
        "rules": _default_rules(),
        "sensor_overrides": {},
    }


def ensure_rules_file() -> Path:
    p = _path()
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(p, _default_doc())
    return p


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def load_doc(*, force: bool = False) -> Dict[str, Any]:
    p = ensure_rules_file()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return _default_doc()
    with _LOCK:
        if not force and _CACHE["doc"] is not None and abs(mtime - float(_CACHE["mtime"])) < 0.01:
            return _CACHE["doc"]  # type: ignore
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                doc = _default_doc()
            if not isinstance(doc.get("rules"), list):
                doc["rules"] = []
        except Exception:
            doc = _default_doc()
        _CACHE["mtime"] = mtime
        _CACHE["doc"] = doc
        return doc


def save_doc(doc: Dict[str, Any]) -> None:
    with _LOCK:
        _atomic_write(_path(), doc)
        _CACHE["doc"] = doc
        try:
            _CACHE["mtime"] = _path().stat().st_mtime
        except OSError:
            _CACHE["mtime"] = time.time()
    try:
        from . import agent_protocol
        agent_protocol.bump_live("rules")
    except Exception:
        pass
    try:
        from . import agent_sync
        agent_sync.bump_sync("rules")
    except Exception:
        pass


def _merged_sensor_rules(doc: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    doc = doc if isinstance(doc, dict) else load_doc()
    overrides = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
    out: List[Dict[str, Any]] = []
    for base in _sensor_builtin_rules():
        r = dict(base)
        ov = overrides.get(str(r["id"])) if isinstance(overrides.get(str(r["id"])), dict) else {}
        if not isinstance(ov, dict):
            ov = {}
        if "enabled" in ov:
            r["enabled"] = bool(ov.get("enabled"))
        sev = str(ov.get("severity") or "").strip().lower()
        if sev in _SEVERITIES:
            r["severity"] = sev
        if "note" in ov and ov.get("note") is not None:
            r["note"] = str(ov.get("note") or "")[:300]
        if "title" in ov and str(ov.get("title") or "").strip():
            r["title"] = str(ov.get("title")).strip()[:120]
        if "etype" in ov and str(ov.get("etype") or "").strip():
            r["etype"] = str(ov.get("etype")).strip()[:64]
        if "summary_contains" in ov:
            r["summary_contains"] = str(ov.get("summary_contains") or "")[:200]
        if "match" in ov:
            m = str(ov.get("match") or "").strip().lower()
            if m in ("substring", "regex", "exact"):
                r["match"] = m
        if "patterns" in ov:
            pats = ov.get("patterns")
            if isinstance(pats, str):
                pats = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
            if isinstance(pats, list):
                r["patterns"] = [str(p) for p in pats if str(p).strip()][:20]
                # 人工改的特征同步为摘要关键字（取第一条非空）
                if r["patterns"] and "summary_contains" not in ov:
                    r["summary_contains"] = str(r["patterns"][0])[:200]
        for key in ("fields", "file_exts", "path_prefixes"):
            if key in ov and isinstance(ov.get(key), list):
                r[key] = [str(x) for x in ov.get(key) if str(x).strip()]
        if "signed_filter" in ov:
            signed_filter = str(ov.get("signed_filter") or "").strip().lower()
            if signed_filter in ("", "any", "unsigned", "signed"):
                r["signed_filter"] = signed_filter
        # 列表展示用：patterns 与 summary_contains 对齐
        sc = str(r.get("summary_contains") or "").strip()
        if sc and not r.get("patterns"):
            r["patterns"] = [sc]
        r["customized"] = bool(ov)
        out.append(r)
    return out


def list_rules(*, enabled_only: bool = False, include_sensor: bool = True) -> List[Dict[str, Any]]:
    doc = load_doc()
    custom = []
    for r in (doc.get("rules") or []):
        if not isinstance(r, dict):
            continue
        item = dict(r)
        item.setdefault("source", "custom")
        item.setdefault("builtin", False)
        # 防止旧文件里误塞了 sensor- 前缀的自定义规则覆盖内置
        if str(item.get("id") or "").startswith("sensor-"):
            continue
        custom.append(item)
    rules = (_merged_sensor_rules(doc) if include_sensor else []) + custom
    if enabled_only:
        rules = [r for r in rules if r.get("enabled", True)]
    return [_enrich_rule_item(dict(r)) for r in rules]


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    rid = str(rule_id or "").strip()
    for r in list_rules():
        if str(r.get("id") or "") == rid:
            return dict(r)
    return None


def is_sensor_rule_id(rule_id: str) -> bool:
    return str(rule_id or "").startswith("sensor-")


def _sensor_text_match(hay: str, needle: str, how: str) -> bool:
    if not needle:
        return True
    how = (how or "substring").lower()
    if how == "exact":
        return hay == needle.lower()
    if how == "regex":
        try:
            return bool(re.search(needle, hay, re.I))
        except re.error:
            return needle.lower() in hay
    return needle.lower() in hay


def sensor_event_allowed(etype: str, summary: str, detail: Optional[Dict[str, Any]] = None) -> bool:
    """传感器事件是否允许入库。

    内置传感器与快照规则共用字段、扩展名、签名、路径和匹配方式。
    etype 仍是传感器的稳定入口，规则 ID 不允许被修改或删除。

    注意：若摘要/etype 已命中某条传感器规则，但被 signed_filter 等条件挡下，
    必须返回 False（禁止再「无匹配 → 默认放行」，否则 Valid 签名 FIM 会继续告警）。
    """
    et = str(etype or "").strip().lower()
    detail = detail if isinstance(detail, dict) else {}
    if not et and not str(summary or "").strip():
        return True
    matched: List[Dict[str, Any]] = []
    gated_out = False  # 命中规则主体但被签名/路径等过滤器挡下
    for r in _merged_sensor_rules():
        want_et = str(r.get("etype") or "").strip().lower()
        how = str(r.get("match") or "substring")
        needles = [str(r.get("summary_contains") or "").strip()]
        for p in (r.get("patterns") or []):
            if str(p).strip():
                needles.append(str(p).strip())
        needles = [n for n in needles if n]
        if want_et and et != want_et and not et.startswith(want_et):
            continue

        fields = [str(x).strip() for x in (r.get("fields") or []) if str(x).strip()]
        values: List[str] = []
        for field in fields:
            if field == "etype":
                values.append(et)
            elif field == "summary":
                values.append(str(summary or ""))
            elif detail.get(field) not in (None, ""):
                value = detail.get(field)
                values.append(json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value))
        if not values:
            values = [str(summary or "")]
        haystacks = [value.lower() for value in values]
        if needles and not any(
            _sensor_text_match(hay, needle, how)
            for hay in haystacks
            for needle in needles
        ):
            continue

        path = str(detail.get("path") or detail.get("image") or detail.get("target_path") or "")
        prefixes = [str(x).strip().lower() for x in (r.get("path_prefixes") or []) if str(x).strip()]
        if prefixes and (not path or not any(path.lower().startswith(prefix) for prefix in prefixes)):
            gated_out = True
            continue
        exts = {str(x).strip().lstrip(".").lower() for x in (r.get("file_exts") or []) if str(x).strip()}
        if exts:
            ext = Path(path).suffix.lstrip(".").lower()
            if not ext or ext not in exts:
                gated_out = True
                continue
        signed_filter = str(r.get("signed_filter") or "").lower()
        signed = str(detail.get("signed") or "").strip().lower()
        if signed_filter == "signed" and signed != "valid":
            gated_out = True
            continue
        # 与快照规则 _signed_allowed 对齐：未知/空不算未签名
        if signed_filter == "unsigned" and (
            signed == "valid" or not signed or signed in ("unknown", "undefined", "unknownerror", "n/a", "-")
        ):
            gated_out = True
            continue
        if not want_et and not needles:
            continue
        matched.append(r)
    if not matched:
        return False if gated_out else True
    matched.sort(
        key=lambda x: max((len(str(p)) for p in ([x.get("summary_contains")] + list(x.get("patterns") or [])) if p), default=0),
        reverse=True,
    )
    return bool(matched[0].get("enabled", True))


def _normalize_rule(payload: Dict[str, Any], *, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = dict(existing or {})
    title = str(payload.get("title") or base.get("title") or "").strip()
    if not title:
        raise ValueError("标题不能为空")
    rid = str(payload.get("id") or base.get("id") or "").strip()
    if not rid:
        rid = "agent-" + uuid.uuid4().hex[:10]
    sev = str(payload.get("severity") or base.get("severity") or "medium").strip().lower()
    if sev not in _SEVERITIES:
        sev = "medium"
    mods = payload.get("modules") if "modules" in payload else base.get("modules")
    if isinstance(mods, str):
        mods = [x.strip() for x in re.split(r"[,;\s]+", mods) if x.strip()]
    if not isinstance(mods, list) or not mods:
        mods = ["process"]
    mods = [m for m in mods if m in _MODULES] or ["process"]
    fields = payload.get("fields") if "fields" in payload else base.get("fields")
    if isinstance(fields, str):
        fields = [x.strip() for x in re.split(r"[,;\s]+", fields) if x.strip()]
    if not isinstance(fields, list) or not fields:
        fields = list(_FIELD_DEFAULT.get(mods[0], ["path", "name"]))
    pats = payload.get("patterns") if "patterns" in payload else base.get("patterns")
    if isinstance(pats, str):
        # 一行一个，或逗号分隔
        lines = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
        pats = lines
    if not isinstance(pats, list):
        pats = []
    pats = [str(p) for p in pats if str(p).strip()]
    match = str(payload.get("match") or base.get("match") or "substring").strip().lower()
    if match not in ("substring", "regex", "exact"):
        match = "substring"
    enabled = payload.get("enabled") if "enabled" in payload else base.get("enabled", True)
    note = str(payload.get("note") if "note" in payload else base.get("note") or "")[:300]
    # 文件类型：exe / dll / ps1 …（空表示不限）
    exts = payload.get("file_exts") if "file_exts" in payload else base.get("file_exts")
    if isinstance(exts, str):
        exts = [x.strip().lstrip(".").lower() for x in re.split(r"[,;\s]+", exts) if x.strip()]
    if not isinstance(exts, list):
        exts = []
    exts = [str(x).strip().lstrip(".").lower() for x in exts if str(x).strip()][:24]
    # 签名过滤：""/any=不限；unsigned=未签名或签名异常；signed=仅有效签名
    signed_filter = str(
        payload.get("signed_filter") if "signed_filter" in payload else base.get("signed_filter") or ""
    ).strip().lower()
    if signed_filter not in ("", "any", "unsigned", "signed"):
        signed_filter = ""
    # 路径前缀：限制命中路径必须以这些开头（如 C:\ 、C:\Users\）
    path_prefixes = payload.get("path_prefixes") if "path_prefixes" in payload else base.get("path_prefixes")
    if isinstance(path_prefixes, str):
        path_prefixes = [x.strip() for x in re.split(r"[,;\n]+", path_prefixes) if x.strip()]
    if not isinstance(path_prefixes, list):
        path_prefixes = []
    path_prefixes = [str(x).strip() for x in path_prefixes if str(x).strip()][:12]
    if not pats and signed_filter != "unsigned":
        raise ValueError("至少填写一条匹配特征（或将签名条件设为「未签名」）")
    if not pats and signed_filter == "unsigned":
        pats = ["*"]  # 占位，匹配阶段走 signed_filter 专用分支
    out = {
        "id": rid[:64],
        "title": title[:120],
        "severity": sev,
        "modules": mods,
        "fields": fields[:12],
        "patterns": pats[:40],
        "file_exts": exts,
        "signed_filter": signed_filter,
        "path_prefixes": path_prefixes,
        "match": match,
        "enabled": bool(enabled),
        "note": note,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    for key in ("etype", "summary_contains", "parent_name_contains", "building_block"):
        if key in payload:
            val = payload.get(key)
            if key == "building_block":
                out[key] = bool(val)
            elif val is not None and str(val).strip() != "":
                out[key] = str(val).strip()[:200] if key != "etype" else str(val).strip()[:64]
        elif existing and key in existing:
            out[key] = existing[key]
    return out


def create_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    rule = _normalize_rule(payload or {})
    if is_sensor_rule_id(rule["id"]):
        raise ValueError("不能创建 sensor- 前缀的内置传感器规则 ID")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        if any(str(r.get("id")) == rule["id"] for r in rules):
            raise ValueError(f"规则 ID 已存在: {rule['id']}")
        rule["source"] = "custom"
        rule["builtin"] = False
        rules.append(rule)
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "item": rule}


def upsert_imported_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Elastic 等批量导入：按 ID 覆盖，保留 source/building_block 等元数据。"""
    payload = payload or {}
    rid = str(payload.get("id") or "").strip()
    if not rid:
        raise ValueError("缺少 id")
    if is_sensor_rule_id(rid):
        raise ValueError("不能写入 sensor- 前缀规则")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        existing = rules[idx] if idx >= 0 else None
        rule = _normalize_rule(payload, existing=existing or {})
        for k in ("source", "building_block", "elastic_rule_id", "technique", "tactic"):
            if k in payload:
                rule[k] = payload[k]
        src = str(rule.get("source") or payload.get("source") or "custom").strip().lower()
        rule["source"] = src if src in ("custom", "elastic") else "custom"
        rule["builtin"] = False
        created = idx < 0
        if idx >= 0:
            rules[idx] = rule
        else:
            rules.append(rule)
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "created": created, "item": rule}


def _update_sensor_override(rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """内置传感器规则：允许人工改标题/级别/关键字/事件类型/备注/开关，落在 sensor_overrides。"""
    rid = str(rule_id or "").strip()
    base = next((r for r in _sensor_builtin_rules() if r["id"] == rid), None)
    if not base:
        raise ValueError("内置传感器规则不存在")
    payload = payload or {}
    # 重置为出厂默认
    if payload.get("reset_default"):
        with _LOCK:
            doc = load_doc(force=True)
            ov_all = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
            ov_all.pop(rid, None)
            doc["sensor_overrides"] = ov_all
            save_doc(doc)
        return {"ok": True, "item": get_rule(rid) or dict(base)}

    with _LOCK:
        doc = load_doc(force=True)
        ov_all = doc.get("sensor_overrides") if isinstance(doc.get("sensor_overrides"), dict) else {}
        cur = dict(ov_all.get(rid) or {}) if isinstance(ov_all.get(rid), dict) else {}
        if "enabled" in payload:
            cur["enabled"] = bool(payload.get("enabled"))
        if "severity" in payload:
            sev = str(payload.get("severity") or "").strip().lower()
            if sev in _SEVERITIES:
                cur["severity"] = sev
        if "note" in payload:
            cur["note"] = str(payload.get("note") or "")[:300]
        if "title" in payload and str(payload.get("title") or "").strip():
            cur["title"] = str(payload.get("title")).strip()[:120]
        if "etype" in payload and str(payload.get("etype") or "").strip():
            cur["etype"] = str(payload.get("etype")).strip()[:64]
        # 摘要关键字：直接字段，或取 patterns 第一行
        if "summary_contains" in payload:
            cur["summary_contains"] = str(payload.get("summary_contains") or "")[:200]
        if "patterns" in payload:
            pats = payload.get("patterns")
            if isinstance(pats, str):
                pats = [x.strip() for x in pats.replace(",", "\n").splitlines() if x.strip()]
            if isinstance(pats, list):
                pats = [str(p) for p in pats if str(p).strip()][:20]
                cur["patterns"] = pats
                if pats and "summary_contains" not in payload:
                    cur["summary_contains"] = pats[0][:200]
        if "match" in payload:
            m = str(payload.get("match") or "").strip().lower()
            if m in ("substring", "regex", "exact"):
                cur["match"] = m
        if "fields" in payload:
            fields = payload.get("fields")
            if isinstance(fields, str):
                fields = [x.strip() for x in re.split(r"[,;\s]+", fields) if x.strip()]
            if isinstance(fields, list):
                cur["fields"] = [str(x).strip() for x in fields if str(x).strip()][:12]
        if "file_exts" in payload:
            exts = payload.get("file_exts")
            if isinstance(exts, str):
                exts = [x.strip() for x in re.split(r"[,;\s]+", exts) if x.strip()]
            if isinstance(exts, list):
                cur["file_exts"] = [str(x).strip().lstrip(".").lower() for x in exts if str(x).strip()][:24]
        if "path_prefixes" in payload:
            prefixes = payload.get("path_prefixes")
            if isinstance(prefixes, str):
                prefixes = [x.strip() for x in re.split(r"[,;\n]+", prefixes) if x.strip()]
            if isinstance(prefixes, list):
                cur["path_prefixes"] = [str(x).strip() for x in prefixes if str(x).strip()][:12]
        if "signed_filter" in payload:
            signed_filter = str(payload.get("signed_filter") or "").strip().lower()
            if signed_filter in ("", "any", "unsigned", "signed"):
                cur["signed_filter"] = signed_filter
        ov_all[rid] = cur
        doc["sensor_overrides"] = ov_all
        save_doc(doc)
    item = get_rule(rid) or dict(base)
    return {"ok": True, "item": item}


def update_rule(rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        return _update_sensor_override(rid, payload or {})
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        if idx < 0:
            raise ValueError("规则不存在")
        merged = dict(payload or {})
        merged["id"] = rid  # 不允许改 ID
        existing = rules[idx]
        rule = _normalize_rule(merged, existing=existing)
        prev_src = str(existing.get("source") or "").lower()
        if is_elastic_rule(existing) or prev_src == "elastic":
            rule["source"] = "elastic"
        else:
            rule["source"] = "custom"
        rule["builtin"] = False
        for k in ("elastic_rule_id", "building_block", "technique", "tactic", "rule_channel"):
            if k in existing and k not in merged:
                rule[k] = existing[k]
        rules[idx] = rule
        doc["rules"] = rules
        save_doc(doc)
    return {"ok": True, "item": rule}


def delete_rule(rule_id: str) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        raise ValueError("内置传感器规则不能删除，可关闭启用开关")
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        new_rules = [r for r in rules if str(r.get("id")) != rid]
        if len(new_rules) == len(rules):
            raise ValueError("规则不存在")
        doc["rules"] = new_rules
        save_doc(doc)
    return {"ok": True}


def set_rule_enabled(rule_id: str, enabled: bool) -> Dict[str, Any]:
    rid = str(rule_id or "").strip()
    if is_sensor_rule_id(rid):
        return _update_sensor_override(rid, {"enabled": bool(enabled)})
    with _LOCK:
        doc = load_doc(force=True)
        rules = [r for r in (doc.get("rules") or []) if isinstance(r, dict)]
        idx = next((i for i, r in enumerate(rules) if str(r.get("id")) == rid), -1)
        if idx < 0:
            raise ValueError("规则不存在")
        rules[idx]["enabled"] = bool(enabled)
        rules[idx]["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        doc["rules"] = rules
        save_doc(doc)
        item = dict(rules[idx])
    return {"ok": True, "item": item}


def bulk_set_rules_enabled(
    enabled: bool,
    *,
    rule_ids: Optional[List[str]] = None,
    source: str = "",
    scope: str = "filtered",
) -> Dict[str, Any]:
    """批量开关。source: elastic|custom|''；scope=filtered 时仅 rule_ids。"""
    want_ids = {str(x).strip() for x in (rule_ids or []) if str(x).strip()}
    src = str(source or "").strip().lower()
    changed: List[str] = []
    skipped: List[str] = []
    for r in list_rules(include_sensor=True):
        rid = str(r.get("id") or "")
        if not rid:
            continue
        if want_ids and rid not in want_ids:
            continue
        if src == "elastic" and not is_elastic_rule(r):
            continue
        if src == "custom" and (r.get("builtin") or r.get("source") == "sensor"):
            continue
        if src == "sensor" and not (r.get("builtin") or r.get("source") == "sensor"):
            continue
        try:
            set_rule_enabled(rid, enabled)
            changed.append(rid)
        except ValueError:
            skipped.append(rid)
    if changed:
        try:
            from . import agent_protocol, agent_sync
            agent_protocol.bump_live("rules")
            agent_sync.bump_sync("rules")
        except Exception:
            pass
    return {"ok": True, "enabled": bool(enabled), "changed": len(changed), "ids": changed[:500], "skipped": skipped[:50]}


def _item_blob(item: Dict[str, Any], fields: List[str]) -> str:
    parts = []
    for f in fields or []:
        v = item.get(f)
        if v not in (None, ""):
            parts.append(str(v))
    if not parts:
        for f in ("name", "display_name", "path", "command", "command_line", "task_name", "local", "remote"):
            v = item.get(f)
            if v:
                parts.append(str(v))
    return "\n".join(parts)


def _item_ext(item: Dict[str, Any]) -> str:
    ext = str(item.get("ext") or "").strip().lstrip(".").lower()
    if ext:
        return ext
    for k in ("name", "path", "command_line", "command", "execute", "image"):
        v = str(item.get(k) or "")
        if not v:
            continue
        m = re.search(r"\.([A-Za-z0-9]{1,10})(?:[\"'\s\\]|$)", v)
        if m:
            return m.group(1).lower()
    return ""


def _ext_allowed(item: Dict[str, Any], file_exts: List[str]) -> bool:
    if not file_exts:
        return True
    return _item_ext(item) in {str(x).lower().lstrip(".") for x in file_exts}


_UNSIGNED_STATUSES = frozenset({
    "notsigned", "not signed", "unsigned",
    "hashmismatch", "hash mismatch",
    "nottrusted", "untrusted", "invalid", "invalid signature",
})


def _signed_allowed(item: Dict[str, Any], signed_filter: str) -> bool:
    sf = (signed_filter or "").strip().lower()
    if not sf or sf == "any":
        return True
    signed = str(item.get("signed") or "").strip().lower()
    # 空 / Undefined = 未检测，不算「未签名」，避免网络/任务等无签名字段误报
    if not signed or signed in ("undefined", "unknown", "n/a", "-"):
        return False if sf in ("unsigned", "signed") else True
    valid = signed in ("valid", "valid signature", "signed")
    if sf == "signed":
        return valid
    if sf == "unsigned":
        compact = signed.replace(" ", "")
        return (not valid) and (
            signed in _UNSIGNED_STATUSES
            or compact in {x.replace(" ", "") for x in _UNSIGNED_STATUSES}
        )
    return True


def _path_fields_blob(item: Dict[str, Any]) -> str:
    """进程/文件规则：合并路径、命令行、父进程路径等，供 Temp/Public 片段匹配。"""
    parts: List[str] = []
    for k in (
        "path", "image", "command", "command_line", "execute", "directory",
        "parent_path", "parent_name", "target_path",
    ):
        v = item.get(k)
        if v not in (None, ""):
            parts.append(str(v))
    px = item.get("process_ext")
    if isinstance(px, dict):
        for k in ("path", "parent_path", "parent_name", "name"):
            if px.get(k):
                parts.append(str(px[k]))
        anc = px.get("ancestry")
        if isinstance(anc, list):
            for a in anc:
                if isinstance(a, dict):
                    if a.get("path"):
                        parts.append(str(a["path"]))
                    if a.get("name"):
                        parts.append(str(a["name"]))
    return "\n".join(parts).replace("/", "\\").lower()


def _path_scope_allowed(item: Dict[str, Any], prefixes: List[str]) -> bool:
    """路径范围：盘符前缀用 startswith；\\temp\\、\\public\\ 等在任意相关字段中出现即命中。"""
    if not prefixes:
        return True
    blob = _path_fields_blob(item)
    if not blob.strip():
        return False
    for p in prefixes:
        pref = str(p or "").replace("/", "\\").strip().lower()
        if not pref:
            continue
        if len(pref) >= 3 and pref[1] == ":" and pref[2] == "\\":
            for line in blob.split("\n"):
                if line.startswith(pref):
                    return True
            continue
        frag = pref
        if not frag.startswith("\\"):
            frag = "\\" + frag.strip("\\")
        if not frag.endswith("\\") and "\\" in frag:
            pass
        elif frag.endswith("\\") or "\\" in frag:
            if frag in blob:
                return True
        if pref in blob or frag in blob:
            return True
    return False


def _path_prefix_allowed(item: Dict[str, Any], prefixes: List[str]) -> bool:
    return _path_scope_allowed(item, prefixes)


def _match_text(text: str, patterns: List[str], how: str) -> Optional[str]:
    t = text or ""
    tl = t.lower()
    if not t:
        return None
    how = (how or "substring").lower()
    for p in patterns or []:
        raw = str(p or "")
        if not raw:
            continue
        if how == "exact":
            if tl == raw.lower() or Path(t).name.lower() == raw.lower():
                return raw
        elif how == "regex":
            try:
                if re.search(raw, t, re.I):
                    return raw
            except re.error:
                continue
        else:
            if raw.lower() in tl:
                return raw
    return None


_EVIDENCE_KEYS = (
    "name", "display_name", "task_name", "path", "command", "command_line",
    "pid", "ppid", "parent_name", "parent_path", "user", "local", "remote",
    "remote_ip", "remote_port", "domain", "query", "status", "state", "author",
    "location", "proto", "signed", "signer", "sha256", "company", "file_version",
    "uptime", "process_name", "create_time", "execute", "arguments", "working_directory",
    "triggers", "start_type", "account", "image", "module", "module_name", "host_process",
    "process_path", "ext", "size", "key", "value", "value_name", "old_value", "etype",
)

_OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "onenote.exe", "visio.exe", "mspub.exe",
    "acrord32.exe", "acrobat.exe", "wmplayer.exe",
}
_LOL_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "notepad.exe",
}


def _evidence_of(it: Dict[str, Any]) -> Dict[str, Any]:
    return {k: it.get(k) for k in _EVIDENCE_KEYS if it.get(k) not in (None, "")}


def _heuristic_process_hits(items: List[Any], *, max_hits: int, seen: set) -> List[Dict[str, Any]]:
    """注入/可疑父子等启发式（不依赖完整内核注入检测）。"""
    hits: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "").lower()
        path = str(it.get("path") or it.get("command_line") or "").lower()
        parent = str(it.get("parent_name") or "").lower()
        signed = str(it.get("signed") or "").lower()
        pid = it.get("pid")

        def add(rid: str, title: str, sev: str, matched: str) -> bool:
            key = (rid, str(pid or name or path or matched))
            if key in seen:
                return False
            seen.add(key)
            hits.append({
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "module": "process",
                "matched": matched,
                "rule_source": "agent",
                "evidence": _evidence_of(it),
            })
            return len(hits) >= max_hits

        # 办公/阅读器拉起 LOLBIN —— 常见宏/投放后行为
        if parent in _OFFICE_PARENTS and name in _LOL_CHILDREN:
            if add("agent-heur-office-child", "办公进程拉起脚本解释器", "high", f"{parent} → {name}"):
                return hits
        # 未签名落在系统目录 —— 伪装/替换启发式
        if signed in ("notsigned", "hashmismatch", "nottrusted") and (
            "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path
        ):
            if add("agent-heur-unsigned-system", "系统目录未签名进程", "high", signed or "NotSigned"):
                return hits
        # 未签名 + 临时目录
        if signed in ("notsigned", "hashmismatch") and any(
            x in path for x in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\users\\public\\")
        ):
            if add("agent-heur-unsigned-temp", "临时目录未签名进程", "high", signed or "NotSigned"):
                return hits
        # 父进程丢失（ppid 指向不存在）且自身在临时目录 —— 注入/断链启发式弱信号
        ppid = it.get("ppid")
        if (
            ppid not in (None, 0, "0")
            and not parent
            and any(x in path for x in ("\\temp\\", "\\appdata\\", "\\users\\public\\"))
        ):
            # matched 带可读说明；evidence 仍含子进程完整字段，父名缺失表示链已断
            if add(
                "agent-heur-orphan-temp",
                "临时目录进程父链缺失",
                "medium",
                f"父进程不可见 ppid={ppid}（可能已退出或注入断链）",
            ):
                return hits
    return hits


def match_snapshot(module: str, items: List[Any], *, max_hits: int = 30) -> List[Dict[str, Any]]:
    mod = str(module or "").lower()
    rules = [
        r for r in list_rules(enabled_only=True)
        if mod in (r.get("modules") or []) and not is_elastic_rule(r)
    ]
    hits: List[Dict[str, Any]] = []
    seen = set()
    if rules and items:
        for it in items:
            if not isinstance(it, dict):
                continue
            for rule in rules:
                if not _ext_allowed(it, list(rule.get("file_exts") or [])):
                    continue
                if not _signed_allowed(it, str(rule.get("signed_filter") or "")):
                    continue
                if not _path_prefix_allowed(it, list(rule.get("path_prefixes") or [])):
                    continue
                blob = _item_blob(it, list(rule.get("fields") or []))
                pats = [p for p in list(rule.get("patterns") or []) if p and p != "*"]
                if str(rule.get("signed_filter") or "") == "unsigned" and not pats:
                    hit_pat = f"signed={it.get('signed') or 'empty'}"
                else:
                    hit_pat = _match_text(blob, pats or list(rule.get("patterns") or []), str(rule.get("match") or "substring"))
                if not hit_pat:
                    continue
                rid = str(rule.get("id") or "")
                key = (rid, str(it.get("name") or it.get("task_name") or it.get("pid") or it.get("path") or hit_pat))
                if key in seen:
                    continue
                seen.add(key)
                rsrc = str(rule.get("source") or "custom").lower()
                if rule.get("builtin"):
                    rsrc = "sensor"
                elif is_elastic_rule(rule):
                    rsrc = "elastic"
                hits.append({
                    "rule_id": rid,
                    "title": str(rule.get("title") or rid),
                    "rule_title": str(rule.get("title") or rid),
                    "severity": str(rule.get("severity") or "medium"),
                    "module": mod,
                    "matched": hit_pat,
                    "rule_source": rsrc if rsrc in ("elastic", "custom", "sensor") else "agent",
                    "evidence": _evidence_of(it),
                })
                if len(hits) >= max_hits:
                    return hits
    if mod == "process" and len(hits) < max_hits:
        hits.extend(_heuristic_process_hits(items or [], max_hits=max_hits - len(hits), seen=seen))
    if mod == "process" and len(hits) < max_hits:
        hits.extend(lolbin_hits(items or [], max_hits=max_hits - len(hits), seen=seen))
    return hits


def rule_fim_paths(max_paths: int = 20) -> List[str]:
    """文件类规则的路径前缀 → Agent FIM 监控目录（含扩展名），实现「目录下新建未签名文件」实时命中。"""
    out: List[str] = []
    seen = set()

    def add_drive_roots(exts: str) -> None:
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            spec = f"{letter}:\\"
            if exts:
                spec += "|" + exts
            spec += "|rule"
            if spec.lower() not in seen:
                seen.add(spec.lower())
                out.append(spec)

    for r in list_rules(enabled_only=True, include_sensor=False):
        pats = [str(p) for p in (r.get("patterns") or [])]
        rid = str(r.get("id") or "")
        if rid in ("agent-root-drop", "agent-progdata-temp-unsigned") or any(
            "^" in p and ":\\\\" in p and "[^\\\\]" in p for p in pats
        ):
            if rid == "agent-progdata-temp-unsigned":
                for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                    for sub in (r"ProgramData", r"Windows\Temp"):
                        spec = f"{letter}:\\{sub}|r|exe,dll,bat,cmd,ps1,scr,msi,js,vbs,hta|rule"
                        if spec.lower() not in seen:
                            seen.add(spec.lower())
                            out.append(spec)
                if len(out) >= max_paths:
                    return out
                continue
            exts = ",".join(
                sorted({str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()})
            ) or "exe,dll,bat,cmd,ps1,scr"
            add_drive_roots(exts)
            if len(out) >= max_paths:
                return out
    for r in list_rules(enabled_only=True, include_sensor=False):
        if "file" not in (r.get("modules") or []):
            continue
        prefixes = [str(p).strip() for p in (r.get("path_prefixes") or []) if str(p).strip()]
        if not prefixes:
            continue
        exts = ",".join(sorted({str(e).strip().lstrip(".").lower() for e in (r.get("file_exts") or []) if str(e).strip()}))
        for p in prefixes:
            p = p.replace("/", "\\")
            if not re.match(r"^[A-Za-z]:\\", p):
                continue
            root = p.rstrip("\\")
            spec = (root + "\\") if len(root) == 2 else (root + "|r")
            if exts:
                spec += "|" + exts
            spec += "|rule"
            if spec.lower() in seen:
                continue
            seen.add(spec.lower())
            out.append(spec)
            if len(out) >= max_paths:
                return out
    return out


def lolbin_hits(items: List[Any], *, max_hits: int = 30, seen: Optional[set] = None) -> List[Dict[str, Any]]:
    """LOLBin 内置检测（进程名 + 命令行 + 父进程）。"""
    from . import lolbin

    seen = seen if seen is not None else set()
    disabled = set((load_doc().get("lolbin_disabled") or []))
    out: List[Dict[str, Any]] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        for h in lolbin.match(it, disabled=disabled):
            key = (h["rule_id"], str(it.get("pid") or it.get("entity_id") or it.get("command_line") or ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "rule_id": h["rule_id"],
                "title": "LOLBin · " + h["title"],
                "severity": h["severity"],
                "module": "process",
                "matched": h["matched"],
                "rule_source": "lolbin",
                "technique": h["technique"],
                "tactic": h["tactic"],
                "evidence": _evidence_of(it),
            })
            if len(out) >= max_hits:
                return out
    return out


def report_rule_hits(agent_id: str, module: str, hits: List[Dict[str, Any]], hostname: str = "") -> Dict[str, Any]:
    from . import agent_protocol

    written = 0
    skipped = 0
    for h in hits:
        evd = h.get("evidence") or {}
        obj = str(evd.get("name") or evd.get("task_name") or evd.get("display_name") or "")
        if not obj:
            p = str(evd.get("path") or evd.get("command") or "")
            obj = p.replace("/", "\\").rsplit("\\", 1)[-1] if p else ""
        title = f"规则命中：{h.get('title')}"
        if obj:
            title = f"{title} · {obj}"
        detail = {
            "rule_id": h.get("rule_id"),
            "rule_title": h.get("rule_title") or h.get("title"),
            "rule_source": h.get("rule_source") or "agent",
            "matched": h.get("matched"),
            "evidence": evd,
            "module": h.get("module"),
        }
        for k in _EVIDENCE_KEYS:
            if k in evd and evd.get(k) not in (None, ""):
                detail.setdefault(k, evd[k])
        if h.get("technique"):
            detail["technique"] = h.get("technique")
            detail["tactic"] = h.get("tactic")
        use_mod = str(h.get("module") or module or "process").lower()
        nm = str(evd.get("name") or "").lower()
        if nm in (
            "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "cmd.exe",
        ):
            use_mod = "script"
        cmd_blob = str(evd.get("command_line") or evd.get("command") or h.get("matched") or "")
        if use_mod != "script" and cmd_blob and re.search(
            r"powershell|pwsh|wscript|cscript|mshta|scriptblock|frombase64string|-enc\b",
            cmd_blob,
            re.I,
        ):
            use_mod = "script"
        ev = agent_protocol.report_event({
            "agent_id": agent_id,
            "hostname": hostname,
            "module": use_mod,
            "severity": h.get("severity") or "medium",
            "title": title[:200],
            "detail": detail,
        })
        if ev.get("suppressed"):
            skipped += 1
        elif ev.get("ok") and not ev.get("deduped"):
            written += 1
    return {"ok": True, "hits": len(hits), "events": written, "skipped_whitelist": skipped, "ts": time.time()}


def apply_lolbin(agent_id: str, items: List[Any], hostname: str = "") -> Dict[str, Any]:
    return report_rule_hits(agent_id, "process", lolbin_hits(items), hostname)


def enrich_process_event_detail(
    agent_id: str,
    detail: Dict[str, Any],
    summary: str = "",
) -> Dict[str, Any]:
    """补全进程 detail：摘要解析进程名；命令行为空时从 agent_processes 表回填（ETW 创建过早常见）。"""
    d = dict(detail or {})
    if not d.get("name") and summary:
        m = re.search(r"[:：]\s*([^\s(]+)", str(summary), re.I)
        if m:
            nm = m.group(1).strip().strip('"')
            if nm:
                d.setdefault("name", nm)
    cmd = str(d.get("command_line") or d.get("command") or "").strip()
    if cmd or not agent_id or not d.get("pid"):
        return d
    try:
        from . import agent_edr

        agent_edr.ensure()
        pid = str(d.get("pid"))
        with agent_edr._lock:
            conn = agent_edr._connect()
            try:
                row = conn.execute(
                    """SELECT command_line, name, path FROM agent_processes
                       WHERE agent_id=? AND CAST(pid AS TEXT)=?
                       ORDER BY last_seen DESC LIMIT 1""",
                    (agent_id, pid),
                ).fetchone()
                if row:
                    if row[0]:
                        d["command_line"] = row[0]
                    if not d.get("name") and row[1]:
                        d["name"] = row[1]
                    if not d.get("path") and row[2]:
                        d["path"] = row[2]
            finally:
                conn.close()
    except Exception:
        pass
    return d


def apply_snapshot_rules(agent_id: str, module: str, items: List[Any], hostname: str = "") -> Dict[str, Any]:
    hits = match_snapshot(module, items)
    return report_rule_hits(agent_id, module, hits, hostname)


def _evm_match_blob(ev: Dict[str, Any]) -> str:
    et = str(ev.get("etype") or "").lower()
    summary = str(ev.get("summary") or "").lower()
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    path = str(detail.get("path") or detail.get("image") or "").lower()
    blob = summary + "\n" + path + "\n" + str(detail.get("command_line") or "").lower()
    px = detail.get("process_ext") if isinstance(detail.get("process_ext"), dict) else {}
    if px:
        blob += "\n" + str(px.get("parent_name") or "").lower()
        blob += "\n" + str(px.get("parent_path") or "").lower()
        blob += "\n" + str(px.get("grandparent_name") or "").lower()
    blob += "\n" + str(detail.get("parent_path") or "").lower()
    return blob


def _evm_rule_matches(r: Dict[str, Any], ev: Dict[str, Any]) -> bool:
    et = str(ev.get("etype") or "").lower()
    summary = str(ev.get("summary") or "").lower()
    detail = ev.get("detail") if isinstance(ev.get("detail"), dict) else {}
    want_et = str(r.get("etype") or "").lower()
    if want_et and want_et != et:
        return False
    sc = str(r.get("summary_contains") or "").lower()
    if sc and sc not in summary:
        return False
    prefixes = [str(p).strip() for p in (r.get("path_prefixes") or []) if str(p).strip()]
    if prefixes and not _path_scope_allowed(detail, prefixes):
        return False
    pn = str(r.get("parent_name_contains") or "").strip().lower()
    if pn:
        parent = str(detail.get("parent_name") or "").lower()
        if not parent and isinstance(detail.get("process_ext"), dict):
            parent = str(detail["process_ext"].get("parent_name") or "").lower()
        if pn not in parent:
            return False
    pats = [str(p).strip() for p in (r.get("patterns") or []) if str(p).strip() and str(p).strip() != "*"]
    if not pats:
        return True
    blob = _evm_match_blob(ev)
    how = str(r.get("match") or "substring").lower()
    for p in pats:
        if how == "regex":
            try:
                if re.search(p, blob, re.I):
                    return True
            except re.error:
                continue
        elif p.lower() in blob:
            return True
    return False


def match_live_evm_events(ev: Dict[str, Any]) -> List[Dict[str, Any]]:
    """与 Agent evmEvaluate 对齐：对已上报时间线事件做 EVM 匹配（含 agent-live 自定义规则）。"""
    if not isinstance(ev, dict):
        return []
    try:
        rules = export_evm_document().get("rules") or []
    except Exception:
        return []
    hits: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        if _evm_rule_matches(r, ev):
            hits.append(r)
    return hits[:8]


def export_evm_document() -> Dict[str, Any]:
    """端上 EVM：时间线/传感器启用规则的轻量条件包。"""
    rules: List[Dict[str, Any]] = []
    for r in list_rules(enabled_only=True):
        mods = r.get("modules") or []
        if r.get("source") != "sensor" and "timeline" not in mods:
            if "file" in mods or "process" in mods:
                rules.append({
                    "id": str(r.get("id") or ""),
                    "title": str(r.get("title") or ""),
                    "severity": str(r.get("severity") or "medium"),
                    "etype": "fim_add",
                    "summary_contains": "",
                    "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
                    "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
                    "match": str(r.get("match") or "substring"),
                    "signed_filter": str(r.get("signed_filter") or ""),
                    "building_block": bool(r.get("building_block")),
                })
                rules.append({
                    "id": str(r.get("id") or "") + ".etw",
                    "title": str(r.get("title") or "") + " (ETW创建)",
                    "severity": str(r.get("severity") or "medium"),
                    "etype": "file_create",
                    "summary_contains": "",
                    "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
                    "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
                    "match": str(r.get("match") or "substring"),
                    "signed_filter": str(r.get("signed_filter") or ""),
                    "building_block": bool(r.get("building_block")),
                })
            continue
        evm_item = {
            "id": str(r.get("id") or ""),
            "title": str(r.get("title") or ""),
            "severity": str(r.get("severity") or "medium"),
            "etype": str(r.get("etype") or "").strip(),
            "summary_contains": str(r.get("summary_contains") or "").strip(),
            "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
            "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
            "match": str(r.get("match") or "substring"),
            "signed_filter": str(r.get("signed_filter") or ""),
            "building_block": bool(r.get("building_block")),
        }
        pn = str(r.get("parent_name_contains") or "").strip()
        if pn:
            evm_item["parent_name_contains"] = pn[:64]
        rid = str(r.get("id") or "")
        if r.get("source") == "sensor" and rid in _SENSOR_EVM_SKIP_IDS:
            continue
        rules.append(evm_item)
    def _append_evm_rules(src_rules: List[Dict[str, Any]]) -> None:
        for r in src_rules:
            if not isinstance(r, dict):
                continue
            rules.append({
                "id": str(r.get("id") or ""),
                "title": str(r.get("title") or ""),
                "severity": str(r.get("severity") or "medium"),
                "etype": str(r.get("etype") or "").strip(),
                "summary_contains": str(r.get("summary_contains") or "").strip(),
                "path_prefixes": [str(p) for p in (r.get("path_prefixes") or []) if str(p).strip()][:12],
                "patterns": [str(p) for p in (r.get("patterns") or []) if str(p).strip()][:24],
                "match": str(r.get("match") or "substring"),
                "signed_filter": str(r.get("signed_filter") or ""),
                "building_block": bool(r.get("building_block")),
            })

    try:
        from . import elastic_detection_import as _edi

        _append_evm_rules(_edi.load_evm_import_rules(enabled_only=True))
    except Exception:
        pass
    try:
        from . import protections_import as _pi

        _append_evm_rules(_pi.load_evm_import_rules(enabled_only=True))
    except Exception:
        pass
    doc: Dict[str, Any] = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "rules": rules,
    }
    doc["rev"] = hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
    return doc


def rule_registry_fim_paths() -> List[str]:
    """注册表 FIM 扩展键（与 reg_watch 安全项互补，可按规则扩展）。"""
    out: List[str] = []
    seen = set()
    extras = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
    ]
    for p in extras:
        k = p.lower()
        if k not in seen:
            seen.add(k)
            out.append(p)
    for r in list_rules(enabled_only=True):
        if str(r.get("etype") or "").startswith("registry") or "registry" in str(r.get("title") or "").lower():
            for p in (r.get("path_prefixes") or []):
                ps = str(p).strip()
                if ps.upper().startswith("HK") and ps.lower() not in seen:
                    seen.add(ps.lower())
                    out.append(ps)
    return out[:32]


def list_platform_rule_stats() -> Dict[str, Any]:
    """兼容旧接口：返回独立规则库统计。"""
    rules = _merge_evm_rules_for_ui(list_rules())
    enabled = [r for r in rules if r.get("enabled", True)]
    return {
        "ok": True,
        "source": "Agent 独立规则库",
        "path": str(_path()),
        "count": len(rules),
        "enabled": len(enabled),
        "counts": {"agent_rules": len(rules), "enabled": len(enabled)},
        "items": rules,
    }
