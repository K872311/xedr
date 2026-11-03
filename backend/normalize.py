"""采集报告字段归一化（兼容 Go PascalCase / snake_case）"""
from __future__ import annotations
from typing import Any, Dict

_KEY_MAP = {
    "Location": "location", "Name": "name", "Command": "command", "Version": "version",
    "Vendor": "vendor", "InstallDate": "install_date", "SID": "sid",
    "AccountType": "account_type", "Disabled": "disabled", "Class": "class",
    "LocalAccount": "local_account", "Description": "description", "LastLogon": "last_logon",
    "ProfilePath": "profile_path", "Groups": "groups", "LoggedOn": "logged_on", "Domain": "domain",
    "Serial": "serial", "Desc": "desc", "Proto": "proto", "LocalAddr": "local_addr",
    "RemoteAddr": "remote_addr", "Status": "status", "PID": "pid", "Type": "type",
    "ProcessName": "process_name", "ImageName": "image", "OwningProcess": "pid",
    "Process": "process", "Owner": "owner",
    "Reason": "reason", "Severity": "severity", "Key": "key", "Value": "value",
    "Data": "data", "DisplayName": "display_name", "StartType": "start_type",
    "Path": "path", "TaskName": "task_name", "NextRun": "next_run", "Author": "author",
    "FullPath": "full_path", "Ext": "ext", "Size": "size", "MemKB": "mem_kb",
    "User": "user", "DLLs": "dlls", "IPConfig": "ipconfig", "ArpTable": "arp_table",
    "DNSCache": "dns_cache", "RouteTable": "route_table", "NetStatAll": "netstat_all",
    "CommandLine": "command_line", "LastLogon": "last_logon", "Groups": "groups",
    "ProfilePath": "profile_path", "LoggedOn": "logged_on",
}

_LIST_KEYS = [
    "processes", "services", "scheduled_tasks", "startup_items", "installed_programs",
    "users", "usb_devices", "established_connections", "file_scans", "suspicious_items",
    "prefetch_files", "open_ports", "run_mru", "ps_history", "hotfixes", "drivers",
    "wifi_profiles", "event_log_summary", "event_logs", "browser_artifacts",
    "driver_entries", "dns_cache_entries", "wmi_namespaces",
]

# 上传热路径禁止整树拷贝 / 乱码修复：14 万条 event_logs 会把 POST 拖到 40s+，前端 20s 超时。
_HEAVY_LIST_KEYS = frozenset({
    "file_scans", "event_logs", "mft_records", "files_tree", "mft_artifacts",
})


def _norm_obj(o: Any, *, walk_heavy: bool = True) -> Any:
    if isinstance(o, list):
        return [_norm_obj(x, walk_heavy=walk_heavy) for x in o]
    if isinstance(o, dict):
        out: Dict[str, Any] = {}
        for k, v in o.items():
            nk = _KEY_MAP.get(k, k)
            if (not walk_heavy) and nk in _HEAVY_LIST_KEYS and isinstance(v, list):
                if nk not in out or out[nk] in (None, "", []):
                    out[nk] = v
                continue
            if nk not in out or out[nk] in (None, "", []):
                out[nk] = _norm_obj(v, walk_heavy=walk_heavy)
        return out
    return o


def normalize_report(r: Any) -> Dict[str, Any]:
    if not isinstance(r, dict):
        return {}
    r = _norm_obj(r, walk_heavy=False)
    for key in _LIST_KEYS:
        if r.get(key) is None:
            r[key] = []
    if r.get("network") is None:
        r["network"] = {}
    # 修复 GBK→UTF8 / Latin-1 误读乱码（systeminfo / 进程模块等）。
    # event_logs / file_scans 体量太大，入库热路径不扫；匹配走 SQLite 原文。
    try:
        from .text_fix import fix_mojibake, fix_tree, sanitize_process_modules
        if isinstance(r.get("system_info"), str):
            r["system_info"] = fix_mojibake(r["system_info"])
        for k in ("hostname", "os", "os_name", "timezone"):
            if isinstance(r.get(k), str):
                r[k] = fix_mojibake(r[k])
        if isinstance(r.get("processes"), list) and r["processes"]:
            r["processes"] = fix_tree(r["processes"], depth=0)
            r = sanitize_process_modules(r)
        if isinstance(r.get("services"), list) and r["services"]:
            r["services"] = fix_tree(r["services"][:4000], depth=0)
        # Linux：用服务 ExecStart 回填启动项占位路径（旧 collect 常见）
        try:
            from .linux_sc_import import enrich_linux_startups
            r = enrich_linux_startups(r)
        except Exception:
            pass
    except Exception:
        pass
    return r
