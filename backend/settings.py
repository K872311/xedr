"""系统设置：platform_settings.json（优先 config/），启动时应用到运行时。"""
from __future__ import annotations
import json
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from . import config


def settings_path(*, for_write: bool = False) -> Path:
    return config.resolve_config_file("platform_settings.json", for_write=for_write)


# 兼容旧引用
SETTINGS_PATH = settings_path()

_DEFAULTS: Dict[str, Any] = {
    "auto_import_jg": False,
    # 20～50 人默认：总并发适中，大报告单独限流，避免把列表/上传接口拖死
    "job_max_workers": 10,
    "job_heavy_max": 3,
    "job_per_user_max": 5,  # 单用户同时排队+运行上限；0=不限制
    "session_ttl_days": 7,
    "session_idle_minutes": 30,  # 无操作自动下线；0=关闭
    "report_retention_days": 45,  # 0=不自动清理；默认 45 天防磁盘涨满
    "section_page_size": 600,
    "audit_enabled": True,
    "upload_max_mb": 1024,
    "upload_max_concurrent": 8,
    "job_queue_soft_limit": 60,
    "job_queue_hard_limit": 150,
    "site_name": "CNPC 终端应急响应分析平台",
    "note": "",
    "dir_root": "",
    "dir_rules": "",
    "dir_reports": "",
    "dir_jg": "",
    "dir_backup": "",
    "dir_ioc": "",
    "cfg_db": "",
    "cfg_redis": "",
    "cfg_es": "",
    "cfg_ai": "",
    "eventlog_min_level": "low",  # informational|low|medium|high|critical；log_rules 多为 info/low
    "registration_enabled": True,  # 默认开放申请，管理员可在系统设置关闭
    "registration_default_role": "analyst",
    # Agent 安装包内嵌的平台根地址（终端能访问的局域网/公网 IP，勿填 127.0.0.1）
    "agent_server_url": "",
}

_FIELDS = {
    "auto_import_jg": bool,
    "job_max_workers": int,
    "job_heavy_max": int,
    "job_per_user_max": int,
    "session_ttl_days": int,
    "session_idle_minutes": int,
    "report_retention_days": int,
    "section_page_size": int,
    "audit_enabled": bool,
    "upload_max_mb": int,
    "upload_max_concurrent": int,
    "job_queue_soft_limit": int,
    "job_queue_hard_limit": int,
    "site_name": str,
    "note": str,
    "dir_root": str,
    "dir_rules": str,
    "dir_reports": str,
    "dir_jg": str,
    "dir_backup": str,
    "dir_ioc": str,
    "cfg_db": str,
    "cfg_redis": str,
    "cfg_es": str,
    "cfg_ai": str,
    "eventlog_min_level": str,
    "registration_enabled": bool,
    "registration_default_role": str,
    "agent_server_url": str,
}


def _load_file() -> Dict[str, Any]:
    p = settings_path()
    if not p.exists():
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalize(cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg["job_max_workers"] = max(1, min(64, int(cfg.get("job_max_workers") or 10)))
    cfg["job_heavy_max"] = max(1, min(8, int(cfg.get("job_heavy_max") or 3)))
    cfg["job_per_user_max"] = max(0, min(32, int(cfg.get("job_per_user_max") or 0)))
    cfg["session_ttl_days"] = max(1, min(90, int(cfg.get("session_ttl_days") or 7)))
    try:
        idle = int(cfg.get("session_idle_minutes") if cfg.get("session_idle_minutes") is not None else 30)
    except (TypeError, ValueError):
        idle = 30
    cfg["session_idle_minutes"] = max(0, min(1440, idle))
    cfg["report_retention_days"] = max(0, min(3650, int(cfg.get("report_retention_days") or 0)))
    cfg["section_page_size"] = max(100, min(2000, int(cfg.get("section_page_size") or 600)))
    cfg["upload_max_mb"] = max(5, min(2048, int(cfg.get("upload_max_mb") or 1024)))
    cfg["upload_max_concurrent"] = max(1, min(32, int(cfg.get("upload_max_concurrent") or 8)))
    cfg["job_queue_soft_limit"] = max(10, min(500, int(cfg.get("job_queue_soft_limit") or 60)))
    cfg["job_queue_hard_limit"] = max(
        int(cfg["job_queue_soft_limit"]),
        min(1000, int(cfg.get("job_queue_hard_limit") or 150)),
    )
    cfg["auto_import_jg"] = bool(cfg.get("auto_import_jg"))
    cfg["audit_enabled"] = bool(cfg.get("audit_enabled"))
    cfg["registration_enabled"] = bool(cfg.get("registration_enabled"))
    _reg_role = str(cfg.get("registration_default_role") or "analyst").strip().lower()
    if _reg_role not in ("analyst", "readonly"):
        _reg_role = "analyst"
    cfg["registration_default_role"] = _reg_role
    cfg["site_name"] = str(cfg.get("site_name") or _DEFAULTS["site_name"])[:80]
    cfg["note"] = str(cfg.get("note") or "")[:500]
    cfg["agent_server_url"] = str(cfg.get("agent_server_url") or "").strip()[:400]
    for dk in ("dir_root", "dir_rules", "dir_reports", "dir_jg", "dir_backup", "dir_ioc",
               "cfg_db", "cfg_redis", "cfg_es", "cfg_ai"):
        cfg[dk] = str(cfg.get(dk) or "").strip()[:400]
    return cfg


_SETTINGS_CACHE: Dict[str, Any] = {}
_SETTINGS_CACHE_AT = 0.0
_SETTINGS_CACHE_TTL = 15.0  # 热路径短缓存；保存时失效


def invalidate_settings_cache() -> None:
    global _SETTINGS_CACHE, _SETTINGS_CACHE_AT
    _SETTINGS_CACHE = {}
    _SETTINGS_CACHE_AT = 0.0


def get_settings() -> Dict[str, Any]:
    global SETTINGS_PATH, _SETTINGS_CACHE, _SETTINGS_CACHE_AT
    now = time.time()
    if _SETTINGS_CACHE and (now - _SETTINGS_CACHE_AT) < _SETTINGS_CACHE_TTL:
        return deepcopy(_SETTINGS_CACHE)
    SETTINGS_PATH = settings_path()
    cfg = deepcopy(_DEFAULTS)
    cfg.update({k: v for k, v in _load_file().items() if k in _DEFAULTS})
    remote = None
    try:
        from . import platform_store
        remote = platform_store.load_runtime()
        if isinstance(remote, dict):
            cfg.update({k: v for k, v in remote.items() if k in platform_store.RUNTIME_KEYS})
    except Exception as e:
        print("[settings] mysql load:", e)
        remote = None
    cfg = _normalize(cfg)
    if remote is None:
        try:
            from . import platform_store
            platform_store.seed_runtime_from_local(cfg)
        except Exception:
            pass
    _SETTINGS_CACHE = deepcopy(cfg)
    _SETTINGS_CACHE_AT = now
    return cfg


def save_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    global SETTINGS_PATH
    invalidate_settings_cache()
    logs_patch = patch.get("service_logs") if isinstance(patch.get("service_logs"), dict) else None
    if logs_patch is not None:
        from .service_control import update_all_log_paths
        lr = update_all_log_paths(logs_patch)
        if not lr.get("ok"):
            raise ValueError(lr.get("error") or "日志路径保存失败")
    cur = _load_file()
    for k, typ in _FIELDS.items():
        if k not in patch:
            continue
        v = patch[k]
        if typ is bool:
            if isinstance(v, str):
                cur[k] = v.strip().lower() in ("1", "true", "yes", "on")
            else:
                cur[k] = bool(v)
        elif typ is int:
            try:
                cur[k] = int(v)
            except (TypeError, ValueError):
                continue
        else:
            cur[k] = "" if v is None else str(v)
    # 注册默认角色：仅允许 analyst / readonly
    if "registration_default_role" in cur:
        rr = str(cur.get("registration_default_role") or "analyst").strip().lower()
        cur["registration_default_role"] = rr if rr in ("analyst", "readonly") else "analyst"
    path = settings_path(for_write=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)
    SETTINGS_PATH = path
    try:
        from . import platform_store
        merged = deepcopy(_DEFAULTS)
        merged.update({k: v for k, v in cur.items() if k in _DEFAULTS})
        platform_store.save_runtime(_normalize(merged))
    except Exception as e:
        print("[settings] mysql save:", e)
    invalidate_settings_cache()
    apply_runtime()
    return get_settings()


def apply_runtime() -> Dict[str, Any]:
    """把设置应用到 jobs / auth / 数据目录等运行时。"""
    cfg = get_settings()
    try:
        from . import jobs
        jobs.set_max_workers(int(cfg.get("job_max_workers") or 1))
        jobs.set_heavy_max(int(cfg.get("job_heavy_max") or 2))
    except Exception as e:
        print("[settings] apply jobs:", e)
    try:
        from . import auth
        auth.set_session_ttl_days(int(cfg.get("session_ttl_days") or 7))
    except Exception as e:
        print("[settings] apply auth:", e)
    try:
        # 不传 override：走文件 + 搬家自愈；刚 save 过则文件已是最新值
        config.apply_data_dirs()
    except Exception as e:
        print("[settings] apply paths:", e)
    try:
        from . import ioc_db
        ioc_db.reload()
    except Exception as e:
        print("[settings] apply ioc:", e)
    try:
        from . import ip_catalog
        ip_catalog.ensure_loaded()
    except Exception as e:
        print("[settings] apply ip_catalog:", e)
    try:
        from .cache_config import reload_cache_config
        reload_cache_config()
    except Exception as e:
        print("[settings] apply cache_config:", e)
    try:
        from .http_security import sync_body_limit_from_settings
        sync_body_limit_from_settings()
    except Exception as e:
        print("[settings] apply body_limit:", e)
    return cfg


def _mysql_pool_size() -> int:
    try:
        from .mysql_db import load_db_config
        return max(2, min(32, int((load_db_config() or {}).get("pool_size") or 20)))
    except Exception:
        return 20


def _es_enabled() -> bool:
    try:
        from .es_client import es_config
        return bool((es_config() or {}).get("enabled"))
    except Exception:
        return False


def public_meta() -> Dict[str, Any]:
    """前端只读补充信息。"""
    cfg = get_settings()
    info = config.apply_data_dirs()
    # 自愈可能已改写文件，重新读一遍给前端展示
    cfg = get_settings()
    defaults = info.get("defaults") or config.program_default_dirs()
    logs: Dict[str, str] = {}
    try:
        from .service_control import list_saved_log_paths
        logs = list_saved_log_paths()
    except Exception:
        logs = {}
    return {
        **cfg,
        "paths": {
            "root": info["root"],
            "data_root": info.get("data_root") or info["root"],
            "config": info.get("config") or str(config.CONFIG_DIR),
            "web": info["web"],
            "admin_web": info["admin_web"],
            "rules": info["rules"],
            "reports": info["reports"],
            "jg": info["jg"],
            "backup": info["backup"],
            "ioc": info["ioc"],
            "defaults": defaults,
            "settings_file": str(settings_path()),
            "sources": {
                "root": info.get("source_root"),
                "rules": info.get("source_rules"),
                "reports": info.get("source_reports"),
                "jg": info.get("source_jg"),
                "backup": info.get("source_backup"),
                "ioc": info.get("source_ioc"),
            },
        },
        "service_logs": logs,
        "capacity": {
            "browse_users": 50,
            "analyze_parallel": int(cfg.get("job_max_workers") or 10),
            "analyze_heavy_parallel": int(cfg.get("job_heavy_max") or 3),
            "analyze_per_user": int(cfg.get("job_per_user_max") or 5),
            "upload_concurrent": int(cfg.get("upload_max_concurrent") or 8),
            "queue_soft": int(cfg.get("job_queue_soft_limit") or 60),
            "queue_hard": int(cfg.get("job_queue_hard_limit") or 150),
            "mysql_pool": _mysql_pool_size(),
            "elasticsearch": _es_enabled(),
            "note": (
                "按 20～50 人默认：分析并发 10、大报告 3、单用户同时任务 5、报告保留 45 天。"
                "明细仍在报告 SQLite；MySQL 只做索引；Redis 做会话/小缓存；ES 做告警全文与 IOC 快查（db_config.elasticsearch.enabled）。"
                "到「运行参数」改完保存即生效。"
            ),
        },
        "defaults": deepcopy(_DEFAULTS),
    }
